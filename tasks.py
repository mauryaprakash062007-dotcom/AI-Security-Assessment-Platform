"""
tasks.py
────────
Celery task that runs the two-phase scan pipeline:

  Phase 1 – Nmap:    discover open ports (XML output → parse_nmap_xml)
  Phase 2 – Nuclei:  if web ports found, run Nuclei against them
                     (JSONL output → parse_nuclei_jsonl)

The task writes progress back to the database so the API can expose
a /scan/status/{task_id} endpoint that the frontend polls.
"""

import subprocess
import tempfile
import os
import urllib.request
import ssl
from datetime import datetime
from typing import Optional

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlmodel import select

from celery_app import celery_app
from database import get_session
from models import Scan, Port, NucleiFinding
from scan_parser import parse_nmap_xml, parse_nuclei_jsonl, build_unified_result
import socket

# ── tunables ──────────────────────────────────────────────────────────────────
NMAP_ARGS = [
    "-sV",          # service/version detection
    "--version-intensity", "9",
    "-T4",
    "-Pn",          # aggressive timing (safe on LANs; use -T3 for remote targets)
    "-oX", "-",     # XML to stdout so we can parse without a temp file
    "--open",       # only show open ports
]

NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei")  # assumes nuclei is on PATH
NUCLEI_TEMPLATES_DIR = os.getenv(
    "NUCLEI_TEMPLATES_DIR",
    os.path.expanduser("~/nuclei-templates"),
)

# Focused tags that find real vulnerabilities in a reasonable time (~5-10 min)
# instead of running ALL 11,500+ templates which takes 1+ hour.
NUCLEI_TAGS = ",".join([
    "cve",              # Known CVE vulnerabilities
    "sqli",             # SQL injection
    "xss",              # Cross-site scripting
    "rce",              # Remote code execution
    "lfi",              # Local file inclusion
    "rfi",              # Remote file inclusion  
    "ssrf",             # Server-side request forgery
    "redirect",         # Open redirect
    "exposure",         # Sensitive data exposure
    "misconfig",        # Security misconfiguration
    "default-login",    # Default credentials
    "takeover",         # Subdomain/service takeover
    "unauth",           # Unauthenticated access
    "disclosure",       # Information disclosure
    "tech",             # Technology detection
    "panel",            # Exposed admin panels
    "cisa",             # CISA known exploited vulns
])

NUCLEI_ARGS = [
    "-silent",
    "-json-export", "{output_file}",
    "-tags", NUCLEI_TAGS,
    "-severity", "info,low,medium,high,critical",
    "-timeout", "15",
    "-retries", "2",
    "-bulk-size", "25",
    "-concurrency", "25",
    "-rate-limit", "150",
]
WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 4443, 5000, 9000, 9443}

# Ports to probe via HTTP when nmap finds nothing (covers most real websites)
HTTP_PROBE_PORTS = [
    (443, "https"),
    (80,  "http"),
    (8443, "https"),
    (8080, "http"),
]
# ─────────────────────────────────────────────────────────────────────────────


class ScanTask(Task):
    """Custom base class so we can handle unexpected failures cleanly."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id: Optional[int] = kwargs.get("scan_id") or (args[1] if len(args) > 1 else None)
        if scan_id:
            _mark_scan_failed(scan_id, str(exc))


@celery_app.task(
    bind=True,
    base=ScanTask,
    name="tasks.run_scan_pipeline",
    max_retries=0,
)
def run_scan_pipeline(self, target: str, scan_id: int) -> dict:
    """
    Entry point called by the FastAPI route.

    Parameters
    ----------
    target:  IP address or hostname to scan
    scan_id: PK of the already-created Scan row (status="queued")

    Returns
    -------
    The unified result dict (also stored in the DB).
    """
    try:
        # ── Phase 1: Nmap ─────────────────────────────────────────────────────
        _update_scan_phase(scan_id, "scanning_ports", "nmap")

        nmap_xml = _run_nmap(target)
        nmap_result = parse_nmap_xml(nmap_xml)

        open_ports = nmap_result.get("open_ports", [])
        _persist_ports(scan_id, open_ports)

        # ── Phase 1b: HTTP probing fallback ───────────────────────────────────
        # Many real-world sites (AWS, Cloudflare, etc.) block nmap SYN probes
        # but respond to normal HTTP requests. If nmap found no web ports,
        # probe common web ports via HTTP to detect live web services.
        web_ports = [p for p in open_ports if p["is_web"]]

        if not web_ports:
            print(f"[INFO] Nmap found no web ports for {target}, trying HTTP probing...")
            _update_scan_phase(scan_id, "probing_http", "http_probe")
            probed_ports = _http_probe(target)

            if probed_ports:
                print(f"[INFO] HTTP probing found {len(probed_ports)} web port(s)")
                # Add probed ports to nmap_result so they appear in final output
                for pp in probed_ports:
                    open_ports.append(pp)
                    nmap_result.setdefault("open_ports", []).append(pp)
                _persist_ports(scan_id, probed_ports)
                web_ports = probed_ports
            else:
                print(f"[INFO] HTTP probing also found no web services on {target}")

        # ── Phase 2: Nuclei (web vulnerability scanning) ──────────────────────
        nuclei_findings: list[dict] = []

        if web_ports:
            _update_scan_phase(scan_id, "scanning_web", "nuclei")

            # Build target URLs for every web port found
            target_urls = _build_web_targets(target, web_ports)
            nuclei_findings = _run_nuclei(target_urls)
            _persist_nuclei_findings(scan_id, nuclei_findings)

        # ── Finalise ──────────────────────────────────────────────────────────
        unified = build_unified_result(
            scan_id=scan_id,
            target=target,
            nmap_result=nmap_result,
            nuclei_findings=nuclei_findings,
        )

        _update_scan_phase(
            scan_id,
            status="complete",
            phase="done",
            completed_at=datetime.utcnow(),
        )

        return unified

    except SoftTimeLimitExceeded:
        _mark_scan_failed(scan_id, "Scan timed out after 9 minutes.")
        raise
    except Exception as exc:
        _mark_scan_failed(scan_id, str(exc))
        raise


# ── Private helpers ───────────────────────────────────────────────────────────

def _resolve_target(target: str) -> str:
    """Resolve hostname to IP so Nmap doesn't rely on worker DNS."""
    try:
        ip = socket.gethostbyname(target)
        print(f"[DEBUG] Resolved {target} -> {ip}")
        return ip
    except socket.gaierror:
        print(f"[DEBUG] Could not resolve {target}, using as-is")
        return target


def _http_probe(target: str) -> list[dict]:
    """
    Probe common web ports via actual HTTP/HTTPS requests.
    This works even when nmap is blocked by firewalls because it uses
    the same HTTP connection that a browser would use.
    """
    discovered = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port, scheme in HTTP_PROBE_PORTS:
        url = f"{scheme}://{target}:{port}/"
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0 (SecurityScan)")
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            server = resp.headers.get("Server", "")
            print(f"[HTTP-PROBE] {url} -> {resp.status} (Server: {server})")
            discovered.append({
                "port":    port,
                "proto":   "tcp",
                "service": "https" if scheme == "https" else "http",
                "product": server.split("/")[0] if server else "",
                "version": server.split("/")[1] if "/" in server else "",
                "is_web":  True,
            })
        except Exception as e:
            print(f"[HTTP-PROBE] {url} -> failed ({type(e).__name__}: {e})")
            continue

    return discovered


def _run_nmap(target: str) -> str:
    resolved = _resolve_target(target)
    cmd = ["nmap"] + NMAP_ARGS + [resolved]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Nmap exited {result.returncode}: {result.stderr[:400]}")
    return result.stdout


def _run_nuclei(target_urls: list[str]) -> list[dict]:
    if not target_urls:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as targets_file:
        targets_file.write("\n".join(target_urls))
        targets_path = targets_file.name

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        output_path = tmp.name

    try:
        args = [a.replace("{output_file}", output_path) for a in NUCLEI_ARGS]
        cmd = [NUCLEI_BIN, "-list", targets_path] + args

        print(f"[DEBUG] Running Nuclei command: {' '.join(cmd)}")
        print(f"[DEBUG] Target URLs: {target_urls}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,   # hard cap at 10 minutes
            )
            if result.stderr:
                print(f"[DEBUG] Nuclei stderr (last 500 chars): {result.stderr[-500:]}")
        except subprocess.TimeoutExpired:
            print("[WARN] Nuclei timed out after 10 min, using partial results")

        with open(output_path, "r") as fh:
            raw = fh.read()

        findings = parse_nuclei_jsonl(raw)
        print(f"[INFO] Nuclei found {len(findings)} findings")
        return findings
        
    finally:
        if os.path.exists(targets_path):
            os.unlink(targets_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def _build_web_targets(target: str, web_ports: list[dict]) -> list[str]:
    urls = set()
    for p in web_ports:
        port_num = p["port"]
        scheme = "https" if port_num in {443, 8443, 4443, 9443} else "http"
        # For standard ports, use clean URL (no port number) since nuclei
        # handles them better and avoids duplicate scanning
        if port_num == 80:
            urls.add(f"http://{target}")
        elif port_num == 443:
            urls.add(f"https://{target}")
        else:
            urls.add(f"{scheme}://{target}:{port_num}")
    return list(urls)


# ── DB helpers ────────────────────────────────────────────────────────────────

def _update_scan_phase(
    scan_id: int,
    status: str,
    phase: str,
    completed_at: Optional[datetime] = None,
) -> None:
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.phase = phase
            if completed_at:
                scan.completed_at = completed_at
            session.add(scan)
            session.commit()


def _mark_scan_failed(scan_id: int, reason: str) -> None:
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = f"failed: {reason[:200]}"
            scan.phase = "failed"
            scan.completed_at = datetime.utcnow()
            session.add(scan)
            session.commit()


def _persist_ports(scan_id: int, open_ports: list[dict]) -> None:
    with get_session() as session:
        for p in open_ports:
            port_rec = Port(
                scan_id=scan_id,
                port=p["port"],
                service=p.get("service", ""),
                product=p.get("product") or None,
                version=p.get("version") or None,
                is_web=p.get("is_web", False),
            )
            session.add(port_rec)
        session.commit()


def _persist_nuclei_findings(scan_id: int, findings: list[dict]) -> None:
    with get_session() as session:
        for f in findings:
            rec = NucleiFinding(
                scan_id=scan_id,
                template_id=f.get("template_id"),
                template_name=f.get("template_name"),
                severity=f.get("severity"),
                host=f.get("host"),
                matched_at=f.get("matched_at"),
                description=f.get("description"),
                tags=f.get("tags"),
            )
            session.add(rec)
        session.commit()
