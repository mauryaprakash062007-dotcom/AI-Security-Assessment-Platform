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
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
        targets_to_scan = [target]
        
        # ── Phase 0: Subdomain Enumeration ────────────────────────────────────
        import re
        is_domain = re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target)
        # Avoid running on IPs or things like 'localhost'
        if is_domain and not target.replace(".", "").isdigit() and target != "localhost":
            _update_scan_phase(scan_id, "enumerating_subdomains", "subfinder")
            subdomains = _run_subfinder(target)
            if subdomains:
                # Limit to top 10 to avoid massive scan times
                targets_to_scan.extend(subdomains[:10])
                targets_to_scan = list(set(targets_to_scan))
                logger.info(f"Subfinder found {len(subdomains)} subdomains. Scanning {len(targets_to_scan)} targets.")

        # ── Phase 1: Nmap ─────────────────────────────────────────────────────
        _update_scan_phase(scan_id, "scanning_ports", "nmap")

        nmap_xml = _run_nmap(targets_to_scan)
        nmap_result = parse_nmap_xml(nmap_xml)

        open_ports = nmap_result.get("open_ports", [])
        _persist_ports(scan_id, open_ports)

        # ── Phase 1b: HTTP probing fallback ───────────────────────────────────
        # Many real-world sites (AWS, Cloudflare, etc.) block nmap SYN probes
        # but respond to normal HTTP requests. If nmap found no web ports,
        # probe common web ports via HTTP to detect live web services.
        web_ports = [p for p in open_ports if p["is_web"]]

        if not web_ports:
            logger.info(f"Nmap found no web ports for {target}, trying HTTP probing...")
            _update_scan_phase(scan_id, "probing_http", "http_probe")
            probed_ports = _http_probe(target)

            if probed_ports:
                logger.info(f"HTTP probing found {len(probed_ports)} web port(s)")
                # Add probed ports to nmap_result so they appear in final output
                for pp in probed_ports:
                    open_ports.append(pp)
                    nmap_result.setdefault("open_ports", []).append(pp)
                _persist_ports(scan_id, probed_ports)
                web_ports = probed_ports
            else:
                logger.info(f"HTTP probing also found no web services on {target}")

        # ── Phase 2: Active Validation (WAF Detection) ────────────────────────
        waf_status = None
        if web_ports:
            _update_scan_phase(scan_id, "probing_waf", "wafw00f")
            target_urls = _build_web_targets(target, web_ports)
            if target_urls:
                waf_status = _run_wafw00f(target_urls[0])
                with get_session() as session:
                    scan_record = session.get(Scan, scan_id)
                    scan_record.waf_status = waf_status
                    session.add(scan_record)
                    session.commit()

        # ── Phase 3: Distributed Nuclei Scanning (Chord) ──────────────────────
        if web_ports and target_urls:
            _update_scan_phase(scan_id, "scanning_web", "nuclei")
            
            from celery import chord
            # Break down the scan into smaller chunks (e.g. 1 URL per task)
            # This allows massive parallelization across a fleet of celery workers
            header = [run_nuclei_target.s(scan_id, [url]) for url in target_urls]
            callback = finalize_scan.s(scan_id, target, nmap_result)
            
            # Replace the current task with the chord so the frontend can continue
            # polling this exact task_id, which will now resolve when the chord finishes!
            raise self.replace(chord(header, callback))

        # If no web ports were found, finalize immediately
        return finalize_scan(None, scan_id, target, nmap_result)

    except SoftTimeLimitExceeded:
        _mark_scan_failed(scan_id, "Scan timed out after 9 minutes.")
        raise
    except Exception as exc:
        if type(exc).__name__ in ("Replace", "Ignore"):
            raise
        _mark_scan_failed(scan_id, str(exc))
        raise


# ── Private helpers ───────────────────────────────────────────────────────────

def _resolve_target(target: str) -> str:
    """Resolve hostname to IP so Nmap doesn't rely on worker DNS."""
    try:
        ip = socket.gethostbyname(target)
        logger.debug(f"Resolved {target} -> {ip}")
        return ip
    except socket.gaierror:
        logger.debug(f"Could not resolve {target}, using as-is")
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
            logger.info(f"[HTTP-PROBE] {url} -> {resp.status} (Server: {server})")
            discovered.append({
                "port":    port,
                "proto":   "tcp",
                "service": "https" if scheme == "https" else "http",
                "product": server.split("/")[0] if server else "",
                "version": server.split("/")[1] if "/" in server else "",
                "cpe":     "",
                "is_web":  True,
            })
        except Exception as e:
            logger.warning(f"[HTTP-PROBE] {url} -> failed ({type(e).__name__}: {e})")
            continue

    return discovered


def _run_subfinder(domain: str) -> list[str]:
    """Run subfinder to enumerate subdomains."""
    try:
        logger.debug(f"Running subfinder on {domain}")
        cmd = ["subfinder", "-d", domain, "-silent"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = res.stdout
        subdomains = [line.strip() for line in output.split('\n') if line.strip()]
        return subdomains
    except Exception as e:
        logger.error(f"[SUBFINDER] Error: {e}")
        return []


def _run_nmap(targets: list[str]) -> str:
    resolved_targets = []
    for t in targets:
        resolved_targets.append(_resolve_target(t))
        
    cmd = ["nmap"] + NMAP_ARGS + resolved_targets
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Nmap exited {result.returncode}: {result.stderr[:400]}")
    return result.stdout


def _run_wafw00f(target_url: str) -> str:
    """Run wafw00f to detect Web Application Firewalls."""
    try:
        logger.debug(f"Running wafw00f on {target_url}")
        cmd = ["wafw00f", target_url]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = res.stdout
        
        if "No WAF detected" in output or "is behind" not in output:
            return "No WAF Detected"
            
        # Parse the specific WAF name
        for line in output.split('\n'):
            if "is behind" in line and "WAF" in line:
                import re
                clean_line = re.sub(r'\x1b\[.*?m', '', line)
                return clean_line.strip()
                
        return "Unknown WAF Detected"
    except Exception as e:
        logger.error(f"[WAFW00F] Error: {e}")
        return "WAF Detection Failed"


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

        logger.debug(f"Running Nuclei command: {' '.join(cmd)}")
        logger.debug(f"Target URLs: {target_urls}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,   # hard cap at 10 minutes
            )
            if result.stderr:
                logger.debug(f"Nuclei stderr (last 500 chars): {result.stderr[-500:]}")
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei timed out after 10 min, using partial results")

        with open(output_path, "r") as fh:
            raw = fh.read()

        findings = parse_nuclei_jsonl(raw)
        logger.info(f"Nuclei found {len(findings)} findings")
        return findings
        
    finally:
        if os.path.exists(targets_path):
            os.unlink(targets_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def _build_web_targets(target: str, web_ports: list[dict]) -> list[str]:
    urls = set()
    import re
    for p in web_ports:
        port_num = p["port"]
        scheme = "https" if port_num in {443, 8443, 4443, 9443} else "http"
        
        # Extract the specific subdomain if it was appended by the parser
        actual_target = target
        service = p.get("service", "")
        match = re.search(r'\[(.*?)\]', service)
        if match:
            actual_target = match.group(1)
            
        # For standard ports, use clean URL (no port number) since nuclei
        # handles them better and avoids duplicate scanning
        if port_num == 80:
            urls.add(f"http://{actual_target}")
        elif port_num == 443:
            urls.add(f"https://{actual_target}")
        else:
            urls.add(f"{scheme}://{actual_target}:{port_num}")
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
                cpe=p.get("cpe") or None,
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

# ── Distributed Tasks (Chord children & callback) ─────────────────────────────

@celery_app.task(bind=True, base=ScanTask, name="tasks.run_nuclei_target", max_retries=0)
def run_nuclei_target(self, scan_id: int, target_urls: list[str]) -> list[dict]:
    """Run nuclei on a subset of target URLs (part of a Celery Chord)."""
    findings = _run_nuclei(target_urls)
    _persist_nuclei_findings(scan_id, findings)
    return findings


@celery_app.task(bind=True, base=ScanTask, name="tasks.finalize_scan", max_retries=0)
def finalize_scan(self, chord_results: Optional[list[list[dict]]], scan_id: int, target: str, nmap_result: dict) -> dict:
    """
    Callback task that runs after all nuclei targets are scanned.
    """
    # Flatten the list of lists returned by the chord
    nuclei_findings = []
    if chord_results:
        for findings in chord_results:
            nuclei_findings.extend(findings)

    # Re-fetch waf_status from DB since it was saved in phase 2
    waf_status = None
    with get_session() as session:
        scan_record = session.get(Scan, scan_id)
        if scan_record:
            waf_status = scan_record.waf_status

    unified = build_unified_result(
        scan_id=scan_id,
        target=target,
        nmap_result=nmap_result,
        nuclei_findings=nuclei_findings,
    )
    
    # Inject WAF context into unified result before AI remediation runs
    if waf_status and waf_status != "No WAF Detected":
        unified["waf_status"] = waf_status

    _update_scan_phase(
        scan_id,
        status="complete",
        phase="done",
        completed_at=datetime.utcnow(),
    )

    return unified


# ── ATEM (Autonomous Threat Exposure Management) ─────────────────────────────

@celery_app.task(name="tasks.poll_threat_intelligence")
def poll_threat_intelligence():
    """
    Periodic task (Celery Beat) that polls NVD for critical CVEs published 
    in the last 24 hours, and cross-references them against our known assets.
    """
    import requests
    from datetime import datetime, timedelta
    from models import ZeroDayAlert
    
    logger.info("[ATEM] Waking up to poll for new Zero-Days...")
    
    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)
    
    # NVD API 2.0 date format: YYYY-MM-DDTHH:MM:SS.000
    # Note: For production without an API key, NVD is heavily rate-limited. 
    # This is a conceptual implementation of the polling logic.
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": yesterday.isoformat() + ".000",
        "pubEndDate": now.isoformat() + ".000",
        "cvssV3Severity": "CRITICAL"
    }
    
    try:
        resp = requests.get(nvd_url, params=params, timeout=20)
        if resp.status_code != 200:
            logger.error(f"[ATEM] Failed to poll NVD: {resp.status_code}")
            return
            
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        logger.info(f"[ATEM] Found {len(vulnerabilities)} critical CVEs published in the last 24 hours.")
        
        with get_session() as session:
            # Get all distinct products we have ever scanned
            all_ports = session.exec(select(Port)).all()
            
            for v_data in vulnerabilities:
                cve = v_data.get("cve", {})
                cve_id = cve.get("id")
                
                # Extract all vulnerable CPE criteria from this CVE
                cve_cpes = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable", False):
                                cpe_criteria = match.get("criteria", "").lower()
                                if cpe_criteria:
                                    cve_cpes.append(cpe_criteria)
                
                # Match against our historical assets via exact or partial CPE matching
                for p in all_ports:
                    if not p.cpe:
                        continue
                        
                    asset_cpe = p.cpe.lower()
                    
                    # NVD CPE format is cpe:2.3:part:vendor:product:version:...
                    # Nmap sometimes provides cpe:/part:vendor:product:version
                    # We will do a generic matching: vendor, product, and version must align.
                    
                    # Simplify comparison by checking if the specific Nmap CPE string is contained in the NVD criteria 
                    # or if the core components match.
                    match_found = False
                    
                    for cve_cpe in cve_cpes:
                        # Extract product and version for more resilient matching
                        # cpe:2.3:a:apache:http_server:2.4.49:...
                        parts = cve_cpe.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5]
                            
                            # check if vendor, product, and version are all present in the asset's CPE
                            if vendor in asset_cpe and product in asset_cpe and version != "*" and version in asset_cpe:
                                match_found = True
                                break
                    
                    if match_found:
                        existing_alert = session.exec(
                            select(ZeroDayAlert).where(
                                ZeroDayAlert.target == f"Historical Scan ID: {p.scan_id}",
                                ZeroDayAlert.cve_id == cve_id
                            )
                        ).first()
                        
                        if not existing_alert:
                            logger.warning(f"[ATEM] 🚨 EXACT CPE MATCH! {cve_id} affects {p.cpe} (Target: {p.scan_id})")
                            
                            alert = ZeroDayAlert(
                                target=f"Historical Scan ID: {p.scan_id}",
                                cve_id=cve_id,
                                description=f"AUTONOMOUS ALERT: A new critical vulnerability was just published matching your specific asset configuration ({p.cpe}).",
                                severity="CRITICAL"
                            )
                            session.add(alert)
                            session.commit()
                            
    except Exception as e:
        logger.error(f"[ATEM] Error polling NVD: {e}")
