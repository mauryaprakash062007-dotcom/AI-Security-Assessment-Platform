"""
scan_parser.py
──────────────
Pure-Python helpers that transform raw tool output into the unified
dict structure used everywhere in the application.
"""

import json
import xml.etree.ElementTree as ET
from typing import Any

from ml_risk_engine import calculate_ml_risk

WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 4443, 5000, 9000, 9443}


def parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    root = ET.fromstring(xml_output)

    result: dict[str, Any] = {
        "host": "",
        "status": "unknown",
        "open_ports": [],
    }

    host_el = root.find("host")
    if host_el is None:
        return result

    addr_el = host_el.find("address[@addrtype='ipv4']")
    if addr_el is None:
        addr_el = host_el.find("address")
    if addr_el is not None:
        result["host"] = addr_el.get("addr", "")

    status_el = host_el.find("status")
    if status_el is not None:
        result["status"] = status_el.get("state", "unknown")

    ports_el = host_el.find("ports")
    if ports_el is None:
        return result

    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        port_num = int(port_el.get("portid", 0))
        proto    = port_el.get("protocol", "tcp")

        svc_el  = port_el.find("service")
        service = svc_el.get("name", "")    if svc_el is not None else ""
        product = svc_el.get("product", "") if svc_el is not None else ""
        version = svc_el.get("version", "") if svc_el is not None else ""

        result["open_ports"].append({
            "port":    port_num,
            "proto":   proto,
            "service": service,
            "product": product,
            "version": version,
            "is_web":  port_num in WEB_PORTS,
        })

    return result


def parse_nuclei_jsonl(jsonl_output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Nuclei can output a JSON array or one object per line (JSONL)
    raw = jsonl_output.strip()
    if not raw:
        return findings

    # Try parsing the whole output as a JSON array first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            objects = parsed
        else:
            objects = [parsed]
    except json.JSONDecodeError:
        # Fall back to JSONL (one object per line)
        objects = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        info = obj.get("info", {})
        tags = info.get("tags", [])

        findings.append({
            "template_id":   obj.get("template-id", ""),
            "template_name": info.get("name", ""),
            "severity":      info.get("severity", "info").lower(),
            "host":          obj.get("host", ""),
            "matched_at":    obj.get("matched-at", ""),
            "description":   info.get("description", ""),
            "tags":          ",".join(tags) if isinstance(tags, list) else str(tags),
        })

    return findings


def build_unified_result(
    scan_id: int,
    target: str,
    nmap_result: dict[str, Any],
    nuclei_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_summary:
            severity_summary[sev] += 1

    scan_result_for_ml = {
        "open_ports":       nmap_result.get("open_ports", []),
        "nuclei_findings":  nuclei_findings,
        "severity_summary": severity_summary,
    }
    risk = calculate_ml_risk(scan_result_for_ml, [])

    return {
        "scan_id":          scan_id,
        "target":           target,
        "resolved_host":    nmap_result.get("host", target),
        "host_status":      nmap_result.get("status", "unknown"),
        "open_ports":       nmap_result.get("open_ports", []),
        "web_ports_found":  [p for p in nmap_result.get("open_ports", []) if p["is_web"]],
        "nuclei_findings":  nuclei_findings,
        "severity_summary": severity_summary,
        "total_findings":   len(nuclei_findings),
        "risk_score":       risk["risk_score"],
        "risk_level":       risk["risk_level"],
        "confidence":       risk["confidence"],
    }
