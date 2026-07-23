"""
scan_parser.py
──────────────
Pure-Python helpers that transform raw tool output into the unified
dict structure used everywhere in the application.
"""

import json
import xml.etree.ElementTree as ET
from typing import Any

from cvss_risk_engine import calculate_risk_score

WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000, 4443, 5000, 9000, 9443}


def parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    root = ET.fromstring(xml_output)

    result: dict[str, Any] = {
        "host": "",
        "status": "unknown",
        "open_ports": [],
    }

    hosts_found = []
    
    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        
        host_addr = ""
        if addr_el is not None:
            host_addr = addr_el.get("addr", "")
            
        # Try to get hostname if available
        hostname = host_addr
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", host_addr)

        if hostname:
            hosts_found.append(hostname)

        status_el = host_el.find("status")
        if status_el is not None and result["status"] == "unknown":
            # Just take the status of the first host
            result["status"] = status_el.get("state", "unknown")

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

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

            # Embed the subdomain in the service name so it shows in the UI and AI context
            if hostname:
                service = f"{service} [{hostname}]"

            cpe = ""
            if svc_el is not None:
                cpe_el = svc_el.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    cpe = cpe_el.text

            result["open_ports"].append({
                "port":    port_num,
                "proto":   proto,
                "service": service,
                "product": product,
                "version": version,
                "cpe":     cpe,
                "is_web":  port_num in WEB_PORTS,
            })
            
    if hosts_found:
        result["host"] = ", ".join(hosts_found)

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


def filter_false_positives(open_ports: list[dict[str, Any]], nuclei_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Cross-references Nuclei findings against Nmap port and service fingerprinting.
    Drops findings that are biologically impossible (e.g. IIS on Linux, or Apache on Nginx).
    """
    filtered = []
    
    # Collect known products from Nmap to use as a baseline
    known_products = [p.get("product", "").lower() for p in open_ports if p.get("product")]
    
    for finding in nuclei_findings:
        tags = finding.get("tags", "").lower()
        template_id = finding.get("template_id", "").lower()
        name = finding.get("template_name", "").lower()
        
        is_false_positive = False
        
        # Rule 1: If Nuclei claims an IIS vulnerability, but Nmap says it's Apache/Nginx
        if "iis" in tags or "iis" in template_id:
            if any("apache" in prod or "nginx" in prod for prod in known_products):
                is_false_positive = True
                
        # Rule 2: If Nuclei claims Apache, but Nmap says IIS/Nginx
        if "apache" in tags or "apache" in template_id:
            if any("iis" in prod or "nginx" in prod for prod in known_products):
                is_false_positive = True

        if not is_false_positive:
            filtered.append(finding)
            
    return filtered


def build_unified_result(
    scan_id: int,
    target: str,
    nmap_result: dict[str, Any],
    nuclei_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    # 1. Filter False Positives using contextual fingerprinting
    open_ports = nmap_result.get("open_ports", [])
    valid_nuclei_findings = filter_false_positives(open_ports, nuclei_findings)

    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in valid_nuclei_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_summary:
            severity_summary[sev] += 1

    risk_score = calculate_risk_score([], valid_nuclei_findings)
    if risk_score >= 90:
        risk_level = "Critical"
    elif risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    return {
        "scan_id":          scan_id,
        "target":           target,
        "resolved_host":    nmap_result.get("host", target),
        "host_status":      nmap_result.get("status", "unknown"),
        "open_ports":       open_ports,
        "web_ports_found":  [p for p in open_ports if p["is_web"]],
        "nuclei_findings":  valid_nuclei_findings,
        "severity_summary": severity_summary,
        "total_findings":   len(valid_nuclei_findings),
        "risk_score":       risk_score,
        "risk_level":       risk_level,
        "confidence":       1.0,
    }
