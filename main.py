"""
main.py  (refactored)
──────────────────────
FastAPI application.
"""

import asyncio
import csv
import io
import json as json_mod
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from auth import get_api_key
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from input_validator import validate_target, ValidationError
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from sqlmodel import select

from celery_app import celery_app
from cve_engine import lookup_vulnerabilities
from database import create_db_and_tables, get_session
from models import NucleiFinding, Port, Scan, Vulnerability, ZeroDayAlert, AttackPath, AttackPathStep
from nvd_engine import search_nvd
from cvss_risk_engine import calculate_risk_score
from tasks import run_scan_pipeline
from unified_engine import get_unified_vulnerabilities

app = FastAPI(title="Security Platform API – Async Edition")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
def read_root():
    return {"message": "Security Assessment Platform Backend is running."}

@app.get("/api/auth/verify")
def verify_auth(api_key: str = Depends(get_api_key)):
    return {"status": "ok", "message": "Authenticated"}

class ScanRequest(BaseModel):
    target: str


@app.post("/scan", status_code=202)
@limiter.limit("5/minute")
def start_scan(request: Request, body: ScanRequest, api_key: str = Depends(get_api_key)):
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target must not be empty")

    try:
        validate_target(target)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    with get_session() as session:
        scan_record = Scan(target=target, status="queued", phase="queued")
        session.add(scan_record)
        session.commit()
        session.refresh(scan_record)
        scan_id = scan_record.id

    task = run_scan_pipeline.delay(target, scan_id)

    with get_session() as session:
        scan_record = session.get(Scan, scan_id)
        scan_record.task_id = task.id
        session.add(scan_record)
        session.commit()

    return {
        "message":  "Scan started",
        "scan_id":  scan_id,
        "task_id":  task.id,
        "poll_url": f"/scan/status/{task.id}",
    }


@app.get("/scan/status/{task_id}")
def get_task_status(task_id: str, api_key: str = Depends(get_api_key)):
    result = celery_app.AsyncResult(task_id)

    response: dict = {
        "task_id": task_id,
        "state":   result.state,
    }

    if result.state == "SUCCESS":
        response["result"] = result.result
    elif result.state == "FAILURE":
        response["error"] = str(result.info)
    elif result.state in ("STARTED", "PENDING"):
        with get_session() as session:
            stmt = select(Scan).where(Scan.task_id == task_id)
            scan = session.exec(stmt).first()
            if scan:
                response["phase"]   = scan.phase
                response["status"]  = scan.status
                response["scan_id"] = scan.id

    return response


@app.get("/scan/result/{scan_id}")
def get_scan_result(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        ports = session.exec(
            select(Port).where(Port.scan_id == scan_id)
        ).all()

        nuclei_findings = session.exec(
            select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)
        ).all()

        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in nuclei_findings:
            sev = (f.severity or "info").lower()
            if sev in severity_summary:
                severity_summary[sev] += 1

        # Fetch CVEs for risk calculation (if they exist in DB)
        vulnerabilities_in_db = session.exec(
            select(Vulnerability).join(Port, Vulnerability.port_id == Port.id).where(Port.scan_id == scan_id)
        ).all()
        risk_score = calculate_risk_score(vulnerabilities_in_db, nuclei_findings)
        
        # Risk level determination based on standard CVSS tiers
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
            "target":           scan.target,
            "status":           scan.status,
            "phase":            scan.phase,
            "created_at":       scan.created_at,
            "completed_at":     scan.completed_at,
            "ai_remediation":   scan.ai_remediation,
            "open_ports":       [
                {
                    "port":    p.port,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "is_web":  p.is_web,
                }
                for p in ports
            ],
            "nuclei_findings":  [
                {
                    "template_id":   f.template_id,
                    "template_name": f.template_name,
                    "severity":      f.severity,
                    "host":          f.host,
                    "matched_at":    f.matched_at,
                    "description":   f.description,
                    "tags":          f.tags,
                }
                for f in nuclei_findings
            ],
            "severity_summary": severity_summary,
            "total_findings":   len(nuclei_findings),
            "risk_score":       risk_score,
            "risk_level":       risk_level,
        }


@app.get("/history")
def get_scan_history(api_key: str = Depends(get_api_key)):
    with get_session() as session:
        scans = session.exec(select(Scan)).all()
        return scans


@app.get("/zero-day-alerts")
def get_zero_day_alerts(api_key: str = Depends(get_api_key)):
    """Retrieve all autonomous zero-day alerts generated by the ATEM engine."""
    with get_session() as session:
        alerts = session.exec(select(ZeroDayAlert).order_by(ZeroDayAlert.discovered_at.desc())).all()
        return alerts


@app.get("/history/{scan_id}")
def get_scan(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        ports = session.exec(
            select(Port).where(Port.scan_id == scan_id)
        ).all()
        return {"scan": scan, "ports": ports}


@app.get("/vulnerabilities/{scan_id}")
def get_vulnerabilities(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        ports = session.exec(
            select(Port).where(Port.scan_id == scan_id)
        ).all()
        findings = []
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        vulnerabilities = get_unified_vulnerabilities(ports)
        for vuln in vulnerabilities:
            # Find the corresponding port to link the vulnerability
            port = next((p for p in ports if p.port == vuln["port"]), None)
            if not port:
                continue
            
            existing = session.exec(
                select(Vulnerability).where(
                    Vulnerability.port_id == port.id,
                    Vulnerability.cve_id == vuln["cve"],
                )
            ).first()
            if not existing:
                session.add(
                    Vulnerability(
                        port_id=port.id,
                        cve_id=vuln["cve"],
                        severity=vuln["severity"],
                        description=vuln["description"],
                    )
                )
            sev = vuln.get("severity", "unknown").lower()
            if sev in severity_summary:
                severity_summary[sev] += 1
            findings.append({
                "port": port.port, "service": port.service,
                "product": port.product, "version": port.version,
                "cve": vuln["cve"], "severity": vuln["severity"],
                "description": vuln["description"],
            })

        session.commit()

        scan = session.get(Scan, scan_id)
        if scan and not scan.ai_remediation:
            from ai_remediation import generate_remediation_summary
            nuclei_findings = session.exec(select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)).all()
            nuclei_list = [{"template_id": f.template_id, "severity": f.severity} for f in nuclei_findings]
            vuln_list = [{"cve": v.cve_id, "severity": v.severity, "port": p.port} for v in session.exec(select(Vulnerability).where(Vulnerability.port_id.in_([p.id for p in ports]))) for p in ports if p.id == v.port_id]
            
            scan.ai_remediation = generate_remediation_summary(vuln_list, nuclei_list)
            session.add(scan)
            session.commit()

        return {
            "scan_id": scan_id,
            "summary": severity_summary,
            "total_vulnerabilities": len(findings),
            "vulnerabilities": findings,
            "ai_remediation": scan.ai_remediation if scan else None,
        }

@app.get("/scans/{scan_id}/attack-path")
def get_attack_path(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        existing_path = session.exec(select(AttackPath).where(AttackPath.scan_id == scan_id)).first()
        
        if existing_path:
            steps = session.exec(select(AttackPathStep).where(AttackPathStep.attack_path_id == existing_path.id).order_by(AttackPathStep.step_number)).all()
            return {
                "scan_id": scan_id,
                "summary": existing_path.summary,
                "steps": [s.model_dump() for s in steps]
            }
            
        # If it doesn't exist, generate it
        from ai_threat_modeler import generate_attack_path
        
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
        nuclei_findings = session.exec(select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)).all()
        nuclei_list = [{"template_id": f.template_id, "severity": f.severity} for f in nuclei_findings]
        vuln_list = [{"cve": v.cve_id, "severity": v.severity, "port": p.port} for v in session.exec(select(Vulnerability).where(Vulnerability.port_id.in_([p.id for p in ports]))) for p in ports if p.id == v.port_id]
        
        ap_data = generate_attack_path(vuln_list, nuclei_list, scan.waf_status)
        
        if ap_data.get("summary", "").startswith("Failed to generate AI attack path"):
            return {
                "scan_id": scan_id,
                "summary": ap_data.get("summary"),
                "steps": []
            }
            
        new_path = AttackPath(scan_id=scan_id, summary=ap_data.get("summary", "Generated Attack Path"))
        session.add(new_path)
        session.commit()
        session.refresh(new_path)
        
        for step_data in ap_data.get("steps", []):
            step = AttackPathStep(
                attack_path_id=new_path.id,
                step_number=step_data.get("step_number", 1),
                title=step_data.get("title", ""),
                description=step_data.get("description", ""),
                mitre_tactic=step_data.get("mitre_tactic"),
                mitre_technique=step_data.get("mitre_technique"),
                mitre_technique_name=step_data.get("mitre_technique_name")
            )
            session.add(step)
        
        session.commit()
        
        # Return the generated data
        return {
            "scan_id": scan_id,
            "summary": new_path.summary,
            "steps": ap_data.get("steps", [])
        }



def _get_db_vulnerabilities(session, ports):
    port_ids = [p.id for p in ports]
    if not port_ids:
        return []
    db_vulns = session.exec(select(Vulnerability).where(Vulnerability.port_id.in_(port_ids))).all()
    
    vuln_results = []
    for v in db_vulns:
        port = next((p for p in ports if p.id == v.port_id), None)
        vuln_results.append({
            "cve": v.cve_id,
            "severity": v.severity,
            "description": v.description,
            "port": port.port if port else None,
            "service": port.service if port else None,
            "product": port.product if port else None,
            "version": port.version if port else None,
            "source": "DB"
        })
    return vuln_results

@app.get("/stored-vulnerabilities/{scan_id}")
def get_stored_vulnerabilities(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        ports = session.exec(
            select(Port).where(Port.scan_id == scan_id)
        ).all()
        results = _get_db_vulnerabilities(session, ports)
        return {"scan_id": scan_id, "stored_vulnerabilities": results}


@app.get("/report/{scan_id}")
def generate_report(scan_id: int, api_key: str = Depends(get_api_key)):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
        nuclei_findings = session.exec(
            select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)
        ).all()
        vuln_results = _get_db_vulnerabilities(session, ports)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vuln_results:
        sev = str(vuln.get("severity", "unknown")).lower()
        if sev in summary:
            summary[sev] += 1

    nuclei_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = (f.severity or "info").lower()
        if sev in nuclei_sev:
            nuclei_sev[sev] += 1
    risk_score = calculate_risk_score(vuln_results, nuclei_findings)
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

    high_count = summary["high"] + summary["critical"]
    executive_summary = (
        f"{len(vuln_results)} vulnerabilities detected. "
        f"{high_count} high/critical severity vulnerabilities require immediate attention."
    )
    return {
        "target":            scan.target,
        "status":            scan.status,
        "scan_date":         scan.created_at,
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "executive_summary": executive_summary,
        "summary":           summary,
        "ports":             ports,
        "vulnerabilities":   vuln_results,
    }


@app.get("/report/{scan_id}/pdf")
def generate_pdf_report(scan_id: int, api_key: str = Depends(get_api_key)):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
        nuclei_findings = session.exec(
            select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)
        ).all()
        
        attack_path = session.exec(select(AttackPath).where(AttackPath.scan_id == scan_id)).first()
        attack_path_steps = []
        if attack_path:
            attack_path_steps = session.exec(
                select(AttackPathStep)
                .where(AttackPathStep.attack_path_id == attack_path.id)
                .order_by(AttackPathStep.step_number)
            ).all()

        vuln_results = _get_db_vulnerabilities(session, ports)

    nuclei_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = (f.severity or "info").lower()
        if sev in nuclei_sev:
            nuclei_sev[sev] += 1

    risk_score = calculate_risk_score(vuln_results, nuclei_findings)
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
    risk = {"risk_score": risk_score, "risk_level": risk_level, "confidence": 0.8}

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vuln_results:
        sev = str(v.get("severity", "")).lower()
        if sev in summary:
            summary[sev] += 1

    pdf_path = f"/tmp/report_{scan_id}.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold",
                                 spaceAfter=12, textColor=colors.HexColor("#1e3a5f"))
    style_h2    = ParagraphStyle("h2", fontSize=14, fontName="Helvetica-Bold",
                                 spaceBefore=16, spaceAfter=8,
                                 textColor=colors.HexColor("#1e3a5f"))
    style_body  = ParagraphStyle("body", fontSize=10, fontName="Helvetica",
                                 spaceAfter=6, leading=14)
    style_small = ParagraphStyle("small", fontSize=8, fontName="Helvetica",
                                 spaceAfter=4, textColor=colors.grey)

    SEV_COLORS = {
        "critical": colors.HexColor("#dc2626"),
        "high":     colors.HexColor("#ea580c"),
        "medium":   colors.HexColor("#d97706"),
        "low":      colors.HexColor("#16a34a"),
        "info":     colors.HexColor("#2563eb"),
    }

    def sev_color(sev):
        return SEV_COLORS.get((sev or "").lower(), colors.grey)

    def hex_color(c):
        return f"{int(c.red*255):02x}{int(c.green*255):02x}{int(c.blue*255):02x}"

    content = []

    content.append(Paragraph("Security Assessment Report", style_title))
    content.append(Paragraph(f"<b>Target:</b> {scan.target}", style_body))
    content.append(Paragraph(f"<b>Scan Date:</b> {scan.created_at}", style_body))
    content.append(Paragraph(f"<b>Status:</b> {scan.status}", style_body))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Risk Summary", style_h2))
    rc = sev_color(risk["risk_level"].lower())
    risk_table = Table([
        [Paragraph("<b>Risk Level</b>", style_body),
         Paragraph("<b>Risk Score</b>", style_body),
         Paragraph("<b>Confidence</b>", style_body)],
        [Paragraph(f"<font color='#{hex_color(rc)}'>{risk['risk_level']}</font>", style_body),
         Paragraph(f"{risk['risk_score']}/100", style_body),
         Paragraph(f"{int(risk['confidence']*100)}%", style_body)],
    ], colWidths=[5*cm, 5*cm, 5*cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("PADDING",    (0,0), (-1,-1), 8),
    ]))
    content.append(risk_table)
    content.append(Spacer(1, 12))

    content.append(Paragraph("Executive Summary", style_h2))
    total_high = summary["high"] + summary["critical"]
    exec_text = (
        f"{len(vuln_results)} CVE vulnerabilities and {len(nuclei_findings)} Nuclei findings "
        f"detected across {len(ports)} open ports. "
        f"{total_high} high/critical severity issues require immediate attention. "
        f"Risk Level: {risk['risk_level']} (confidence: {int(risk['confidence']*100)}%)."
    )
    content.append(Paragraph(exec_text, style_body))

    content.append(Paragraph("Severity Breakdown", style_h2))
    sev_data = [["Category", "Critical", "High", "Medium", "Low"],
                ["CVE Vulnerabilities", str(summary["critical"]), str(summary["high"]),
                 str(summary["medium"]), str(summary["low"])],
                ["Nuclei Findings", str(nuclei_sev["critical"]), str(nuclei_sev["high"]),
                 str(nuclei_sev["medium"]), str(nuclei_sev["low"])]]
    sev_table = Table(sev_data, colWidths=[5*cm, 3*cm, 3*cm, 3*cm, 3*cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
        ("ALIGN",      (1,0), (-1,-1), "CENTER"),
        ("PADDING",    (0,0), (-1,-1), 8),
    ]))
    content.append(sev_table)
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"Open Ports ({len(ports)})", style_h2))
    if ports:
        port_data = [["Port", "Service", "Product", "Version", "Web?"]]
        for p in ports:
            port_data.append([str(p.port), p.service or "—", p.product or "—",
                              (p.version or "—")[:30], "Yes" if p.is_web else "No"])
        port_table = Table(port_data, colWidths=[2*cm, 3*cm, 4*cm, 5*cm, 2*cm])
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
            ("PADDING",    (0,0), (-1,-1), 6),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
        ]))
        content.append(port_table)
    else:
        content.append(Paragraph("No open ports found.", style_body))
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"Nuclei Findings ({len(nuclei_findings)})", style_h2))
    if nuclei_findings:
        for f in nuclei_findings:
            c = sev_color(f.severity or "info")
            content.append(Paragraph(
                f"<b>{f.template_name or f.template_id}</b> "
                f"[<font color='#{hex_color(c)}'>{(f.severity or 'info').upper()}</font>]",
                style_body))
            content.append(Paragraph(f"<b>Matched:</b> {f.matched_at or '—'}", style_small))
            if f.description:
                content.append(Paragraph(f.description[:300], style_small))
            if f.tags:
                content.append(Paragraph(f"<b>Tags:</b> {f.tags}", style_small))
            content.append(Spacer(1, 6))
    else:
        content.append(Paragraph("No Nuclei findings.", style_body))
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"CVE Vulnerabilities ({len(vuln_results)})", style_h2))
    if vuln_results:
        for v in vuln_results:
            c = sev_color(v.get("severity", ""))
            content.append(Paragraph(
                f"<b>{v['cve']}</b> — "
                f"<font color='#{hex_color(c)}'>{v.get('severity','Unknown')}</font> "
                f"| Port {v.get('port','?')} ({v.get('service','?')}) | Source: {v.get('source','')}",
                style_body))
            content.append(Paragraph(v.get("description","")[:200], style_small))
            content.append(Spacer(1, 4))
    else:
        content.append(Paragraph("No CVE vulnerabilities found.", style_body))
    content.append(Spacer(1, 12))

    if scan.ai_remediation:
        content.append(Paragraph("AI Security Analysis & Remediation", style_h2))
        
        # We need to sanitize and format the markdown for ReportLab slightly
        # We can just split by double newline for paragraphs and strip out markdown artifacts
        remediation_paragraphs = scan.ai_remediation.split('\n\n')
        for para in remediation_paragraphs:
            # ReportLab requires valid XML if using Paragraphs, so we strip bold markdown
            cleaned_para = para.replace('**', '')
            # Escape HTML chars to prevent XML parsing errors
            cleaned_para = cleaned_para.replace('<', '&lt;').replace('>', '&gt;')
            
            content.append(Paragraph(cleaned_para, style_body))
            content.append(Spacer(1, 6))

    if attack_path:
        content.append(Paragraph("Cyber Kill Chain (Attack Path)", style_h2))
        content.append(Paragraph(attack_path.summary, style_body))
        content.append(Spacer(1, 6))
        
        for step in attack_path_steps:
            step_text = (
                f"<b>Step {step.step_number}: {step.title}</b><br/>"
                f"<i>{step.mitre_tactic} - {step.mitre_technique} ({step.mitre_technique_name})</i><br/>"
                f"{step.description}"
            )
            content.append(Paragraph(step_text, style_body))
            content.append(Spacer(1, 6))

    doc.build(content)
    return FileResponse(
        path=pdf_path,
        filename=f"security_report_{scan.target}_{scan_id}.pdf",
        media_type="application/pdf"
    )


# ── JSON export ───────────────────────────────────────────────────────────────

@app.get("/report/{scan_id}/json")
def generate_json_report(scan_id: int, api_key: str = Depends(get_api_key)):
    """Download the full scan report as a JSON file."""
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
        nuclei_findings = session.exec(
            select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)
        ).all()

    vuln_results = get_unified_vulnerabilities(ports)

    nuclei_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = (f.severity or "info").lower()
        if sev in nuclei_sev:
            nuclei_sev[sev] += 1

    risk_score = calculate_risk_score(vuln_results, nuclei_findings)
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
    risk = {"risk_score": risk_score, "risk_level": risk_level, "confidence": 0.8}

    report_data = {
        "scan_id":         scan_id,
        "target":          scan.target,
        "status":          scan.status,
        "scan_date":       scan.created_at.isoformat() if scan.created_at else None,
        "completed_at":    scan.completed_at.isoformat() if scan.completed_at else None,
        "risk_score":      risk["risk_score"],
        "risk_level":      risk["risk_level"],
        "confidence":      risk.get("confidence", 0),
        "severity_summary": nuclei_sev,
        "open_ports": [
            {"port": p.port, "service": p.service, "product": p.product,
             "version": p.version, "is_web": p.is_web}
            for p in ports
        ],
        "nuclei_findings": [
            {"template_id": f.template_id, "template_name": f.template_name,
             "severity": f.severity, "host": f.host, "matched_at": f.matched_at,
             "description": f.description, "tags": f.tags}
            for f in nuclei_findings
        ],
        "cve_vulnerabilities": vuln_results,
        "ai_remediation": scan.ai_remediation,
    }

    json_bytes = json_mod.dumps(report_data, indent=2, default=str).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report_{scan.target}_{scan_id}.json"'},
    )


# ── CSV export ────────────────────────────────────────────────────────────────

@app.get("/report/{scan_id}/csv")
def generate_csv_report(scan_id: int, api_key: str = Depends(get_api_key)):
    """Download the scan report as a flat CSV file."""
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
        nuclei_findings = session.exec(
            select(NucleiFinding).where(NucleiFinding.scan_id == scan_id)
        ).all()

    vuln_results = get_unified_vulnerabilities(ports)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "type", "port", "service", "product", "version",
        "severity", "cve_id", "template_id", "description",
        "matched_at", "tags",
    ])

    # Port rows
    for p in ports:
        writer.writerow([
            "port", p.port, p.service or "", p.product or "", p.version or "",
            "", "", "", "", "", "",
        ])

    # Nuclei finding rows
    for f in nuclei_findings:
        writer.writerow([
            "nuclei", "", "", "", "",
            f.severity or "", "", f.template_id or "",
            (f.description or "")[:500], f.matched_at or "", f.tags or "",
        ])

    # CVE vulnerability rows
    for v in vuln_results:
        writer.writerow([
            "cve", v.get("port", ""), v.get("service", ""),
            v.get("product", ""), v.get("version", ""),
            v.get("severity", ""), v.get("cve", ""), "",
            (v.get("description", "") or "")[:500], "", "",
        ])

    # AI Remediation
    if scan.ai_remediation:
        writer.writerow([
            "ai_remediation", "", "", "", "",
            "", "", "", scan.ai_remediation, "", "",
        ])

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report_{scan.target}_{scan_id}.csv"'},
    )


# ── WebSocket live scan progress ──────────────────────────────────────────────

PHASE_PCT = {
    "queued": 5, "scanning_ports": 40, "nmap": 40, "probing_http": 55,
    "scanning_web": 75, "nuclei": 75, "complete": 100, "done": 100, "failed": 100,
}


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan_progress(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    try:
        prev_phase = None
        while True:
            with get_session() as session:
                scan = session.get(Scan, scan_id)

            if not scan:
                await websocket.send_json({"type": "error", "detail": "Scan not found"})
                break

            phase  = scan.phase or "queued"
            status = scan.status or "queued"

            # Only send updates when the phase changes (or first message)
            if phase != prev_phase:
                pct = PHASE_PCT.get(phase, 5)
                if phase in ("done", "complete"):
                    await websocket.send_json({
                        "type": "complete", "scan_id": scan_id,
                        "phase": "done", "pct": 100,
                    })
                    break
                elif phase == "failed" or status.startswith("failed"):
                    await websocket.send_json({
                        "type": "failed", "scan_id": scan_id,
                        "phase": "failed", "status": status, "pct": 100,
                    })
                    break
                else:
                    await websocket.send_json({
                        "type": "progress", "scan_id": scan_id,
                        "phase": phase, "status": status, "pct": pct,
                    })
                prev_phase = phase

            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass


# ── Scan diff (compare two scans) ─────────────────────────────────────────────

@app.get("/scan/diff")
def diff_scans(scan_a: int = Query(...), scan_b: int = Query(...)):
    """Compare two scans and return added/removed/unchanged ports and findings."""
    with get_session() as session:
        sa = session.get(Scan, scan_a)
        sb = session.get(Scan, scan_b)
        if not sa or not sb:
            raise HTTPException(status_code=404, detail="One or both scans not found")

        ports_a = session.exec(select(Port).where(Port.scan_id == scan_a)).all()
        ports_b = session.exec(select(Port).where(Port.scan_id == scan_b)).all()
        nf_a    = session.exec(select(NucleiFinding).where(NucleiFinding.scan_id == scan_a)).all()
        nf_b    = session.exec(select(NucleiFinding).where(NucleiFinding.scan_id == scan_b)).all()

    # ── Port diff (keyed by port number) ──────────────────────────────────
    def port_dict(p):
        return {"port": p.port, "service": p.service, "product": p.product,
                "version": p.version, "is_web": p.is_web}

    set_a = {p.port for p in ports_a}
    set_b = {p.port for p in ports_b}

    ports_added   = [port_dict(p) for p in ports_b if p.port not in set_a]
    ports_removed = [port_dict(p) for p in ports_a if p.port not in set_b]
    ports_unchanged = [port_dict(p) for p in ports_b if p.port in set_a]

    # ── Nuclei diff (keyed by template_id + matched_at) ───────────────────
    def finding_dict(f):
        return {"template_id": f.template_id, "template_name": f.template_name,
                "severity": f.severity, "host": f.host, "matched_at": f.matched_at,
                "description": f.description, "tags": f.tags}

    def finding_key(f):
        return (f.template_id or "", f.matched_at or "")

    keys_a = {finding_key(f) for f in nf_a}
    keys_b = {finding_key(f) for f in nf_b}

    findings_new       = [finding_dict(f) for f in nf_b if finding_key(f) not in keys_a]
    findings_fixed     = [finding_dict(f) for f in nf_a if finding_key(f) not in keys_b]
    findings_unchanged = [finding_dict(f) for f in nf_b if finding_key(f) in keys_a]

    # ── Risk delta ────────────────────────────────────────────────────────
    def risk_for(ports_list, nf_list):
        risk_score = calculate_risk_score([], nf_list)
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
        return {"risk_score": risk_score, "risk_level": risk_level}

    risk_a = risk_for(ports_a, nf_a)
    risk_b = risk_for(ports_b, nf_b)

    return {
        "scan_a": {"id": sa.id, "target": sa.target,
                   "created_at": sa.created_at.isoformat() if sa.created_at else None},
        "scan_b": {"id": sb.id, "target": sb.target,
                   "created_at": sb.created_at.isoformat() if sb.created_at else None},
        "ports": {
            "added":     ports_added,
            "removed":   ports_removed,
            "unchanged": ports_unchanged,
        },
        "nuclei_findings": {
            "new":       findings_new,
            "fixed":     findings_fixed,
            "unchanged": findings_unchanged,
        },
        "risk_delta": {
            "before": {"score": risk_a["risk_score"], "level": risk_a["risk_level"]},
            "after":  {"score": risk_b["risk_score"], "level": risk_b["risk_level"]},
        },
    }


@app.get("/live-vulnerabilities/{scan_id}")
def live_vulnerabilities(scan_id: int):
    with get_session() as session:
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
    results = []
    for port in ports:
        vulns = search_nvd(f"{port.product} {port.version}")
        results.append({"product": port.product, "version": port.version, "vulnerabilities": vulns})
    return {"scan_id": scan_id, "results": results}


@app.get("/unified-vulnerabilities/{scan_id}")
def unified_vulnerabilities(scan_id: int):
    with get_session() as session:
        ports = session.exec(select(Port).where(Port.scan_id == scan_id)).all()
    findings = []
    for port in ports:
        nvd_results = search_nvd(f"{port.product} {port.version}")
        if isinstance(nvd_results, list) and nvd_results:
            for vuln in nvd_results:
                findings.append({
                    "source": "NVD", "port": port.port, "service": port.service,
                    "product": port.product, "version": port.version,
                    "cve": vuln["cve"], "severity": vuln.get("severity"),
                    "description": vuln["description"],
                })
        else:
            for vuln in lookup_vulnerabilities(port.product, port.version):
                findings.append({
                    "source": "LOCAL", "port": port.port, "service": port.service,
                    "product": port.product, "version": port.version,
                    "cve": vuln["cve"], "severity": vuln["severity"],
                    "description": vuln["description"],
                })
    return {"scan_id": scan_id, "total_vulnerabilities": len(findings), "vulnerabilities": findings}
