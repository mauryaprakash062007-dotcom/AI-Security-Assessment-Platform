def calculate_risk_score(vulnerabilities: list, nuclei_findings: list) -> int:
    """
    Calculates a 0-100 risk score based on the highest severity finding,
    adjusted dynamically by contextual factors (e.g., public web exposure, sensitive ports).
    """
    severity_map = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 5,
        "unknown": 0
    }

    max_score = 0

    # 1. Analyze CVE Vulnerabilities
    for v in vulnerabilities:
        sev = str(v.get("severity", "") if isinstance(v, dict) else getattr(v, "severity", "")).lower()
        base_score = severity_map.get(sev, 0)
        
        port_num = v.get("port") if isinstance(v, dict) else getattr(v, "port", None)
        
        # Contextual modifiers
        context_modifier = 0
        
        # Extremely sensitive internal/management ports exposed
        if port_num in (22, 3389, 445, 139, 1433, 3306):
            context_modifier += 10
        
        # Standard web ports get a slight bump because they are highly targeted
        if port_num in (80, 443, 8080, 8443):
            context_modifier += 5

        adjusted_score = base_score + context_modifier
        if adjusted_score > max_score:
            max_score = adjusted_score

    # 2. Analyze Nuclei Findings
    for f in nuclei_findings:
        sev = str(f.get("severity", "") if isinstance(f, dict) else getattr(f, "severity", "")).lower()
        base_score = severity_map.get(sev, 0)
        
        # Nuclei findings usually target web by default, bump slightly
        context_modifier = 5
        
        adjusted_score = base_score + context_modifier
        if adjusted_score > max_score:
            max_score = adjusted_score

    # 3. Cumulative Risk Bump
    # Add a little bump for multiple issues of the same severity to simulate cumulative risk
    bump = (len(vulnerabilities) + len(nuclei_findings)) // 2
    
    final_score = min(100, max_score + bump)
    return final_score
