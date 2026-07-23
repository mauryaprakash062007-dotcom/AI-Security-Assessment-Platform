import pytest
from cvss_risk_engine import calculate_risk_score

def test_calculate_risk_score_critical():
    vulnerabilities = [{"severity": "critical", "port": 443}]
    nuclei_findings = []
    
    score = calculate_risk_score(vulnerabilities, nuclei_findings)
    # Base 90 + Web Port Bump 5 = 95
    assert score == 95

def test_calculate_risk_score_high_sensitive_port():
    vulnerabilities = [{"severity": "high", "port": 22}]
    nuclei_findings = []
    
    score = calculate_risk_score(vulnerabilities, nuclei_findings)
    # Base 75 + Sensitive Port Bump 10 = 85
    assert score == 85

def test_calculate_risk_score_nuclei_findings():
    vulnerabilities = []
    nuclei_findings = [{"severity": "medium"}]
    
    score = calculate_risk_score(vulnerabilities, nuclei_findings)
    # Base 50 + Nuclei Bump 5 = 55
    assert score == 55

def test_calculate_risk_score_cumulative_bump():
    vulnerabilities = [{"severity": "low", "port": 8080}]
    nuclei_findings = [{"severity": "info"}, {"severity": "info"}]
    
    score = calculate_risk_score(vulnerabilities, nuclei_findings)
    # Vuln base 25 + web bump 5 = 30
    # Nuclei base 5 + bump 5 = 10
    # Max score = 30
    # Cumulative bump = (1 + 2) // 2 = 1
    # Total = 31
    assert score == 31

def test_calculate_risk_score_max_cap():
    vulnerabilities = [{"severity": "critical", "port": 22}, {"severity": "critical", "port": 3389}]
    nuclei_findings = [{"severity": "critical"} for _ in range(10)]
    
    score = calculate_risk_score(vulnerabilities, nuclei_findings)
    # Base 90 + Sensitive Port Bump 10 = 100
    # Cumulative bump will be added but it should cap at 100
    assert score == 100
