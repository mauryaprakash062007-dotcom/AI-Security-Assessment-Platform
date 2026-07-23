import pytest
from scan_parser import parse_nmap_xml, parse_nuclei_jsonl

def test_parse_nmap_xml():
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <status state="up"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache httpd" version="2.4.41">
                    <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
                </service>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="nginx" version="1.18.0"/>
            </port>
            <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    result = parse_nmap_xml(xml_data)
    assert result["host"] == "192.168.1.100"
    assert result["status"] == "up"
    
    open_ports = result["open_ports"]
    assert len(open_ports) == 2
    
    port_80 = next(p for p in open_ports if p["port"] == 80)
    assert port_80["service"] == "http"
    assert port_80["product"] == "Apache httpd"
    assert port_80["version"] == "2.4.41"
    assert port_80["cpe"] == "cpe:/a:apache:http_server:2.4.41"
    assert port_80["is_web"] is True

    port_443 = next(p for p in open_ports if p["port"] == 443)
    assert port_443["service"] == "https"
    assert port_443["product"] == "nginx"
    assert port_443["is_web"] is True

def test_parse_nuclei_jsonl():
    jsonl_data = """{"template-id": "CVE-2021-41773", "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "critical", "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.", "tags": ["cve", "cve2021", "apache", "lfi"]}, "host": "http://192.168.1.100", "matched-at": "http://192.168.1.100/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"}
{"template-id": "tech-detect", "info": {"name": "Technology Detection", "severity": "info", "tags": ["tech"]}, "host": "http://192.168.1.100", "matched-at": "http://192.168.1.100"}"""
    
    findings = parse_nuclei_jsonl(jsonl_data)
    assert len(findings) == 2
    
    cve_finding = findings[0]
    assert cve_finding["template_id"] == "CVE-2021-41773"
    assert cve_finding["severity"] == "critical"
    assert cve_finding["host"] == "http://192.168.1.100"
    assert "cve2021" in cve_finding["tags"]
    assert "apache" in cve_finding["tags"]

    tech_finding = findings[1]
    assert tech_finding["template_id"] == "tech-detect"
    assert tech_finding["severity"] == "info"
