import pytest
from scan_parser import filter_false_positives

def test_filter_false_positives_iis_on_nginx():
    open_ports = [
        {"port": 80, "product": "nginx/1.18.0"}
    ]
    nuclei_findings = [
        {"template_id": "iis-shortname", "template_name": "IIS Shortname Vulnerability", "tags": "iis,windows"},
        {"template_id": "nginx-version", "template_name": "Nginx Version Detect", "tags": "nginx"}
    ]
    
    filtered = filter_false_positives(open_ports, nuclei_findings)
    assert len(filtered) == 1
    assert filtered[0]["template_id"] == "nginx-version"

def test_filter_false_positives_apache_on_iis():
    open_ports = [
        {"port": 443, "product": "Microsoft IIS httpd 10.0"}
    ]
    nuclei_findings = [
        {"template_id": "apache-struts", "template_name": "Apache Struts RCE", "tags": "apache,rce"},
        {"template_id": "iis-auth-bypass", "template_name": "IIS Auth Bypass", "tags": "iis"}
    ]
    
    filtered = filter_false_positives(open_ports, nuclei_findings)
    assert len(filtered) == 1
    assert filtered[0]["template_id"] == "iis-auth-bypass"

def test_filter_false_positives_no_conflict():
    open_ports = [
        {"port": 80, "product": "Apache httpd"}
    ]
    nuclei_findings = [
        {"template_id": "apache-struts", "template_name": "Apache Struts RCE", "tags": "apache,rce"},
        {"template_id": "generic-xss", "template_name": "Reflected XSS", "tags": "xss"}
    ]
    
    filtered = filter_false_positives(open_ports, nuclei_findings)
    assert len(filtered) == 2
