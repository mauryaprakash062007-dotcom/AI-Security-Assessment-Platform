from cve_engine import lookup_vulnerabilities
from nvd_engine import search_nvd

def _build_query(product, version, service):
    parts = []

    if product and product.strip() and product.strip() not in ("", "None", "tcpwrapped"):
        parts.append(product.strip())
    elif service and service.strip() not in ("", "None", "tcpwrapped", "unknown"):
        # Fall back to service name e.g. "http", "ssh", "postgresql"
        parts.append(service.strip())

    if version and version.strip() and version.strip() != "None":
        ver = version.split()[0]
        parts.append(ver)

    return " ".join(parts)

def get_unified_vulnerabilities(ports):
    findings = []

    for port in ports:
        # Skip ports with no useful info
        if not getattr(port, 'cpe', "") and (not port.product or port.product.strip() in ("", "None")):
            continue

        query = _build_query(port.product, port.version, port.service)
        cpe = getattr(port, 'cpe', "")
        
        # Even if query is empty, we might have a cpe
        if not query and not cpe:
            continue

        nvd_results = search_nvd(query, cpe)

        if isinstance(nvd_results, list) and len(nvd_results) > 0:
            for vuln in nvd_results:
                findings.append({
                    "source":      "NVD",
                    "port":        port.port,
                    "service":     port.service,
                    "product":     port.product,
                    "version":     port.version,
                    "cve":         vuln["cve"],
                    "severity":    vuln.get("severity", "Unknown"),
                    "description": vuln["description"],
                })
        else:
            # Fall back to local CVE database
            local_results = lookup_vulnerabilities(port.product, port.version)
            for vuln in local_results:
                findings.append({
                    "source":      "LOCAL",
                    "port":        port.port,
                    "service":     port.service,
                    "product":     port.product,
                    "version":     port.version,
                    "cve":         vuln["cve"],
                    "severity":    vuln["severity"],
                    "description": vuln["description"],
                })

    return findings
