KNOWN_VULNS = {
    ("OpenSSH", "6.6.1p1 Ubuntu 2ubuntu2.13"): [
        {
            "cve": "CVE-2018-15473",
            "severity": "Medium",
            "description": "Username enumeration vulnerability"
        }
    ],

    ("Apache httpd", "2.4.7"): [
        {
            "cve": "CVE-2017-3167",
            "severity": "High",
            "description": "Authentication bypass vulnerability"
        },
        {
            "cve": "CVE-2017-3169",
            "severity": "Medium",
            "description": "Denial of service vulnerability"
        }
    ]
}


def lookup_vulnerabilities(product, version):
    return KNOWN_VULNS.get(
        (product, version),
        []
    )
