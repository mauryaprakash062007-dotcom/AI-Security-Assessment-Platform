import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_nvd(keyword):
    # Clean up bad keywords before searching
    if not keyword or keyword.strip() in ("None", "", "None None"):
        return []

    # Remove "None" from keyword
    keyword = keyword.replace("None", "").strip()
    if not keyword:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    try:
        response = requests.get(NVD_API, params=params, timeout=10)

        # NVD rate limits to 5 req/s without API key — back off if hit
        if response.status_code == 429:
            time.sleep(6)
            response = requests.get(NVD_API, params=params, timeout=10)

        response.raise_for_status()
        data = response.json()
        results = []

        for vuln in data.get("vulnerabilities", []):
            cve         = vuln["cve"]
            cve_id      = cve.get("id")
            descriptions = cve.get("descriptions", [])
            description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")
            published    = cve.get("published")
            metrics      = cve.get("metrics", {})
            severity     = _extract_severity(metrics)

            results.append({
                "cve":         cve_id,
                "severity":    severity,
                "published":   published,
                "description": description
            })

        return results

    except Exception as e:
        return {"error": str(e)}


def _extract_severity(metrics: dict) -> str:
    if "cvssMetricV31" in metrics:
        return metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"].capitalize()
    if "cvssMetricV30" in metrics:
        return metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"].capitalize()
    if "cvssMetricV2" in metrics:
        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"
    return "Unscored (pre-NVD)"
