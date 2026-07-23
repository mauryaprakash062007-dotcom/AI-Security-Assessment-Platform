import os
import requests
import json

def generate_remediation_summary(vulnerabilities: list, nuclei_findings: list) -> str:
    """
    Calls the OpenAI API to generate a brief, actionable remediation summary
    based on the findings of the scan.
    """
    api_key = os.getenv("NVIDIA_API_KEY", "")
    if not api_key:
        return "No API key provided. AI Remediation is disabled."

    # Prepare a condensed summary of findings to avoid token limits
    cve_list = [f"{v['cve']} ({v.get('severity', 'Unknown')}) on port {v.get('port', 'Unknown')}" for v in vulnerabilities[:15]]
    nuclei_list = [f"{n.get('template_id', 'Unknown')} ({n.get('severity', 'Unknown')})" for n in nuclei_findings[:15]]

    if not cve_list and not nuclei_list:
        return "No significant vulnerabilities found. System appears secure based on current scan."

    prompt = (
        "You are a friendly cybersecurity expert speaking to a normal, non-technical website owner. "
        "Review the following vulnerabilities found on their server:\n"
        f"CVEs: {', '.join(cve_list)}\n"
        f"Web Vulnerabilities (Nuclei): {', '.join(nuclei_list)}\n\n"
        "Please provide an easy-to-understand summary of the risks in plain English. "
        "Do not just list technical terms and open ports. Instead, clearly explain what security aspects are missing, "
        "why it matters for their website, and what specific steps they can take to fix or mitigate these issues. "
        "Format the response beautifully using markdown headings and bullet points."
    )

    models_to_try = ["deepseek-ai/deepseek-v4-pro", "meta/llama-3.1-8b-instruct"]
    last_error = None

    for model in models_to_try:
        try:
            response = requests.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024,
                    "temperature": 0.5,
                    "chat_template_kwargs": {"thinking": False}
                },
                timeout=45
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            last_error = str(e)
            continue
            
    return f"Failed to generate AI remediation: {last_error}"
