import os
import json
import requests

def generate_attack_path(vulnerabilities: list, nuclei_findings: list, waf_status: str = None) -> dict:
    """
    Calls the LLM API to generate a constrained Attack Path mapped to MITRE ATT&CK.
    If a WAF is present, the AI is prompted to adapt the attack path with evasion techniques.
    Returns a JSON-serializable dictionary.
    """
    api_key = os.getenv("NVIDIA_API_KEY", "")
    
    cve_list = [f"{v['cve']} ({v.get('severity', 'Unknown')}) on port {v.get('port', 'Unknown')}" for v in vulnerabilities[:15]]
    nuclei_list = [f"{n.get('template_id', 'Unknown')} ({n.get('severity', 'Unknown')})" for n in nuclei_findings[:15]]

    if not cve_list and not nuclei_list:
        return {
            "summary": "No significant vulnerabilities found to construct an attack path.",
            "steps": []
        }

    prompt = (
        "You are an expert Penetration Tester. I will provide you with a list of confirmed open ports and confirmed vulnerabilities. "
        "Your task is to construct a logical Attack Path (Kill Chain) demonstrating how an attacker could compromise this system. "
        "CRITICAL RULE 1: You may ONLY use the exact CVEs and vulnerabilities provided in the list. Do not invent, assume, or hallucinate any vulnerabilities or services that are not explicitly provided.\n"
        "CRITICAL RULE 2: You MUST return your response as a raw JSON object. Do not wrap it in markdown blockquotes like ```json.\n\n"
        f"CVEs: {', '.join(cve_list)}\n"
        f"Web Vulnerabilities (Nuclei): {', '.join(nuclei_list)}\n"
        f"WAF Status: {waf_status if waf_status else 'No WAF Detected'}\n\n"
        "If a WAF is detected, you MUST include a specific step demonstrating how an attacker would bypass or evade the WAF (Defense Evasion) before exploiting the vulnerabilities.\n\n"
        "The JSON MUST exactly match this schema:\n"
        "{\n"
        '  "summary": "A 2 sentence overview of the kill chain",\n'
        '  "steps": [\n'
        "    {\n"
        '      "step_number": 1,\n'
        '      "title": "Short title",\n'
        '      "description": "How the attacker uses the specific vulnerability",\n'
        '      "mitre_tactic": "Initial Access",\n'
        '      "mitre_technique": "T1190",\n'
        '      "mitre_technique_name": "Exploit Public-Facing Application"\n'
        "    }\n"
        "  ]\n"
        "}"
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
                    "max_tokens": 4096,
                    "temperature": 0.2,
                    "chat_template_kwargs": {"thinking": False}
                },
                timeout=45
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"].strip()
            
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group(0)
            return json.loads(content)
        except Exception as e:
            last_error = str(e)
            continue
            
    return {
        "summary": f"Failed to generate AI attack path: {last_error}",
        "steps": []
    }
