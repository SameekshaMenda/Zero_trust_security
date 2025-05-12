# backend/scanner/external_api_integrations.py
import requests
import os

def run_shodan_scan(hostname):
    findings = []
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        findings.append("⚠ SHODAN_API_KEY not set in environment variables.")
        return findings

    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{hostname}?key={api_key}", timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("ports"):
                findings.append(f"✔ Open Ports: {data['ports']}")
            if data.get("vulns"):
                for vuln in data["vulns"]:
                    findings.append(f"❌ Vulnerability found: {vuln} [OWASP API1:2023]")
            else:
                findings.append("✔ No known vulnerabilities found in Shodan scan.")
        else:
            findings.append(f"⚠ Shodan scan failed with status {response.status_code}: {response.text}")
    except Exception as e:
        findings.append(f"⚠ Shodan API request error: {e}")

    return findings

