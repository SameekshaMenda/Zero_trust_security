import requests

def advanced_scan(url):
    issues = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if not url.startswith("https://"):
            issues.append("❌ Insecure protocol (HTTPS missing)")

        required_headers = {
            "Content-Security-Policy": "Mitigates XSS",
            "X-Frame-Options": "Clickjacking prevention",
            "Strict-Transport-Security": "Enforce HTTPS",
            "X-Content-Type-Options": "Prevent MIME sniffing"
        }

        for header, purpose in required_headers.items():
            if header not in headers:
                issues.append(f"❌ Missing {header} ({purpose})")

        if "Access-Control-Allow-Origin" in headers and "*" in headers["Access-Control-Allow-Origin"]:
            issues.append("⚠️ CORS policy too open")

        if "Authorization" not in headers:
            issues.append("⚠️ No Authorization token in headers")

        return {
            "url": url,
            "status_code": response.status_code,
            "issues": issues or ["✅ No major issues detected"]
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "issues": ["❌ Connection failed or timed out"]
        }
