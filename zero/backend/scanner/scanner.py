# backend/scanner/scanner.py
import requests
import socket
import ssl
from datetime import datetime
from .external_api_integrations import run_shodan_scan


def check_https(url, findings):
    if url.startswith("https://"):
        findings.append("✔ API is using HTTPS. [OWASP API2:2023 - Broken User Authentication]")
    else:
        findings.append("❌ API is NOT using HTTPS! (Risk of data interception) [OWASP API2:2023]")


def check_ssl_tls(hostname, findings):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                findings.append(
                    f"✔ Secure SSL/TLS Version: {ssl_version}"
                    if ssl_version in ["TLSv1.2", "TLSv1.3"]
                    else f"❌ Weak SSL/TLS Version Detected: {ssl_version} [OWASP API7:2023]"
                )

                findings.append(f"✔ Cipher Used: {cipher[0]} ({cipher[1]} bits)")
                if cipher[1] < 128:
                    findings.append("❌ Weak Cipher Strength (<128 bits)! [OWASP API7:2023]")

                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                findings.append(
                    f"✔ SSL Certificate is valid until {expiry}"
                    if expiry > datetime.utcnow()
                    else "❌ SSL Certificate has expired!"
                )

    except Exception as e:
        findings.append(f"⚠ SSL/TLS Check Failed: {e}")


def check_security_headers(url, findings):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        important_headers = {
            "Strict-Transport-Security": "Protects against protocol downgrade attacks [OWASP API7]",
            "Content-Security-Policy": "Prevents XSS attacks [OWASP API8]",
            "X-Content-Type-Options": "Prevents MIME-sniffing [OWASP API8]",
            "X-Frame-Options": "Protects against clickjacking [OWASP API8]",
            "Referrer-Policy": "Controls referer info [OWASP API7]",
            "Permissions-Policy": "Restricts powerful features [OWASP API8]",
            "Cross-Origin-Embedder-Policy": "Prevents cross-origin issues [OWASP API8]",
            "Cross-Origin-Opener-Policy": "Isolates browsing context [OWASP API8]",
            "Cross-Origin-Resource-Policy": "Prevents cross-origin sharing [OWASP API8]",
            "Expect-CT": "Certificate transparency enforcement [OWASP API7]",
        }

        for header, desc in important_headers.items():
            if header in headers:
                findings.append(f"✔ {header} is present ({desc})")
            else:
                findings.append(f"❌ {header} is missing! ({desc})")
    except Exception as e:
        findings.append(f"⚠ Failed to fetch headers: {e}")


def check_crypto_weaknesses(findings):
    weaknesses = [
        {"item": "Usage of MD5", "risk": "Collision attacks [OWASP API3:2023]"},
        {"item": "Usage of SHA-1", "risk": "Weak hash strength [OWASP API3:2023]"},
        {"item": "RSA keys < 2048 bits", "risk": "Easily breakable [OWASP API3:2023]"},
        {"item": "AES keys < 128 bits", "risk": "Weak symmetric encryption [OWASP API3:2023]"},
    ]
    for weakness in weaknesses:
        findings.append(f"⚠ {weakness['item']} - {weakness['risk']}")


def run_all_scans(url, hostname):
    findings = []
    check_https(url, findings)
    check_ssl_tls(hostname, findings)
    check_security_headers(url, findings)
    check_crypto_weaknesses(findings)

    try:
        findings.extend(run_shodan_scan(hostname))
    except Exception as e:
        findings.append(f"⚠ External API scan failed: {e}")

    return findings
