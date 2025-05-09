import requests
import ssl
import socket
import pdfkit
from urllib.parse import urlparse
from jinja2 import Template
from datetime import datetime
import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

findings = []

@app.route('/download/<filename>', methods=['GET'])
def download_report(filename):
    file_path = os.path.join(os.getcwd(), filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=False)
    return jsonify({'error': 'File not found'}), 404

# --- HTTPS Validator ---
def check_https(url):
    findings.append("Checking HTTPS Usage...")
    if url.startswith('https://'):
        findings.append("✔ API is using HTTPS. [OWASP API2:2019 - Broken User Authentication]")
    else:
        findings.append("❌ API is NOT using HTTPS! (Risk of data interception) [OWASP API2:2019]")

# --- SSL/TLS and Cipher Analyzer ---
def check_ssl_tls(hostname):
    findings.append("Analyzing SSL/TLS Version and Cipher...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                if ssl_version in ['TLSv1.2', 'TLSv1.3']:
                    findings.append(f"✔ Secure SSL/TLS Version: {ssl_version}")
                else:
                    findings.append(f"❌ Weak SSL/TLS Version Detected: {ssl_version} [OWASP A6:2017]")
                findings.append(f"✔ Cipher Used: {cipher[0]} ({cipher[1]} bits)")
                if cipher[1] < 128:
                    findings.append("❌ Weak Cipher Strength (<128 bits)! [OWASP A6:2017]")
    except Exception as e:
        findings.append(f"⚠ SSL/TLS Check Failed: {e}")

# --- Security Headers Checker ---
def check_security_headers(url):
    findings.append("Checking Important Security Headers...")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        important_headers = {
            "Strict-Transport-Security": "Protects against protocol downgrade attacks [OWASP A6]",
            "Content-Security-Policy": "Prevents XSS attacks [OWASP A7]",
            "X-Content-Type-Options": "Prevents MIME-sniffing [OWASP A5]",
            "X-Frame-Options": "Protects against clickjacking [OWASP A5]",
            "Referrer-Policy": "Controls information sent in Referer header [OWASP A6]",
        }
        for header, reason in important_headers.items():
            if header in headers:
                findings.append(f"✔ {header} is present ({reason})")
            else:
                findings.append(f"❌ {header} is missing! ({reason})")
    except Exception as e:
        findings.append(f"⚠ Failed to fetch headers: {e}")

# --- Cryptographic Weakness Analyzer ---
def check_crypto_weaknesses():
    findings.append("Checking Common Cryptographic Weaknesses (Theoretical)...")
    weaknesses = [
        {"item": "Usage of MD5 for hashing", "risk": "Collision attacks [OWASP A3:2017]"},
        {"item": "Usage of SHA-1 instead of SHA-256", "risk": "Weak hash strength [OWASP A3:2017]"},
        {"item": "RSA keys < 2048 bits", "risk": "Easier to break with modern computing [OWASP A3:2017]"},
        {"item": "AES keys < 128 bits", "risk": "Insufficient symmetric key strength [OWASP A3:2017]"},
    ]
    for weakness in weaknesses:
        findings.append(f"⚠ {weakness['item']} - {weakness['risk']}")

# --- HTML Report Generator ---
def generate_html_report(url):
    template = Template("""
    <html>
    <head>
        <title>API Vulnerability Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #003366; }
            .section { margin-bottom: 20px; }
            .finding { margin-left: 20px; margin-bottom: 5px; }
            .good { color: green; }
            .bad { color: red; }
            .warn { color: orange; }
        </style>
    </head>
    <body>
        <h1>API Cryptography Vulnerability Report</h1>
        <p><strong>Scanned URL:</strong> {{ url }}</p>
        <p><strong>Scan Date:</strong> {{ date }}</p>
        <div class="section">
            <h2>Findings</h2>
            {% for item in findings %}
                <div class="finding {% if '✔' in item %}good{% elif '❌' in item %}bad{% elif '⚠' in item %}warn{% endif %}">{{ item }}</div>
            {% endfor %}
        </div>
        <hr>
        <p><em>Mapped to OWASP API Top 10 and OWASP Web Top 10 vulnerabilities where applicable.</em></p>
    </body>
    </html>
    """)
    return template.render(url=url, findings=findings, date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# --- Save as PDF ---
def save_pdf(html_content, filename="API_Vulnerability_Report.pdf"):
    try:
        config = None
        if os.name == 'nt':  # Windows
            path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
            config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)
        pdfkit.from_string(html_content, filename, configuration=config)
        print(f"📄 Report successfully saved as: {filename}")
        
    except Exception as e:
        print(f"Error generating PDF: {e}")
        print("Make sure 'wkhtmltopdf' is installed and the path is correct.")

# --- Scan Endpoint ---
@app.route('/scan', methods=['GET'])
def scan():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL parameter is missing'}), 400

    parsed_url = urlparse(url)
    hostname = parsed_url.netloc or parsed_url.path

    findings.clear()
    check_https(url)
    check_ssl_tls(hostname)
    check_security_headers(url)
    check_crypto_weaknesses()

    html_report = generate_html_report(url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_hostname = hostname.replace('.', '_')
    filename = f"API_Vulnerability_Report_{safe_hostname}_{timestamp}.pdf"

    save_pdf(html_report, filename=filename)

    return jsonify({
        'message': 'Scan completed successfully',
        'report': findings,
        'pdf_filename': filename
    })

# --- Run Flask App ---
if __name__ == "__main__":
    app.run(debug=True, port=5001)
