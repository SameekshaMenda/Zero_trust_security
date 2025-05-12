# backend/scanner/report_generator.py
import pdfkit
from jinja2 import Template
import os

def generate_html_report(url, findings):
    template = """
    <html>
    <head><title>API Scan Report</title></head>
    <body>
        <h1>API Security Report</h1>
        <p><strong>Scanned URL:</strong> {{ url }}</p>
        <ul>
        {% for finding in findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </body>
    </html>
    """
    rendered = Template(template).render(url=url, findings=findings)
    return rendered

def save_pdf(html_content, path):
    pdfkit.from_string(html_content, path)
