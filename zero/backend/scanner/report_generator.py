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

# Add this configuration (path to your wkhtmltopdf executable)
config = pdfkit.configuration(wkhtmltopdf='C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe')  # Adjust path as needed

def save_pdf(html_content, path):
    options = {
        'page-size': 'A4',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
    }
    pdfkit.from_string(html_content, path, options=options, configuration=config)
