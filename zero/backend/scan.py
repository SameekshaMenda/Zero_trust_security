# backend/app.py
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import os
from urllib.parse import urlparse
from datetime import datetime
from scanner.scanner import run_all_scans
from scanner.report_generator import generate_html_report, save_pdf
from pymongo import MongoClient

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")
client = MongoClient(MONGO_URI)
db = client["scanner"]
scans_collection = db["inputs"]

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

REPORT_PATH = os.path.join("reports", "generated", "report.pdf")

@app.route('/view-report', methods=['POST'])
def view_report():
    print("Received method:", request.method)
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({'error': 'URL is missing'}), 400

    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    findings = run_all_scans(url, hostname)
    html = generate_html_report(url, findings)
    
    # Store scan in database
    scan_record = {
        "url": url,
        "hostname": hostname,
        "findings": findings,
        "timestamp": datetime.utcnow()
    }
    scans_collection.insert_one(scan_record)


    return jsonify({'html': html, 'findings': findings, 'url': url})

@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    data = request.json
    findings = data.get("findings", [])
    url = data.get("url", "N/A")

    html = generate_html_report(url, findings)
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    save_pdf(html, REPORT_PATH)
    return jsonify({'message': 'PDF generated', 'download_url': '/download-report'})

@app.route('/download-report', methods=['GET'])
def download_report():
    if os.path.exists(REPORT_PATH):
        return send_file(REPORT_PATH, as_attachment=True)
    return jsonify({'error': 'No report found'}), 404

if __name__ == "__main__":
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    app.run(debug=True)