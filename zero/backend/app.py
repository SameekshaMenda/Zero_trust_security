from flask import Flask, request, jsonify, redirect, send_from_directory, send_file, session
from flask_cors import CORS
from flask_pymongo import PyMongo

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    verify_jwt_in_request,
    get_jwt_identity,
    jwt_required,
    get_jwt
)
from flask_jwt_extended.exceptions import NoAuthorizationError, JWTExtendedException
from pymongo import MongoClient
from datetime import timedelta, datetime
from config import Config
from dotenv import load_dotenv
from routes.auth_routes import auth_bp
from scanner.scanner import run_all_scans
from scanner.report_generator import generate_html_report, save_pdf
from jwt import ExpiredSignatureError, InvalidTokenError
import jwt as pyjwt
import os
from urllib.parse import urlparse
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='../frontend')
app.config.from_object(Config)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
# With this single configuration:
CORS(app, resources={
    r"/*": {
        "origins": ["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:8000"],
        "supports_credentials": True,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# JWT Setup
jwt = JWTManager(app)

# Register Auth Blueprint
app.register_blueprint(auth_bp, url_prefix="/auth")

# MongoDB Setup
mongo_uri = os.getenv("MONGO_URI", "mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")
client = MongoClient(mongo_uri)
mongo = PyMongo(app)
# Databases
users_db = client["zero_trust_db"]
users_collection = users_db.users
reports = users_db["reports"]
scans_collection = users_db.inputs

# Report path
REPORT_PATH = os.path.join("reports", "generated", "report.pdf")

# Serve static pages
@app.route('/')
def serve_login():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/admin_dashboard.html')
def serve_admin_dashboard():
    return send_from_directory(app.static_folder, 'admin_dashboard.html')

@app.route('/user_dashboard.html')
def serve_user_dashboard():
    return send_from_directory(app.static_folder, 'user_dashboard.html')

@app.route('/<path:path>')
def serve_static(path):
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] == 'admin':
        return send_from_directory(app.static_folder, 'admin_dashboard.html')
    else:
        return send_from_directory(app.static_folder, 'user_dashboard.html')

@app.before_request
def check_valid_token():
    protected_routes = ['/admin_dashboard.html', '/user_dashboard.html']
    if request.path in protected_routes:
        token = request.cookies.get('token')
        if not token:
            return redirect('/?auth_required=1')
        try:
            pyjwt.decode(
                token,
                app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={'verify_exp': True, 'leeway': 30}
            )
        except ExpiredSignatureError:
            return redirect('/?session_expired=1')
        except InvalidTokenError as e:
            print(f"Invalid token error: {str(e)}")
            return redirect('/?invalid_token=1')

@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "error": "session_expired",
        "message": "Your session has expired. Please log in again."
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "error": "invalid_token",
        "message": "Invalid token. Please log in again."
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "error": "authorization_required",
        "message": "You need to be logged in to access this."
    }), 401

def get_user_data_from_db(user_id):
    user_data = users_collection.find_one({"_id": user_id})
    if user_data:
        return {
            "user_id": user_data["_id"],
            "name": user_data["name"],
            "email": user_data["email"],
            "profile_picture": user_data.get("profile_picture", "default.jpg")
        }
    else:
        return {"message": "User not found!"}

@app.route('/api/user_dashboard_data', methods=['GET'])
def user_dashboard_data():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        token = token.split()[1] if " " in token else token
        decoded_token = pyjwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=['HS256'])
        user_id = decoded_token['sub']
        user_data = get_user_data_from_db(user_id)
        return jsonify(user_data)
    except ExpiredSignatureError:
        return jsonify({'message': 'Token expired!'}), 401
    except InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

# SCANNER FEATURES

@app.route('/view-report', methods=['POST'])
def view_report():
    data = request.json
    url = data.get("url")
    username = data.get("username", "unknown") 
    if not url:
        return jsonify({'error': 'URL is missing'}), 400

    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    findings = run_all_scans(url, hostname)
    html = generate_html_report(url, findings)

    # Always save the scan results
    scan_record = {
        "url": url,
        "hostname": hostname,
        "findings": findings,
        "username": username,
        "timestamp": datetime.utcnow()
    }
    scans_collection.insert_one(scan_record)

    return jsonify({
        'html': html, 
        'findings': findings, 
        'url': url,
        'message': 'Scan results saved to database'
    })

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Validate the token here (e.g., decode using JWT)
            pass
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/generate-pdf', methods=['POST', 'OPTIONS'])
def generate_pdf():
    # Handle preflight CORS request
    if request.method == 'OPTIONS':
        return jsonify({'message': 'Preflight OK'}), 200

    # Authenticate request
    verify_jwt_in_request()
    current_user = get_jwt_identity()
    print(f"Generating PDF for user: {current_user}")  # Debug

    try:
        data = request.get_json()
        findings = data.get("findings", [])
        url = data.get("url", "N/A")

        html = generate_html_report(url, findings)
        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
        save_pdf(html, REPORT_PATH)
        
        return jsonify({'message': 'PDF generated', 'download_url': '/download-report'})
    
    except Exception as e:
        print(f"PDF generation error: {str(e)}")  # Debug
        return jsonify({'error': str(e)}), 500


@app.route('/download-report', methods=['GET'])
@jwt_required()
def download_report():
    if os.path.exists(REPORT_PATH):
        return send_file(
            REPORT_PATH,
            as_attachment=True,
            download_name=f"API_Security_Report_{datetime.now().date()}.pdf"
        )
    return jsonify({'error': 'No report found'}), 404






@app.route('/get-scan-history', methods=['GET'])
@jwt_required()
def get_scan_history():
    current_user = get_jwt_identity()
    scans = list(scans_collection.find({"username": current_user}).sort("timestamp", -1))
    
    # Convert ObjectId to string for JSON serialization
    for scan in scans:
        scan['_id'] = str(scan['_id'])
    
    return jsonify(scans)

@app.route('/get-scan-details/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan_details(scan_id):
    current_user = get_jwt_identity()
    scan = scans_collection.find_one({"_id": ObjectId(scan_id), "username": current_user})
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    scan['_id'] = str(scan['_id'])
    return jsonify(scan)

@app.route('/download-scan-report/<scan_id>', methods=['GET'])
@jwt_required()
def download_scan_report(scan_id):
    current_user = get_jwt_identity()
    scan = scans_collection.find_one({"_id": ObjectId(scan_id), "username": current_user})
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    html = generate_html_report(scan['url'], scan['findings'])
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    save_pdf(html, REPORT_PATH)
    
    return send_file(
        REPORT_PATH,
        as_attachment=True,
        download_name=f"API_Security_Report_{scan['url'].replace('https://', '').replace('/', '_')}.pdf"
    )

@app.route('/history', methods=['GET'])
@jwt_required()
def history():
    """
    Returns all reports for the logged-in user.
    Frontend must send Authorization: Bearer <token>.
    """
    username = get_jwt_identity()
    # fetch all reports for this user, sort by timestamp desc
    docs = reports.find({"username": username}).sort("created_at", -1)
    
    result = []
    for d in docs:
        result.append({
            "url": d["url"],
            "timestamp": d["created_at"].isoformat(),
            "findings": d["findings"]
        })
    return jsonify({"reports": result}), 200

@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    """
    Returns all scan reports unprotected.
    """
    docs = scans_collection.find().sort("created_at", -1)
    out = []
    for d in docs:
        out.append({
            "_id": str(d["_id"]),
            "url": d.get("url", ""),
            "hostname": d.get("hostname", ""),
            "findings": d.get("findings", []),
            "username": d.get("username", ""),
            "timestamp": d.get("created_at", datetime.utcnow()).isoformat()
        })
    return jsonify({"reports": out}), 200


if __name__ == "__main__":
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    app.run(debug=True)
