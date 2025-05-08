from flask import Blueprint, request, jsonify, current_app, send_file
import bcrypt, pyotp, jwt, qrcode, io
from datetime import datetime, timedelta
from pymongo import MongoClient

auth_bp = Blueprint('auth', __name__)

# MongoDB setup
def get_mongo_client():
    with current_app.app_context():
        client = MongoClient(current_app.config["MONGO_URI"])
    return client

# 📝 Register a new user
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    client = get_mongo_client()
    db = client["zero_trust_db"]
    users_collection = db["users"]

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    mfa_secret = pyotp.random_base32()

    users_collection.insert_one({
        "username": username,
        "password_hash": password_hash,
        "mfa_secret": mfa_secret,
        "role": "user"
    })

    # Generate provisioning URI (for Google Authenticator)
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="ZeroTrustApp")

    return jsonify({
        "message": "User registered successfully",
        "mfa_secret": mfa_secret,
        "provisioning_uri": provisioning_uri  # Frontend can generate QR from this
    }), 201

# ✅ Generate QR code (optional route for scanning in app)
@auth_bp.route("/qr/<username>", methods=["GET"])
def generate_qr(username):
    client = get_mongo_client()
    db = client["zero_trust_db"]
    users_collection = db["users"]

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    totp = pyotp.TOTP(user["mfa_secret"])
    uri = totp.provisioning_uri(name=username, issuer_name="ZeroTrustApp")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# 🔐 Login with OTP and return JWT
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")

    if not username or not password or not otp:
        return jsonify({"error": "Username, password, and OTP required"}), 400

    client = get_mongo_client()
    db = client["zero_trust_db"]
    users_collection = db["users"]

    user = users_collection.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(otp):
        return jsonify({"error": "Invalid OTP"}), 401

    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(minutes=5)
    }, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")

    return jsonify({"message": "Login successful", "token": token}), 200
