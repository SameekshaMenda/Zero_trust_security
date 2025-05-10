from flask import Blueprint, request, jsonify, current_app, send_file
import bcrypt, jwt, qrcode, io, base64, hmac, hashlib, time, os
from datetime import datetime, timedelta
from pymongo import MongoClient
from qr_utils import generate_qr_code, build_otp_uri

auth_bp = Blueprint('auth', __name__)

# MongoDB setup
def get_mongo_client():
    with current_app.app_context():
        client = MongoClient(current_app.config["MONGO_URI"])
    return client

# 🔐 Generate a Base32 secret
def generate_base32_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8').replace('=', '')

# 🔐 Verify OTP without pyotp
def verify_totp(secret, otp, window=1):
    def get_hotp_token(secret, intervals_no):
        key = base64.b32decode(secret, casefold=True)
        msg = intervals_no.to_bytes(8, 'big')
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        token = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % 1000000
        return str(token).zfill(6)

    timestep = 30
    current_interval = int(time.time()) // timestep
    for i in range(-window, window + 1):
        if get_hotp_token(secret, current_interval + i) == otp:
            return True
    return False

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
    mfa_secret = generate_base32_secret()

    users_collection.insert_one({
        "username": username,
        "password_hash": password_hash,
        "mfa_secret": mfa_secret,
        "role": "user"
    })

    otp_uri = build_otp_uri(mfa_secret, username)

    # Generate QR Code image
    img = generate_qr_code(secret=mfa_secret, user=username, save_to_file=False)

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    qr_base64 = base64.b64encode(buf.read()).decode('utf-8')

    return jsonify({
        "message": "User registered successfully",
        "mfa_secret": mfa_secret,
        "qr_code": f"data:image/png;base64,{qr_base64}"
    }), 201

# ✅ Optional: Serve QR code by username
@auth_bp.route("/qr/<username>", methods=["GET"])
def generate_qr(username):
    client = get_mongo_client()
    db = client["zero_trust_db"]
    users_collection = db["users"]

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    img = generate_qr_code(secret=user["mfa_secret"], user=username, save_to_file=False)

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# 🔑 Login with OTP and get JWT
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

    if not verify_totp(user["mfa_secret"], otp):
        return jsonify({"error": "Invalid OTP"}), 401

    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(minutes=5)
    }, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")

    return jsonify({"message": "Login successful", "token": token}), 200
