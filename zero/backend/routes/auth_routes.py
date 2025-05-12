from flask import Blueprint, request, jsonify, current_app, send_file, jsonify, current_app, make_response
import bcrypt, jwt, qrcode, io, base64, hmac, hashlib, time, os
from datetime import timedelta
import datetime
from pymongo import MongoClient
from qr_utils import generate_qr_code, build_otp_uri
# from flask_jwt_extended import decode_token, get_jwt_identity
# from jwt.exceptions import ExpiredSignatureError
from flask_jwt_extended import decode_token
# from flask import request, jsonify, current_app
from jwt import ExpiredSignatureError, decode, InvalidTokenError
from flask_jwt_extended import (
    JWTManager,
    create_access_token,  # This is the critical one you were missing
    jwt_required,
    get_jwt_identity,
    get_jwt
)

from utils import jwt_required_cookie

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
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        otp = data.get("otp")

        if not all([username, password, otp]):
            return jsonify({"error": "Username, password, and OTP are required"}), 400

        client = get_mongo_client()
        db = client["zero_trust_db"]
        users_collection = db["users"]

        user = users_collection.find_one({"username": username})
        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        if not verify_totp(user["mfa_secret"], otp):
            return jsonify({"error": "Invalid OTP"}), 401

        # Create token with proper datetime usage
        token = create_access_token(
            identity=username,
            additional_claims={
                "role": user["role"],
                "fresh": True
            }
        )
        print(f"Generated token: {token}")
        response_data = {
         "message": "Login successful",
         "role": user["role"],
         "username": username,
         "redirect": "admin_dashboard.html" if user["role"] == "admin" else "user_dashboard.html",
         "token": token  # Ensure token is include      here
        }


        response = make_response(jsonify(response_data))
        response.set_cookie(
            "token",
            token,
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=300,  # 5 minutes in seconds
            path='/',
        )

        # Debug log
        print(f"Token set: {token}")
        return response

    except Exception as e:
        print("Login error:", str(e))  # More detailed error logging
        return jsonify({"error": "Internal server error"}), 500
    

@auth_bp.route("/debug/token", methods=["GET"])
def debug_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "No token found in Authorization header"}), 401

    try:
        token = auth_header.split()[1]  # Extract the token from "Bearer <token>"
        decoded = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        now = datetime.datetime.utcnow()
        expires = datetime.datetime.fromtimestamp(decoded["exp"])
        return jsonify({
            "valid": True,
            "username": decoded["sub"],
            "issued_at": datetime.datetime.fromtimestamp(decoded["iat"]).isoformat(),
            "expires_at": expires.isoformat(),
            "current_time": now.isoformat(),
            "seconds_remaining": (expires - now).total_seconds(),
            "token_data": decoded
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401



@auth_bp.route("/debug/time", methods=["GET"])
def debug_time():
    return jsonify({
        "server_time": datetime.datetime.utcnow().isoformat(),
        "jwt_secret_set": current_app.config["JWT_SECRET_KEY"] is not None,
        "jwt_expires": str(current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", "Not set"))
    })


# Endpoint to handle role-based access for Admin
@auth_bp.route("/admin_dashboard", methods=["GET"])
def admin_dashboard():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "Authorization required"}), 401

    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    if payload["role"] != "admin":
        return jsonify({"error": "Unauthorized access"}), 403

    # Admin Dashboard logic
    return jsonify({"message": "Welcome to Admin Dashboard!"}), 200


import logging

logging.basicConfig(level=logging.DEBUG)

@auth_bp.route("/user_dashboard")
def employee_dashboard():
    token = request.cookies.get("token")
    if not token:
        logging.debug("No token found in request cookies.")
        return jsonify({"error": "No token provided"}), 401

    try:
        decoded = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": True})
        username = decoded["username"]
        logging.debug(f"Decoded token for user: {username}")
        return current_app.send_static_file('user_dashboard.html')
    except jwt.ExpiredSignatureError:
        logging.debug("Token expired.")
        return jsonify({"error": "Session expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        logging.debug("Invalid token.")
        return jsonify({"error": "Invalid token"}), 401


@auth_bp.route("/refresh_token", methods=["POST"])
def refresh_token():
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "No refresh token provided"}), 401
    try:
        decoded = jwt.decode(refresh_token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        new_token = create_access_token(identity=decoded["identity"], expires_delta=timedelta(minutes=5))
        response = make_response(jsonify({"message": "Token refreshed"}))
        response.set_cookie("token", new_token, httponly=True, secure=False, samesite="Lax", max_age=300)
        return response
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

@auth_bp.route("/logout", methods=["POST"])
def logout():
    # Create a response indicating successful logout
    response = jsonify({"message": "Logged out successfully"})
    
    # Expire the cookie by setting it with a past expiration time
    response.set_cookie("token", "", expires=0, httponly=True, secure=True, samesite="Strict")
    
    return response

@auth_bp.route("/protected", methods=["GET"])
def protected_route():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "Token missing"}), 401

    try:
        # Make sure to use the same secret key as when creating the token
        decoded_token = jwt.decode(
            token, 
            current_app.config["JWT_SECRET_KEY"],  # Note: Fix typo if present in your code
            algorithms=["HS256"],
            options={"verify_exp": True}  # Ensure expiration is verified
        )
        return jsonify({"message": "Access granted"})
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Session expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    

@auth_bp.route("/check_token", methods=["GET"])
def check_token():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "No token"}), 401
    
    try:
        decoded = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        expires = datetime.datetime.fromtimestamp(decoded["exp"])
        now = datetime.datetime.utcnow()
        return jsonify({
            "valid": True,
            "username": decoded["sub"],
            "expires": expires.isoformat(),
            "current_time": now.isoformat(),
            "seconds_remaining": (expires - now).total_seconds()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@auth_bp.route("/app_config", methods=["GET"])
def app_config():
    return jsonify({
        "JWT_SECRET_KEY": current_app.config["JWT_SECRET_KEY"] is not None,
        "JWT_ACCESS_TOKEN_EXPIRES": str(current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES"))
    })    

