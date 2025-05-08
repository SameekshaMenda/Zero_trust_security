from flask import Blueprint, request, jsonify, current_app
import bcrypt, pyotp, jwt
from datetime import datetime, timedelta
from pymongo import MongoClient

auth_bp = Blueprint('auth', __name__)

# MongoDB setup
def get_mongo_client():
    with current_app.app_context():
        client = MongoClient(current_app.config["MONGO_URI"])
    return client

# Register a new user
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    client = get_mongo_client()  # Initialize MongoDB client inside the route
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
        "role": "user"  # Default to user role
    })

    return jsonify({"message": "User registered", "mfa_secret": mfa_secret})


# User login and JWT generation
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    otp = data["otp"]

    client = get_mongo_client()  # Initialize MongoDB client inside the route
    db = client["zero_trust_db"]
    users_collection = db["users"]

    user = users_collection.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(otp):
        return jsonify({"error": "Invalid OTP"}), 401

    # Create JWT token with expiration time of 5 minutes
    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(minutes=5)  # Token expires in 5 minutes
    }, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")

    return jsonify({"token": token})

