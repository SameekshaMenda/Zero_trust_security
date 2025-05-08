from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
import bcrypt, pyotp
from db import users_collection
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    user = users_collection.find_one({"username": data["username"]})
    if not user or not bcrypt.checkpw(data["password"].encode(), user["password_hash"]):
        return jsonify({"msg": "Bad credentials"}), 401

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(data["otp"]):
        return jsonify({"msg": "Invalid OTP"}), 401

    token = create_access_token(identity=user["username"], additional_claims={"role": user["role"]})
    return jsonify(token=token)
