# Access Control (fake internal services example)
@auth_bp.route("/access_hr_data", methods=["GET"])
def access_hr_data():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "Authorization required"}), 401

    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    if payload["role"] != "admin":
        return jsonify({"error": "Unauthorized access"}), 403

    # Process HR Data access logic
    return jsonify({"message": "Accessing HR Data..."}), 200



@auth_bp.route("/access_admin_panel", methods=["GET"])
def access_admin_panel():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "Authorization required"}), 401

    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    if payload["role"] != "admin":
        return jsonify({"error": "Unauthorized access"}), 403

    # Admin panel logic
    return jsonify({"message": "Accessing Admin Panel..."}), 200

@auth_bp.route("/request_confidential_report", methods=["GET"])
def request_confidential_report():
    token = request.cookies.get("token")
    if not token:
        return jsonify({"error": "Authorization required"}), 401

    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    # Logic for requesting a confidential report
    return jsonify({"message": "Requesting Confidential Report..."}), 200

@auth_bp.route("/make-admin", methods=["POST"])
def promote_user_to_admin():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        if payload.get("role") != "admin":
            return jsonify({"error": "Unauthorized"}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    data = request.json
    username = data.get("username")
    client = get_mongo_client()
    db = client["zero_trust_db"]
    users_collection = db["users"]
    result = users_collection.update_one({"username": username}, {"$set": {"role": "admin"}})

    if result.modified_count == 0:
        return jsonify({"error": "User not found or already admin"}), 400

    return jsonify({"message": f"User '{username}' promoted to admin."}), 200
