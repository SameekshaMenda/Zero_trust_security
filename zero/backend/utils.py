from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime

def jwt_required_cookie(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        
        if not token:
            return jsonify({"error": "Missing token"}), 401
            
        try:
            # Verify the JWT
            payload = jwt.decode(
                token, 
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={"verify_exp": True}
            )
            # Add the payload to the request
            request.jwt_payload = payload
            return fn(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
            
    return wrapper