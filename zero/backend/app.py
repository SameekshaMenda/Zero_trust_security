from flask import Flask, request, jsonify, redirect, send_from_directory
from flask_cors import CORS
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
from config import Config
from dotenv import load_dotenv
from routes.auth_routes import auth_bp
import datetime
from datetime import timedelta
from flask import session,jsonify
import jwt as pyjwt
from jwt import ExpiredSignatureError, InvalidTokenError

import os
from utils import jwt_required_cookie


client = MongoClient("mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")
db = client.get_database("zero_trust_db")  # Replace with your actual database name
users_collection = db.users 


load_dotenv()
app = Flask(__name__, static_folder='../frontend')
app.config.from_object(Config)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)  # 5 minute expiration
CORS(app, origins=["http://127.0.0.1:8000"],supports_credentials=True) 

# JWT setup
jwt = JWTManager(app)

# CORS - Configure properly for your needs
CORS(app, supports_credentials=True)

# Register the Blueprint
app.register_blueprint(auth_bp, url_prefix="/auth")

# Serve static files
@app.route('/')
def serve_login():
    return send_from_directory(app.static_folder, '/login.html')

@app.route('/admin_dashboard.html')
def serve_admin_dashboard():
    return send_from_directory(app.static_folder, 'admin_dashboard.html')

@app.route('/user_dashboard.html')
def serve_user_dashboard():
    return send_from_directory(app.static_folder, 'user_dashboard.html')

@app.route('/<path:path>')
def serve_static(path):
    # Check if the file exists
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(app.static_folder, path)
    
    # For SPA routing, serve index.html
    return send_from_directory(app.static_folder, 'login.html')

# Role-based dashboard routes
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
            # Add 30-second leeway for clock sync differences
            jwt.decode(
                token, 
                current_app.config['JWT_SECRET_KEY'], 
                algorithms=['HS256'],
                options={'verify_exp': True, 'leeway': 30}
            )
        except jwt.ExpiredSignatureError:
            return redirect('/?session_expired=1')
        except jwt.InvalidTokenError as e:
            print(f"Invalid token error: {str(e)}")
            return redirect('/?invalid_token=1')
        
# Secure cookie settings
@app.after_request
def set_secure_headers(response):
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# JWT error handlers
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
    # Fetch user data from MongoDB collection
    user_data = users_collection.find_one({"_id": user_id})  # Assuming the user_id is stored as _id
    
    if user_data:
        return {
            "user_id": user_data["_id"],
            "name": user_data["name"],
            "email": user_data["email"],
            "profile_picture": user_data.get("profile_picture", "default.jpg")  # Optional
        }
    else:
        return {"message": "User not found!"}
    


@app.route('/api/user_dashboard_data', methods=['GET'])
def user_dashboard_data():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401

    try:
        # Remove "Bearer " if present
        token = token.split()[1] if " " in token else token
        decoded_token = pyjwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=['HS256'])
        user_id = decoded_token['sub']

        print(decoded_token)

        user_data = get_user_data_from_db(user_id)  # Your own function
        return jsonify(user_data)
    
    except ExpiredSignatureError:
        return jsonify({'message': 'Token expired!'}), 401
    except InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401




if __name__ == "__main__":
    app.run(debug=True)