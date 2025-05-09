from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from config import Config
from dotenv import load_dotenv
from routes.auth_routes import auth_bp  # Import the Blueprint object

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# JWT setup
jwt = JWTManager(app)

# CORS
CORS(app)

# Register the Blueprint
app.register_blueprint(auth_bp)  # This is where you register the blueprint

# MongoDB setup
mongo_client = MongoClient(app.config['MONGO_URI'])
db = mongo_client.get_database('zero_trust_db')  # Specify your database name
  # This uses the database name from the URI
users_collection = db['users']

if __name__ == "__main__":
    app.run(debug=True)
