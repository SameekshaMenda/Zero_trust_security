import os

class Config:
    # Secret key for Flask sessions and CSRF protection
    SECRET_KEY = os.environ.get("SECRET_KEY") or "f70ade13777a1d210ee55f70d467cde912947e7f4dbdf0a422e1f595c7a2830f"

    # JWT secret key used to sign and verify JWTs
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "192ab109ccc2e3f2ce23e8a5d8989c32583a02cfeddcb50336d43df829a91f07"

    # Optional: configure JWT expiration
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

    MONGO_URI = os.environ.get("MONGO_URI") or "mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/"

    # CORS settings if needed
    CORS_HEADERS = 'Content-Type'
