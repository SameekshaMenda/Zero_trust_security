import pyotp
import qrcode
from pymongo import MongoClient

# MongoDB setup
client = MongoClient("mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")  # Update if using Atlas
db = client["zero_trust_db"]
users_collection = db["users"]

# Fetch user by username
username = "sinchana"  # You can change this or make it input()
user = users_collection.find_one({"username": username})

if not user:
    print("User not found in the database.")
else:
    secret = user["mfa_secret"]
    totp = pyotp.TOTP(secret)
    
    # Generate OTP and test
    otp = totp.now()
    print("Username:", username)
    print("OTP:", otp)
    print("Valid:", totp.verify(otp))  # Should print True

    # Generate provisioning URI and QR code
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="ZeroTrustApp")
    print("Provisioning URI:", provisioning_uri)
    
    qr = qrcode.make(provisioning_uri)
    qr.show()
