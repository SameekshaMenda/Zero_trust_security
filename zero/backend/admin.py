import bcrypt, base64, os
from pymongo import MongoClient

client = MongoClient("mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")
db = client["zero_trust_db"]
users = db["users"]

username = "adminuser"
password = "admin"
hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
mfa_secret = base64.b32encode(os.urandom(10)).decode().replace("=", "")

users.insert_one({
    "username": username,
    "password_hash": hashed_pw,
    "mfa_secret": mfa_secret,
    "role": "admin"
})

print("Admin user created.")
print("Use this MFA secret in your authenticator app:", mfa_secret)
