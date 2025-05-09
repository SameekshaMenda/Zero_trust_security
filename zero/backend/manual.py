import base64
import os
import qrcode
from PIL import Image
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")  # Adjust if needed
db = client["zero_trust_db"]
collection = db["users"]

user = collection.find_one({"username": "sinchana"})
if not user:
    print("User not found.")
    exit()

secret = user['mfa_secret']  # ✅ Load existing secret from database

def generate_qr_code(secret, user='sinchana', issuer='ZeroTrustApp'):
    otp_uri = f'otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30'
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    filename = f'{user}_qrcode.png'
    img.save(filename)
    print(f"✅ QR Code saved as: {filename}")
    
    try:
        img.show()
    except Exception as e:
        print("❌ Could not open image automatically. Open it manually.")

# === MAIN ===
if __name__ == "__main__":
    print("Your Base32 Secret (from DB):", secret)
    generate_qr_code(secret)
