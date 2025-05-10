import base64
import qrcode
from PIL import Image
from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb+srv://sameeksa19:sameeksha@cluster0.2allbhh.mongodb.net/")
db = client["zero_trust_db"]
collection = db["users"]

# Fetch the latest registered user (or change logic as needed)
user = collection.find_one(sort=[('_id', -1)])  # fetch most recently added user
if not user:
    print("❌ No user found in the database.")
    exit()

username = user['username'].strip()
secret = user['mfa_secret']

# Function to generate and show QR code
def generate_qr_code(secret, user, issuer='ZeroTrustApp'):
    otp_uri = f'otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30'
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    filename = f'{user}_mfa_qrcode.png'
    img.save(filename)
    print(f"✅ QR Code saved as: {filename}")
    
    try:
        img.show()  # Opens the image on supported systems
    except Exception as e:
        print("⚠️ Couldn't open image viewer. Open it manually from the file.")

# Execute
if __name__ == "__main__":
    print("📦 Username:", username)
    print("🔐 Base32 MFA Secret:", secret)
    generate_qr_code(secret, username)
    print("✅ QR Code generated successfully.")