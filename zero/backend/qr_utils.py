# qr_utils.py
import qrcode
from PIL import Image

def build_otp_uri(secret: str, user: str, issuer: str = "ZeroTrustApp") -> str:
    """
    Construct the OTP Auth URI manually (used by authenticator apps).
    """
    return f"otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

def generate_qr_code(secret, user, issuer='ZeroTrustApp', save_to_file=True):
    otp_uri = build_otp_uri(secret, user, issuer)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    if save_to_file:
        filename = f'{user}_mfa_qrcode.png'
        img.save(filename)
        try:
            img.show()
        except Exception:
            print("⚠️ Couldn't open image viewer.")
        return filename
    else:
        return img
