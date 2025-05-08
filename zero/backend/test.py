import pyotp
import qrcode
secret = "RHBX4HV5WPS3FWTSHR4EMJWS6J75USQ6"
totp = pyotp.TOTP(secret)
otp = totp.now()
print("OTP:", otp)
print("Valid:", totp.verify(otp))  # Should print True
provisioning_uri = totp.provisioning_uri(name="sinchana", issuer_name="ZeroTrustApp")

# Generate and show QR code
qr = qrcode.make(provisioning_uri)
qr.show()