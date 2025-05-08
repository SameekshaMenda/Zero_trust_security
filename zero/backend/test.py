import pyotp
secret = "JLKZWFVUA74F63FK62EOOG7XSHQRRDOL"
totp = pyotp.TOTP(secret)
otp = totp.now()
print("OTP:", otp)
print("Valid:", totp.verify(otp))  # Should print True
