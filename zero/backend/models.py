# User doc sample
{
    "username": "admin",
    "password_hash": bcrypt.hashpw(b"yourpass", bcrypt.gensalt()),
    "role": "admin",
    "mfa_secret": pyotp.random_base32(),
    "created_at": datetime.utcnow()
}
