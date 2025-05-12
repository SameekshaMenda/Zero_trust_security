# utils.py
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps

def jwt_required_cookie(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request(locations=["cookies"])
        return fn(*args, **kwargs)
    return wrapper
