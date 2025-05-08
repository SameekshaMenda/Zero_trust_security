from flask import Blueprint

def register_routes(app):
    from .auth_routes import auth_bp
    app.register_blueprint(auth_bp)
