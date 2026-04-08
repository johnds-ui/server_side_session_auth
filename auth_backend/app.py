"""
app.py — Flask application factory.

Usage
-----
from auth_backend.app import create_app
app = create_app("production")
"""
import os
import secrets as _secrets

from flask import Flask, jsonify

from .config import config_by_name
from .extensions import db, limiter
from .middleware.session import register_middleware
from .routes.admin import admin_bp
from .routes.auth import auth_bp


def create_app(config_name: str | None = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "production")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    limiter.init_app(app)

    # ------------------------------------------------------------------
    # Middleware (before/after request hooks)
    # ------------------------------------------------------------------
    register_middleware(app)

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(429)
    def too_many_requests(_e):
        return jsonify({"error": "Too many requests — slow down"}), 429

    @app.errorhandler(500)
    def internal_error(_e):
        return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------
    # Create tables (development convenience; use Alembic in production)
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()
        _bootstrap_secrets(app)
        _seed_default_roles()

    return app


def _bootstrap_secrets(app: Flask) -> None:
    """
    Generate SECRET_KEY and INTERNAL_SERVICE_TOKEN on first startup and
    persist them in the DB.  On every subsequent startup the values are
    loaded from the DB — NEVER from environment variables.

    Generating new values only when the record does not yet exist means
    all existing sessions survive a process restart.
    """
    from .models import AppSecret

    needs_commit = False
    for key_name, byte_length in [
        ("flask_secret_key", 64),
        ("internal_service_token", 32),
    ]:
        record = AppSecret.query.filter_by(key_name=key_name).first()
        if not record:
            record = AppSecret(
                key_name=key_name,
                key_value=_secrets.token_hex(byte_length),
            )
            db.session.add(record)
            needs_commit = True

    if needs_commit:
        db.session.commit()

    app.config["SECRET_KEY"] = (
        AppSecret.query.filter_by(key_name="flask_secret_key").first().key_value
    )
    app.config["INTERNAL_SERVICE_TOKEN"] = (
        AppSecret.query.filter_by(key_name="internal_service_token").first().key_value
    )


def _seed_default_roles() -> None:
    """Insert default roles if they do not yet exist."""
    from .models import Role

    defaults = [
        {
            "name": "customer",
            "permissions": {
                "order": ["create", "view_own", "cancel_own"],
                "menu": ["view"],
                "profile": ["view_own", "update_own"],
            },
        },
        {
            "name": "waiter",
            "permissions": {
                "order": ["view", "update_status"],
                "menu": ["view"],
            },
        },
        {
            "name": "restaurant_admin",
            "permissions": {
                "order": ["view", "update_status", "cancel"],
                "menu": ["view", "create", "update", "delete"],
                "staff": ["view", "create", "update", "delete"],
                "report": ["view"],
            },
        },
    ]

    for r in defaults:
        if not Role.query.filter_by(name=r["name"]).first():
            db.session.add(Role(name=r["name"], permissions=r["permissions"]))

    db.session.commit()
