"""
wsgi.py — production WSGI entry point.

Run with gunicorn from the project root:
    gunicorn "auth_backend.wsgi:app" --bind 0.0.0.0:5050 --workers 4
"""
import os

from dotenv import load_dotenv

# Load .env from the auth_backend directory
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from .app import create_app  # noqa: E402 (load_dotenv must come first)

app = create_app(os.environ.get("FLASK_ENV", "production"))
