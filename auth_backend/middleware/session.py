"""
middleware/session.py — request-level middleware for Flask.

Security model
--------------
Every state-changing request (POST / PUT / PATCH / DELETE) is protected
by TWO independent server-side checks:

  1. Origin header check  — refuses requests from untrusted browser origins.
  2. CSRF double-token    — the client must echo back the per-session CSRF
                            token (received at login) as X-CSRF-Token header.
                            The value is compared server-side, constant-time,
                            against the token stored in auth_sessions.csrf_token.

When a session expires or times out, `validate_session` zeroes the
csrf_token column and returns an error.  The middleware then sets
`g.clear_auth_cookie = True` which the after_request hook uses to
delete the stale cookie from the browser automatically — no client-side
JS required.

Exempt from CSRF token check (no valid session exists at those endpoints):
  - POST /auth/login
"""
from flask import Flask, current_app, g, jsonify, request

from ..decorators import _get_session_id
from ..services.auth_service import validate_session
from ..utils.security import constant_time_compare

# Paths exempt from the per-session CSRF token check.
# Login is exempt because the client has no token before the first login.
# The Origin check still applies to all state-changing requests.
_CSRF_TOKEN_EXEMPT = {"/auth/login"}


def register_middleware(app: Flask) -> None:
    # ------------------------------------------------------------------
    # Before-request: session load → Origin check → CSRF double-token
    # ------------------------------------------------------------------
    @app.before_request
    def load_session_and_verify_csrf():
        # Reset per-request auth context
        g.session = None
        g.user_id = None
        g.role = None
        g.tenant_id = None
        g.branch_id = None
        g.clear_auth_cookie = False  # signals after_request to wipe the cookie

        # ── 1. Load session from cookie ──────────────────────────────
        session_id = _get_session_id()
        if session_id:
            session, error = validate_session(session_id)
            if session:
                g.session = session
                g.user_id = str(session.user_id)
                g.role = session.role
                g.tenant_id = str(session.tenant_id) if session.tenant_id else None
                g.branch_id = str(session.branch_id) if session.branch_id else None
            else:
                # Cookie present but session expired / timed-out:
                # signal the after_request hook to purge the cookie.
                g.clear_auth_cookie = True

        # Only state-changing methods require CSRF protection
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None

        # ── 2. Origin header check (defence-in-depth on top of SameSite=Strict)
        origin = request.headers.get("Origin", "")
        if origin:  # no Origin = server-to-server call, skip
            trusted = current_app.config.get("CSRF_TRUSTED_ORIGINS", [])
            if not any(origin.startswith(t) for t in trusted if t):
                return jsonify({"error": "CSRF check failed: untrusted origin"}), 403

        # ── 3. Per-session CSRF double-token check ───────────────────
        # Only enforced when a valid server-side session exists and the
        # endpoint is not on the exempt list (e.g. /auth/login).
        if g.session and request.path not in _CSRF_TOKEN_EXEMPT:
            client_token = request.headers.get("X-CSRF-Token", "")
            server_token = g.session.csrf_token or ""

            if not server_token:
                # Session exists but has no CSRF token stored — reject
                return jsonify({"error": "CSRF token missing on session"}), 403

            if not constant_time_compare(client_token, server_token):
                return jsonify(
                    {"error": "CSRF token mismatch — re-authenticate to get a new token"}
                ), 403

        return None

    # ------------------------------------------------------------------
    # After-request: security headers + conditional cookie purge
    # ------------------------------------------------------------------
    @app.after_request
    def add_security_headers(response):
        # Delete stale auth cookie when the session was already invalid
        if g.get("clear_auth_cookie"):
            cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "auth_session")
            response.delete_cookie(
                cookie_name,
                path="/",
                httponly=True,
                secure=current_app.config.get("SESSION_COOKIE_SECURE", True),
                samesite=current_app.config.get("SESSION_COOKIE_SAMESITE", "Strict"),
            )

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response
