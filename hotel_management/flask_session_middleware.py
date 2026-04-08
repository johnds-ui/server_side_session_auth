"""
hotel_management/flask_session_middleware.py
Django middleware that authenticates requests using the Flask auth service's
server-side session cookie.

Add AFTER AuthenticationMiddleware in settings.py MIDDLEWARE list:

    MIDDLEWARE = [
        ...
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "hotel_management.flask_session_middleware.FlaskSessionMiddleware",
        ...
    ]

Required settings
-----------------
FLASK_SESSION_COOKIE_NAME = "auth_session"   # must match Flask config
FLASK_AUTH_EXEMPT_PATHS = ["/admin/login/", ...]  # paths that skip Flask auth

NOTE: INTERNAL_SERVICE_TOKEN is NOT in settings.py — it is read from the
auth_app_secrets DB table at first use via _load_internal_token().
"""
from __future__ import annotations

from django.conf import settings
from django.contrib.auth import authenticate

FLASK_COOKIE = getattr(settings, "FLASK_SESSION_COOKIE_NAME", "auth_session")

_DEFAULT_EXEMPT = [
    "/admin/login/",
    "/accounts/login/",
    "/accounts/register/",
    "/accounts/password_reset/",
    "/accounts/password_reset_done/",
    "/accounts/reset/",
    "/static/",
    "/media/",
]

EXEMPT_PATHS: list[str] = getattr(settings, "FLASK_AUTH_EXEMPT_PATHS", _DEFAULT_EXEMPT)

# Cached internal service token — loaded from DB on first request, never from env
_cached_internal_token: str | None = None


def _load_internal_token() -> str:
    """
    Read the internal service token from auth_app_secrets (written by Flask service).
    Cached in-process after first DB read.  Returns "" on any DB error.
    """
    global _cached_internal_token
    if _cached_internal_token is not None:
        return _cached_internal_token

    try:
        from sqlalchemy import create_engine, text

        d = settings.DATABASES["default"]
        db_url = (
            f"postgresql://{d['USER']}:{d['PASSWORD']}"
            f"@{d.get('HOST', 'localhost')}:{d.get('PORT', '5432')}/{d['NAME']}"
        )
        engine = create_engine(db_url, pool_pre_ping=True)
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT key_value FROM auth_app_secrets"
                    " WHERE key_name = 'internal_service_token'"
                )
            ).fetchone()
        _cached_internal_token = row[0] if row else ""
    except Exception:
        _cached_internal_token = ""

    return _cached_internal_token


class FlaskSessionMiddleware:
    """
    On every request:
      1. Read the auth_session cookie.
      2. If present and the Django user is not yet authenticated,
         delegate to FlaskSessionAuthBackend to validate via shared DB.
      3. Attach flask_role / flask_tenant_id / flask_branch_id / flask_is_fresh
         to request.user so Django views can do RBAC/ABAC checks.

    Session expiry handling:
      When an auth cookie is present but the underlying Flask session has
      expired or timed out (idle / absolute), the middleware:
        a. Flushes the Django session (rotates key, wipes all data).
        b. Tags the request so __call__ deletes the stale auth cookie from
           the browser response — the attacker cannot reuse it.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        stale_cookie = self._authenticate(request)
        response = self.get_response(request)
        if stale_cookie:
            # Remove the dead auth cookie so the browser discards it immediately.
            response.delete_cookie(
                FLASK_COOKIE,
                path="/",
                samesite="Strict",
            )
        return response

    # ------------------------------------------------------------------

    def _authenticate(self, request) -> bool:
        """
        Authenticate the request against the Flask session DB.
        Returns True if the auth cookie was present but the session was dead
        (caller should delete the cookie from the response).
        """
        # Always initialise flask_session so views can safely read it
        request.flask_session = {}

        if any(request.path.startswith(p) for p in EXEMPT_PATHS):
            return False

        session_id = request.COOKIES.get(FLASK_COOKIE)
        if not session_id:
            return False

        # Only attempt Flask auth if Django hasn't already authenticated
        if not request.user.is_authenticated:
            user = authenticate(request, session_id=session_id)
            if user:
                request.user = user

        # If user is now authenticated, ensure flask_* attrs exist for views
        if request.user.is_authenticated:
            flask_role = getattr(request.user, "flask_role", None) or getattr(request.user, "role", "customer")
            request.flask_session = {
                "role": flask_role,
                "tenant_id": getattr(request.user, "flask_tenant_id", None),
                "branch_id": getattr(request.user, "flask_branch_id", None),
                "is_fresh": getattr(request.user, "flask_is_fresh", False),
                "fresh_until": getattr(request.user, "flask_fresh_until", None),
            }
            # Sync Flask role onto request.user in-memory (no DB write).
            request.user.role = flask_role
            return False
        else:
            request.flask_session = {}
            # Cookie was present but session validation failed (expired / timed out).
            # Flush the Django session: rotates the session key and wipes all stored
            # data — an attacker cannot reuse the old Django session ID either.
            request.session.flush()
            return True  # signal __call__ to delete the auth cookie
