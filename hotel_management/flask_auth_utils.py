"""
hotel_management/flask_auth_utils.py

Proxy helper + Flask-aware auth decorators for Django views.
All role/ABAC checks use request.flask_session populated by FlaskSessionMiddleware.

Roles: customer | waiter | restaurant_admin
"""
from __future__ import annotations

from functools import wraps
from typing import Callable

import requests as http
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FLASK_URL: str = getattr(settings, "FLASK_AUTH_SERVICE_URL", "http://localhost:5050")
FLASK_TIMEOUT: int = 5

ROLE_HIERARCHY: dict[str, int] = {
    "customer": 0,
    "waiter": 1,
    "restaurant_admin": 2,
}


# ---------------------------------------------------------------------------
# Server-to-server proxy call
# ---------------------------------------------------------------------------

def call_flask(
    method: str,
    path: str,
    *,
    request=None,
    json: dict | None = None,
) -> tuple["http.Response | None", "str | None"]:
    """
    Make a server-to-server call from Django to the Flask auth service.
    Forwards auth_session cookie and X-CSRF-Token header from the browser request.
    No Origin header is sent so Flask skips the origin check (server-to-server).
    """
    url = f"{FLASK_URL}{path}"
    cookie_name = getattr(settings, "FLASK_SESSION_COOKIE_NAME", "auth_session")
    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}

    if request is not None:
        sid = request.COOKIES.get(cookie_name)
        if sid:
            cookies[cookie_name] = sid
        csrf_token = request.session.get("flask_csrf_token", "")
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token

    try:
        resp = http.request(
            method.upper(),
            url,
            json=json,
            cookies=cookies,
            headers=headers,
            timeout=FLASK_TIMEOUT,
        )
        return resp, None
    except http.exceptions.ConnectionError:
        return None, "Authentication service is unavailable. Please try again."
    except http.exceptions.Timeout:
        return None, "Authentication service timed out. Please try again."
    except Exception:
        return None, "An unexpected error occurred during authentication."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flask_session(request) -> dict:
    return getattr(request, "flask_session", {})


def _current_role(request) -> str | None:
    return _flask_session(request).get("role")


def _current_tenant_id(request) -> str | None:
    return _flask_session(request).get("tenant_id")


# ---------------------------------------------------------------------------
# Base: require any valid session
# ---------------------------------------------------------------------------

def flask_login_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated(request, *args, **kwargs):
        if not _current_role(request):
            messages.warning(request, "Please log in to continue.")
            return redirect("accounts:login")
        return f(request, *args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# RBAC: minimum role
# ---------------------------------------------------------------------------

def flask_role_required(*roles: str) -> Callable:
    """Allow if user's role is one of *roles* or higher in hierarchy."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(request, *args, **kwargs):
            current = _current_role(request)
            if not current:
                login_url = "accounts:admin_login" if set(roles) & {"restaurant_admin", "waiter"} else "accounts:login"
                messages.warning(request, "Please log in to continue.")
                return redirect(login_url)
            if current in roles:
                return f(request, *args, **kwargs)
            user_level = ROLE_HIERARCHY.get(current, -1)
            required_level = min(ROLE_HIERARCHY.get(r, 999) for r in roles)
            if user_level >= required_level:
                return f(request, *args, **kwargs)
            messages.error(request, "You do not have permission to access this page.")
            return redirect("accounts:login")
        return decorated
    return decorator


def flask_admin_required(f: Callable) -> Callable:
    """Require restaurant_admin role."""
    return flask_role_required("restaurant_admin")(f)


def flask_waiter_or_admin_required(f: Callable) -> Callable:
    """Require waiter or restaurant_admin role."""
    return flask_role_required("waiter", "restaurant_admin")(f)


# ---------------------------------------------------------------------------
# ABAC: restaurant isolation
# ---------------------------------------------------------------------------

def flask_restaurant_required(f: Callable) -> Callable:
    """
    Ensures the logged-in staff member has a restaurant assigned (tenant_id set).
    Customers are not required to have a tenant_id.
    """
    @wraps(f)
    def decorated(request, *args, **kwargs):
        current = _current_role(request)
        if not current:
            return redirect("accounts:login")
        if current in ("waiter", "restaurant_admin") and not _current_tenant_id(request):
            messages.error(request, "Your account is not assigned to any restaurant.")
            return redirect("accounts:login")
        return f(request, *args, **kwargs)
    return decorated


def abac_own_restaurant(resource_restaurant_id) -> bool:
    """
    Call from inside a view to verify a resource belongs to the
    current user's restaurant.  Pass the restaurant's PK (UUID or int).
    """
    from django.http import HttpRequest
    # This is used as a helper inside views, not a decorator
    raise NotImplementedError("Use restaurant_abac_check decorator instead")


def restaurant_abac_check(get_restaurant_pk: Callable) -> Callable:
    """
    Decorator factory for Django views.
    `get_restaurant_pk(request, **kwargs)` must return the restaurant PK
    that owns the requested resource.
    Rejects with 403 if it doesn't match the user's tenant.

    Example:
        @restaurant_abac_check(lambda req, pk, **kw: Order.objects.get(pk=pk).restaurant_id)
        def my_view(request, pk): ...
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(request, *args, **kwargs):
            current = _current_role(request)
            if not current:
                return redirect("accounts:login")

            # Customers bypass tenant check — their isolation is handled by queryset filtering
            if current == "customer":
                return f(request, *args, **kwargs)

            tenant_id = _current_tenant_id(request)
            if not tenant_id:
                messages.error(request, "Your account is not assigned to any restaurant.")
                return redirect("accounts:login")

            resource_restaurant_pk = get_restaurant_pk(request, *args, **kwargs)
            if resource_restaurant_pk is None:
                # Resource has no restaurant assigned yet — deny access
                from django.shortcuts import render as _render
                return _render(request, "403.html", status=403)
            if str(resource_restaurant_pk) != str(tenant_id):
                from django.http import HttpResponseForbidden
                from django.shortcuts import render as _render
                return _render(request, "403.html", status=403)

            return f(request, *args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Fresh auth: require recent re-authentication
# ---------------------------------------------------------------------------

def flask_fresh_required(f: Callable) -> Callable:
    """Sensitive admin actions require recent password confirmation."""
    @wraps(f)
    def decorated(request, *args, **kwargs):
        if not _current_role(request):
            return redirect("accounts:admin_login")
        if not _flask_session(request).get("is_fresh"):
            messages.warning(request, "Please confirm your password to proceed.")
            request.session["reauth_next"] = request.path
            return redirect("accounts:admin_reauth")
        return f(request, *args, **kwargs)
    return decorated
