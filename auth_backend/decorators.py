"""
decorators.py — auth, RBAC, ABAC, and internal-token decorators.

Usage
-----
@require_auth                       → any authenticated user
@require_role("admin")              → single role (exact or higher in hierarchy)
@require_min_role("manager")        → minimum level in the hierarchy
@require_fresh_auth                 → session must be freshly re-authed
@require_internal_token             → for Django→Flask internal API calls
@abac_check("booking", "view",
            resource_loader=fn)     → attribute-based access control
"""
from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import current_app, g, jsonify, request

from .services.auth_service import is_session_fresh, validate_session
from .utils.security import constant_time_compare

# ---------------------------------------------------------------------------
# Role hierarchy  (higher index = more privilege)
# ---------------------------------------------------------------------------

ROLE_HIERARCHY: dict[str, int] = {
    "customer": 0,
    "waiter": 1,
    "restaurant_admin": 2,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_session_id() -> str | None:
    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "auth_session")
    return request.cookies.get(cookie_name)


def _load_user() -> tuple[bool, object]:
    """
    Load and validate the session from the request cookie.
    Sets g.session, g.user_id, g.role, g.tenant_id, g.branch_id.
    Returns (True, None) or (False, error_response_tuple).
    """
    # Already loaded by the session middleware earlier in this request
    if g.get("user_id"):
        return True, None

    session_id = _get_session_id()
    if not session_id:
        return False, (jsonify({"error": "Authentication required"}), 401)

    session, error = validate_session(session_id)
    if error:
        return False, (jsonify({"error": error}), 401)

    g.session = session
    g.user_id = str(session.user_id)
    g.role = session.role
    g.tenant_id = str(session.tenant_id) if session.tenant_id else None
    g.branch_id = str(session.branch_id) if session.branch_id else None
    return True, None


# ---------------------------------------------------------------------------
# require_auth
# ---------------------------------------------------------------------------

def require_auth(f: Callable) -> Callable:
    """Ensures the caller has a valid server-side session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ok, err = _load_user()
        if not ok:
            return err
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# require_role / require_min_role  (RBAC)
# ---------------------------------------------------------------------------

def require_role(*roles: str) -> Callable:
    """
    Allow access if the user's role is in *roles* OR has a higher
    hierarchy level than all listed roles.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            ok, err = _load_user()
            if not ok:
                return err

            if g.role in roles:
                return f(*args, **kwargs)

            user_level = ROLE_HIERARCHY.get(g.role, -1)
            required_level = min(ROLE_HIERARCHY.get(r, 999) for r in roles)
            if user_level >= required_level:
                return f(*args, **kwargs)

            return jsonify({"error": "Insufficient permissions"}), 403
        return decorated
    return decorator


def require_min_role(min_role: str) -> Callable:
    """Allow access if the user's role is >= *min_role* in the hierarchy."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            ok, err = _load_user()
            if not ok:
                return err

            user_level = ROLE_HIERARCHY.get(g.role, -1)
            required_level = ROLE_HIERARCHY.get(min_role, 999)
            if user_level < required_level:
                return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# require_fresh_auth
# ---------------------------------------------------------------------------

def require_fresh_auth(f: Callable) -> Callable:
    """
    Requires the session to be freshly authenticated (recent login or reauth).
    Use on sensitive operations: account deletion, admin actions, etc.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        ok, err = _load_user()
        if not ok:
            return err

        if not is_session_fresh(g.session):
            return (
                jsonify({"error": "Re-authentication required", "code": "REAUTH_REQUIRED"}),
                403,
            )
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# require_internal_token
# ---------------------------------------------------------------------------

def require_internal_token(f: Callable) -> Callable:
    """
    Validates the X-Internal-Token header for service-to-service calls
    (e.g. Django calling the /auth/validate endpoint).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Internal-Token", "")
        expected = current_app.config.get("INTERNAL_SERVICE_TOKEN", "")
        if not expected or not constant_time_compare(token, expected):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# ABAC policy registry
# ---------------------------------------------------------------------------

_abac_policies: dict[tuple[str, str], Callable] = {}


def register_abac_policy(resource_type: str, action: str) -> Callable:
    """
    Register a policy function for (resource_type, action).
    The decorated function receives (context: dict, resource: dict) -> bool.
    """
    def decorator(f: Callable) -> Callable:
        _abac_policies[(resource_type, action)] = f
        return f
    return decorator


def abac_check(
    resource_type: str,
    action: str,
    resource_loader: Callable[[dict], dict] | None = None,
) -> Callable:
    """
    Decorator factory.

    resource_loader(kwargs) -> resource dict with attributes like:
        owner_id, tenant_id, branch_id, created_by, ...

    The matching policy (registered via @register_abac_policy) decides access.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            ok, err = _load_user()
            if not ok:
                return err

            policy = _abac_policies.get((resource_type, action))
            if policy is None:
                return jsonify({"error": f"No ABAC policy for {resource_type}:{action}"}), 403

            resource: dict = resource_loader(kwargs) if resource_loader else {}
            context: dict = {
                "user_id": g.user_id,
                "role": g.role,
                "tenant_id": g.tenant_id,
                "branch_id": g.branch_id,
            }

            if not policy(context, resource):
                return jsonify({"error": "Access denied"}), 403

            return f(*args, **kwargs)
        return decorated
    return decorator
