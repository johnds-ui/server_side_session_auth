"""
routes/auth.py — public auth endpoints.

POST /auth/register     → create account (email + password)
POST /auth/login        → login with email + password
POST /auth/logout       → invalidate session
GET  /auth/me           → current user info (requires session)
POST /auth/reauth       → re-verify password, mark session fresh
GET  /auth/validate     → internal endpoint for Django session validation
"""
from flask import Blueprint, current_app, g, jsonify, make_response, request

from ..decorators import _get_session_id, require_auth, require_internal_token
from ..extensions import db, limiter
from ..models import Role, User
from ..services.auth_service import (
    audit,
    login_user,
    logout_session,
    reauth_user,
    validate_session,
)
from ..utils.security import hash_password

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _set_session_cookie(response, session_id: str, max_age: int) -> None:
    response.set_cookie(
        current_app.config["SESSION_COOKIE_NAME"],
        value=str(session_id),
        max_age=max_age,
        httponly=True,
        secure=current_app.config["SESSION_COOKIE_SECURE"],
        samesite=current_app.config["SESSION_COOKIE_SAMESITE"],
        path="/",
    )


def _clear_session_cookie(response) -> None:
    response.delete_cookie(
        current_app.config["SESSION_COOKIE_NAME"],
        path="/",
        httponly=True,
        secure=current_app.config["SESSION_COOKIE_SECURE"],
        samesite=current_app.config["SESSION_COOKIE_SAMESITE"],
    )


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Basic length sanity — prevents outsized bcrypt/argon2 DoS
    if len(email) > 255 or len(password) > 1024:
        return jsonify({"error": "Invalid input"}), 400

    session, error = login_user(email, password)
    if error:
        return jsonify({"error": error}), 401

    max_age = int(current_app.config["SESSION_ABSOLUTE_TIMEOUT"].total_seconds())
    response = make_response(
        jsonify(
            {
                "message": "Login successful",
                # Return CSRF token once — client must store in memory (NOT another cookie)
                # and send as X-CSRF-Token header on every state-changing request.
                "csrf_token": session.csrf_token,
                "user": {
                    "id": str(session.user_id),
                    "role": session.role,
                    "tenant_id": str(session.tenant_id) if session.tenant_id else None,
                },
            }
        ),
        200,
    )
    _set_session_cookie(response, session.id, max_age=max_age)
    # Also expose via header for non-browser clients
    response.headers["X-CSRF-Token"] = session.csrf_token
    return response


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
def logout():
    session_id = _get_session_id()
    if session_id:
        logout_session(session_id)  # zeroes csrf_token + sets is_valid=False in DB

    # Always delete the cookie regardless of whether the session was found.
    # This handles the case where the session was already expired server-side.
    response = make_response(jsonify({"message": "Logged out"}), 200)
    _clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    auth_session = g.session
    user: User = db.session.get(User, auth_session.user_id)

    return jsonify(
        {
            "user": user.to_public_dict(),
            "session": auth_session.to_info_dict(),
        }
    )


# ---------------------------------------------------------------------------
# POST /auth/reauth
# ---------------------------------------------------------------------------

@auth_bp.route("/reauth", methods=["POST"])
@require_auth
@limiter.limit("5 per minute")
def reauth():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""

    if not password:
        return jsonify({"error": "Password is required"}), 400

    session_id = _get_session_id()
    ok, error, session_killed = reauth_user(session_id, password)
    if not ok:
        response = make_response(
            jsonify({"error": error, "session_terminated": session_killed}),
            401,
        )
        if session_killed:
            # Clear the auth cookie so the browser can't reuse the dead session
            _clear_session_cookie(response)
        return response

    return jsonify({"message": "Re-authentication successful", "fresh": True})


# ---------------------------------------------------------------------------
# GET /auth/validate  — internal, called by Django middleware
# ---------------------------------------------------------------------------

@auth_bp.route("/validate", methods=["GET"])
@require_internal_token
def validate():
    """
    Django calls this with:
        GET /auth/validate
        X-Internal-Token: <INTERNAL_SERVICE_TOKEN>
        Cookie: auth_session=<id>   OR   ?session_id=<id>
    """
    session_id = request.args.get("session_id") or _get_session_id()
    if not session_id:
        return jsonify({"valid": False, "error": "No session provided"}), 401

    session, error = validate_session(session_id)
    if error:
        return jsonify({"valid": False, "error": error}), 401

    user: User = db.session.get(User, session.user_id)
    return jsonify(
        {
            "valid": True,
            "user": user.to_public_dict(),
            "session": session.to_info_dict(),
        }
    )


# ---------------------------------------------------------------------------
# POST /auth/register  — create a new customer account
# No auth session required. CSRF checks skipped (no session → g.session=None).
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    requested_role = (data.get("role") or "customer").strip().lower()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if len(email) > 255 or len(password) > 1024:
        return jsonify({"error": "Invalid input"}), 400

    # Only customer and restaurant_admin may self-register without a tenant.
    # Waiter is allowed only when a valid tenant_id is supplied (admin adding staff).
    raw_tid = data.get("tenant_id")
    if requested_role == "waiter" and not raw_tid:
        return jsonify({"error": "Waiters can only be added by a restaurant admin"}), 403
    if requested_role not in {"customer", "restaurant_admin", "waiter"}:
        return jsonify({"error": "Role not permitted for registration"}), 403

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    role: Role | None = Role.query.filter_by(name=requested_role).first()
    if not role:
        return jsonify({"error": f"Role '{requested_role}' not configured — seed roles first"}), 500

    # For restaurant_admin create a new tenant automatically.
    # For waiter, the caller may supply an existing tenant_id (admin adding staff).
    import uuid as _uuid
    tenant_id = None
    if requested_role == "restaurant_admin":
        from auth_backend.models import Tenant
        tenant = Tenant(id=_uuid.uuid4(), name=email)
        db.session.add(tenant)
        db.session.flush()
        tenant_id = tenant.id
    elif requested_role == "waiter":
        raw_tid = data.get("tenant_id")
        if raw_tid:
            try:
                tenant_id = _uuid.UUID(str(raw_tid))
            except ValueError:
                return jsonify({"error": "Invalid tenant_id"}), 400
            # Validate tenant exists
            from auth_backend.models import Tenant
            if not Tenant.query.get(tenant_id):
                return jsonify({"error": "Restaurant not found"}), 404

    new_user = User(
        email=email,
        password_hash=hash_password(password),
        role_id=role.id,
        is_active=True,
        tenant_id=tenant_id,
    )
    db.session.add(new_user)
    audit("register", meta={"email": email, "role": requested_role})
    db.session.commit()

    return jsonify({
        "message": "Registration successful",
        "user_id": str(new_user.id),
        "user": {
            "email": email,
            "role": requested_role,
            "tenant_id": tenant_id,
        },
    }), 201
