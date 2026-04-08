"""
routes/admin.py — protected routes with restaurant-scoped RBAC + ABAC.

Roles:
    customer         — own orders only, within the restaurant they ordered from
    waiter           — all orders of their assigned restaurant
    restaurant_admin — everything within their restaurant (menu, orders, staff)

ABAC principle: every resource check compares ctx["tenant_id"] (== restaurant's
flask_tenant_id) against the resource's tenant_id. A restaurant_admin from
restaurant A can NEVER touch data of restaurant B.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

from ..decorators import (
    abac_check,
    register_abac_policy,
    require_fresh_auth,
    require_min_role,
    require_role,
)
from ..extensions import db
from ..models import AuditLog, AuthSession, User
from ..services.auth_service import audit

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ===========================================================================
# ABAC — restaurant-scoped policy definitions
# ===========================================================================

@register_abac_policy("order", "view")
def _policy_order_view(ctx: dict, res: dict) -> bool:
    role = ctx["role"]
    if role == "restaurant_admin":
        return ctx["tenant_id"] == res.get("tenant_id")
    if role == "waiter":
        return ctx["tenant_id"] == res.get("tenant_id")
    if role == "customer":
        return ctx["user_id"] == res.get("owner_id")
    return False


@register_abac_policy("order", "update_status")
def _policy_order_update(ctx: dict, res: dict) -> bool:
    role = ctx["role"]
    # Both waiter and restaurant_admin can update orders in their restaurant
    if role in ("waiter", "restaurant_admin"):
        return ctx["tenant_id"] == res.get("tenant_id")
    return False


@register_abac_policy("order", "cancel")
def _policy_order_cancel(ctx: dict, res: dict) -> bool:
    role = ctx["role"]
    if role == "restaurant_admin":
        return ctx["tenant_id"] == res.get("tenant_id")
    if role == "customer":
        return ctx["user_id"] == res.get("owner_id")
    return False


@register_abac_policy("menu", "manage")
def _policy_menu_manage(ctx: dict, res: dict) -> bool:
    # Only restaurant_admin of the same restaurant
    return ctx["role"] == "restaurant_admin" and ctx["tenant_id"] == res.get("tenant_id")


@register_abac_policy("staff", "manage")
def _policy_staff_manage(ctx: dict, res: dict) -> bool:
    return ctx["role"] == "restaurant_admin" and ctx["tenant_id"] == res.get("tenant_id")


@register_abac_policy("report", "view")
def _policy_report_view(ctx: dict, res: dict) -> bool:
    return ctx["role"] == "restaurant_admin" and ctx["tenant_id"] == res.get("tenant_id")


# ===========================================================================
# Resource loaders (tenant_id comes from session context)
# ===========================================================================

def _restaurant_resource(_kwargs: dict) -> dict:
    """Resource is scoped to the current user's restaurant (tenant)."""
    return {"tenant_id": g.tenant_id}


# ===========================================================================
# USER MANAGEMENT  (restaurant_admin only, fresh auth)
# ===========================================================================

@admin_bp.route("/staff", methods=["GET"])
@require_role("restaurant_admin")
def list_staff():
    """List all users in the same restaurant tenant."""
    users = User.query.filter_by(tenant_id=g.tenant_id).order_by(User.email).all()
    return jsonify([u.to_public_dict() for u in users])


@admin_bp.route("/staff/<user_id>/role", methods=["PATCH"])
@require_role("restaurant_admin")
@require_fresh_auth
def update_staff_role(user_id: str):
    """Change a staff member's role within the restaurant."""
    from ..models import Role
    data = request.get_json(silent=True) or {}
    role_name = data.get("role", "").strip()

    if role_name not in ("customer", "waiter", "restaurant_admin"):
        return jsonify({"error": "Invalid role. Must be customer, waiter, or restaurant_admin"}), 400

    user: User | None = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ABAC: can only manage users in their own restaurant
    if str(user.tenant_id) != g.tenant_id:
        return jsonify({"error": "Access denied — user belongs to a different restaurant"}), 403

    # Prevent self-demotion
    if str(user.id) == g.user_id and role_name != "restaurant_admin":
        return jsonify({"error": "You cannot change your own admin role"}), 400

    role_obj = Role.query.filter_by(name=role_name).first()
    if not role_obj:
        return jsonify({"error": f"Role '{role_name}' not seeded"}), 500

    old_role = user.role.name if user.role else None
    user.role_id = role_obj.id
    audit("admin_change_role", user_id=g.user_id, meta={
        "target": user_id, "from": old_role, "to": role_name, "restaurant": g.tenant_id
    })
    db.session.commit()
    return jsonify({"message": f"Role updated to {role_name}"})


@admin_bp.route("/staff/<user_id>/lock", methods=["POST"])
@require_role("restaurant_admin")
@require_fresh_auth
def lock_staff(user_id: str):
    user: User | None = db.session.get(User, user_id)
    if not user or str(user.tenant_id) != g.tenant_id:
        return jsonify({"error": "User not found or access denied"}), 404
    user.locked_until = datetime.now(timezone.utc) + timedelta(hours=24)
    audit("admin_lock_user", user_id=g.user_id, meta={"target": user_id})
    db.session.commit()
    return jsonify({"message": "User locked for 24 hours"})


@admin_bp.route("/staff/<user_id>/unlock", methods=["POST"])
@require_role("restaurant_admin")
@require_fresh_auth
def unlock_staff(user_id: str):
    user: User | None = db.session.get(User, user_id)
    if not user or str(user.tenant_id) != g.tenant_id:
        return jsonify({"error": "User not found or access denied"}), 404
    user.locked_until = None
    user.failed_login_attempts = 0
    audit("admin_unlock_user", user_id=g.user_id, meta={"target": user_id})
    db.session.commit()
    return jsonify({"message": "User unlocked"})


# ===========================================================================
# AUDIT LOGS  (restaurant_admin: own restaurant only)
# ===========================================================================

@admin_bp.route("/audit-logs", methods=["GET"])
@require_role("restaurant_admin")
def audit_logs():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    tenant_user_ids = [
        u.id for u in User.query.filter_by(tenant_id=g.tenant_id).with_entities(User.id).all()
    ]
    paginated = (
        AuditLog.query
        .filter(AuditLog.user_id.in_(tenant_user_ids))
        .order_by(AuditLog.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    return jsonify({
        "logs": [
            {
                "id": log.id,
                "user_id": str(log.user_id) if log.user_id else None,
                "action": log.action,
                "ip_address": log.ip_address,
                "meta": log.meta,
                "created_at": log.created_at.isoformat(),
            }
            for log in paginated.items
        ],
        "total": paginated.total,
        "page": page,
        "pages": paginated.pages,
    })


# ===========================================================================
# ACTIVE SESSIONS  (restaurant_admin: own restaurant only)
# ===========================================================================

@admin_bp.route("/sessions", methods=["GET"])
@require_role("restaurant_admin")
def active_sessions():
    sessions = (
        AuthSession.query
        .filter_by(is_valid=True, tenant_id=g.tenant_id)
        .order_by(AuthSession.last_active.desc())
        .limit(100)
        .all()
    )
    return jsonify([
        {
            "id": str(s.id),
            "user_id": str(s.user_id),
            "role": s.role,
            "ip_address": s.ip_address,
            "last_active": s.last_active.isoformat(),
            "expires_at": s.expires_at.isoformat(),
        }
        for s in sessions
    ])


@admin_bp.route("/sessions/<session_id>/revoke", methods=["POST"])
@require_role("restaurant_admin")
@require_fresh_auth
def revoke_session(session_id: str):
    session: AuthSession | None = db.session.get(AuthSession, session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    # ABAC: can only revoke sessions within own restaurant
    if str(session.tenant_id) != g.tenant_id:
        return jsonify({"error": "Access denied"}), 403
    session.is_valid = False
    session.csrf_token = ""
    audit("admin_revoke_session", user_id=g.user_id, meta={"session_id": session_id})
    db.session.commit()
    return jsonify({"message": "Session revoked"})


# ===========================================================================
# REPORT  (restaurant_admin: own restaurant)
# ===========================================================================

@admin_bp.route("/reports/restaurant", methods=["GET"])
@abac_check("report", "view", resource_loader=_restaurant_resource)
def restaurant_report():
    return jsonify({
        "report": "restaurant_summary",
        "tenant_id": g.tenant_id,
        "generated_by": g.user_id,
    })


