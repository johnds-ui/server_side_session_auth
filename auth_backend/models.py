import uuid
from datetime import datetime, timezone

from sqlalchemy.dialects.postgresql import JSONB, UUID

from .extensions import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Tenant  (multi-tenant support)
# ---------------------------------------------------------------------------

class Tenant(db.Model):
    __tablename__ = "auth_tenants"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(255), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)

    users = db.relationship("User", back_populates="tenant")

    def to_dict(self) -> dict:
        return {"id": str(self.id), "name": self.name, "is_active": self.is_active}


# ---------------------------------------------------------------------------
# Role  (RBAC)
# ---------------------------------------------------------------------------

class Role(db.Model):
    __tablename__ = "auth_roles"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # name must be one of: guest | customer | receptionist | manager | admin
    name = db.Column(db.String(50), unique=True, nullable=False)
    # Stored as {"resource_type": ["action", ...], ...}
    permissions = db.Column(JSONB, default=dict, nullable=False)

    users = db.relationship("User", back_populates="role")


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "auth_users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(512), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey("auth_roles.id"), nullable=False)
    tenant_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("auth_tenants.id"), nullable=True, index=True
    )
    # Branch the user is assigned to (receptionists / managers)
    branch_id = db.Column(UUID(as_uuid=True), nullable=True, index=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    role = db.relationship("Role", back_populates="users")
    tenant = db.relationship("Tenant", back_populates="users")
    sessions = db.relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="user")

    def to_public_dict(self) -> dict:
        return {
            "id": str(self.id),
            "email": self.email,
            "role": self.role.name if self.role else None,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "branch_id": str(self.branch_id) if self.branch_id else None,
            "is_active": self.is_active,
        }


# ---------------------------------------------------------------------------
# AuthSession  (server-side sessions — cookie holds only the UUID)
# ---------------------------------------------------------------------------

class AuthSession(db.Model):
    __tablename__ = "auth_sessions"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("auth_users.id"), nullable=False, index=True
    )
    tenant_id = db.Column(UUID(as_uuid=True), nullable=True)
    branch_id = db.Column(UUID(as_uuid=True), nullable=True)
    role = db.Column(db.String(50), nullable=False)

    # Freshness — set True on login/reauth, expires after FRESH_AUTH_DURATION
    is_fresh_auth = db.Column(db.Boolean, default=True, nullable=False)
    fresh_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)
    last_active = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    is_valid = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Per-session CSRF token — generated server-side on login, verified on
    # every state-changing request, zeroed-out on logout or timeout.
    csrf_token = db.Column(db.String(64), nullable=False, default="")

    user = db.relationship("User", back_populates="sessions")

    def to_info_dict(self) -> dict:
        return {
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "fresh_until": self.fresh_until.isoformat() if self.fresh_until else None,
        }


# ---------------------------------------------------------------------------
# AuditLog  (immutable — never update, only insert)
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "auth_audit_logs"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("auth_users.id"), nullable=True, index=True
    )
    action = db.Column(db.String(100), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    # Free-form context: email attempted, session_id, target resource, etc.
    meta = db.Column(JSONB, default=dict, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    user = db.relationship("User", back_populates="audit_logs")


# ---------------------------------------------------------------------------
# BranchAccess  (optional — maps users to hotel branches explicitly)
# ---------------------------------------------------------------------------

class BranchAccess(db.Model):
    __tablename__ = "auth_branch_access"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("auth_users.id"), nullable=False, index=True
    )
    branch_id = db.Column(UUID(as_uuid=True), nullable=False, index=True)
    granted_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("user_id", "branch_id", name="uq_user_branch"),)


# ---------------------------------------------------------------------------
# AppSecret  (dynamically generated secrets stored only in DB — never in env)
# ---------------------------------------------------------------------------

class AppSecret(db.Model):
    """
    Stores application-level secrets that are generated at first startup
    and persisted in the database.  Nothing sensitive lives in .env.

    Key names used by this service:
        flask_secret_key          — Flask SECRET_KEY
        internal_service_token    — shared token for Django ↔ Flask calls
    """
    __tablename__ = "auth_app_secrets"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)
    key_value = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)
    # Non-null when the key was regenerated while keeping the name stable
    rotated_at = db.Column(db.DateTime(timezone=True), nullable=True)
