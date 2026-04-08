import random
import secrets
import uuid
from datetime import datetime, timezone

from flask import current_app, request

from ..extensions import db
from ..models import AuditLog, AuthSession, User
from ..utils.security import verify_password, needs_rehash, hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _client_ip() -> str:
    # Only trust X-Forwarded-For when behind a known reverse proxy
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _user_agent() -> str:
    return (request.headers.get("User-Agent") or "")[:512]


# ---------------------------------------------------------------------------
# Audit logging  (fire-and-forget within same transaction)
# ---------------------------------------------------------------------------

def audit(action: str, user_id=None, meta: dict | None = None) -> None:
    """Insert an audit log entry. Call before db.session.commit() in the same tx."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=_client_ip(),
        user_agent=_user_agent(),
        meta=meta or {},
    )
    db.session.add(entry)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login_user(email: str, password: str) -> tuple["AuthSession | None", "str | None"]:
    """
    Verify credentials, create a server-side session, and return it.
    Returns (session, None) on success or (None, error_message) on failure.
    """
    cfg = current_app.config
    user: User | None = User.query.filter_by(email=email.lower().strip()).first()

    # If the user does not exist run a dummy verify to keep timing consistent
    if not user:
        verify_password("dummy_plain", "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        audit("login_failed", meta={"email": email, "reason": "user_not_found"})
        db.session.commit()
        return None, "Invalid credentials"

    if not user.is_active:
        audit("login_failed", user_id=user.id, meta={"reason": "account_inactive"})
        db.session.commit()
        return None, "Invalid credentials"

    now = _utcnow()

    # Account lockout check
    if user.locked_until and now < user.locked_until:
        audit("login_failed", user_id=user.id, meta={"reason": "account_locked"})
        db.session.commit()
        return None, "Account temporarily locked — try again later"

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= cfg["MAX_FAILED_LOGINS"]:
            user.locked_until = now + cfg["ACCOUNT_LOCKOUT_DURATION"]
            audit(
                "account_locked",
                user_id=user.id,
                meta={"attempts": user.failed_login_attempts},
            )
        else:
            audit(
                "login_failed",
                user_id=user.id,
                meta={"reason": "bad_password", "attempts": user.failed_login_attempts},
            )
        db.session.commit()
        return None, "Invalid credentials"

    # Transparent Argon2 rehash if parameters changed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    # Clear lockout state
    user.failed_login_attempts = 0
    user.locked_until = None

    session = AuthSession(
        id=uuid.uuid4(),
        user_id=user.id,
        tenant_id=user.tenant_id,
        branch_id=user.branch_id,
        role=user.role.name,
        is_fresh_auth=True,
        fresh_until=now + cfg["FRESH_AUTH_DURATION"],
        created_at=now,
        last_active=now,
        expires_at=now + cfg["SESSION_ABSOLUTE_TIMEOUT"],
        ip_address=_client_ip(),
        user_agent=_user_agent(),
        is_valid=True,
        # Fresh 64-char CSRF token — unique per session, stored only in DB
        csrf_token=secrets.token_hex(32),
    )
    db.session.add(session)
    audit("login_success", user_id=user.id, meta={"session_id": str(session.id)})
    db.session.commit()
    return session, None


# ---------------------------------------------------------------------------
# Session cleanup  (no external scheduler needed)
# ---------------------------------------------------------------------------

def cleanup_expired_sessions() -> int:
    """
    Hard-delete session rows that are already dead:
      • is_valid = False   (logged out, timed out, killed on reauth failure)
      • expires_at < NOW() (absolute timeout passed)
      • last_active < NOW() - SESSION_IDLE_TIMEOUT  (idle timeout passed)

    Called probabilistically from validate_session (1-in-50 chance) so dead
    rows are purged continuously without a separate scheduled job.
    Returns the number of rows deleted.
    """
    cfg = current_app.config
    now = _utcnow()
    idle_cutoff = now - cfg["SESSION_IDLE_TIMEOUT"]

    deleted = (
        AuthSession.query
        .filter(
            db.or_(
                AuthSession.is_valid.is_(False),
                AuthSession.expires_at < now,
                AuthSession.last_active < idle_cutoff,
            )
        )
        .delete(synchronize_session=False)
    )
    db.session.commit()
    return deleted


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------

def validate_session(session_id: str) -> tuple["AuthSession | None", "str | None"]:
    """
    Look up a session by ID, enforce idle and absolute timeouts, refresh
    last_active, and return (session, None) or (None, error).

    On 1-in-50 calls also runs a background cleanup to purge dead rows,
    keeping the auth_sessions table lean without a separate scheduler.
    """
    cfg = current_app.config
    session: AuthSession | None = AuthSession.query.filter_by(
        id=session_id, is_valid=True
    ).first()

    if not session:
        return None, "Session not found or invalid"

    now = _utcnow()

    if now > session.expires_at:
        session.is_valid = False
        session.csrf_token = ""  # invalidate CSRF token immediately
        db.session.commit()
        return None, "Session expired"

    idle_timeout = cfg["SESSION_IDLE_TIMEOUT"]
    last = session.last_active
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    if now > last + idle_timeout:
        session.is_valid = False
        session.csrf_token = ""  # invalidate CSRF token immediately
        db.session.commit()
        return None, "Session timed out due to inactivity"

    session.last_active = now
    db.session.commit()

    # Probabilistic cleanup: ~2% of requests trigger a dead-session purge.
    # Runs AFTER committing the valid session update so it never blocks auth.
    if random.randint(1, 50) == 1:
        try:
            cleanup_expired_sessions()
        except Exception:
            pass  # never let cleanup failure break a valid login

    return session, None


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def logout_session(session_id: str) -> None:
    session: AuthSession | None = AuthSession.query.filter_by(
        id=session_id, is_valid=True
    ).first()
    if session:
        session.is_valid = False
        session.csrf_token = ""  # zero out CSRF token — cannot be reused
        audit("logout", user_id=session.user_id, meta={"session_id": session_id})
        db.session.commit()


# ---------------------------------------------------------------------------
# Re-authentication (sensitive actions)
# ---------------------------------------------------------------------------

def reauth_user(session_id: str, password: str) -> tuple[bool, "str | None", bool]:
    """
    Verify the password again and mark the session as fresh.
    Returns (True, None, False) on success.
    Returns (False, error, session_killed) on failure.
    When session_killed=True the session has been invalidated server-side;
    the caller MUST clear the auth cookie and force re-login.
    """
    cfg = current_app.config
    session: AuthSession | None = AuthSession.query.filter_by(
        id=session_id, is_valid=True
    ).first()
    if not session:
        return False, "Invalid session", False

    user: User | None = db.session.get(User, session.user_id)
    if not user or not verify_password(password, user.password_hash):
        # SECURITY: immediately terminate the current session on any wrong reauth
        # password.  This prevents an attacker who has gained temporary physical
        # access from brute-forcing the reauth gate while using the victim's session.
        if session:
            session.is_valid = False
            session.csrf_token = ""          # invalidate CSRF token instantly
            session.is_fresh_auth = False
        audit(
            "reauth_failed_session_killed",
            user_id=session.user_id if session else None,
            meta={"session_id": session_id, "reason": "wrong_reauth_password"},
        )
        db.session.commit()
        return (
            False,
            "Incorrect password — your session has been terminated for security. "
            "Please log in again.",
            True,
        )

    now = _utcnow()
    session.is_fresh_auth = True
    session.fresh_until = now + cfg["FRESH_AUTH_DURATION"]
    audit("reauth_success", user_id=user.id, meta={"session_id": session_id})
    db.session.commit()
    return True, None, False


# ---------------------------------------------------------------------------
# Freshness helper
# ---------------------------------------------------------------------------

def is_session_fresh(session: "AuthSession") -> bool:
    if not session.is_fresh_auth or not session.fresh_until:
        return False
    ft = session.fresh_until
    if ft.tzinfo is None:
        ft = ft.replace(tzinfo=timezone.utc)
    return _utcnow() < ft
