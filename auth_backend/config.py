import os
from datetime import timedelta


class BaseConfig:
    # ------------------------------------------------------------------
    # Core
    # SECRET_KEY is NOT sourced from env — it is generated once at startup
    # and stored in the auth_app_secrets DB table (see app._bootstrap_secrets).
    # ------------------------------------------------------------------
    SECRET_KEY: str = "_replaced_from_db_at_startup_"
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/hotel_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # ------------------------------------------------------------------
    # Session cookie
    # ------------------------------------------------------------------
    SESSION_COOKIE_NAME: str = "auth_session"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"

    # ------------------------------------------------------------------
    # Session timeouts
    # ------------------------------------------------------------------
    SESSION_IDLE_TIMEOUT: timedelta = timedelta(minutes=5)   # inactive sessions killed after 5 min
    SESSION_ABSOLUTE_TIMEOUT: timedelta = timedelta(hours=8)
    FRESH_AUTH_DURATION: timedelta = timedelta(minutes=5)    # reauth gate triggers after 5 min

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    RATELIMIT_STORAGE_URL: str = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT: str = "200 per hour"

    # ------------------------------------------------------------------
    # Account lockout
    # ------------------------------------------------------------------
    MAX_FAILED_LOGINS: int = int(os.environ.get("MAX_FAILED_LOGINS", "5"))
    ACCOUNT_LOCKOUT_DURATION: timedelta = timedelta(minutes=15)

    # ------------------------------------------------------------------
    # Internal service auth (Django ↔ Flask)
    # Token is NOT in env — generated at startup and stored in DB,
    # same table as SECRET_KEY (key_name="internal_service_token").
    # ------------------------------------------------------------------
    INTERNAL_SERVICE_TOKEN: str = "_replaced_from_db_at_startup_"

    # ------------------------------------------------------------------
    # CSRF — trusted origins that may POST to this service
    # ------------------------------------------------------------------
    CSRF_TRUSTED_ORIGINS: list[str] = [
        o.strip()
        for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "http://localhost:8000").split(",")
        if o.strip()
    ]


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = False


class ProductionConfig(BaseConfig):
    DEBUG = False


config_by_name: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": ProductionConfig,
}
