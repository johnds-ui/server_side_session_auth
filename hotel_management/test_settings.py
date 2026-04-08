from .settings import *


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

SILENCED_SYSTEM_CHECKS = ["fields.E210"]
