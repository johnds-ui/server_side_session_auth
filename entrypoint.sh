#!/bin/sh
set -e

if [ -z "${POSTGRES_HOST:-}" ]; then
  echo "POSTGRES_HOST is not set. Start the app with docker compose or pass the PostgreSQL environment variables." >&2
  exit 1
fi

echo "Waiting for PostgreSQL at ${POSTGRES_HOST}:${POSTGRES_PORT:-5432}..."
python - <<'PY'
import os
import socket
import sys
import time

host = os.environ["POSTGRES_HOST"]
port = int(os.environ.get("POSTGRES_PORT", "5432"))
deadline = time.time() + 60
last_error = None

while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            print(f"PostgreSQL is reachable at {host}:{port}")
            break
    except OSError as exc:
        last_error = exc
        time.sleep(2)
else:
    print(f"Could not reach PostgreSQL at {host}:{port}: {last_error}", file=sys.stderr)
    sys.exit(1)
PY

python manage.py migrate --noinput

exec "$@"
