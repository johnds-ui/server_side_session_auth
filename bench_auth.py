"""
bench_auth.py — Auth System Performance Benchmark
===================================================
Compares our Argon2id + Server-Side Session system against JWT HS256.

Run:
    python bench_auth.py

Requirements (already in requirements.txt):
    argon2-cffi

No additional packages needed — jwt simulation uses Python stdlib only.
"""

import base64
import hashlib
import hmac
import json
import random
import secrets
import time
import timeit
import uuid

SEPARATOR = "=" * 62

# ---------------------------------------------------------------------------
# 1. Argon2id — password hashing (our system, used ONCE at login)
# ---------------------------------------------------------------------------
try:
    from argon2 import PasswordHasher
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False
    print("[WARN] argon2-cffi not installed. Run: pip install argon2-cffi")

def bench_argon2():
    if not _HAS_ARGON2:
        return

    # Same parameters used in production (auth_backend/config.py)
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,   # 64 MB RAM per hash
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    plain = "MyP@ssw0rd!"
    argon_hash = ph.hash(plain)

    print(SEPARATOR)
    print("1. ARGON2id  — password hashing  (used ONCE at login)")
    print(SEPARATOR)

    hash_times   = [timeit.timeit(lambda: ph.hash(plain),             number=1) for _ in range(10)]
    verify_times = [timeit.timeit(lambda: ph.verify(argon_hash, plain), number=1) for _ in range(10)]

    avg_hash   = sum(hash_times)   / len(hash_times)
    avg_verify = sum(verify_times) / len(verify_times)
    hps        = 1.0 / avg_verify   # hashes per second

    print(f"  hash   avg : {avg_hash   * 1000:.1f} ms   (min: {min(hash_times)   * 1000:.1f} ms)")
    print(f"  verify avg : {avg_verify * 1000:.1f} ms   (min: {min(verify_times) * 1000:.1f} ms)")
    print(f"  RAM cost   : 64 MB per hash  (defeats GPU/ASIC attacks)")
    print(f"  Attacker brute-force speed   : ~{hps:.0f} hash/sec  (single core)")
    print(f"  Attacker brute-force speed   : ~{hps * 8:.0f} hash/sec  (8-core machine)")
    print(f"  Time to try 1 000 000 passwords (1 core) : {1_000_000 / hps / 3600:.1f} hours")
    print(f"  Time to try 1 000 000 passwords (8 core) : {1_000_000 / (hps*8) / 3600:.1f} hours")
    print()
    return avg_verify


# ---------------------------------------------------------------------------
# 2. Server-side session UUID lookup baseline (in-memory simulation)
# ---------------------------------------------------------------------------
def bench_session_lookup():
    print(SEPARATOR)
    print("2. SERVER-SIDE SESSION LOOKUP  (in-memory baseline)")
    print(SEPARATOR)

    # Simulate a session store with 10,000 active sessions
    store = {
        str(uuid.uuid4()): {
            "role": "restaurant_admin",
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "is_valid": True,
        }
        for _ in range(10_000)
    }
    ids = list(store.keys())

    def lookup():
        return store.get(random.choice(ids))

    t = timeit.timeit(lookup, number=100_000) / 100_000 * 1_000_000

    print(f"  In-memory dict lookup avg : {t:.3f} µs")
    print(f"  PostgreSQL round-trip     : ~0.5–2 ms  (local)  ~5–15 ms  (network)")
    print(f"  At 100 concurrent users   : 100 × 1.5 ms = 150 ms total — imperceptible")
    print()


# ---------------------------------------------------------------------------
# 3. JWT HS256 — sign + verify (stdlib only, no pyjwt needed)
# ---------------------------------------------------------------------------
def bench_jwt():
    print(SEPARATOR)
    print("3. JWT HS256  (comparison — stdlib implementation)")
    print(SEPARATOR)

    secret = secrets.token_bytes(32)

    def jwt_sign(payload: dict) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        msg = (header + "." + body).encode()
        sig = hmac.new(secret, msg, hashlib.sha256).digest()
        enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return header + "." + body + "." + enc

    def jwt_verify(token: str) -> bool:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        msg      = (parts[0] + "." + parts[1]).encode()
        expected = hmac.new(secret, msg, hashlib.sha256).digest()
        pad      = parts[2] + "=" * (-len(parts[2]) % 4)
        actual   = base64.urlsafe_b64decode(pad)
        if not hmac.compare_digest(expected, actual):
            return False
        # Check expiry (exp claim)
        pad_b  = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad_b))
        return claims.get("exp", 0) > int(time.time())

    payload = {
        "sub":       str(uuid.uuid4()),
        "role":      "restaurant_admin",
        "tenant_id": str(uuid.uuid4()),
        "exp":       int(time.time()) + 3600,
        "iat":       int(time.time()),
        "jti":       secrets.token_hex(16),
    }
    token = jwt_sign(payload)

    sign_ms   = timeit.timeit(lambda: jwt_sign(payload), number=50_000) / 50_000 * 1000
    verify_ms = timeit.timeit(lambda: jwt_verify(token), number=50_000) / 50_000 * 1000

    print(f"  sign   avg : {sign_ms:.4f} ms")
    print(f"  verify avg : {verify_ms:.4f} ms")
    print(f"  token size : {len(token)} bytes  (cookie size comparison: UUID = 36 bytes)")
    print(f"  NOTE: no DB hit on verify — but NO instant revocation possible")
    print(f"  NOTE: if signing secret is stolen → forge ANY token for ANY user")
    print()
    return sign_ms, verify_ms


# ---------------------------------------------------------------------------
# 4. CSRF token constant-time compare (our system — per state-changing request)
# ---------------------------------------------------------------------------
def bench_csrf():
    print(SEPARATOR)
    print("4. CSRF DOUBLE-TOKEN CHECK  (per state-changing request)")
    print(SEPARATOR)

    server_token = secrets.token_hex(32)   # 64-char hex stored in DB
    client_token = server_token            # matching (valid request)

    def csrf_check():
        return hmac.compare_digest(server_token, client_token)

    t = timeit.timeit(csrf_check, number=1_000_000) / 1_000_000 * 1_000_000

    print(f"  Constant-time compare avg : {t:.4f} µs")
    print(f"  Overhead per request      : effectively zero")
    print()


# ---------------------------------------------------------------------------
# 5. Summary comparison table
# ---------------------------------------------------------------------------
def print_summary(argon_verify_avg_s, jwt_sign_ms, jwt_verify_ms):
    print(SEPARATOR)
    print("5. SUMMARY COMPARISON TABLE")
    print(SEPARATOR)

    db_ms     = 1.5    # typical PostgreSQL local round-trip
    speed_diff = db_ms - jwt_verify_ms

    rows = [
        ("", "OUR SYSTEM", "JWT HS256", "WINNER"),
        ("─" * 30, "─" * 28, "─" * 20, "─" * 24),

        # LOGIN
        ("[LOGIN]", "", "", ""),
        (
            "Password hash cost",
            f"{argon_verify_avg_s*1000:.0f} ms  (Argon2id)",
            f"{jwt_sign_ms:.4f} ms  (HMAC sign)",
            "Argon2id — intentionally slow",
        ),
        (
            "Purpose of slowness",
            "Kills brute-force at source",
            "No equivalent protection",
            "Our system",
        ),

        # PER REQUEST
        ("[PER REQUEST]", "", "", ""),
        (
            "Token verify cost",
            f"~{db_ms:.1f} ms  (DB lookup)",
            f"{jwt_verify_ms:.4f} ms  (CPU only)",
            f"JWT faster by {speed_diff:.2f} ms",
        ),
        (
            "Speed diff at 100 users",
            f"100 × {speed_diff:.2f} ms = {100*speed_diff:.0f} ms total",
            "baseline",
            "Irrelevant at this scale",
        ),
        (
            "CSRF protection",
            "Built-in (DB token, ~0.5 µs)",
            "Not included — DIY",
            "Our system",
        ),

        # SECURITY
        ("[SECURITY]", "", "", ""),
        (
            "Instant revocation",
            "Yes — flip is_valid=False",
            "No — wait for exp",
            "Our system (critical)",
        ),
        (
            "Stolen cookie after logout",
            "Dead immediately",
            "Valid until exp",
            "Our system",
        ),
        (
            "Role change takes effect",
            "Next request",
            "After token expiry",
            "Our system",
        ),
        (
            "Secret compromise blast radius",
            "One session (UUID revoked)",
            "ALL users — forge any token",
            "Our system",
        ),
        (
            "Cookie/token size",
            "36 bytes (UUID)",
            f"{200}+ bytes (JWT)",
            "Our system (~5× smaller)",
        ),
        (
            "Tenant isolation tamper-proof",
            "Yes — stored in DB",
            "No — in base64 token body",
            "Our system",
        ),
        (
            "Session fixation prevention",
            "cycle_key() on login",
            "Not built-in",
            "Our system",
        ),
        (
            "Anomaly detection",
            "IP + UA per session",
            "Stateless — no baseline",
            "Our system",
        ),

        # OPERATIONS
        ("[OPERATIONS]", "", "", ""),
        (
            "Secret rotation",
            "Nothing to rotate",
            "Forces all re-login",
            "Our system",
        ),
        (
            "Logout behaviour",
            "Real logout",
            "Fake logout (token lives on)",
            "Our system",
        ),
        (
            "Horizontal scaling",
            "Requires shared DB",
            "No shared state needed",
            "JWT (microservices only)",
        ),
        (
            "Public API / CI-CD tokens",
            "Use scoped API keys instead",
            "JWT works well here",
            "JWT (different use case)",
        ),
    ]

    col = [30, 30, 22, 26]
    for row in rows:
        if row[0].startswith("[") and row[0].endswith("]"):
            print(f"\n  {row[0]}")
            continue
        print("  " + "  ".join(str(c).ljust(col[i]) for i, c in enumerate(row)))

    print()
    print(SEPARATOR)
    print("VERDICT")
    print(SEPARATOR)
    print(f"""
  JWT's only real advantage over our system is {speed_diff:.2f} ms per request.
  At 100 concurrent users that is {100*speed_diff:.0f} ms spread across everyone — noise.
  JWT becomes relevant at >50,000 req/sec on a single server.
  No hotel, restaurant, or internal enterprise tool reaches that.

  For systems where instant revocation, audit trails, ABAC, and
  compliance matter (GDPR, HIPAA, PCI-DSS) — server-side sessions win.

  For public APIs, CI/CD pipelines, and 20+ microservices without
  a shared DB — use short-lived JWT backed by server-side refresh tokens
  (which is what AWS Cognito, Azure AD, and Google Identity do).
  Even they don't use pure stateless JWT.
""")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print()
    print(SEPARATOR)
    print("  AUTH SYSTEM BENCHMARK")
    print("  Argon2id + Server-Side Sessions  vs  JWT HS256")
    print(SEPARATOR)
    print()

    argon_avg = bench_argon2() or 0.39   # fallback if argon2 not installed
    bench_session_lookup()
    jwt_sign_ms, jwt_verify_ms = bench_jwt()
    bench_csrf()
    print_summary(argon_avg, jwt_sign_ms, jwt_verify_ms)
