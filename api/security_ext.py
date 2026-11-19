"""
Production security extensions for the MÜDEK API.

Provides:
- `install(app, pool)`: wires global exception handler, CORS, structured logging,
  login brute-force limiter, must-change-password middleware, and audit logging.
- `audit_log(pool, user_id, action, target, meta)`: record destructive actions.
- `ensure_hardening_tables(pool)`: creates audit_log table and adds
  must_change_password column if missing.
"""
from __future__ import annotations

import logging
import os
import time
import traceback
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


log = logging.getLogger("mudek")


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

def ensure_hardening_tables(pool) -> None:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          BIGSERIAL PRIMARY KEY,
                ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                user_id     BIGINT,
                username    TEXT,
                ip          TEXT,
                action      TEXT NOT NULL,
                target      TEXT,
                status_code INTEGER,
                meta        TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS audit_log_user_idx ON audit_log (user_id)")
        # Revoked JWT tokens (logout). jti is short-lived (24h); we still store
        # expires_at so old rows can be purged.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti        TEXT PRIMARY KEY,
                user_id    BIGINT,
                revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS revoked_tokens_exp_idx ON revoked_tokens (expires_at)")
        # Self-servis şifre sıfırlama token'ları. Token ham değil sha256 olarak
        # saklanır; tek kullanımlık (used_at) ve kısa ömürlüdür (expires_at).
        # Migration 011 ile aynı şema — burada da garantiye alınır ki migration
        # unutulsa bile özellik çalışsın.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         BIGSERIAL PRIMARY KEY,
                user_id    BIGINT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at    TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ip         TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS prt_token_hash_idx ON password_reset_tokens (token_hash)")
        cur.execute("CREATE INDEX IF NOT EXISTS prt_user_idx ON password_reset_tokens (user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS prt_expires_idx ON password_reset_tokens (expires_at)")
        conn.commit()


def audit_log(pool, *, user_id: Optional[int], username: Optional[str],
              ip: Optional[str], action: str, target: Optional[str] = None,
              status_code: Optional[int] = None, meta: Optional[str] = None) -> None:
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log (user_id, username, ip, action, target, status_code, meta)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (user_id, username, ip, action, target, status_code, meta),
            )
            conn.commit()
    except Exception as exc:
        log.warning("audit_log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Login brute-force limiter (in-memory, per-IP sliding window)
# ---------------------------------------------------------------------------

class LoginLimiter:
    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.window = 60.0
        self._hits: dict[str, deque] = defaultdict(deque)

    def check(self, ip: str) -> bool:
        now = time.monotonic()
        dq = self._hits[ip]
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.max:
            return False
        dq.append(now)
        return True

    def reset(self, ip: str) -> None:
        self._hits.pop(ip, None)


# ---------------------------------------------------------------------------
# Middleware: must-change-password gate
# ---------------------------------------------------------------------------

class MustChangePasswordMiddleware(BaseHTTPMiddleware):
    """
    If a user authenticated with an unchanged default password, block every
    endpoint except the ones needed to change it.
    """
    ALLOWED_PATHS = {
        "/api/change-password",
        "/api/auth/me",
        "/api/logout",
        "/api/forgot-password",
        "/api/reset-password",
        "/health",
    }

    def __init__(self, app, pool):
        super().__init__(app)
        self.pool = pool

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.ALLOWED_PATHS or path == "/api/login" or not path.startswith("/api/"):
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return await call_next(request)

        token = auth.split(" ", 1)[1].strip()
        try:
            import jwt
            from database import SECRET_KEY
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = int(payload.get("user_id", 0))
        except Exception:
            return await call_next(request)

        try:
            with self.pool.connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT must_change_password FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
        except Exception as exc:
            log.warning("must_change_password check failed: %s", exc)
            return await call_next(request)

        if row and row[0]:
            return JSONResponse(
                status_code=403,
                content={"detail": "Varsayılan şifreyi değiştirmeden işlem yapamazsınız.", "must_change_password": True},
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

def _install_exception_handlers(app: FastAPI, env: str) -> None:
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(request: Request, exc: StarletteHTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Geçersiz istek verisi"})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.error("UNHANDLED %s %s\n%s", request.method, request.url.path, traceback.format_exc())
        detail = "Sunucu hatası oluştu"
        if env != "production":
            detail = f"{type(exc).__name__}: {exc}"
        return JSONResponse(status_code=500, content={"detail": detail})


# ---------------------------------------------------------------------------
# Access log middleware
# ---------------------------------------------------------------------------

class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            elapsed = (time.monotonic() - start) * 1000
            log.exception("%s %s err in %.1fms", request.method, request.url.path, elapsed)
            raise
        elapsed = (time.monotonic() - start) * 1000
        if response.status_code >= 400 or elapsed > 1000:
            log.info("%s %s -> %d in %.1fms", request.method, request.url.path,
                     response.status_code, elapsed)
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Record every successful mutation (POST/PUT/DELETE/PATCH) to audit_log."""
    AUDIT_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    # login + şifre sıfırlama uçları kendi audit kayıtlarını yazıyor.
    SKIP_PATHS = {"/api/login", "/api/forgot-password", "/api/reset-password"}

    def __init__(self, app, pool):
        super().__init__(app)
        self.pool = pool

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        try:
            if (
                request.method in self.AUDIT_METHODS
                and request.url.path.startswith("/api/")
                and request.url.path not in self.SKIP_PATHS
                and response.status_code < 500
            ):
                user_id, username = _user_from_request(request)
                audit_log(
                    self.pool,
                    user_id=user_id, username=username,
                    ip=client_ip(request),
                    action=f"{request.method} {request.url.path}",
                    target=None, status_code=response.status_code,
                )
        except Exception as exc:
            log.warning("audit middleware failed: %s", exc)
        return response


def _user_from_request(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, None
    try:
        import jwt
        from database import SECRET_KEY
        payload = jwt.decode(auth.split(" ", 1)[1].strip(), SECRET_KEY, algorithms=["HS256"])
        return int(payload.get("user_id", 0)) or None, payload.get("username")
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Public install hook
# ---------------------------------------------------------------------------

def install(app: FastAPI, pool) -> LoginLimiter:
    env = os.getenv("ENVIRONMENT", "production").strip().lower()
    level = logging.DEBUG if env == "development" else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    origins_raw = os.getenv("CORS_ORIGINS", "").strip()
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    allow_credentials = True
    if not origins or origins == ["*"]:
        origins = ["*"]
        allow_credentials = False

    existing_cors = any(m.cls is CORSMiddleware for m in app.user_middleware)
    if existing_cors:
        app.user_middleware = [m for m in app.user_middleware if m.cls is not CORSMiddleware]
        app.middleware_stack = None

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

    app.add_middleware(AuditMiddleware, pool=pool)
    app.add_middleware(MustChangePasswordMiddleware, pool=pool)
    app.add_middleware(AccessLogMiddleware)

    _install_exception_handlers(app, env)

    rate = int(os.getenv("LOGIN_RATE_LIMIT_PER_MINUTE", "10"))
    return LoginLimiter(max_per_minute=rate)


def client_ip(request: Request) -> str:
    # TRUSTED_PROXY_COUNT: kaç proxy katmanı arkasındayız (varsayılan 1 = tek nginx).
    # XFF listesinin sonundaki N IP proxy'ye ait; geriye kalan ilk IP gerçek client.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
        proxy_count = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))
        # En az proxy_count kadar IP varsa kırparak gerçek client'ı al;
        # aksi hâlde (proxy yoksa) doğrudan client.host'a düş.
        if len(ips) > proxy_count:
            return ips[-(proxy_count + 1)]
    return request.client.host if request.client else "unknown"
