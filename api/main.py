from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import pandas as pd
import psycopg
from psycopg_pool import ConnectionPool
import os
import io
import re
import logging
import traceback
import jwt
from datetime import date, datetime, timedelta, timezone
import secrets
import unicodedata

from database import DB_URL, SECRET_KEY
from security_ext import install as install_security, LoginLimiter, client_ip, audit_log, ensure_hardening_tables
from committee_pdf import build_committee_consolidated_pdf
from auth_utils import (
    _hash_password,
    _is_bcrypt_hash,
    _verify_password,
    generate_random_password,
    _validate_password_policy,
)
from password_reset import router as password_reset_router, init_password_reset

# ---------------------------------------------------------------------------
# Connection pool — created once at module load, opened at startup
# ---------------------------------------------------------------------------
pool = ConnectionPool(DB_URL, min_size=2, max_size=10, open=False)


# Parola yardımcıları (_hash_password, _is_bcrypt_hash, _verify_password,
# generate_random_password, _validate_password_policy) artık auth_utils
# modülünde tanımlı ve yukarıda import edildi.


# ======================================================
# Yardımcı fonksiyonlar
# ======================================================

def create_username(full_name: str, email: Optional[str] = None) -> str:
    if email:
        return email.split("@")[0]
    username = full_name.lower().strip()
    username = unicodedata.normalize("NFKD", username)
    username = "".join(c for c in username if not unicodedata.combining(c))
    username = username.replace(" ", ".")
    return "".join(c for c in username if c.isalnum() or c == ".")


def _normalize_student_no(raw) -> str:
    """Öğrenci numarasını kanonik forma getirir — aynı öğrencinin farklı
    derslerde çift kayıt olmasını önler.

    pandas, bir sütunda boş hücre varsa sayıları float okur ('2026001' → '2026001.0').
    Bu yüzden '.0' kuyruğu ve baştaki/sondaki boşluklar temizlenir; böylece
    '2026001.0', ' 2026001 ', '2026001' aynı '2026001' değerine çözülür ve
    students.student_no (UNIQUE) tek satır olarak kalır.
    """
    s = str("" if raw is None else raw).strip()
    m = re.fullmatch(r"(\d+)\.0+", s)
    if m:
        s = m.group(1)
    return s


def student_email(student_no: str) -> str:
    """Okul standardı öğrenci e-postası: f<öğrenci_no>@ktun.edu.tr.

    Öğrenci numarası zaten 'f' ile başlıyorsa ikinci kez eklenmez (çift-f koruması).
    Kullanıcı adı bu e-postanın yerel kısmından türetilir: create_username(_, email).
    """
    sn = _normalize_student_no(student_no)
    local = sn if sn.lower().startswith("f") else f"f{sn}"
    return f"{local}@ktun.edu.tr"


# ======================================================
# Uygulama & Config
# ======================================================

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(application: FastAPI):
    """O3 fix: Modern lifespan context manager (on_event yerine)."""
    # ── Startup ──
    pool.open()
    try:
        ensure_hardening_tables(pool)
    except Exception as e:
        logging.warning("Hardening tabloları kurulumu başarısız: %s", e)
    try:
        _ensure_survey_tables()
    except Exception as e:
        logging.warning("Survey tabloları oluşturulurken hata: %s", e)
    try:
        _ensure_exam_artifacts_table()
    except Exception as e:
        logging.warning("exam_artifacts tablosu oluşturulurken hata: %s", e)
    yield
    # ── Shutdown ──
    pool.close()


app = FastAPI(lifespan=lifespan)

# Security hardening (CORS, exception handler, access log, must-change-password
# middleware, structured logging). Must be attached before routes are registered
# so the middleware wraps every endpoint.
login_limiter: LoginLimiter = install_security(app, pool)

# Şifre sıfırlama (forgot/reset) endpoint'leri ayrı modülde (password_reset.py);
# main.py'ı şişirmemek için router olarak bağlanır. init ile DB pool'u verilir.
init_password_reset(pool)
app.include_router(password_reset_router)

security = HTTPBearer()


# ======================================================
# Veritabanı / Auth yardımcıları
# ======================================================

def rows_to_dicts(cur) -> list[dict]:
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


# JWT token süresi: 24 saat
JWT_EXPIRY_HOURS = 24


def create_jwt(user_id: int, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "jti": secrets.token_hex(16),
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _is_token_revoked(jti: str | None) -> bool:
    """Logout sonrası iptal edilen JWT'leri tespit eder. Tablo yoksa False döner."""
    if not jti:
        return False
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = %s", (jti,))
            return cur.fetchone() is not None
    except Exception:
        # revoked_tokens tablosu henüz oluşturulmamışsa graceful degrade
        return False


def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Oturum süresi doldu, lütfen tekrar giriş yapın")
    except Exception:
        raise HTTPException(status_code=401, detail="Token geçersiz")
    if _is_token_revoked(payload.get("jti")):
        raise HTTPException(status_code=401, detail="Oturum kapatılmış, lütfen tekrar giriş yapın")
    # K3 fix: Şifre değişiminden önceki token'ları reddet
    iat = payload.get("iat")
    if iat:
        user_id = payload.get("user_id")
        try:
            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT password_changed_at FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cur.fetchone()
                if row and row[0]:
                    pw_changed = row[0].timestamp()
                    if iat < pw_changed:
                        raise HTTPException(
                            status_code=401,
                            detail="Şifre değiştirildi, lütfen tekrar giriş yapın",
                        )
        except HTTPException:
            raise
        except Exception:
            pass  # password_changed_at kolonu yoksa graceful degrade
    return payload


def has_permission(user_id: int, perm_code: str) -> bool:
    sql = """
        SELECT EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = %s AND p.code = %s
        )
    """
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (user_id, perm_code))
        return bool(cur.fetchone()[0])


def require_perm(permission_code: str):
    async def _dep(credentials: HTTPAuthorizationCredentials = Depends(security)):
        token_data = decode_jwt(credentials.credentials)
        user_id = int(token_data["user_id"])
        if not has_permission(user_id, permission_code):
            raise HTTPException(status_code=403, detail="Bu işlemi yapma izniniz yok")
        return token_data
    return _dep


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    return decode_jwt(credentials.credentials)


def check_user_role(user_id: int, allowed_roles: list) -> bool:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT r.code FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        return bool(row) and row[0] in allowed_roles


def require_role(required_role: str):
    def wrapper(credentials: HTTPAuthorizationCredentials = Depends(security)):
        token_data = decode_jwt(credentials.credentials)
        if token_data.get("role") != required_role:
            raise HTTPException(403, f"Bu işlem için '{required_role}' yetkisi gerekiyor")
        return token_data
    return wrapper


def require_instructor_permission():
    """Admin, bölüm başkanı, MÜDEK kurul üyesi veya öğretim üyesi yetkisi."""
    def wrapper(credentials: HTTPAuthorizationCredentials = Depends(security)):
        token_data = decode_jwt(credentials.credentials)
        authorized = {"admin", "bolum_baskani", "mudek_kurul_uyesi", "ogretim_uyesi"}
        if token_data.get("role") not in authorized:
            raise HTTPException(403, "Bu işlem için Hoca veya Yönetici yetkisi gerekiyor")
        return token_data
    return wrapper


def require_committee_permission():
    """Sadece admin, bölüm başkanı ve MÜDEK kurul üyesi komisyon işlemleri yapabilir."""
    def dependency(user: dict = Depends(get_current_user)):
        if not check_user_role(user["user_id"], ["admin", "bolum_baskani", "mudek_kurul_uyesi"]):
            raise HTTPException(403, "Bu işlemi yapma yetkiniz yok.")
        return user
    return dependency


MANAGER_ROLES = {"admin", "bolum_baskani", "mudek_kurul_uyesi"}


def _ensure_offering_owned(offering_id: int, user: dict):
    """ogretim_uyesi için offering sahipliği kontrolü; manager rollerinde bypass."""
    role = user.get("role")
    if role in MANAGER_ROLES:
        return
    if role != "ogretim_uyesi":
        raise HTTPException(403, "Yetkisiz")
    user_id = int(user["user_id"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1 FROM course_offerings co
            JOIN instructors i ON co.instructor_id = i.id
            WHERE co.id = %s AND i.user_id = %s
            """,
            (offering_id, user_id),
        )
        if not cur.fetchone():
            raise HTTPException(403, "Bu ders size ait değil")


def _ensure_survey_owned(survey_id: int, user: dict):
    """ogretim_uyesi için survey sahipliği (offering üzerinden); manager rollerinde bypass."""
    role = user.get("role")
    if role in MANAGER_ROLES:
        return
    if role != "ogretim_uyesi":
        raise HTTPException(403, "Yetkisiz")
    user_id = int(user["user_id"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1 FROM surveys s
            JOIN course_offerings co ON s.offering_id = co.id
            JOIN instructors i ON co.instructor_id = i.id
            WHERE s.id = %s AND i.user_id = %s
            """,
            (survey_id, user_id),
        )
        if not cur.fetchone():
            raise HTTPException(403, "Bu anket size ait değil")


# ======================================================
# Health & Login
# ======================================================

@app.get("/health")
def health():
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return {"ok": True}
    except Exception:
        logging.getLogger("mudek").exception("healthcheck failed")
        raise HTTPException(503, "Servis geçici olarak kullanılamıyor")




class LoginRequest(BaseModel):
    username: str
    password: str


from fastapi import Request

@app.post("/api/login")
def login(req: LoginRequest, request: Request):
    """
    Giriş endpoint'i — bcrypt ile doğrulama yapar.
    Eski düz metin şifreleri otomatik olarak bcrypt'e dönüştürür (migration).
    """
    ip = client_ip(request)
    if not login_limiter.check(ip):
        audit_log(pool, user_id=None, username=req.username, ip=ip,
                  action="login.rate_limited", target=None, status_code=429)
        raise HTTPException(429, "Çok fazla giriş denemesi. Lütfen biraz bekleyin.")

    with pool.connection() as conn, conn.cursor() as cur:
        # Kullanıcıyı sadece username ile bul (şifre kontrolü Python'da yapılır)
        cur.execute(
            "SELECT id, username, full_name, email, is_active, password_hash, must_change_password FROM users WHERE username = %s",
            (req.username,),
        )
        row = cur.fetchone()
        if not row:
            audit_log(pool, user_id=None, username=req.username, ip=ip,
                      action="login.failed", target="unknown_user", status_code=401)
            raise HTTPException(401, "Kullanıcı adı veya şifre hatalı")

        cols = [c.name for c in cur.description]
        user_data = dict(zip(cols, row))
        stored_hash = user_data.pop("password_hash")  # Frontend'e gönderme

        # is_active=False de aynı 401 ile cevaplanır — hesap enumeration koruması.
        if not user_data.get("is_active"):
            audit_log(pool, user_id=user_data["id"], username=req.username, ip=ip,
                      action="login.failed", target="inactive", status_code=401)
            raise HTTPException(401, "Kullanıcı adı veya şifre hatalı")

        password_ok = False
        if _is_bcrypt_hash(stored_hash):
            # Modern hesap: yalnızca bcrypt verify. Hash girmek parolayı asla geçirmemeli.
            password_ok = _verify_password(req.password, stored_hash)
        elif stored_hash and stored_hash == req.password:
            # Legacy düz metin hesap — yalnızca hash bcrypt değilse fallback.
            # Başarılı eşleşmede otomatik olarak bcrypt'e migrate edilir.
            password_ok = True
            logging.warning(
                "PLAINTEXT_LOGIN user_id=%s username=%s — hesap bcrypt'e migrate ediliyor",
                user_data["id"], user_data.get("username"),
            )
            try:
                new_hash = _hash_password(req.password)
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_data["id"]))
                conn.commit()
            except Exception:
                logging.exception("plaintext->bcrypt migration failed user_id=%s", user_data["id"])

        if not password_ok:
            audit_log(pool, user_id=user_data["id"], username=user_data.get("username"), ip=ip,
                      action="login.failed", target="bad_password", status_code=401)
            raise HTTPException(401, "Kullanıcı adı veya şifre hatalı")

        cur.execute(
            "SELECT r.code FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = %s LIMIT 1",
            (user_data["id"],),
        )
        role_row = cur.fetchone()
        user_data["role"] = role_row[0] if role_row else "guest"

    token = create_jwt(user_data["id"], user_data["username"], user_data["role"])
    login_limiter.reset(ip)
    audit_log(pool, user_id=user_data["id"], username=user_data["username"], ip=ip,
              action="login.success", target=None, status_code=200)
    return {"success": True, "message": "Giriş başarılı", "user": user_data, "token": token}


@app.post("/api/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Stateless JWT için logout: token'ın jti claim'ini revoked_tokens tablosuna
    yazar. Sonraki tüm istekler decode_jwt'de 401 alır.
    """
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=["HS256"],
            options={"verify_exp": False},  # süresi dolmuş token bile revoke edilebilsin
        )
    except Exception:
        return {"success": True, "message": "Çıkış yapıldı"}

    jti = payload.get("jti")
    user_id = payload.get("user_id")
    exp_ts = payload.get("exp")
    if jti and exp_ts:
        try:
            expires_at = datetime.fromtimestamp(int(exp_ts), tz=timezone.utc)
            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO revoked_tokens (jti, user_id, expires_at) "
                    "VALUES (%s, %s, %s) ON CONFLICT (jti) DO NOTHING",
                    (jti, user_id, expires_at),
                )
                # Süresi geçmiş token'ları periyodik olarak temizle
                cur.execute("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
                conn.commit()
        except Exception as exc:
            logging.warning("logout token revoke failed: %s", exc)
    return {"success": True, "message": "Çıkış yapıldı"}


@app.get("/api/auth/me")
def auth_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.full_name, u.email, u.must_change_password,
                   COALESCE(r.code, 'guest') as role
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = %s
            """,
            (token_data["user_id"],),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        return dict(zip([c.name for c in cur.description], row))


# ======================================================
# Şifre Değiştir
# ======================================================

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


@app.post("/api/change-password")
def change_password(
    req: PasswordChangeRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT password_hash, username FROM users WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")

        stored_hash, username = row[0], row[1]
        # Eski şifreyi doğrula: bcrypt yalnızca $2 hash'ler için, plaintext fallback
        # yalnızca legacy (bcrypt olmayan) hash'ler için.
        if _is_bcrypt_hash(stored_hash):
            old_ok = _verify_password(req.old_password, stored_hash)
        else:
            old_ok = bool(stored_hash) and stored_hash == req.old_password

        if not old_ok:
            raise HTTPException(401, "Mevcut şifre hatalı")

        if req.new_password == req.old_password:
            raise HTTPException(400, "Yeni şifre eskisi ile aynı olamaz")
        _validate_password_policy(req.new_password)

        new_hash = _hash_password(req.new_password)
        cur.execute(
            "UPDATE users SET password_hash = %s, must_change_password = FALSE, password_changed_at = NOW() WHERE id = %s",
            (new_hash, user_id),
        )

        # Mevcut JWT'yi revoke et: kullanıcı parola değiştirdikten sonra bu token
        # sürekli geçerli kalmamalı, yeniden login zorunlu olsun.
        jti = token_data.get("jti")
        exp_ts = token_data.get("exp")
        if jti and exp_ts:
            try:
                expires_at = datetime.fromtimestamp(int(exp_ts), tz=timezone.utc)
                cur.execute(
                    "INSERT INTO revoked_tokens (jti, user_id, expires_at) "
                    "VALUES (%s, %s, %s) ON CONFLICT (jti) DO NOTHING",
                    (jti, user_id, expires_at),
                )
            except Exception:
                logging.warning("change-password token revoke failed", exc_info=True)
        conn.commit()

    audit_log(pool, user_id=user_id, username=username, ip=None,
              action="password.change", target=None, status_code=200)
    return {"success": True, "message": "✅ Şifreniz başarıyla değiştirildi", "reauth_required": True}


# ======================================================
# Kullanıcı Yönetimi (RBAC)
# ======================================================

class RoleUpdate(BaseModel):
    role: str


@app.get("/api/users", dependencies=[Depends(require_perm("manage_users"))])
def list_users():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.full_name, u.email, u.is_active,
                   COALESCE(r.code, 'guest') as role
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            ORDER BY u.id
            """
        )
        return rows_to_dicts(cur)


@app.get("/api/roles", dependencies=[Depends(require_perm("manage_users"))])
def list_roles():
    """Tüm rolleri döndürür. Frontend, rol seçim kutularını bu listeden doldurur."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, code, COALESCE(name, code) AS name FROM roles ORDER BY id")
        return rows_to_dicts(cur)


@app.put("/api/users/{user_id}/role", dependencies=[Depends(require_perm("manage_users"))])
def update_user_role(user_id: int, payload: RoleUpdate):
    new_role = payload.role.strip()

    with pool.connection() as conn, conn.cursor() as cur:
        # Rolün geçerliliğini hardcoded set yerine veritabanından doğrula — bu sayede
        # admin tarafından tanımlanan yeni roller (ör. 'student') de atanabilir.
        cur.execute("SELECT id FROM roles WHERE code = %s", (new_role,))
        role_row = cur.fetchone()
        if not role_row:
            raise HTTPException(400, f"Geçersiz rol: {new_role}")

        cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        username = row[1]

        cur.execute(
            "SELECT r.code FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = %s",
            (user_id,),
        )
        current_role_row = cur.fetchone()
        if current_role_row and current_role_row[0] == "admin" and new_role != "admin":
            cur.execute(
                "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE r.code = 'admin'"
            )
            if cur.fetchone()[0] <= 1:
                raise HTTPException(400, "Son admin'in rolü değiştirilemez")

        cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
        cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, role_row[0]))
        conn.commit()

        cur.execute(
            """
            SELECT u.id, u.username, u.full_name, u.email, r.code as role
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = %s
            """,
            (user_id,),
        )
        updated = dict(zip([c.name for c in cur.description], cur.fetchone()))
    return {"success": True, **updated, "message": f"✅ {username} rolü {new_role} olarak güncellendi"}


@app.delete("/api/users/{user_id}", dependencies=[Depends(require_perm("manage_users"))])
def delete_user(user_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, r.code as role
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = %s
            """,
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        if row[2] == "admin":
            cur.execute(
                "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE r.code = 'admin'"
            )
            if cur.fetchone()[0] <= 1:
                raise HTTPException(400, "Son admin silinemez")
        # O1 fix: İlişkili tabloları temizle (cascade)
        cur.execute("DELETE FROM committee_members WHERE user_id = %s", (user_id,))
        cur.execute("UPDATE instructors SET user_id = NULL WHERE user_id = %s", (user_id,))
        cur.execute("UPDATE students SET user_id = NULL WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    return {"success": True, "message": f"✅ {row[1]} silindi"}


@app.post("/api/users/{user_id}/reset-password", dependencies=[Depends(require_perm("manage_users"))])
def reset_user_password(user_id: int):
    """
    Admin tarafından kullanıcının şifresini sıfırlar:
    - Yeni rastgele geçici şifre üretir, bcrypt ile saklar
    - must_change_password=TRUE yapar (kullanıcı ilk girişte değiştirmek zorunda)
    - Kullanıcının tüm aktif tokenlarını revoke eder
    Yanıt sadece bir kez geçici şifreyi gösterir.
    """
    new_temp = generate_random_password(12)
    new_hash = _hash_password(new_temp)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT username, full_name FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        username, full_name = row[0], row[1]
        cur.execute(
            "UPDATE users SET password_hash = %s, must_change_password = TRUE, password_changed_at = NOW() WHERE id = %s",
            (new_hash, user_id),
        )
        # Aktif tokenları revoke et (tüm jti'ler bilinmediği için audit'e güveniyoruz —
        # uygulama ileride password_changed_at iat-check'i ekleyene kadar bu yeterli).
        # Kullanıcı bir sonraki girişinde must_change_password gate'i ile blokludur.
        conn.commit()
    audit_log(pool, user_id=user_id, username=username, ip=None,
              action="password.reset_by_admin", target=None, status_code=200)
    logging.info("ADMIN_PASSWORD_RESET user_id=%s username=%s", user_id, username)
    return {
        "success": True,
        "user_id": user_id,
        "username": username,
        "temporary_password": new_temp,
        "warning": "Bu şifre yalnızca bir kez gösterilir — kullanıcıya güvenli kanaldan iletin.",
        "message": f"✅ {full_name} kullanıcısının şifresi sıfırlandı",
    }


# ======================================================
# Program Çıktıları (PÇ)
# ======================================================

class ProgramOutcomeCreate(BaseModel):
    code: str
    title: str


class ProgramOutcomeUpdate(BaseModel):
    title: str


@app.get("/api/program-outcomes", dependencies=[Depends(get_current_user)])
def get_program_outcomes():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, code, title
            FROM program_outcomes
            ORDER BY CAST(REGEXP_REPLACE(code, '[^0-9]', '', 'g') AS INTEGER)
            """
        )
        return rows_to_dicts(cur)


@app.post("/api/program-outcomes", dependencies=[Depends(require_committee_permission())])
def create_program_outcome(po: ProgramOutcomeCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO program_outcomes (code, title) VALUES (%s, %s) RETURNING id",
            (po.code, po.title),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": f"✅ {po.code} eklendi"}


@app.put("/api/program-outcomes/{po_id}", dependencies=[Depends(require_committee_permission())])
def update_program_outcome(po_id: int, po: ProgramOutcomeUpdate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE program_outcomes SET title = %s WHERE id = %s", (po.title, po_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Program çıktısı bulunamadı")
        conn.commit()
    return {"success": True, "message": "✅ Güncellendi"}


@app.delete("/api/program-outcomes/{po_id}")
def delete_program_outcome(po_id: int, user: dict = Depends(require_committee_permission())):
    """Program çıktısını siler. outcome_matrix ve course_learning_outcomes referansları varsa engellenir."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT code FROM program_outcomes WHERE id = %s", (po_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Program çıktısı bulunamadı")
        cur.execute("SELECT COUNT(*) FROM outcome_matrix WHERE program_outcome_id = %s", (po_id,))
        if cur.fetchone()[0] > 0:
            raise HTTPException(400, "Bu PÇ matris satırlarında kullanılıyor. Önce matrisi temizleyin.")
        cur.execute("DELETE FROM program_outcomes WHERE id = %s", (po_id,))
        conn.commit()
    return {"success": True, "message": f"✅ {row[0]} silindi"}


# ======================================================
# Dersler
# ======================================================

class CourseCreate(BaseModel):
    code: str
    name: str


@app.get("/api/courses", dependencies=[Depends(get_current_user)])
def get_courses():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, code, name FROM courses ORDER BY code")
        return rows_to_dicts(cur)


@app.post("/api/courses", dependencies=[Depends(require_committee_permission())])
def create_course(course: CourseCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO courses (code, name) VALUES (%s, %s) RETURNING id",
            (course.code, course.name),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": f"✅ Ders eklendi: {course.code}"}


@app.delete("/api/courses/{course_id}", dependencies=[Depends(require_committee_permission())])
def delete_course(course_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM course_offerings WHERE course_id = %s", (course_id,))
        if cur.fetchone()[0] > 0:
            raise HTTPException(400, "Bu ders açılışlarda kullanılıyor")
        cur.execute("DELETE FROM courses WHERE id = %s", (course_id,))
        conn.commit()
    return {"success": True, "message": "✅ Ders silindi"}


# ======================================================
# Öğretim Üyeleri
# ======================================================

class InstructorCreate(BaseModel):
    title: str
    name: str
    email: Optional[str] = None


@app.get("/api/instructors", dependencies=[Depends(get_current_user)])
def get_instructors():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, title, name, email FROM instructors ORDER BY name")
        return rows_to_dicts(cur)


@app.post("/api/instructors", dependencies=[Depends(require_committee_permission())])
def create_instructor(instructor: InstructorCreate):
    email = (instructor.email or "").strip() or None
    with pool.connection() as conn, conn.cursor() as cur:
        # Email çakışmalarını önceden tespit et — UNIQUE violation 500 yerine 400 dönsün.
        if email:
            cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
            if cur.fetchone():
                raise HTTPException(400, f"Bu e-posta zaten bir kullanıcıya ait: {email}")
            cur.execute("SELECT id FROM instructors WHERE LOWER(email) = LOWER(%s)", (email,))
            if cur.fetchone():
                raise HTTPException(400, f"Bu e-posta zaten bir hocaya ait: {email}")

        cur.execute(
            "INSERT INTO instructors (title, name, email) VALUES (%s, %s, %s) RETURNING id",
            (instructor.title, instructor.name, email),
        )
        new_instructor_id = cur.fetchone()[0]

        base_username = create_username(instructor.name, email)
        username = base_username
        counter = 1
        while True:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if not cur.fetchone():
                break
            username = f"{base_username}{counter}"
            counter += 1

        temp_password = generate_random_password(12)
        hashed_temp = _hash_password(temp_password)
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, email, is_active, must_change_password) "
            "VALUES (%s, %s, %s, %s, TRUE, TRUE) RETURNING id",
            (username, hashed_temp, instructor.name, email),
        )
        new_user_id = cur.fetchone()[0]

        cur.execute("SELECT id FROM roles WHERE code = 'ogretim_uyesi'")
        role_row = cur.fetchone()
        if role_row:
            cur.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)",
                (new_user_id, role_row[0]),
            )

        # instructors.user_id bağlantısını kur
        cur.execute("UPDATE instructors SET user_id = %s WHERE id = %s", (new_user_id, new_instructor_id))
        conn.commit()

    logging.info(
        "TEMP_PASSWORD_ISSUED type=instructor user_id=%s username=%s",
        new_user_id, username,
    )
    return {
        "success": True,
        "id": new_instructor_id,
        "user_id": new_user_id,
        "username": username,
        "temporary_password": temp_password,
        "warning": "Bu şifre yalnızca bir kez gösterilir — lütfen kaydedin ve kullanıcıya iletin.",
        "message": f"✅ {instructor.title} {instructor.name} eklendi",
    }


@app.delete("/api/instructors/{instructor_id}", dependencies=[Depends(require_committee_permission())])
def delete_instructor(instructor_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM course_offerings WHERE instructor_id = %s", (instructor_id,))
        if cur.fetchone()[0] > 0:
            raise HTTPException(400, "Bu hoca ders açılışlarında atanmış")
        # O6 fix: İlişkili user hesabını da temizle
        cur.execute("SELECT user_id FROM instructors WHERE id = %s", (instructor_id,))
        row = cur.fetchone()
        cur.execute("DELETE FROM instructors WHERE id = %s", (instructor_id,))
        if row and row[0]:
            # Hocaya ait user hesabı varsa ve başka rolü yoksa deaktive et
            cur.execute(
                "SELECT COUNT(*) FROM instructors WHERE user_id = %s",
                (row[0],),
            )
            if cur.fetchone()[0] == 0:
                cur.execute(
                    "UPDATE users SET is_active = FALSE WHERE id = %s",
                    (row[0],),
                )
        conn.commit()
    return {"success": True, "message": "✅ Hoca silindi"}


# ======================================================
# Ders Açılışları (Course Offerings)
# ======================================================

class CourseOfferingCreate(BaseModel):
    course_id: int
    term: str
    section: str
    instructor_id: Optional[int] = None


class CourseOfferingUpdate(BaseModel):
    term: Optional[str] = None
    section: Optional[str] = None
    instructor_id: Optional[int] = None


@app.get("/api/course-offerings", dependencies=[Depends(get_current_user)])
def get_course_offerings():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT co.id, co.term, co.section,
                   c.code as course_code, c.name as course_name,
                   i.name as instructor_name
            FROM course_offerings co
            JOIN courses c ON co.course_id = c.id
            LEFT JOIN instructors i ON co.instructor_id = i.id
            ORDER BY co.term DESC, c.code, co.section
            """
        )
        return rows_to_dicts(cur)


@app.post("/api/course-offerings", dependencies=[Depends(require_committee_permission())])
def create_course_offering(offering: CourseOfferingCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO course_offerings (course_id, term, section, instructor_id) VALUES (%s, %s, %s, %s) RETURNING id",
            (offering.course_id, offering.term, offering.section, offering.instructor_id),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": "✅ Ders açılışı oluşturuldu"}


@app.put("/api/course-offerings/{offering_id}", dependencies=[Depends(require_committee_permission())])
def update_course_offering(offering_id: int, upd: CourseOfferingUpdate):
    sets, vals = [], []
    if upd.term is not None:
        sets.append("term = %s"); vals.append(upd.term)
    if upd.section is not None:
        sets.append("section = %s"); vals.append(upd.section)
    if "instructor_id" in upd.model_fields_set:
        sets.append("instructor_id = %s"); vals.append(upd.instructor_id)
    if not sets:
        return {"success": True, "message": "Değişiklik yok"}
    vals.append(offering_id)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE course_offerings SET {', '.join(sets)} WHERE id = %s", tuple(vals))
        if cur.rowcount == 0:
            raise HTTPException(404, "Offering bulunamadı")
        conn.commit()
    return {"success": True, "message": "✅ Güncellendi"}


@app.delete("/api/course-offerings/{offering_id}", dependencies=[Depends(require_committee_permission())])
def delete_course_offering(offering_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM exams WHERE offering_id = %s", (offering_id,))
        if cur.fetchone()[0] > 0:
            raise HTTPException(400, "Bu açılışa bağlı sınavlar var")
        cur.execute("DELETE FROM course_offerings WHERE id = %s", (offering_id,))
        conn.commit()
    return {"success": True, "message": "✅ Ders açılışı silindi"}


# ======================================================
# Hoca kendi derslerini / sınavlarını görsün
# ======================================================

@app.get("/api/my-courses")
def get_my_courses(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, name FROM instructors WHERE user_id = %s", (user_id,))
        instructor = cur.fetchone()
        if not instructor:
            return {"offerings": [], "message": "Henüz ders atanmamış", "instructor_id": None, "instructor_name": ""}
        instructor_id, instructor_name = int(instructor[0]), instructor[1]
        cur.execute(
            """
            SELECT co.id, co.term, co.section,
                   c.code as course_code, c.name as course_name, c.id as course_id
            FROM course_offerings co
            JOIN courses c ON co.course_id = c.id
            WHERE co.instructor_id = %s
            ORDER BY co.term DESC, c.code
            """,
            (instructor_id,),
        )
        offerings = rows_to_dicts(cur)
    return {"instructor_id": instructor_id, "instructor_name": instructor_name, "offerings": offerings}


@app.get("/api/my-exams")
def get_my_exams(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM instructors WHERE user_id = %s", (user_id,))
        instructor = cur.fetchone()
        if not instructor:
            return []
        instructor_id = int(instructor[0])
        cur.execute(
            """
            SELECT e.id, e.title, e.exam_type, e.date,
                   c.code as course_code, c.name as course_name,
                   co.term, co.section
            FROM exams e
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            WHERE co.instructor_id = %s
            ORDER BY e.date DESC
            """,
            (instructor_id,),
        )
        return rows_to_dicts(cur)


# ======================================================
# Sınavlar
# ======================================================

class ExamCreate(BaseModel):
    offering_id: int
    title: str
    exam_type: Optional[str] = None   # 'midterm' | 'final' | 'resit'
    date: date


@app.get("/api/exams")
def list_exams(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "student")

    with pool.connection() as conn, conn.cursor() as cur:
        if role in MANAGER_ROLES:
            cur.execute(
                """
                SELECT e.id, e.title, e.exam_type, e.date,
                       c.code AS course_code, c.name AS course_name,
                       i.name AS instructor_name
                FROM exams e
                JOIN course_offerings co ON e.offering_id = co.id
                JOIN courses c ON co.course_id = c.id
                LEFT JOIN instructors i ON co.instructor_id = i.id
                ORDER BY e.date DESC
                """
            )
        elif role == "ogretim_uyesi":
            cur.execute("SELECT id FROM instructors WHERE user_id = %s", (user_id,))
            inst_row = cur.fetchone()
            if not inst_row:
                return []
            cur.execute(
                """
                SELECT e.id, e.title, e.exam_type, e.date,
                       c.code AS course_code, c.name AS course_name,
                       i.name AS instructor_name
                FROM exams e
                JOIN course_offerings co ON e.offering_id = co.id
                JOIN courses c ON co.course_id = c.id
                LEFT JOIN instructors i ON co.instructor_id = i.id
                WHERE co.instructor_id = %s
                ORDER BY e.date DESC
                """,
                (int(inst_row[0]),),
            )
        else:
            return []
        return rows_to_dicts(cur)


@app.post("/api/exams", dependencies=[Depends(require_instructor_permission())])
def create_exam(exam: ExamCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO exams (offering_id, title, exam_type, date) VALUES (%s, %s, %s, %s) RETURNING id",
            (exam.offering_id, exam.title, exam.exam_type, exam.date),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": f"✅ Sınav oluşturuldu: {exam.title}"}


@app.delete("/api/exams/{exam_id}", dependencies=[Depends(require_instructor_permission())])
def delete_exam(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM responses WHERE question_id IN (SELECT id FROM questions WHERE exam_id = %s)",
            (exam_id,),
        )
        cur.execute(
            "DELETE FROM question_outcomes WHERE question_id IN (SELECT id FROM questions WHERE exam_id = %s)",
            (exam_id,),
        )
        cur.execute("DELETE FROM questions WHERE exam_id = %s", (exam_id,))
        cur.execute("DELETE FROM exams WHERE id = %s", (exam_id,))
        conn.commit()
    return {"success": True, "message": "✅ Sınav silindi"}


# ======================================================
# Sınav Proje/Ödev Ağırlığı (Excel şablonu uyumu)
# ======================================================

class ExamProjectConfig(BaseModel):
    project_weight: float       # 0..1 (örn. 0.40 = %40 proje, %60 sorular)
    project_max_points: float   # proje üzerinden alınan maksimum puan (örn. 40)


class ExamProjectScore(BaseModel):
    student_no: str
    score: float


class ExamProjectScoresPayload(BaseModel):
    scores: List[ExamProjectScore]


@app.put("/api/exams/{exam_id}/project-config")
def set_exam_project_config(
    exam_id: int,
    cfg: ExamProjectConfig,
    user: dict = Depends(require_instructor_permission()),
):
    """
    Sınava proje/ödev ağırlığı atar. Excel şablonu mantığı:
        exam_total = q_norm × (1 - project_weight) + p_norm × project_weight
    project_weight = 0 → proje bileşeni yok (default).
    """
    if not (0.0 <= cfg.project_weight <= 1.0):
        raise HTTPException(400, "project_weight 0..1 aralığında olmalı")
    if cfg.project_max_points < 0:
        raise HTTPException(400, "project_max_points negatif olamaz")
    if cfg.project_weight > 0 and cfg.project_max_points <= 0:
        raise HTTPException(400, "Proje ağırlığı > 0 ise project_max_points > 0 olmalı")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM exams WHERE id = %s", (exam_id,))
        if not cur.fetchone():
            raise HTTPException(404, "Sınav bulunamadı")
        cur.execute(
            "UPDATE exams SET project_weight = %s, project_max_points = %s WHERE id = %s",
            (cfg.project_weight, cfg.project_max_points, exam_id),
        )
        conn.commit()
    return {"success": True, "message": "✅ Proje ağırlığı güncellendi"}


@app.get("/api/exams/{exam_id}/project-config")
def get_exam_project_config(
    exam_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(project_weight,0), COALESCE(project_max_points,0) "
            "FROM exams WHERE id = %s",
            (exam_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Sınav bulunamadı")
        return {
            "exam_id": exam_id,
            "project_weight": float(row[0]),
            "project_max_points": float(row[1]),
        }


@app.post("/api/exams/{exam_id}/project-scores")
def set_exam_project_scores(
    exam_id: int,
    payload: ExamProjectScoresPayload,
    user: dict = Depends(require_instructor_permission()),
):
    """Öğrenci proje/ödev puanlarını toplu kaydeder. Mevcut kayıtlar üzerine yazılır."""
    if not payload.scores:
        raise HTTPException(400, "En az bir öğrenci puanı girilmeli")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(project_weight,0), COALESCE(project_max_points,0) "
            "FROM exams WHERE id = %s",
            (exam_id,),
        )
        exam_row = cur.fetchone()
        if not exam_row:
            raise HTTPException(404, "Sınav bulunamadı")
        pw = float(exam_row[0])
        pmp = float(exam_row[1])

        warnings: list[str] = []
        invalid: list[str] = []
        for s in payload.scores:
            score = float(s.score)
            if score < 0:
                invalid.append(f"{s.student_no}: negatif puan ({score})")
            elif pw > 0 and pmp > 0 and score > pmp:
                invalid.append(f"{s.student_no}: {score} > project_max_points ({pmp})")
        if invalid:
            raise HTTPException(
                400,
                "Geçersiz proje puanları: " + "; ".join(invalid[:10])
                + (" ..." if len(invalid) > 10 else ""),
            )
        if pw <= 0:
            warnings.append(
                "Sınavın project_weight=0 — proje puanları kaydedildi ama hesaplamaya katılmayacak. "
                "Önce project-config ile project_weight ayarlayın."
            )

        student_nos = [s.student_no for s in payload.scores]
        cur.execute(
            "SELECT id, student_no FROM students WHERE student_no = ANY(%s)",
            (student_nos,),
        )
        sid_by_no = {sn: int(sid) for sid, sn in cur.fetchall()}
        missing = [sn for sn in student_nos if sn not in sid_by_no]
        if missing:
            raise HTTPException(
                400,
                f"Şu öğrenciler bulunamadı: {', '.join(missing[:10])}"
                + (" ..." if len(missing) > 10 else ""),
            )

        rows = [
            (exam_id, sid_by_no[s.student_no], float(s.score))
            for s in payload.scores
        ]
        cur.executemany(
            "INSERT INTO exam_project_scores (exam_id, student_id, score) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (exam_id, student_id) DO UPDATE SET score = EXCLUDED.score",
            rows,
        )
        conn.commit()
    resp: dict = {"success": True, "saved": len(rows)}
    if warnings:
        resp["warnings"] = warnings
    return resp


@app.get("/api/exams/{exam_id}/project-scores")
def get_exam_project_scores(
    exam_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.student_no, s.name, COALESCE(eps.score, 0) AS score
            FROM students s
            LEFT JOIN exam_project_scores eps
                   ON eps.student_id = s.id AND eps.exam_id = %s
            WHERE s.id IN (
                SELECT DISTINCT r.student_id FROM responses r
                JOIN questions q ON q.id = r.question_id
                WHERE q.exam_id = %s
            )
            ORDER BY s.student_no
            """,
            (exam_id, exam_id),
        )
        return rows_to_dicts(cur)


@app.get("/api/exams/{exam_id}/meta")
def get_exam_meta(exam_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Sınava ait offering/course bilgilerini döndürür (doc-mapping için)."""
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.id AS exam_id, e.title AS exam_title, e.exam_type,
                   co.id AS offering_id, co.course_id,
                   c.code AS course_code, c.name AS course_name
            FROM exams e
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            WHERE e.id = %s
            """,
            (exam_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Sınav bulunamadı")
        return dict(zip([d[0] for d in cur.description], row))


# ======================================================
# Sınav Kanıtları (Exam Artifacts) — En İyi / Orta / En Kötü
# ======================================================

_EXAM_ARTIFACT_TYPES = {"best", "average", "worst"}


def _assert_exam_access(cur, exam_id: int, user_id: int, role: str) -> None:
    """Kullanıcı manager rolündeyse bypass; aksi halde sınavın hocası mı kontrol edilir."""
    cur.execute(
        "SELECT co.instructor_id FROM exams e "
        "JOIN course_offerings co ON e.offering_id = co.id WHERE e.id = %s",
        (exam_id,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Sınav bulunamadı")
    if role in MANAGER_ROLES:
        return
    cur.execute("SELECT id FROM instructors WHERE user_id = %s", (user_id,))
    inst = cur.fetchone()
    if not inst or inst[0] != row[0]:
        raise HTTPException(403, "Bu sınava erişim yetkiniz yok")


@app.post("/api/exams/{exam_id}/artifacts")
async def upload_exam_artifact(
    exam_id: int,
    file: UploadFile = File(...),
    artifact_type: str = Form(...),
    description: Optional[str] = Form(None),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """MÜDEK denetimi için en iyi/orta/en kötü sınav kağıdı/proje kanıtı yükler."""
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    a_type = (artifact_type or "").strip().lower()
    if a_type not in _EXAM_ARTIFACT_TYPES:
        raise HTTPException(
            400, f"Geçersiz artifact_type. Geçerli değerler: {', '.join(sorted(_EXAM_ARTIFACT_TYPES))}"
        )

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_exam_access(cur, exam_id, user_id, role)

    file_location, original_name, size, ctype = await _save_uploaded_file(file)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO exam_artifacts
                (exam_id, artifact_type, file_path, original_name, file_size,
                 content_type, description, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, uploaded_at
            """,
            (exam_id, a_type, file_location, original_name, size, ctype,
             description, user_id),
        )
        new_id, uploaded_at = cur.fetchone()
        conn.commit()
    return {
        "success": True,
        "id": int(new_id),
        "exam_id": exam_id,
        "artifact_type": a_type,
        "original_name": original_name,
        "file_size": size,
        "content_type": ctype,
        "description": description,
        "uploaded_at": uploaded_at.isoformat() if uploaded_at else None,
    }


@app.get("/api/exams/{exam_id}/artifacts")
def list_exam_artifacts(
    exam_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Sınava ait yüklenmiş tüm kanıt dosyalarını listeler."""
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_exam_access(cur, exam_id, user_id, role)
        cur.execute(
            """
            SELECT a.id, a.exam_id, a.artifact_type, a.original_name,
                   a.file_size, a.content_type, a.description,
                   a.uploaded_by, u.full_name AS uploaded_by_name,
                   a.uploaded_at
            FROM exam_artifacts a
            LEFT JOIN users u ON u.id = a.uploaded_by
            WHERE a.exam_id = %s
            ORDER BY a.artifact_type, a.uploaded_at DESC
            """,
            (exam_id,),
        )
        return rows_to_dicts(cur)


@app.get("/api/exam-artifacts/{artifact_id}/download")
def download_exam_artifact(
    artifact_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT exam_id, file_path, original_name, content_type "
            "FROM exam_artifacts WHERE id = %s",
            (artifact_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kanıt bulunamadı")
        exam_id, file_path, original_name, ctype = row
        _assert_exam_access(cur, exam_id, user_id, role)

    if not os.path.exists(file_path):
        raise HTTPException(410, "Dosya artık sunucuda yok")
    return FileResponse(
        file_path,
        filename=original_name,
        media_type=ctype or "application/octet-stream",
    )


@app.delete("/api/exam-artifacts/{artifact_id}")
def delete_exam_artifact(
    artifact_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT exam_id, file_path FROM exam_artifacts WHERE id = %s",
            (artifact_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kanıt bulunamadı")
        exam_id, file_path = row
        _assert_exam_access(cur, exam_id, user_id, role)
        cur.execute("DELETE FROM exam_artifacts WHERE id = %s", (artifact_id,))
        conn.commit()

    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except OSError as e:
        logging.warning("Artifact dosya silinemedi %s: %s", file_path, e)

    return {"success": True, "message": "✅ Kanıt silindi"}


# ======================================================
# Sorular
# ======================================================

class QuestionCreate(BaseModel):
    q_no: int
    text: Optional[str] = None
    points: float


@app.get("/api/exams/{exam_id}/questions", dependencies=[Depends(get_current_user)])
def get_exam_questions(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, q_no, text, points FROM questions WHERE exam_id = %s ORDER BY q_no",
            (exam_id,),
        )
        return rows_to_dicts(cur)


@app.post("/api/exams/{exam_id}/questions", dependencies=[Depends(require_instructor_permission())])
def create_question(exam_id: int, question: QuestionCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO questions (exam_id, q_no, text, points) VALUES (%s, %s, %s, %s) RETURNING id",
            (exam_id, question.q_no, question.text, question.points),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": f"✅ Soru {question.q_no} eklendi"}


@app.put("/api/questions/{question_id}", dependencies=[Depends(require_instructor_permission())])
def update_question(question_id: int, question: QuestionCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE questions SET q_no = %s, text = %s, points = %s WHERE id = %s",
            (question.q_no, question.text, question.points, question_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Soru bulunamadı")
        conn.commit()
    return {"success": True, "message": "✅ Soru güncellendi"}


@app.delete("/api/questions/{question_id}", dependencies=[Depends(require_instructor_permission())])
def delete_question(question_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM questions WHERE id = %s", (question_id,))
        if not cur.fetchone():
            raise HTTPException(404, "Soru bulunamadı")
        cur.execute("DELETE FROM questions WHERE id = %s", (question_id,))
        conn.commit()
    return {"success": True, "message": "✅ Soru silindi"}


# ======================================================
# Öğrenci Hesap Yardımcıları
# ======================================================

def _ensure_student_role(cur) -> int:
    """'student' rolünün id'sini döndürür; yoksa oluşturur."""
    cur.execute("SELECT id FROM roles WHERE code = 'student'")
    r = cur.fetchone()
    if r:
        return int(r[0])
    cur.execute(
        "INSERT INTO roles (code, name) VALUES ('student', 'Öğrenci') RETURNING id"
    )
    return int(cur.fetchone()[0])


def _ensure_student_account(cur, student_no: str, full_name: str,
                            email: str | None, student_role_id: int) -> dict:
    """
    Öğrenci için (users, students) kayıtlarını idempotent olarak oluşturur.
    Hiç yoksa yeni hesap açılır; rastgele güvenli geçici şifre (bcrypt) atanır ve
    must_change_password=TRUE yapılır — öğrenci ilk girişte change-password
    sayfasından kendi şifresini belirler.

    Aynı öğrenci no farklı derslerde tekrar yüklense de çift kayıt oluşmaz:
    users tek satır (kullanıcı adı = f<no>), students tek satır (student_no UNIQUE);
    ikinci yüklemede yalnızca enrollment eklenir.

    Dönen dict:
        {user_id, student_id, created: bool, default_password: str | None}
    default_password yalnızca YENİ oluşturulduysa doludur (çağıran tarafa
    toplu halde CSV/Excel çıktısı vermek için).
    """
    student_no = _normalize_student_no(student_no)
    if not student_no:
        raise ValueError("Öğrenci numarası boş olamaz")
    full_name = (full_name or "").strip() or f"Öğrenci {student_no}"
    # Kullanıcı adı HER ZAMAN okul standardı f<no>'dan türetilir (sağlanan e-posta
    # sütunundan bağımsız) — böylece aynı öğrenci no hep aynı kullanıcıya çözülür
    # ve çift hesap oluşmaz. Saklanan e-posta: verildiyse o, yoksa okul standardı.
    email = (email or student_email(student_no)).strip() or student_email(student_no)
    username = create_username(full_name, student_email(student_no))

    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    u = cur.fetchone()
    created = False
    default_password = None
    if u:
        user_id = int(u[0])
    else:
        # O2 fix: Öğrenci numarası yerine rastgele güvenli şifre üretilir.
        # Öğrenci ilk girişte change-password sayfasından yeni şifre belirler.
        default_password = generate_random_password(10)
        hashed_pw = _hash_password(default_password)
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, email, is_active, must_change_password) "
            "VALUES (%s, %s, %s, %s, TRUE, TRUE) RETURNING id",
            (username, hashed_pw, full_name, email),
        )
        user_id = int(cur.fetchone()[0])
        cur.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (user_id, student_role_id),
        )
        created = True

    cur.execute("SELECT id FROM students WHERE student_no = %s", (student_no,))
    s = cur.fetchone()
    if s:
        student_id = int(s[0])
        cur.execute(
            "UPDATE students SET user_id = COALESCE(user_id, %s), "
            "name = COALESCE(NULLIF(name, ''), %s) WHERE id = %s",
            (user_id, full_name, student_id),
        )
    else:
        cur.execute(
            "INSERT INTO students (student_no, name, user_id) VALUES (%s, %s, %s) RETURNING id",
            (student_no, full_name, user_id),
        )
        student_id = int(cur.fetchone()[0])

    return {
        "user_id": user_id,
        "student_id": student_id,
        "username": username,
        "created": created,
        "default_password": default_password,
    }


# ======================================================
# Excel Not Yükleme
# ======================================================

@app.post("/api/exams/{exam_id}/upload-results")
async def upload_excel_results(
    exam_id: int,
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    if not file.filename.endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Sadece Excel dosyası yükleyebilirsiniz")

    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT co.instructor_id FROM exams e JOIN course_offerings co ON e.offering_id = co.id WHERE e.id = %s",
            (exam_id,),
        )
        exam_row = cur.fetchone()
        if not exam_row:
            raise HTTPException(404, "Sınav bulunamadı")

        cur.execute(
            "SELECT r.code FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = %s",
            (user_id,),
        )
        role_row = cur.fetchone()
        user_role = role_row[0] if role_row else None

        if user_role != "admin":
            cur.execute(
                "SELECT i.id FROM instructors i WHERE i.user_id = %s",
                (user_id,),
            )
            user_instructor = cur.fetchone()
            if not user_instructor or user_instructor[0] != exam_row[0]:
                raise HTTPException(403, "Bu sınava Excel yükleme yetkiniz yok!")

    # ── Excel Okuma ──────────────────────────────────────────────────────────
    # Beklenen format (tek başlık satırı):
    #   | Öğrenci No | Ad Soyad | S1 | S2 | S3 | ...
    #   | 2021001    | Ali Veli | 15 |  8 | 20 | ...
    try:
        content = await file.read()
        df = pd.read_excel(io.BytesIO(content), header=0, dtype=str)
        df.columns = [str(c).strip() for c in df.columns]
        df = df.dropna(how="all")  # tamamen boş satırları sil

        if df.empty:
            raise ValueError("Excel dosyası boş veya okunamadı.")

        # ── Esnek sütun eşleştirme ───────────────────────────────────────────
        def normalize(s: str) -> str:
            """Türkçe karakterleri ve boşlukları normalize eder."""
            return (s.strip().lower()
                    .replace("ö", "o").replace("ü", "u").replace("ş", "s")
                    .replace("ç", "c").replace("ğ", "g").replace("ı", "i")
                    .replace(" ", "").replace("_", "").replace("-", ""))

        OGRNO_VARIANTS = {"ogrno", "ogrencino", "studentno", "no", "numara",
                          "ogrencinum", "ogrenciNo", "ogrno"}
        NAME_VARIANTS  = {"adsoyad", "name", "fullname", "ad", "isim", "adisoyadı", "adi"}
        # Excel şablonu uyumu — opsiyonel proje/ödev sütunu
        PROJECT_VARIANTS = {"proje", "odev", "project", "assignment", "p", "proj"}

        # Soru sütunları: S1, S2, Soru1, Soru 1, Q1, 1.Soru vb.
        SORU_PATTERN = re.compile(
            r'^(s|soru|q|question)\s*(\d+)$|^(\d+)\s*[.\-_]\s*(soru|s|q)$',
            re.IGNORECASE
        )

        ogrno_col   = None
        name_col    = None
        project_col = None
        q_cols      = {}  # {soru_no(int): col_name(str)}

        for col in df.columns:
            n = normalize(col)
            if ogrno_col is None and n in OGRNO_VARIANTS:
                ogrno_col = col
                continue
            if name_col is None and n in NAME_VARIANTS:
                name_col = col
                continue
            if project_col is None and n in PROJECT_VARIANTS:
                project_col = col
                continue
            m = SORU_PATTERN.match(col.strip())
            if m:
                num = int(m.group(2) or m.group(3))
                q_cols[num] = col

        if ogrno_col is None:
            cols_str = ", ".join(df.columns.tolist())
            raise ValueError(
                f"Öğrenci No sütunu bulunamadı.\n"
                f"Sütun adı 'Öğrenci No', 'OgrNo' veya 'No' olmalı.\n"
                f"Dosyadaki sütunlar: {cols_str}"
            )

        if not q_cols:
            cols_str = ", ".join(df.columns.tolist())
            raise ValueError(
                f"Soru sütunları bulunamadı.\n"
                f"Soru sütunları 'S1', 'S2', 'Soru1', 'Q1' gibi formatlardan biri olmalı.\n"
                f"Dosyadaki sütunlar: {cols_str}"
            )

        # ── Veritabanından soru bilgilerini al ───────────────────────────────
        with pool.connection() as conn, conn.cursor() as cur:
            # Sınavın offering_id + proje yapılandırmasını al
            cur.execute(
                "SELECT offering_id, COALESCE(project_weight,0), COALESCE(project_max_points,0) "
                "FROM exams WHERE id = %s",
                (exam_id,),
            )
            exam_offering_row = cur.fetchone()
            exam_offering_id = exam_offering_row[0] if exam_offering_row else None
            exam_project_weight = float(exam_offering_row[1]) if exam_offering_row else 0.0
            exam_project_max = float(exam_offering_row[2]) if exam_offering_row else 0.0

            cur.execute(
                "SELECT id, q_no, points FROM questions WHERE exam_id = %s ORDER BY q_no",
                (exam_id,),
            )
            q_map = {int(r[1]): {"id": int(r[0]), "points": float(r[2])} for r in cur.fetchall()}

            if not q_map:
                raise ValueError("Bu sınava ait soru tanımlanmamış. Önce soruları ekleyin.")

            upload_warnings: list[str] = []
            project_invalid_rows: list[str] = []
            project_scores_recorded = 0
            if project_col is not None and exam_project_weight <= 0:
                upload_warnings.append(
                    f"'{project_col}' sütunu bulundu ancak sınavın project_weight=0. "
                    "Proje puanları kaydedildi fakat hesaplamaya dahil edilmeyecek. "
                    "Önce project-config ile project_weight ayarlayın."
                )

            # Proje aktifken sütunsuz dosyayı sessizce import etmek başarı notu
            # hesabını bozar — yükleme commit edilmeden reddedilir.
            if exam_project_weight > 0 and project_col is None:
                raise ValueError(
                    "Excel formatında proje notu sütunu eksik. "
                    f"Bu sınav için proje ağırlığı tanımlı (%{exam_project_weight * 100:.0f}). "
                    "Lütfen güncel şablonu indirip 'Proje' sütununu doldurarak tekrar yükleyin."
                )

            # Student rolünü bul veya oluştur (paylaşılan yardımcı)
            student_role_id = _ensure_student_role(cur)

            students_processed = 0
            responses_inserted = 0
            skipped_rows       = 0
            absent_students    = 0
            new_accounts       = []   # [{student_no, full_name, default_password}]

            def _is_blank_cell(val) -> bool:
                """Excel hücresi gerçekten boş mu? (NaN, '', 'nan', 'none')"""
                if val is None:
                    return True
                s = str(val).strip()
                return s == "" or s.lower() in ("nan", "none")

            for _, row in df.iterrows():
                ogrno = _normalize_student_no(row[ogrno_col])
                if not ogrno or ogrno.lower() in ("nan", "none", ""):
                    skipped_rows += 1
                    continue

                # ── DZ (Devamsız) Tespiti ──────────────────────────────────
                # Öğrenci numarası dolu ama tüm soru ve proje hücreleri boş ise
                # öğrenci sınava girmemiş kabul edilir; responses/project_scores'a
                # hiçbir satır eklenmez (DÖÇ sınıf ortalamasını düşürmez).
                all_q_blank = all(
                    _is_blank_cell(row.get(col)) for col in q_cols.values()
                )
                project_blank = (
                    project_col is None or _is_blank_cell(row.get(project_col))
                )
                if all_q_blank and project_blank:
                    name_for_dz = None
                    if name_col:
                        rn = str(row.get(name_col, "")).strip()
                        if rn and rn.lower() not in ("nan", "none", ""):
                            name_for_dz = rn
                    full_name_dz = name_for_dz or f"Öğrenci {ogrno}"
                    acct = _ensure_student_account(
                        cur, ogrno, full_name_dz, None, student_role_id
                    )
                    if acct["created"]:
                        new_accounts.append({
                            "student_no": ogrno,
                            "full_name":  full_name_dz,
                            "username":   acct["username"],
                            "default_password": acct["default_password"],
                        })
                    if exam_offering_id:
                        cur.execute(
                            "INSERT INTO enrollments (student_id, offering_id) "
                            "VALUES (%s, %s) ON CONFLICT (student_id, offering_id) DO NOTHING",
                            (acct["student_id"], exam_offering_id),
                        )
                    absent_students += 1
                    continue

                name = None
                if name_col:
                    raw_name = str(row.get(name_col, "")).strip()
                    if raw_name and raw_name.lower() not in ("nan", "none", ""):
                        name = raw_name
                full_name = name or f"Öğrenci {ogrno}"

                acct = _ensure_student_account(
                    cur, ogrno, full_name, None, student_role_id
                )
                student_id = acct["student_id"]
                if acct["created"]:
                    new_accounts.append({
                        "student_no": ogrno,
                        "full_name":  full_name,
                        "username":   acct["username"],
                        "default_password": acct["default_password"],
                    })

                # ── Enrollment (ders kaydı) ─────────────────────────────────
                if exam_offering_id:
                    cur.execute(
                        "INSERT INTO enrollments (student_id, offering_id) VALUES (%s, %s) ON CONFLICT (student_id, offering_id) DO NOTHING",
                        (student_id, exam_offering_id),
                    )

                students_processed += 1

                # Puanları kaydet (virgüllü ondalık da kabul edilir)
                for q_no, col_name in q_cols.items():
                    if q_no not in q_map:
                        continue
                    q_info = q_map[q_no]
                    try:
                        score = float(str(row[col_name]).replace(",", "."))
                    except (ValueError, TypeError):
                        score = 0.0
                    score = max(0.0, min(score, q_info["points"]))
                    is_correct = score > 0
                    cur.execute(
                        """
                        INSERT INTO responses (question_id, student_id, score, is_correct)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (question_id, student_id) DO UPDATE SET score = EXCLUDED.score, is_correct = EXCLUDED.is_correct
                        """,
                        (q_info["id"], student_id, score, is_correct),
                    )
                    responses_inserted += 1

                # Opsiyonel proje/ödev puanı
                if project_col:
                    raw = str(row[project_col]).strip()
                    if raw and raw.lower() not in ("nan", "none"):
                        try:
                            p_score = float(raw.replace(",", "."))
                        except (ValueError, TypeError):
                            p_score = None
                        if p_score is not None:
                            if p_score < 0:
                                project_invalid_rows.append(f"{ogrno}: negatif ({p_score})")
                                continue
                            if exam_project_weight > 0 and exam_project_max > 0 and p_score > exam_project_max:
                                project_invalid_rows.append(
                                    f"{ogrno}: {p_score} > project_max_points ({exam_project_max})"
                                )
                                continue
                            try:
                                cur.execute(
                                    """
                                    INSERT INTO exam_project_scores (exam_id, student_id, score)
                                    VALUES (%s, %s, %s)
                                    ON CONFLICT (exam_id, student_id) DO UPDATE SET score = EXCLUDED.score
                                    """,
                                    (exam_id, student_id, p_score),
                                )
                                project_scores_recorded += 1
                            except psycopg.errors.UndefinedTable:
                                # Migration uygulanmamış — proje sütunu sessizce atlanır
                                pass

            if project_invalid_rows:
                conn.rollback()
                raise ValueError(
                    "Geçersiz proje puanları (yükleme iptal edildi): "
                    + "; ".join(project_invalid_rows[:10])
                    + (" ..." if len(project_invalid_rows) > 10 else "")
                )

            conn.commit()

        if new_accounts:
            logging.info(
                "TEMP_PASSWORD_ISSUED type=student_batch count=%d",
                len(new_accounts),
            )
        return {
            "success": True,
            "students_processed": students_processed,
            "responses_inserted": responses_inserted,
            "project_scores_recorded": project_scores_recorded,
            "absent_students": absent_students,
            "skipped_rows": skipped_rows,
            # Yeni oluşturulan öğrenci hesapları — teacher/admin bu listeyi
            # indirip öğrencilere dağıtır. Şifreler sadece BURADA görünür
            # (veritabanında bcrypt hash tutulur).
            "new_accounts": new_accounts,
            **({"warning": "Öğrenci şifreleri yalnızca bir kez gösterilir — lütfen indirip dağıtın."} if new_accounts else {}),
            **({"warnings": upload_warnings} if upload_warnings else {}),
            "message": (
                f"✅ {students_processed} öğrenci, {responses_inserted} puan kaydedildi."
                + (f" · {project_scores_recorded} proje puanı" if project_scores_recorded else "")
                + (f" · {absent_students} DZ (devamsız) öğrenci hesaba katılmadı" if absent_students else "")
                + (f" · {len(new_accounts)} yeni hesap açıldı" if new_accounts else "")
                + (f" ({skipped_rows} boş satır atlandı)" if skipped_rows else "")
            ),
        }

    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        logging.error("upload_excel_results 500:\n" + traceback.format_exc())
        raise HTTPException(500, "Dosya işlenirken beklenmeyen bir hata oluştu")


# ======================================================
# Öğrenci Listesi Yükleme
# ======================================================

@app.post("/api/offerings/{offering_id}/upload-students",
          dependencies=[Depends(require_instructor_permission())])
async def upload_student_list(
    offering_id: int,
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    if not file.filename.endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Sadece Excel dosyası yükleyebilirsiniz")

    decode_jwt(credentials.credentials)



    try:
        df = pd.read_excel(file.file, engine="openpyxl")
        df.columns = [c.strip() for c in df.columns]

        if "Ogrenci No" not in df.columns:
            if "Öğrenci No" in df.columns:
                df.rename(columns={"Öğrenci No": "Ogrenci No"}, inplace=True)
            else:
                raise HTTPException(400, "Excel'de 'Ogrenci No' kolonu bulunamadı!")

        processed_count = 0
        new_accounts    = []   # [{student_no, full_name, default_password}]

        with pool.connection() as conn, conn.cursor() as cur:
            student_role_id = _ensure_student_role(cur)

            for _, row in df.iterrows():
                try:
                    student_no = _normalize_student_no(row["Ogrenci No"])
                    if not student_no or student_no == "nan":
                        continue

                    full_name = str(row.get("Ad Soyad", "")).strip()
                    if not full_name or full_name == "nan":
                        full_name = f"Öğrenci {student_no}"

                    email = row.get("Email", None)
                    if pd.isna(email) or not email:
                        email = None
                    else:
                        email = str(email).strip()

                    acct = _ensure_student_account(
                        cur, student_no, full_name, email, student_role_id
                    )
                    s_id = acct["student_id"]
                    if acct["created"]:
                        new_accounts.append({
                            "student_no": student_no,
                            "full_name":  full_name,
                            "default_password": acct["default_password"],
                        })

                    cur.execute(
                        "INSERT INTO enrollments (student_id, offering_id) VALUES (%s, %s) ON CONFLICT (student_id, offering_id) DO NOTHING",
                        (s_id, offering_id),
                    )
                    processed_count += 1

                except Exception:
                    continue

            conn.commit()

        return {
            "success": True,
            "processed_count": processed_count,
            "new_accounts": new_accounts,
            "message": (
                f"✅ {processed_count} öğrenci başarıyla kaydedildi."
                + (f" · {len(new_accounts)} yeni hesap açıldı. Geçici şifreler "
                   f"listede (new_accounts) — yalnızca bir kez gösterilir, "
                   f"indirip öğrencilere güvenli kanaldan iletin." if new_accounts else "")
            ),
        }

    except HTTPException:
        raise
    except Exception:
        logging.error("upload_student_list 500:\n" + traceback.format_exc())
        raise HTTPException(500, "Öğrenci listesi işlenirken bir hata oluştu")


# ======================================================
# Raporlar / Sınav İstatistikleri
# ======================================================

@app.get("/api/exams/{exam_id}/questions/stats", dependencies=[Depends(get_current_user)])
def question_stats(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT q_no, points, attempts, correct_count, correct_rate_pct, avg_score FROM question_stats WHERE exam_id = %s ORDER BY q_no",
            (exam_id,),
        )
        return rows_to_dicts(cur)


@app.get("/api/exams/{exam_id}/detailed-results", dependencies=[Depends(get_current_user)])
def get_detailed_exam_results(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        # Postgres aggregate rule: ARRAY_AGG(DISTINCT x ORDER BY y) is only valid
        # when y appears in the DISTINCT argument list. We use correlated subqueries
        # to build a pre-deduped (sequence_number, description) set per question.
        cur.execute(
            """
            SELECT q.id AS question_id, q.q_no, q.text, q.points,
                   COALESCE((
                     SELECT ARRAY_AGG(x.sn ORDER BY x.sn)
                     FROM (
                       SELECT DISTINCT clo.sequence_number AS sn
                       FROM question_outcomes qo
                       JOIN course_learning_outcomes clo ON qo.outcome_id = clo.id
                       WHERE qo.question_id = q.id
                     ) x
                   ), ARRAY[]::int[]) AS doc_seq_numbers,
                   COALESCE((
                     SELECT ARRAY_AGG(x.descr ORDER BY x.sn)
                     FROM (
                       SELECT DISTINCT clo.sequence_number AS sn,
                                       clo.description AS descr
                       FROM question_outcomes qo
                       JOIN course_learning_outcomes clo ON qo.outcome_id = clo.id
                       WHERE qo.question_id = q.id
                     ) x
                   ), ARRAY[]::text[]) AS doc_descriptions
            FROM questions q
            WHERE q.exam_id = %s
            ORDER BY q.q_no
            """,
            (exam_id,),
        )
        questions = rows_to_dicts(cur)

        cur.execute(
            """
            SELECT s.id AS student_id, s.student_no, s.name,
                   q.q_no, q.points AS max_points, COALESCE(r.score, 0) AS student_score
            FROM students s
            JOIN responses r ON s.id = r.student_id
            JOIN questions q ON r.question_id = q.id
            WHERE q.exam_id = %s
            ORDER BY s.student_no, q.q_no
            """,
            (exam_id,),
        )
        responses = rows_to_dicts(cur)

    students_dict: dict = {}
    for resp in responses:
        sno = resp["student_no"]
        if sno not in students_dict:
            students_dict[sno] = {
                "student_id": resp["student_id"],
                "student_no": sno,
                "name": resp["name"],
                "scores": {},
            }
        students_dict[sno]["scores"][resp["q_no"]] = {
            "score": float(resp["student_score"]),
            "max": float(resp["max_points"]),
        }

    return {"questions": questions, "students": list(students_dict.values())}


@app.get("/api/exams/{exam_id}/results")
def get_exam_results(exam_id: int, user: dict = Depends(require_instructor_permission())):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.student_no, s.name, SUM(r.score) as total_score
            FROM students s
            JOIN responses r ON s.id = r.student_id
            JOIN questions q ON r.question_id = q.id
            WHERE q.exam_id = %s
            GROUP BY s.id, s.student_no, s.name
            ORDER BY total_score DESC
            """,
            (exam_id,),
        )
        results = rows_to_dicts(cur)

    scores = [r["total_score"] for r in results]
    stats = (
        {"average": sum(scores) / len(scores), "max": max(scores), "min": min(scores), "count": len(scores)}
        if scores
        else {"average": 0, "max": 0, "min": 0, "count": 0}
    )
    return {"results": results, "stats": stats}


@app.get("/api/exams/{exam_id}/header", dependencies=[Depends(get_current_user)])
def exam_header_api(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM exam_header WHERE exam_id = %s", (exam_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Sınav bulunamadı")
        return dict(zip([c.name for c in cur.description], row))


@app.get("/api/exams/{exam_id}/po/attainment", dependencies=[Depends(get_current_user)])
def po_attainment_api(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT po_code, attainment_pct FROM po_attainment WHERE exam_id = %s ORDER BY po_code",
            (exam_id,),
        )
        return rows_to_dicts(cur)


# ======================================================
# DÖÇ (Ders Öğrenim Çıktıları)
# ======================================================

class LearningOutcomeCreate(BaseModel):
    course_id: int
    sequence_number: int
    description: str


@app.get("/api/learning-outcomes/{course_id}", dependencies=[Depends(get_current_user)])
def get_learning_outcomes(course_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        # Önce offering_id olarak dene, sonra direkt course_id olarak
        cur.execute(
            """
            SELECT id, sequence_number, description
            FROM course_learning_outcomes
            WHERE course_id = (SELECT course_id FROM course_offerings WHERE id = %s)
               OR course_id = %s
            ORDER BY sequence_number
            """,
            (course_id, course_id),
        )
        return rows_to_dicts(cur)


@app.post("/api/learning-outcomes", dependencies=[Depends(require_instructor_permission())])
def create_learning_outcome(lo: LearningOutcomeCreate):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT course_id FROM course_offerings WHERE id = %s", (lo.course_id,))
        row = cur.fetchone()
        real_course_id = row[0] if row else lo.course_id
        cur.execute(
            "INSERT INTO course_learning_outcomes (course_id, sequence_number, description) VALUES (%s, %s, %s) RETURNING id",
            (real_course_id, lo.sequence_number, lo.description),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": "✅ DÖÇ eklendi"}


@app.delete("/api/learning-outcomes/{lo_id}", dependencies=[Depends(require_instructor_permission())])
def delete_learning_outcome(lo_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM course_learning_outcomes WHERE id = %s", (lo_id,))
        conn.commit()
    return {"success": True, "message": "✅ Silindi"}


@app.get("/api/exams/{exam_id}/learning-outcomes")
def get_exam_learning_outcomes(
    exam_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Sınavın bağlı olduğu dersin DÖÇ listesi (doc-mapping için)."""
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT clo.id, clo.sequence_number, clo.description
            FROM course_learning_outcomes clo
            WHERE clo.course_id = (
                SELECT o.course_id FROM course_offerings o
                JOIN exams e ON e.offering_id = o.id
                WHERE e.id = %s
            )
            ORDER BY clo.sequence_number
            """,
            (exam_id,),
        )
        return rows_to_dicts(cur)


# ======================================================
# DÖÇ–PÇ Matrisi
# ======================================================

class MatrixItem(BaseModel):
    outcome_id: int
    program_outcome_id: int
    value: int


@app.get("/api/courses/{course_id}/matrix", dependencies=[Depends(get_current_user)])
def get_matrix_values(course_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT m.outcome_id, m.program_outcome_id, m.value
            FROM outcome_matrix m
            JOIN course_learning_outcomes clo ON m.outcome_id = clo.id
            WHERE clo.course_id = (
                SELECT course_id FROM course_offerings WHERE id = %s
                UNION SELECT id FROM courses WHERE id = %s
                LIMIT 1
            )
            """,
            (course_id, course_id),
        )
        return rows_to_dicts(cur)


@app.post("/api/matrix/save")
def save_matrix(
    items: List[MatrixItem],
    user: dict = Depends(require_instructor_permission()),
):
    """
    DÖÇ → PÇ ağırlık matrisini kaydeder. Excel şablonu uyumlu kurallar:
      - value 0 olan satırlar (matriste işaretlenmemiş hücreler) sessizce
        atlanır, mevcut kayıt varsa silinir.
      - Negatif değer kabul edilmez (validation).
    Yetki: admin / komite üyeleri her dersi kaydedebilir; öğretim üyesi
    yalnızca kendi açtığı offering'in dersine ait DÖÇ'leri düzenleyebilir.
    """
    if not items:
        raise HTTPException(400, "Matris boş olamaz")
    for item in items:
        if item.value < 0:
            raise HTTPException(
                400,
                f"Negatif ağırlık geçersiz (DÖÇ={item.outcome_id}, "
                f"PÇ={item.program_outcome_id}, value={item.value})",
            )

    is_manager = user.get("role") in MANAGER_ROLES

    with pool.connection() as conn, conn.cursor() as cur:
        if not is_manager:
            outcome_ids = list({item.outcome_id for item in items})
            cur.execute(
                "SELECT DISTINCT course_id FROM course_learning_outcomes WHERE id = ANY(%s)",
                (outcome_ids,),
            )
            course_ids = [r[0] for r in cur.fetchall()]
            if not course_ids:
                raise HTTPException(400, "Geçersiz DÖÇ id'leri")
            cur.execute(
                """
                SELECT DISTINCT co.course_id
                FROM course_offerings co
                JOIN instructors i ON i.id = co.instructor_id
                WHERE co.course_id = ANY(%s) AND i.user_id = %s
                """,
                (course_ids, int(user["user_id"])),
            )
            owned = {r[0] for r in cur.fetchall()}
            if not set(course_ids).issubset(owned):
                raise HTTPException(403, "Bu dersin matrisini düzenleme yetkiniz yok")

        for item in items:
            if item.value <= 0:
                cur.execute(
                    "DELETE FROM outcome_matrix WHERE outcome_id = %s AND program_outcome_id = %s",
                    (item.outcome_id, item.program_outcome_id),
                )
                continue
            cur.execute(
                """
                INSERT INTO outcome_matrix (outcome_id, program_outcome_id, value)
                VALUES (%s, %s, %s)
                ON CONFLICT (outcome_id, program_outcome_id) DO UPDATE SET value = EXCLUDED.value
                """,
                (item.outcome_id, item.program_outcome_id, item.value),
            )
        conn.commit()
    return {"success": True, "message": "✅ Matris kaydedildi"}


# ======================================================
# Soru → DÖÇ Ağırlıkları
# ======================================================

class QuestionOutcomeWeight(BaseModel):
    outcome_id: int
    weight: float


class QuestionOutcomesPayload(BaseModel):
    outcomes: List[QuestionOutcomeWeight]


@app.post("/api/questions/{question_id}/outcomes")
def set_question_outcomes(
    question_id: int,
    payload: QuestionOutcomesPayload,
    user: dict = Depends(require_instructor_permission()),
):
    """
    Soru → DÖÇ ağırlıklarını kaydeder.
    UI ham sayılar gönderirse normalize edilir (toplam = 1) — Excel şablonundaki
    "soru sütunu toplamı = 1" kuralına birebir uyumludur.
    Payload: {"outcomes": [{"outcome_id": 1, "weight": 15}, ...]}
    Yetki: Hoca / komite üyesi / yönetici.
    """
    if not payload.outcomes:
        raise HTTPException(400, "En az bir DÖÇ ağırlığı girilmeli")

    total = 0.0
    for item in payload.outcomes:
        if item.weight < 0:
            raise HTTPException(400, "weight negatif olamaz")
        total += item.weight

    if total <= 0:
        raise HTTPException(400, "Toplam weight 0 olamaz")

    normalized = [
        {"outcome_id": item.outcome_id, "weight": item.weight / total}
        for item in payload.outcomes
    ]

    try:
        from mudek_service import save_question_outcome_weights  # type: ignore
        with pool.connection() as conn:
            save_question_outcome_weights(conn=conn, question_id=question_id, weights=normalized)
            conn.commit()
        return {"success": True, "normalized": True}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        logging.error("set_question_outcomes 500:\n" + traceback.format_exc())
        raise HTTPException(500, "Kaydetme sırasında bir hata oluştu")


@app.get("/api/questions/{question_id}/outcomes")
def get_question_outcomes(
    question_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)
):
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT qo.outcome_id, clo.sequence_number, clo.description, qo.weight
            FROM question_outcomes qo
            JOIN course_learning_outcomes clo ON clo.id = qo.outcome_id
            WHERE qo.question_id = %s
            ORDER BY clo.sequence_number
            """,
            (question_id,),
        )
        return rows_to_dicts(cur)


# ======================================================
# MÜDEK Hesaplama
# ======================================================

@app.get("/api/exams/{exam_id}/attainment")
def get_attainment(exam_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
    decode_jwt(credentials.credentials)
    try:
        from mudek_service import compute_exam_attainment  # type: ignore
    except Exception:
        raise HTTPException(500, "mudek_service.compute_exam_attainment bulunamadı")
    try:
        with pool.connection() as conn:
            att = compute_exam_attainment(conn=conn, exam_id=exam_id)
        return {
            "success":    True,
            "exam_id":    att.exam_id,
            "exam_title": att.exam_title,
            "category":   att.category,
            "doc_scores": att.doc_scores,
            "pc_scores":  att.pc_scores,
        }
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/exams/{exam_id}/attainment/validate")
def validate_attainment(exam_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
    decode_jwt(credentials.credentials)
    try:
        from mudek_service import validate_question_outcome_weights  # type: ignore
    except Exception:
        raise HTTPException(500, "mudek_service.validate_question_outcome_weights bulunamadı")
    with pool.connection() as conn:
        report = validate_question_outcome_weights(conn=conn, exam_id=exam_id)
    return {"success": True, "ok": report.ok, "details": report.details}


@app.get("/api/mudek/analysis/{course_id}")
def get_mudek_analysis(
    course_id: int,
    evidence: int = 0,
    user: dict = Depends(require_instructor_permission()),
):
    """
    Dersin MÜDEK DÖÇ/PÇ analiz raporunu döndürür.
    Yalnızca geçen öğrenciler ve bütünleme replace mantığı uygulanır (mudek_service ile uyumlu).
    Yetki: Hoca / komite üyesi / yönetici.

    Query params:
      evidence=1 → response'a `doc_evidence` (DÖÇ→soru katkıları) ve
                   `pc_evidence` (PÇ→DÖÇ katkıları) kanıt zincirleri eklenir.
    """

    try:
        from mudek_service import calculate_course_attainment, MissingDataError  # type: ignore

        collect = bool(evidence)
        with pool.connection() as conn:
            result = calculate_course_attainment(
                conn=conn, course_id=course_id, collect_evidence=collect,
            )

        response = {
            "course_id":        result.course_id,
            "doc_attainment":   result.doc_attainment,
            "pc_attainment":    result.pc_attainment,
            "doc_status":       result.doc_status,
            "doc_threshold":    0.60,
            "students_total":   result.students_total,
            "students_passing": result.students_passing,
            "letter_grade_distribution": result.letter_grade_distribution,
            "warning":          "; ".join(result.warnings) if result.warnings else None,
            "exam_results": [
                {
                    "exam_id":    e.exam_id,
                    "exam_title": e.exam_title,
                    "exam_type":  e.exam_type,
                    "category":   e.category,
                    "doc_scores": e.doc_scores,
                    "pc_scores":  e.pc_scores,
                }
                for e in result.exam_results
            ],
        }

        if collect:
            response["doc_evidence"] = {
                str(oid): [
                    {
                        "exam_id":          ev.exam_id,
                        "exam_title":       ev.exam_title,
                        "category":         ev.category,
                        "question_id":      ev.question_id,
                        "q_no":             ev.q_no,
                        "q_text":           ev.q_text,
                        "q_norm":           ev.q_norm,
                        "weight":           ev.weight,
                        "contribution_pct": ev.contribution_pct,
                    } for ev in ev_list
                ]
                for oid, ev_list in result.doc_evidence.items()
            }
            response["pc_evidence"] = {
                str(po_id): [
                    {
                        "outcome_id":       ev.outcome_id,
                        "outcome_seq":      ev.outcome_seq,
                        "doc_score":        ev.doc_score,
                        "matrix_value":     ev.matrix_value,
                        "contribution_pct": ev.contribution_pct,
                    } for ev in ev_list
                ]
                for po_id, ev_list in result.pc_evidence.items()
            }

        return response

    except Exception as e:
        err_msg = str(e)
        if "bulunamadı" in err_msg or "MissingData" in type(e).__name__:
            return {"error": err_msg}
        logging.error("mudek_analysis 500:\n" + traceback.format_exc())
        raise HTTPException(status_code=500, detail="Analiz sırasında bir hata oluştu")


# ======================================================
# Anket Yönetimi
# ======================================================

@app.post("/api/offerings/{offering_id}/start-survey")
def start_survey(offering_id: int, user: dict = Depends(require_instructor_permission())):
    _ensure_offering_owned(offering_id, user)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM course_learning_outcomes WHERE course_id = (SELECT course_id FROM course_offerings WHERE id = %s)",
            (offering_id,),
        )
        if cur.fetchone()[0] == 0:
            raise HTTPException(400, "Bu dersin DÖÇ'leri girilmemiş! Önce DÖÇ tanımlayın.")

        cur.execute(
            "SELECT id FROM surveys WHERE offering_id = %s AND is_active = TRUE", (offering_id,)
        )
        if cur.fetchone():
            raise HTTPException(400, "Bu ders için zaten aktif bir anket var.")

        cur.execute(
            "INSERT INTO surveys (offering_id, is_active) VALUES (%s, TRUE) RETURNING id",
            (offering_id,),
        )
        survey_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "survey_id": survey_id, "message": "✅ Anket başlatıldı!"}


@app.get("/api/offerings/{offering_id}/survey-status")
def get_survey_status(offering_id: int, user: dict = Depends(get_current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, is_active, created_at FROM surveys WHERE offering_id = %s AND is_active = TRUE",
            (offering_id,),
        )
        row = cur.fetchone()
    if row:
        return {"active": True, "survey_id": row[0], "created_at": row[2]}
    return {"active": False}


@app.get("/api/offerings/{offering_id}/stats", dependencies=[Depends(get_current_user)])
def get_survey_stats(offering_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM enrollments WHERE offering_id = %s", (offering_id,))
        total_students = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(DISTINCT student_id) FROM survey_responses WHERE survey_id = (SELECT id FROM surveys WHERE offering_id = %s)",
            (offering_id,),
        )
        responded_students = cur.fetchone()[0]

        cur.execute(
            """
            SELECT clo.sequence_number, clo.description,
                   COALESCE(AVG(sr.score), 0) as avg_score
            FROM course_learning_outcomes clo
            JOIN course_offerings co ON clo.course_id = co.course_id
            LEFT JOIN surveys s ON s.offering_id = co.id
            LEFT JOIN survey_responses sr ON sr.outcome_id = clo.id AND sr.survey_id = s.id
            WHERE co.id = %s
            GROUP BY clo.id, clo.sequence_number, clo.description
            ORDER BY clo.sequence_number
            """,
            (offering_id,),
        )
        outcomes_data = rows_to_dicts(cur)

    for item in outcomes_data:
        item["avg_score"] = float(round(item["avg_score"], 2))

    return {
        "participation": {
            "total": total_students,
            "responded": responded_students,
            "rate": round((responded_students / total_students * 100) if total_students > 0 else 0, 1),
        },
        "outcomes": outcomes_data,
    }


# Öğrenci tarafı anket endpoint'leri

@app.get("/api/my-surveys")
def get_my_surveys(user: dict = Depends(require_role("student"))):
    user_id = user["user_id"]
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM students WHERE user_id = %s", (user_id,))
        student_row = cur.fetchone()
        if not student_row:
            return []
        student_id = student_row[0]
        cur.execute(
            """
            SELECT s.id as survey_id, c.code, c.name, co.term
            FROM surveys s
            JOIN course_offerings co ON s.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            JOIN enrollments e ON co.id = e.offering_id
            WHERE e.student_id = %s AND s.is_active = TRUE
              AND s.id NOT IN (SELECT survey_id FROM survey_responses WHERE student_id = %s)
            """,
            (student_id, student_id),
        )
        return rows_to_dicts(cur)


@app.get("/api/surveys/{survey_id}/questions")
def get_survey_questions(survey_id: int, user: dict = Depends(require_role("student"))):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT offering_id FROM surveys WHERE id = %s", (survey_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Anket bulunamadı")
        cur.execute(
            """
            SELECT clo.id, clo.sequence_number, clo.description
            FROM course_learning_outcomes clo
            JOIN course_offerings co ON clo.course_id = co.course_id
            WHERE co.id = %s
            ORDER BY clo.sequence_number
            """,
            (row[0],),
        )
        return rows_to_dicts(cur)


@app.post("/api/surveys/{survey_id}/submit")
def submit_survey_response(
    survey_id: int,
    answers: dict = Body(...),
    user: dict = Depends(require_role("student")),
):
    user_id = user["user_id"]
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM students WHERE user_id = %s", (user_id,))
        student_id = cur.fetchone()[0]

        cur.execute(
            "SELECT 1 FROM survey_responses WHERE survey_id = %s AND student_id = %s",
            (survey_id, student_id),
        )
        if cur.fetchone():
            raise HTTPException(400, "Bu anketi zaten doldurdunuz.")

        for outcome_id, score in answers.items():
            if not (1 <= int(score) <= 5):
                continue
            cur.execute(
                "INSERT INTO survey_responses (survey_id, student_id, outcome_id, score) VALUES (%s, %s, %s, %s)",
                (survey_id, student_id, outcome_id, score),
            )
        conn.commit()
    return {"success": True, "message": "✅ Anket cevaplarınız kaydedildi."}


# ======================================================
# Anket Modülü — Genişletilmiş (Yeni Tablolar + Endpoint'ler)
# ======================================================
# Bu bölüm mevcut anket sistemini genişletir:
#   • MÜDEK 11 kriter referans tablosu
#   • Özel anket soruları (Likert / Çoktan seçmeli / Açık uçlu)
#   • Detaylı sonuç görüntüleme
#   • Kriter bazlı raporlama

def _ensure_survey_tables():
    """
    Genişletilmiş anket tablolarını oluşturur ve MÜDEK kriterlerini seed'ler.
    İlk çağrıda çalışır, sonrasında IF NOT EXISTS ile atlanır.
    """
    with pool.connection() as conn, conn.cursor() as cur:
        # Özel anket soruları tablosu (DÖÇ sorularının yanına eklenen ek sorular)
        # Anket soruları doğrudan program_outcomes (PÇ) tablosuna referans verir;
        # eski mudek_criteria tablosu kaldırıldı (bkz. migration 004).
        cur.execute("""
            CREATE TABLE IF NOT EXISTS survey_questions (
                id          SERIAL PRIMARY KEY,
                survey_id   INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
                q_type      VARCHAR(20) NOT NULL DEFAULT 'likert',  -- 'likert', 'multiple_choice', 'open_ended'
                q_text      TEXT NOT NULL,
                q_order     INTEGER NOT NULL DEFAULT 0,
                options     TEXT,                                   -- JSON string for MC options, NULL for others
                program_outcome_id INTEGER REFERENCES program_outcomes(id) ON DELETE SET NULL,
                created_at  TIMESTAMP DEFAULT NOW()
            )
        """)

        # Özel soru yanıtları tablosu
        cur.execute("""
            CREATE TABLE IF NOT EXISTS survey_question_responses (
                id            SERIAL PRIMARY KEY,
                question_id   INTEGER NOT NULL REFERENCES survey_questions(id) ON DELETE CASCADE,
                student_id    INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                score         INTEGER,          -- Likert (1-5) veya MC index
                text_answer   TEXT,             -- Açık uçlu cevap
                created_at    TIMESTAMP DEFAULT NOW(),
                UNIQUE (question_id, student_id)
            )
        """)

        # Ders dönem değerlendirme tablosu (offering_reflections)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS offering_reflections (
                id            SERIAL PRIMARY KEY,
                offering_id   INTEGER UNIQUE NOT NULL
                              REFERENCES course_offerings(id) ON DELETE CASCADE,
                a5_text       TEXT,
                b_text        TEXT,
                c_text        TEXT,
                instructor_id INTEGER REFERENCES users(id),
                updated_at    TIMESTAMP DEFAULT NOW()
            )
        """)

        conn.commit()


def _ensure_exam_artifacts_table():
    """Migration 005 production'da uygulanır; dev için güvence."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "DO $$ BEGIN "
            "  CREATE TYPE exam_artifact_type AS ENUM ('best','average','worst'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        )
        cur.execute("""
            CREATE TABLE IF NOT EXISTS exam_artifacts (
                id             SERIAL PRIMARY KEY,
                exam_id        INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
                artifact_type  exam_artifact_type NOT NULL,
                file_path      VARCHAR NOT NULL,
                original_name  VARCHAR NOT NULL,
                file_size      BIGINT,
                content_type   VARCHAR(120),
                description    TEXT,
                uploaded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                uploaded_at    TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS exam_artifacts_exam_idx ON exam_artifacts (exam_id)"
        )
        conn.commit()


# O3 fix: startup/shutdown mantığı yukarıdaki lifespan() context manager'a taşındı.


# ------ Pydantic modelleri ------

class SurveyQuestionCreate(BaseModel):
    q_type: str = "likert"        # 'likert' | 'multiple_choice' | 'open_ended'
    q_text: str
    q_order: int = 0
    options: Optional[str] = None  # JSON string, ör: '["Evet","Hayır","Kararsız"]'
    program_outcome_id: Optional[int] = None  # PÇ FK, opsiyonel


class SurveySubmitFull(BaseModel):
    """Hem DÖÇ Likert hem de özel soru cevaplarını içerir."""
    doc_answers: dict = {}      # {outcome_id: score}  — mevcut DÖÇ cevapları
    custom_answers: dict = {}   # {question_id: {"score": N} veya {"text": "..."}}


# ------ Endpoint'ler ------


@app.post("/api/surveys/{survey_id}/close")
def close_survey(survey_id: int, user: dict = Depends(require_instructor_permission())):
    """Aktif bir anketi kapatır. Yalnızca hoca/admin yapabilir."""
    _ensure_survey_owned(survey_id, user)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, is_active FROM surveys WHERE id = %s", (survey_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Anket bulunamadı")
        if not row[1]:
            raise HTTPException(400, "Bu anket zaten kapatılmış.")
        cur.execute("UPDATE surveys SET is_active = FALSE WHERE id = %s", (survey_id,))
        conn.commit()
    return {"success": True, "message": "✅ Anket kapatıldı."}


@app.post("/api/surveys/{survey_id}/questions")
def add_survey_question(
    survey_id: int,
    question: SurveyQuestionCreate,
    user: dict = Depends(require_instructor_permission()),
):
    """Ankete özel bir soru ekler (DÖÇ sorularının yanı sıra)."""
    _ensure_survey_owned(survey_id, user)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM surveys WHERE id = %s", (survey_id,))
        if not cur.fetchone():
            raise HTTPException(404, "Anket bulunamadı")
        if question.program_outcome_id is not None:
            cur.execute(
                "SELECT 1 FROM program_outcomes WHERE id = %s",
                (question.program_outcome_id,),
            )
            if not cur.fetchone():
                raise HTTPException(400, "Geçersiz program çıktısı (PÇ) referansı.")
        cur.execute(
            """INSERT INTO survey_questions (survey_id, q_type, q_text, q_order, options, program_outcome_id)
               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
            (survey_id, question.q_type, question.q_text, question.q_order,
             question.options, question.program_outcome_id),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": "✅ Soru eklendi."}


@app.delete("/api/survey-questions/{question_id}")
def delete_survey_question(
    question_id: int,
    user: dict = Depends(require_instructor_permission()),
):
    """Bir özel anket sorusunu siler."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT survey_id FROM survey_questions WHERE id = %s", (question_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Soru bulunamadı")
        survey_id = int(row[0])
    _ensure_survey_owned(survey_id, user)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM survey_question_responses WHERE question_id = %s", (question_id,))
        cur.execute("DELETE FROM survey_questions WHERE id = %s", (question_id,))
        conn.commit()
    return {"success": True, "message": "✅ Soru silindi."}


@app.get("/api/surveys/{survey_id}/custom-questions")
def get_survey_custom_questions(survey_id: int, user: dict = Depends(get_current_user)):
    """Bir anketin özel sorularını döndürür (DÖÇ soruları hariç)."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT sq.id, sq.q_type, sq.q_text, sq.q_order, sq.options,
                      sq.program_outcome_id, po.code AS program_outcome_code
               FROM survey_questions sq
               LEFT JOIN program_outcomes po ON sq.program_outcome_id = po.id
               WHERE sq.survey_id = %s
               ORDER BY sq.q_order, sq.id""",
            (survey_id,),
        )
        return rows_to_dicts(cur)


@app.post("/api/surveys/{survey_id}/submit-full")
def submit_survey_full(
    survey_id: int,
    payload: SurveySubmitFull,
    user: dict = Depends(require_role("student")),
):
    """
    Öğrencinin hem DÖÇ Likert cevaplarını hem de özel soru cevaplarını
    tek istekte göndermesine olanak tanır.
    """
    user_id = user["user_id"]
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM students WHERE user_id = %s", (user_id,))
        student_row = cur.fetchone()
        if not student_row:
            raise HTTPException(400, "Öğrenci kaydınız bulunamadı.")
        student_id = student_row[0]

        # Daha önce cevap verilmiş mi kontrol et
        cur.execute(
            "SELECT 1 FROM survey_responses WHERE survey_id = %s AND student_id = %s",
            (survey_id, student_id),
        )
        if cur.fetchone():
            raise HTTPException(400, "Bu anketi zaten doldurdunuz.")

        # 1) DÖÇ Likert cevaplarını kaydet (mevcut survey_responses tablosuna)
        for outcome_id, score in payload.doc_answers.items():
            if not (1 <= int(score) <= 5):
                continue
            cur.execute(
                "INSERT INTO survey_responses (survey_id, student_id, outcome_id, score) VALUES (%s, %s, %s, %s)",
                (survey_id, student_id, outcome_id, score),
            )

        # 2) Özel soru cevaplarını kaydet (yeni survey_question_responses tablosuna)
        for question_id, answer in payload.custom_answers.items():
            score_val = answer.get("score") if isinstance(answer, dict) else None
            text_val = answer.get("text") if isinstance(answer, dict) else None
            # Basit değer ise (int) direkt score olarak al
            if isinstance(answer, (int, float)):
                score_val = int(answer)
                text_val = None
            elif isinstance(answer, str):
                score_val = None
                text_val = answer
            cur.execute(
                """INSERT INTO survey_question_responses (question_id, student_id, score, text_answer)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (question_id, student_id) DO UPDATE
                   SET score = EXCLUDED.score, text_answer = EXCLUDED.text_answer""",
                (question_id, student_id, score_val, text_val),
            )

        conn.commit()
    return {"success": True, "message": "✅ Anket cevaplarınız kaydedildi."}


@app.get("/api/surveys/{survey_id}/results")
def get_survey_results(
    survey_id: int,
    user: dict = Depends(require_instructor_permission()),
):
    """
    Bir anketin detaylı sonuçlarını döndürür:
      - DÖÇ bazlı ortalamalar (mevcut survey_responses)
      - Özel soru yanıt dağılımları
      - MÜDEK kriter bazlı ortalamalar
      - Katılım istatistikleri
    Hoca/admin yetkisi gerektirir.
    """
    _ensure_survey_owned(survey_id, user)
    with pool.connection() as conn, conn.cursor() as cur:
        # Anket bilgisi
        cur.execute(
            """SELECT s.id, s.offering_id, s.is_active, s.created_at,
                      c.code AS course_code, c.name AS course_name, co.term, co.section
               FROM surveys s
               JOIN course_offerings co ON s.offering_id = co.id
               JOIN courses c ON co.course_id = c.id
               WHERE s.id = %s""",
            (survey_id,),
        )
        survey_info = cur.fetchone()
        if not survey_info:
            raise HTTPException(404, "Anket bulunamadı")
        cols = [c.name for c in cur.description]
        survey_data = dict(zip(cols, survey_info))
        offering_id = survey_data["offering_id"]

        # Katılım istatistikleri
        cur.execute("SELECT COUNT(*) FROM enrollments WHERE offering_id = %s", (offering_id,))
        total_students = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(DISTINCT student_id) FROM survey_responses WHERE survey_id = %s",
            (survey_id,),
        )
        responded_students = cur.fetchone()[0]

        # DÖÇ bazlı ortalamalar
        cur.execute(
            """SELECT clo.id, clo.sequence_number, clo.description,
                      COALESCE(AVG(sr.score), 0) as avg_score,
                      COUNT(sr.id) as response_count
               FROM course_learning_outcomes clo
               JOIN course_offerings co ON clo.course_id = co.course_id
               LEFT JOIN survey_responses sr ON sr.outcome_id = clo.id AND sr.survey_id = %s
               WHERE co.id = %s
               GROUP BY clo.id, clo.sequence_number, clo.description
               ORDER BY clo.sequence_number""",
            (survey_id, offering_id),
        )
        doc_results = []
        for r in cur.fetchall():
            doc_results.append({
                "outcome_id": r[0],
                "sequence_number": r[1],
                "description": r[2],
                "avg_score": round(float(r[3]), 2),
                "response_count": r[4],
            })

        # Özel soru sonuçları
        cur.execute(
            """SELECT sq.id, sq.q_type, sq.q_text, sq.q_order, sq.options,
                      sq.program_outcome_id, po.code AS program_outcome_code,
                      COALESCE(AVG(sqr.score), 0) as avg_score,
                      COUNT(sqr.id) as response_count
               FROM survey_questions sq
               LEFT JOIN program_outcomes po ON sq.program_outcome_id = po.id
               LEFT JOIN survey_question_responses sqr ON sq.id = sqr.question_id
               WHERE sq.survey_id = %s
               GROUP BY sq.id, sq.q_type, sq.q_text, sq.q_order, sq.options,
                        sq.program_outcome_id, po.code
               ORDER BY sq.q_order, sq.id""",
            (survey_id,),
        )
        custom_results = []
        for r in cur.fetchall():
            item = {
                "question_id": r[0],
                "q_type": r[1],
                "q_text": r[2],
                "q_order": r[3],
                "options": r[4],
                "program_outcome_id": r[5],
                "program_outcome_code": r[6],
                "avg_score": round(float(r[7]), 2),
                "response_count": r[8],
            }
            # Açık uçlu sorular için tüm cevapları getir
            if r[1] == "open_ended":
                cur.execute(
                    "SELECT text_answer FROM survey_question_responses WHERE question_id = %s AND text_answer IS NOT NULL",
                    (r[0],),
                )
                item["text_answers"] = [row[0] for row in cur.fetchall()]
            # Çoktan seçmeli sorular için dağılım getir
            elif r[1] == "multiple_choice":
                cur.execute(
                    """SELECT score, COUNT(*) FROM survey_question_responses
                       WHERE question_id = %s AND score IS NOT NULL
                       GROUP BY score ORDER BY score""",
                    (r[0],),
                )
                item["distribution"] = {str(row[0]): row[1] for row in cur.fetchall()}
            # Likert sorular için dağılım getir
            elif r[1] == "likert":
                cur.execute(
                    """SELECT score, COUNT(*) FROM survey_question_responses
                       WHERE question_id = %s AND score IS NOT NULL
                       GROUP BY score ORDER BY score""",
                    (r[0],),
                )
                item["distribution"] = {str(row[0]): row[1] for row in cur.fetchall()}
            custom_results.append(item)

        # PÇ bazlı özet — Python'da hesaplanır
        criterion_summary: dict[str, dict] = {}

        # 1) Özel sorulardan direkt PÇ ortalamaları
        for cq in custom_results:
            po_code = cq.get("program_outcome_code")
            if po_code and cq["q_type"] == "likert" and cq["avg_score"] > 0:
                criterion_summary.setdefault(po_code, {"scores": [], "source": "custom_questions"})
                criterion_summary[po_code]["scores"].append(cq["avg_score"])

        # 2) DÖÇ → PÇ (outcome_matrix) ağırlıklı ortalama — saf Python hesabı
        if doc_results:
            doc_avg_map = {d["outcome_id"]: d["avg_score"] for d in doc_results if d["avg_score"] > 0}
            if doc_avg_map:
                cur.execute(
                    """SELECT om.outcome_id, om.program_outcome_id, om.value, po.code
                       FROM outcome_matrix om
                       JOIN program_outcomes po ON om.program_outcome_id = po.id
                       WHERE om.outcome_id = ANY(%s) AND om.value > 0""",
                    (list(doc_avg_map.keys()),),
                )
                po_sum: dict[str, float] = {}
                po_wsum: dict[str, float] = {}
                for oid, _, val, po_code in cur.fetchall():
                    score = doc_avg_map.get(int(oid))
                    if score is None:
                        continue
                    po_sum[po_code] = po_sum.get(po_code, 0.0) + score * float(val)
                    po_wsum[po_code] = po_wsum.get(po_code, 0.0) + float(val)
                for po_code, wsum in po_wsum.items():
                    if wsum > 0:
                        criterion_summary.setdefault(po_code, {"scores": [], "source": "doc_to_pc"})
                        criterion_summary[po_code]["scores"].append(round(po_sum[po_code] / wsum, 2))

    return {
        "survey": survey_data,
        "participation": {
            "total": total_students,
            "responded": responded_students,
            "rate": round((responded_students / total_students * 100) if total_students > 0 else 0, 1),
        },
        "doc_results": doc_results,
        "custom_results": custom_results,
        "criterion_summary": {
            code: {
                "avg": round(sum(v["scores"]) / len(v["scores"]), 2),
                "source": v["source"],
            }
            for code, v in criterion_summary.items()
            if v["scores"]
        },
    }


@app.get("/api/offerings/{offering_id}/survey-results")
def get_offering_survey_results(
    offering_id: int,
    user: dict = Depends(require_instructor_permission()),
):
    """Bir offering'e ait aktif/son anketin sonuçlarını döndürür."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM surveys WHERE offering_id = %s ORDER BY created_at DESC LIMIT 1",
            (offering_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Bu ders için anket bulunamadı.")
    # Mevcut detaylı sonuç endpoint'ine yönlendir
    return get_survey_results(row[0], user)


@app.get("/api/mudek/survey-criteria-report")
def get_survey_criteria_report(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Tüm aktif/kapanmış anketlerden Program Çıktıları (PÇ) bazında
    toplu başarı raporunu döndürür.

    İki katmanlı veri kaynağı:
      1) Özel sorulardaki program_outcome_id eşlemesi (doğrudan)
      2) DÖÇ → PÇ matrisi üzerinden (dolaylı, outcome_matrix)

    Yalnızca admin / bölüm başkanı / MÜDEK kurul üyesi erişebilir.
    """
    token_data = decode_jwt(credentials.credentials)
    if token_data.get("role") not in MANAGER_ROLES:
        raise HTTPException(403, "Bu rapor için yetkiniz yok.")

    with pool.connection() as conn, conn.cursor() as cur:
        # Tüm program çıktıları (PÇ)
        cur.execute("SELECT id, code, title FROM program_outcomes ORDER BY code")
        po_list = rows_to_dicts(cur)

        # 1) Özel sorulardan doğrudan PÇ ortalamaları
        cur.execute("""
            SELECT po.code,
                   AVG(sqr.score) as avg_score,
                   COUNT(DISTINCT sqr.student_id) as respondent_count
            FROM survey_questions sq
            JOIN program_outcomes po ON sq.program_outcome_id = po.id
            JOIN survey_question_responses sqr ON sq.id = sqr.question_id
            WHERE sqr.score IS NOT NULL
            GROUP BY po.code
            ORDER BY po.code
        """)
        custom_scores = {row[0]: {"avg": round(float(row[1]), 2), "n": row[2]}
                         for row in cur.fetchall()}

        # 2) DÖÇ → PÇ (program_outcomes) üzerinden dolaylı PÇ skoru
        cur.execute("""
            SELECT po.code,
                   SUM(avg_scores.avg_score * om.value) / NULLIF(SUM(om.value), 0) as weighted_avg,
                   SUM(avg_scores.respondent_count) as total_respondents
            FROM program_outcomes po
            JOIN outcome_matrix om ON po.id = om.program_outcome_id
            JOIN (
                SELECT sr.outcome_id,
                       AVG(sr.score) as avg_score,
                       COUNT(DISTINCT sr.student_id) as respondent_count
                FROM survey_responses sr
                GROUP BY sr.outcome_id
            ) avg_scores ON om.outcome_id = avg_scores.outcome_id
            GROUP BY po.code
            ORDER BY po.code
        """)
        po_scores = {row[0]: {"avg": round(float(row[1]), 2) if row[1] else 0, "n": row[2]}
                     for row in cur.fetchall()}

    # Sonuçları birleştir
    report = []
    for po in po_list:
        code = po["code"]
        entry = {
            "code": code,
            "title": po["title"],
            "custom_question_avg": custom_scores.get(code, {}).get("avg"),
            "custom_question_respondents": custom_scores.get(code, {}).get("n", 0),
            "po_weighted_avg": po_scores.get(code, {}).get("avg"),
            "po_respondents": po_scores.get(code, {}).get("n", 0),
        }
        # Bileşik skor: varsa her iki kaynağın ortalaması
        avgs = [v for v in [entry["custom_question_avg"], entry["po_weighted_avg"]] if v]
        entry["combined_avg"] = round(sum(avgs) / len(avgs), 2) if avgs else None
        entry["combined_pct"] = int((entry["combined_avg"] / 5) * 100) if entry["combined_avg"] else 0
        report.append(entry)

    return {"criteria_report": report}


@app.get("/api/surveys/all")
def list_all_surveys(user: dict = Depends(require_instructor_permission())):
    """
    Tüm anketleri (aktif + kapanmış) listeler.
      - Yöneticiler (admin, bölüm başkanı, MÜDEK kurul üyesi): tüm anketler
      - Öğretim üyesi: yalnızca kendi atandığı offering'lere ait anketler
    """
    role = user.get("role")
    user_id = int(user["user_id"])
    base_query = """
        SELECT s.id, s.offering_id, s.is_active, s.created_at,
               c.code AS course_code, c.name AS course_name,
               co.term, co.section,
               i.name AS instructor_name,
               (SELECT COUNT(DISTINCT student_id) FROM survey_responses WHERE survey_id = s.id) as response_count,
               (SELECT COUNT(*) FROM enrollments WHERE offering_id = s.offering_id) as total_students,
               (SELECT COUNT(*) FROM survey_questions WHERE survey_id = s.id) as custom_question_count
        FROM surveys s
        JOIN course_offerings co ON s.offering_id = co.id
        JOIN courses c ON co.course_id = c.id
        LEFT JOIN instructors i ON co.instructor_id = i.id
    """
    with pool.connection() as conn, conn.cursor() as cur:
        if role == "ogretim_uyesi":
            cur.execute(
                base_query +
                " WHERE co.instructor_id = (SELECT id FROM instructors WHERE user_id = %s)"
                " ORDER BY s.created_at DESC",
                (user_id,),
            )
        else:
            cur.execute(base_query + " ORDER BY s.created_at DESC")
        return rows_to_dicts(cur)


# ======================================================
# MÜDEK PUKÖ & Geri Bildirim
# ======================================================

class ReflectionIn(BaseModel):
    analysis:    Optional[str] = None
    action_plan: Optional[str] = None
    feedback:    Optional[str] = None


@app.post("/api/exams/{exam_id}/reflection")
def save_exam_reflection(
    exam_id: int,
    data: ReflectionIn,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "student")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM exam_reflections WHERE exam_id = %s", (exam_id,))
        existing = cur.fetchone()

        if role == "ogretim_uyesi":
            cur.execute(
                """
                INSERT INTO exam_reflections (exam_id, instructor_id, analysis_text, action_plan, updated_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (exam_id) DO UPDATE SET
                    analysis_text = EXCLUDED.analysis_text,
                    action_plan   = EXCLUDED.action_plan,
                    instructor_id = EXCLUDED.instructor_id,
                    updated_at    = NOW()
                """,
                (exam_id, user_id, data.analysis, data.action_plan),
            )
        elif role in MANAGER_ROLES:
            if not existing:
                return {"success": False, "detail": "Hoca henüz değerlendirme yazmamış."}
            cur.execute(
                "UPDATE exam_reflections SET feedback_text = %s, reviewer_id = %s, updated_at = NOW() WHERE exam_id = %s",
                (data.feedback, user_id, exam_id),
            )
        else:
            return {"success": False, "detail": "Yazma yetkiniz yok."}

        conn.commit()
    return {"success": True, "message": "Kayıt başarılı."}


@app.get("/api/exams/{exam_id}/reflection", dependencies=[Depends(get_current_user)])
def get_exam_reflection(exam_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT analysis_text, action_plan, updated_at, instructor_id, feedback_text FROM exam_reflections WHERE exam_id = %s",
            (exam_id,),
        )
        row = cur.fetchone()
    if row:
        return {
            "exists":       True,
            "analysis":     row[0],
            "action_plan":  row[1],
            "last_updated": row[2],
            "author_id":    row[3],
            "feedback":     row[4],
        }
    return {"exists": False}


# ======================================================
# Komisyon Yönetimi
# ======================================================

class CommitteeCreate(BaseModel):
    name: str
    description: Optional[str] = None


class MemberCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: Optional[str] = None


@app.get("/api/committees")
def list_committees(user: dict = Depends(get_current_user)):
    """Yöneticiler tüm komiteleri görür; sade kullanıcılar sadece üyesi oldukları."""
    role = user.get("role", "")
    is_manager = role in MANAGER_ROLES
    with pool.connection() as conn, conn.cursor() as cur:
        if is_manager:
            cur.execute(
                """
                SELECT c.id, c.name, c.description, c.created_at,
                       u.full_name as created_by_name,
                       COUNT(cm.id) as member_count
                FROM committees c
                LEFT JOIN users u ON c.created_by = u.id
                LEFT JOIN committee_members cm ON c.id = cm.committee_id
                GROUP BY c.id, c.name, c.description, c.created_at, u.full_name
                ORDER BY c.created_at DESC
                """
            )
        else:
            cur.execute(
                """
                SELECT c.id, c.name, c.description, c.created_at,
                       u.full_name as created_by_name,
                       (SELECT COUNT(*) FROM committee_members cm2 WHERE cm2.committee_id = c.id) as member_count
                FROM committees c
                JOIN committee_members cm ON cm.committee_id = c.id
                LEFT JOIN users u ON c.created_by = u.id
                WHERE cm.user_id = %s
                ORDER BY c.created_at DESC
                """,
                (int(user["user_id"]),),
            )
        return rows_to_dicts(cur)


@app.post("/api/committees")
def create_committee(committee: CommitteeCreate, user: dict = Depends(require_committee_permission())):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO committees (name, description, created_by) VALUES (%s, %s, %s) RETURNING id",
            (committee.name, committee.description, user["user_id"]),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
    return {"success": True, "id": new_id, "message": f"✅ Komisyon oluşturuldu: {committee.name}"}


@app.delete("/api/committees/{committee_id}")
def delete_committee(committee_id: int, user: dict = Depends(require_committee_permission())):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM committee_members WHERE committee_id = %s", (committee_id,))
        cur.execute("DELETE FROM committees WHERE id = %s", (committee_id,))
        conn.commit()
    return {"success": True, "message": "✅ Komisyon silindi"}


@app.get("/api/committees/{committee_id}/members")
def get_committee_members(committee_id: int, user: dict = Depends(get_current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.full_name, u.email, cm.assigned_at,
                   COALESCE(r.code, 'guest') as role
            FROM committee_members cm
            JOIN users u ON cm.user_id = u.id
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE cm.committee_id = %s
            ORDER BY cm.assigned_at DESC
            """,
            (committee_id,),
        )
        return rows_to_dicts(cur)


@app.post("/api/committees/{committee_id}/members")
def add_member_to_committee(
    committee_id: int,
    user_id: int = Body(..., embed=True),
    user: dict = Depends(require_committee_permission()),
):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        cur.execute(
            "SELECT 1 FROM committee_members WHERE committee_id = %s AND user_id = %s",
            (committee_id, user_id),
        )
        if cur.fetchone():
            raise HTTPException(400, "Bu kullanıcı zaten komisyon üyesi")
        cur.execute(
            "INSERT INTO committee_members (committee_id, user_id) VALUES (%s, %s)",
            (committee_id, user_id),
        )
        conn.commit()
    return {"success": True, "message": f"✅ {row[0]} komisyona eklendi"}


@app.delete("/api/committees/{committee_id}/members/{user_id}")
def remove_member_from_committee(
    committee_id: int,
    user_id: int,
    user: dict = Depends(require_committee_permission()),
):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        cur.execute(
            "DELETE FROM committee_members WHERE committee_id = %s AND user_id = %s",
            (committee_id, user_id),
        )
        conn.commit()
    return {"success": True, "message": f"✅ {row[0]} komisyondan çıkarıldı"}


@app.post("/api/committees/create-member")
def create_committee_member(member: MemberCreate, user: dict = Depends(require_committee_permission())):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE username = %s", (member.username,))
        if cur.fetchone():
            raise HTTPException(400, "Bu kullanıcı adı zaten kullanılıyor")
        hashed_pw = _hash_password(member.password)
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, email, is_active, must_change_password) "
            "VALUES (%s, %s, %s, %s, TRUE, TRUE) RETURNING id",
            (member.username, hashed_pw, member.full_name, member.email),
        )
        new_user_id = cur.fetchone()[0]
        cur.execute("SELECT id FROM roles WHERE code = 'komisyon_uyesi'")
        role_row = cur.fetchone()
        if role_row:
            cur.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)",
                (new_user_id, role_row[0]),
            )
        conn.commit()
    return {"success": True, "id": new_user_id, "message": f"✅ Komisyon üyesi oluşturuldu: {member.full_name}"}


@app.get("/api/committees/available-members")
def get_available_members(user: dict = Depends(require_committee_permission())):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.full_name, u.email, COALESCE(r.code, 'guest') as role
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE r.code = 'komisyon_uyesi' AND u.is_active = TRUE
            ORDER BY u.full_name
            """
        )
        return rows_to_dicts(cur)


# ======================================================
# Komisyon Raporları
# ======================================================

# ── Komite raporları için yardımcılar ────────────────────────────────
_ALLOWED_REPORT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".png", ".jpg", ".jpeg",
}
_MAX_REPORT_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# K4 fix: Dosya içerik tipi doğrulaması (magic bytes)
_ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain",
    "image/png",
    "image/jpeg",
}


def _committee_upload_dir() -> str:
    d = os.environ.get("UPLOAD_DIR", "/data/uploads")
    os.makedirs(d, exist_ok=True)
    return d


def _assert_committee_access(cur, committee_id: int, user_id: int, role: str) -> None:
    """Kullanıcı yönetici değilse komite üyesi olmalı."""
    cur.execute("SELECT 1 FROM committees WHERE id = %s", (committee_id,))
    if cur.fetchone() is None:
        raise HTTPException(404, "Komisyon bulunamadı")
    if role in MANAGER_ROLES:
        return
    cur.execute(
        "SELECT 1 FROM committee_members WHERE committee_id = %s AND user_id = %s",
        (committee_id, user_id),
    )
    if not cur.fetchone():
        raise HTTPException(403, "Bu komisyona erişim yetkiniz yok")


def _fetch_report_or_404(cur, committee_id: int, report_id: int) -> dict:
    cur.execute(
        """
        SELECT id, committee_id, uploader_id, title, content, report_type, period,
               status, file_path, submitted_at, reviewed_at, reviewer_id, review_note,
               created_at, updated_at
        FROM committee_reports
        WHERE id = %s AND committee_id = %s
        """,
        (report_id, committee_id),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "Rapor bulunamadı")
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


async def _save_uploaded_file(file: UploadFile) -> tuple[str, str, int, str | None]:
    """Yüklenen dosyayı diske yazar; (file_location, original_name, size, content_type)."""
    original_name = file.filename or "file"
    safe_name = os.path.basename(original_name).replace(" ", "_")
    _, ext = os.path.splitext(safe_name)
    if ext.lower() not in _ALLOWED_REPORT_EXTENSIONS:
        raise HTTPException(
            400,
            f"İzin verilmeyen dosya türü: {ext}. "
            f"İzin verilenler: {', '.join(sorted(_ALLOWED_REPORT_EXTENSIONS))}",
        )

    content = await file.read()
    if len(content) > _MAX_REPORT_FILE_SIZE:
        raise HTTPException(400, "Dosya boyutu 50 MB sınırını aşıyor")

    # K4 fix: Magic bytes ile dosya tipi doğrulaması
    try:
        import magic
        detected_mime = magic.from_buffer(content[:2048], mime=True)
        if detected_mime not in _ALLOWED_MIME_TYPES:
            raise HTTPException(
                400,
                f"Dosya içeriği izin verilen tiplerle uyuşmuyor (algılanan: {detected_mime}). "
                f"Desteklenen tipler: PDF, Word, Excel, PowerPoint, metin, PNG, JPEG",
            )
    except ImportError:
        logging.warning("python-magic yüklü değil, MIME doğrulaması atlanıyor")
    except HTTPException:
        raise
    except Exception as exc:
        logging.warning("MIME doğrulaması sırasında hata: %s", exc)

    upload_dir = _committee_upload_dir()
    unique_name = f"{secrets.token_hex(8)}_{safe_name}"
    file_location = os.path.join(upload_dir, unique_name)
    with open(file_location, "wb") as f:
        f.write(content)
    return file_location, original_name, len(content), (file.content_type or None)


@app.get("/api/committees/{committee_id}/reports")
def get_committee_reports(
    committee_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        cur.execute(
            """
            SELECT r.id, r.title, r.content, r.report_type, r.period, r.status,
                   r.file_path, r.created_at, r.updated_at,
                   r.submitted_at, r.reviewed_at, r.review_note,
                   r.uploader_id,
                   u.full_name AS uploader_name,
                   r.reviewer_id,
                   ru.full_name AS reviewer_name,
                   COALESCE(att.cnt, 0) AS attachment_count
            FROM committee_reports r
            JOIN users u ON u.id = r.uploader_id
            LEFT JOIN users ru ON ru.id = r.reviewer_id
            LEFT JOIN (
                SELECT report_id, COUNT(*) AS cnt
                FROM committee_report_attachments
                GROUP BY report_id
            ) att ON att.report_id = r.id
            WHERE r.committee_id = %s
            ORDER BY r.created_at DESC
            """,
            (committee_id,),
        )
        return rows_to_dicts(cur)


# ── Yeni: rapor metni + onay akışı ────────────────────────────────────
class ReportPayload(BaseModel):
    title: str
    content: Optional[str] = None
    report_type: Optional[str] = None
    period: Optional[str] = None


class ReviewPayload(BaseModel):
    action: str   # "approve" | "reject"
    note: Optional[str] = None


@app.post("/api/committees/{committee_id}/reports")
def create_committee_report(
    committee_id: int,
    payload: ReportPayload,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(400, "Başlık zorunludur")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        cur.execute(
            """
            INSERT INTO committee_reports
                (committee_id, uploader_id, title, content, report_type, period, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'draft')
            RETURNING id
            """,
            (committee_id, user_id, title, payload.content,
             payload.report_type, payload.period),
        )
        new_id = int(cur.fetchone()[0])
        conn.commit()
    return {"success": True, "id": new_id}


@app.get("/api/committees/{committee_id}/reports/{report_id}")
def get_committee_report_detail(
    committee_id: int,
    report_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        cur.execute(
            """
            SELECT r.id, r.committee_id, r.uploader_id, u.full_name AS uploader_name,
                   r.title, r.content, r.report_type, r.period, r.status,
                   r.submitted_at, r.reviewed_at, r.review_note,
                   r.reviewer_id, ru.full_name AS reviewer_name,
                   r.created_at, r.updated_at
            FROM committee_reports r
            JOIN users u ON u.id = r.uploader_id
            LEFT JOIN users ru ON ru.id = r.reviewer_id
            WHERE r.id = %s AND r.committee_id = %s
            """,
            (report_id, committee_id),
        )
        report_rows = rows_to_dicts(cur)
        if not report_rows:
            raise HTTPException(404, "Rapor bulunamadı")
        report = report_rows[0]

        cur.execute(
            """
            SELECT a.id, a.report_id, a.original_name, a.file_size, a.content_type,
                   a.uploaded_at, a.uploaded_by, u.full_name AS uploaded_by_name
            FROM committee_report_attachments a
            LEFT JOIN users u ON u.id = a.uploaded_by
            WHERE a.report_id = %s
            ORDER BY a.uploaded_at ASC
            """,
            (report_id,),
        )
        report["attachments"] = rows_to_dicts(cur)

    return report


@app.put("/api/committees/{committee_id}/reports/{report_id}")
def update_committee_report(
    committee_id: int,
    report_id: int,
    payload: ReportPayload,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(400, "Başlık zorunludur")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        report = _fetch_report_or_404(cur, committee_id, report_id)

        is_owner = report["uploader_id"] == user_id
        is_manager = role in MANAGER_ROLES
        if not (is_owner or is_manager):
            raise HTTPException(403, "Bu raporu düzenleme yetkiniz yok")

        # Sahip yalnızca taslak/reddedilmiş raporu düzenleyebilir;
        # yöneticiler her zaman düzenleyebilir.
        if not is_manager and report["status"] not in ("draft", "rejected"):
            raise HTTPException(409, "Sadece taslak veya reddedilmiş rapor düzenlenebilir")

        cur.execute(
            """
            UPDATE committee_reports
               SET title = %s,
                   content = %s,
                   report_type = %s,
                   period = %s,
                   updated_at = NOW(),
                   status = CASE
                       WHEN status = 'rejected' THEN 'draft'
                       ELSE status
                   END
             WHERE id = %s
            """,
            (title, payload.content, payload.report_type, payload.period, report_id),
        )
        conn.commit()
    return {"success": True}


@app.delete("/api/committees/{committee_id}/reports/{report_id}")
def delete_committee_report(
    committee_id: int,
    report_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        report = _fetch_report_or_404(cur, committee_id, report_id)

        is_owner = report["uploader_id"] == user_id
        is_manager = role in MANAGER_ROLES
        if not (is_owner or is_manager):
            raise HTTPException(403, "Bu raporu silme yetkiniz yok")
        if not is_manager and report["status"] not in ("draft", "rejected"):
            raise HTTPException(409, "Sadece taslak veya reddedilmiş rapor silinebilir")

        # Önce ek dosyalarını topla, ardından DB satırlarını sil, son olarak diski temizle.
        cur.execute(
            "SELECT file_path FROM committee_report_attachments WHERE report_id = %s",
            (report_id,),
        )
        att_paths = [r[0] for r in cur.fetchall()]
        legacy_path = report.get("file_path")

        cur.execute("DELETE FROM committee_reports WHERE id = %s", (report_id,))
        conn.commit()

    for p in att_paths + ([legacy_path] if legacy_path else []):
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            logging.warning("Komite rapor eki silinemedi: %s", p)
    return {"success": True}


@app.post("/api/committees/{committee_id}/reports/{report_id}/attachments")
async def add_report_attachment(
    committee_id: int,
    report_id: int,
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        report = _fetch_report_or_404(cur, committee_id, report_id)

        is_owner = report["uploader_id"] == user_id
        is_manager = role in MANAGER_ROLES
        if not (is_owner or is_manager):
            raise HTTPException(403, "Bu rapora ek yükleme yetkiniz yok")
        if not is_manager and report["status"] not in ("draft", "rejected"):
            raise HTTPException(409, "Sadece taslak/reddedilmiş rapora ek eklenebilir")

    # Dosyayı kaydet (DB transaction'ı dışında — büyük dosyada conn'u tutmamak için)
    file_location, original_name, size, ctype = await _save_uploaded_file(file)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO committee_report_attachments
                (report_id, file_path, original_name, file_size, content_type, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (report_id, file_location, original_name, size, ctype, user_id),
        )
        new_id = int(cur.fetchone()[0])
        cur.execute("UPDATE committee_reports SET updated_at = NOW() WHERE id = %s", (report_id,))
        conn.commit()
    return {"success": True, "id": new_id, "original_name": original_name, "file_size": size}


@app.delete("/api/committees/{committee_id}/reports/{report_id}/attachments/{attachment_id}")
def delete_report_attachment(
    committee_id: int,
    report_id: int,
    attachment_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        report = _fetch_report_or_404(cur, committee_id, report_id)

        is_owner = report["uploader_id"] == user_id
        is_manager = role in MANAGER_ROLES
        if not (is_owner or is_manager):
            raise HTTPException(403, "Bu eki silme yetkiniz yok")
        if not is_manager and report["status"] not in ("draft", "rejected"):
            raise HTTPException(409, "Sadece taslak/reddedilmiş rapordan ek silinebilir")

        cur.execute(
            "SELECT file_path FROM committee_report_attachments WHERE id = %s AND report_id = %s",
            (attachment_id, report_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "Ek bulunamadı")
        path = row[0]

        cur.execute("DELETE FROM committee_report_attachments WHERE id = %s", (attachment_id,))
        cur.execute("UPDATE committee_reports SET updated_at = NOW() WHERE id = %s", (report_id,))
        conn.commit()

    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        logging.warning("Ek diskten silinemedi: %s", path)
    return {"success": True}


@app.get("/api/committees/{committee_id}/reports/{report_id}/attachments/{attachment_id}/download")
def download_report_attachment(
    committee_id: int,
    report_id: int,
    attachment_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        cur.execute(
            """
            SELECT a.file_path, a.original_name, a.content_type
            FROM committee_report_attachments a
            JOIN committee_reports r ON r.id = a.report_id
            WHERE a.id = %s AND a.report_id = %s AND r.committee_id = %s
            """,
            (attachment_id, report_id, committee_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "Ek bulunamadı")
        path, original_name, ctype = row

    if not path or not os.path.isfile(path):
        raise HTTPException(410, "Dosya artık erişilebilir değil")
    return FileResponse(
        path,
        media_type=ctype or "application/octet-stream",
        filename=original_name or "attachment",
    )


@app.post("/api/committees/{committee_id}/reports/{report_id}/submit")
def submit_committee_report(
    committee_id: int,
    report_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        report = _fetch_report_or_404(cur, committee_id, report_id)

        is_owner = report["uploader_id"] == user_id
        is_manager = role in MANAGER_ROLES
        if not (is_owner or is_manager):
            raise HTTPException(403, "Bu raporu gönderme yetkiniz yok")
        if report["status"] not in ("draft", "rejected"):
            raise HTTPException(409, "Sadece taslak/reddedilmiş rapor gönderilebilir")

        cur.execute(
            """
            UPDATE committee_reports
               SET status = 'submitted',
                   submitted_at = NOW(),
                   updated_at = NOW(),
                   reviewer_id = NULL,
                   reviewed_at = NULL,
                   review_note = NULL
             WHERE id = %s
            """,
            (report_id,),
        )
        conn.commit()
    return {"success": True}


@app.post("/api/committees/{committee_id}/reports/{report_id}/review")
def review_committee_report(
    committee_id: int,
    report_id: int,
    payload: ReviewPayload,
    user: dict = Depends(require_committee_permission()),
):
    action = (payload.action or "").lower().strip()
    if action not in ("approve", "reject"):
        raise HTTPException(400, "action 'approve' veya 'reject' olmalı")
    if action == "reject" and not (payload.note or "").strip():
        raise HTTPException(400, "Reddederken bir not yazmanız gerekir")

    user_id = int(user["user_id"])
    new_status = "approved" if action == "approve" else "rejected"

    with pool.connection() as conn, conn.cursor() as cur:
        report = _fetch_report_or_404(cur, committee_id, report_id)
        if report["status"] != "submitted":
            raise HTTPException(409, "Sadece 'gönderildi' durumundaki rapor incelenebilir")

        cur.execute(
            """
            UPDATE committee_reports
               SET status = %s,
                   reviewer_id = %s,
                   reviewed_at = NOW(),
                   review_note = %s,
                   updated_at = NOW()
             WHERE id = %s
            """,
            (new_status, user_id, payload.note, report_id),
        )
        conn.commit()
    return {"success": True, "status": new_status}


# ── Legacy: tek dosyalı yükleme (eski my-committees.html için) ────────
@app.post("/api/committees/{committee_id}/upload")
async def upload_committee_report(
    committee_id: int,
    title: str = Form(...),
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Geriye dönük uyumluluk: tek dosyayı otomatik bir 'draft' rapor + ek olarak kaydeder."""
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])
    role = token_data.get("role", "")

    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)

    file_location, original_name, size, ctype = await _save_uploaded_file(file)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO committee_reports
                (committee_id, uploader_id, title, status)
            VALUES (%s, %s, %s, 'draft')
            RETURNING id
            """,
            (committee_id, user_id, title),
        )
        report_id = int(cur.fetchone()[0])
        cur.execute(
            """
            INSERT INTO committee_report_attachments
                (report_id, file_path, original_name, file_size, content_type, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (report_id, file_location, original_name, size, ctype, user_id),
        )
        conn.commit()
    return {"success": True, "message": "✅ Rapor yüklendi", "report_id": report_id}


@app.get("/api/committees/{committee_id}/consolidated.pdf")
def download_consolidated_pdf(
    committee_id: int,
    period: str | None = None,
    report_type: str | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token_data = decode_jwt(credentials.credentials)
    user_id = token_data["user_id"]
    role = token_data.get("role", "")
    with pool.connection() as conn, conn.cursor() as cur:
        _assert_committee_access(cur, committee_id, user_id, role)
        pdf_bytes = build_committee_consolidated_pdf(
            conn, committee_id, period=period, report_type=report_type
        )
    from fastapi.responses import Response
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="komisyon_{committee_id}_rapor.pdf"'},
    )


# ======================================================
# Admin / Genel Raporlar
# ======================================================

@app.get("/api/admin/mudek-overview")
def get_mudek_overview(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_data = decode_jwt(credentials.credentials)
    if token_data.get("role") not in MANAGER_ROLES:
        raise HTTPException(403, "Yetkiniz yok.")
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.id AS exam_id, c.id AS course_id, c.code AS course_code, c.name AS course_name,
                   i.name AS instructor_name, e.date AS exam_date,
                   CASE WHEN er.analysis_text IS NOT NULL THEN true ELSE false END AS has_report,
                   er.feedback_text, er.updated_at
            FROM exams e
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            JOIN instructors i ON co.instructor_id = i.id
            LEFT JOIN exam_reflections er ON e.id = er.exam_id
            ORDER BY has_report ASC, e.date DESC
            """
        )
        return rows_to_dicts(cur)


@app.get("/api/reports/program-outcomes", dependencies=[Depends(get_current_user)])
def get_program_outcome_stats():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT po.id, po.code, po.title,
                   COALESCE(
                       SUM(avg_scores.score * om.value) / NULLIF(SUM(om.value), 0), 0
                   ) as achievement_score
            FROM program_outcomes po
            LEFT JOIN outcome_matrix om ON po.id = om.program_outcome_id
            LEFT JOIN (
                SELECT outcome_id, AVG(score) as score
                FROM survey_responses GROUP BY outcome_id
            ) avg_scores ON om.outcome_id = avg_scores.outcome_id
            GROUP BY po.id, po.code, po.title
            ORDER BY po.id
            """
        )
        results = rows_to_dicts(cur)
    for row in results:
        row["achievement_score"] = float(round(row["achievement_score"], 2))
        row["percentage"] = int((row["achievement_score"] / 5) * 100)
    return results


@app.get("/api/reports/course-performance", dependencies=[Depends(get_current_user)])
def get_course_performance_report():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT co.id, c.code, c.name as course_name, co.term, co.section,
                   i.name as instructor_name,
                   (SELECT COUNT(*) FROM enrollments e WHERE e.offering_id = co.id) as total_students,
                   (SELECT COUNT(DISTINCT student_id) FROM survey_responses sr
                    JOIN surveys s ON sr.survey_id = s.id WHERE s.offering_id = co.id) as responded_students,
                   (SELECT AVG(sr.score) FROM survey_responses sr
                    JOIN surveys s ON sr.survey_id = s.id WHERE s.offering_id = co.id) as avg_score
            FROM course_offerings co
            JOIN courses c ON co.course_id = c.id
            LEFT JOIN instructors i ON co.instructor_id = i.id
            ORDER BY co.id DESC
            """
        )
        rows = rows_to_dicts(cur)
    for row in rows:
        row["avg_score"] = round(float(row["avg_score"]), 2) if row["avg_score"] else 0.0
        total = row["total_students"]
        resp = row["responded_students"]
        row["participation_rate"] = int((resp / total * 100)) if total > 0 else 0
        row["status"] = (
            "no_data" if row["avg_score"] == 0
            else "success" if row["avg_score"] >= 3.0
            else "danger"
        )
    return rows


@app.get("/api/reports/course-performance/excel", dependencies=[Depends(get_current_user)])
def export_course_performance_excel():
    """Tüm ders-açılışı performans listesini xlsx olarak indirir."""
    rows = get_course_performance_report()

    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment

    wb = Workbook()
    ws = wb.active
    ws.title = "Ders Performans"

    headers = [
        "Ders Kodu", "Ders Adı", "Dönem", "Şube", "Öğretim Üyesi",
        "Toplam Öğrenci", "Yanıtlayan", "Katılım %", "Ortalama Puan", "Durum",
    ]
    ws.append(headers)
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="0B1F45", end_color="0B1F45", fill_type="solid")
    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")

    status_label = {"success": "Başarılı", "danger": "Riskli", "no_data": "Veri Yok"}
    for row in rows:
        ws.append([
            row.get("code", ""),
            row.get("course_name", ""),
            row.get("term", ""),
            row.get("section", ""),
            row.get("instructor_name") or "—",
            row.get("total_students", 0),
            row.get("responded_students", 0),
            row.get("participation_rate", 0),
            row.get("avg_score", 0),
            status_label.get(row.get("status", ""), "—"),
        ])

    # Genişlikleri otomatik yaklaşık ayarla
    widths = [12, 36, 14, 8, 26, 14, 12, 12, 14, 12]
    for idx, w in enumerate(widths, start=1):
        ws.column_dimensions[chr(64 + idx)].width = w
    ws.freeze_panes = "A2"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="ders-performans-raporu.xlsx"'},
    )


@app.get("/api/templates/exam-results.xlsx", dependencies=[Depends(get_current_user)])
def download_exam_results_template(exam_id: int | None = None):
    """Sınav sonuçları yükleme için örnek Excel şablonu.

    exam_id verilirse soru sayısı ve 'Proje' sütunu sınavın gerçek
    yapılandırmasına (project_weight) göre üretilir; sınav bilgisi
    okunamazsa genel şablona düşülür.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    q_count, project_active, exam_specific = 5, True, False
    if exam_id is not None:
        try:
            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT COALESCE(project_weight, 0),"
                    " (SELECT COUNT(*) FROM questions WHERE exam_id = e.id)"
                    " FROM exams e WHERE e.id = %s",
                    (exam_id,),
                )
                row = cur.fetchone()
                if row:
                    project_active = float(row[0]) > 0
                    q_count = int(row[1]) or 5
                    exam_specific = True
        except Exception:
            logging.warning(
                "Şablon için sınav bilgisi okunamadı, genel şablon kullanılıyor",
                exc_info=True,
            )

    wb = Workbook()
    ws = wb.active
    ws.title = "Sinav Sonuclari"

    headers = ["Öğrenci No", "Ad Soyad"] + [f"S{i}" for i in range(1, q_count + 1)]
    if project_active:
        headers.append("Proje")
    ws.append(headers)

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="0B1F45", end_color="0B1F45", fill_type="solid")
    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center")

    sample_scores = [18, 14, 9, 8, 16, 12, 10, 15, 7, 13]
    sample_students = [
        ("20240001", "Ahmet Yılmaz", 75),
        ("20240002", "Ayşe Demir", 80),
        ("20240003", "Mehmet Kaya", 60),
    ]
    for i, (no, name, p_score) in enumerate(sample_students):
        row = [no, name] + [
            sample_scores[(i + j) % len(sample_scores)] for j in range(q_count)
        ]
        if project_active:
            row.append(p_score)
        ws.append(row)

    # Bilgi notu sayfası
    info = wb.create_sheet("Aciklama")
    info["A1"] = "Sınav Sonuçları Şablonu — Açıklama"
    info["A1"].font = Font(bold=True, size=14)
    if not exam_specific:
        project_note = "4. 'Proje' kolonu opsiyoneldir — sınavda proje varsa öğrencinin proje puanı."
    elif project_active:
        project_note = "4. 'Proje' kolonu bu sınav için ZORUNLUDUR — öğrencinin proje puanını girin."
    else:
        project_note = "4. Bu sınav için proje tanımlı değildir — 'Proje' kolonu gerekmez."
    notes = [
        "",
        "1. İlk satır başlık satırıdır, değiştirmeyin.",
        "2. 'Öğrenci No' ve 'Ad Soyad' kolonları zorunludur.",
        "3. S1, S2, ... soru puanlarıdır. Sınavda kaç soru varsa o kadar kolon ekleyin.",
        project_note,
        "5. Boş hücreler 0 olarak değerlendirilir.",
    ]
    for i, line in enumerate(notes, start=2):
        info.cell(row=i, column=1, value=line)

    widths = [14, 26] + [8] * q_count + ([10] if project_active else [])
    for idx, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(idx)].width = w
    ws.freeze_panes = "A2"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="sinav-sonuclari-sablonu.xlsx"'},
    )


@app.get("/api/reports/student-portfolio/{student_no}", dependencies=[Depends(get_current_user)])
def get_student_portfolio(student_no: str):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, student_no, name FROM students WHERE student_no = %s", (student_no,)
        )
        student = cur.fetchone()
        if not student:
            raise HTTPException(404, "Öğrenci bulunamadı")
        student_data = {"id": student[0], "student_no": student[1], "name": student[2]}

        cur.execute(
            """
            SELECT po.code, po.title,
                   SUM(r.score * qo.weight * om.value) AS earned_points,
                   SUM(q.points * qo.weight * om.value) AS total_possible_points
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            JOIN question_outcomes qo ON q.id = qo.question_id
            JOIN outcome_matrix om ON qo.outcome_id = om.outcome_id
            JOIN program_outcomes po ON om.program_outcome_id = po.id
            WHERE r.student_id = %s
            GROUP BY po.code, po.title
            ORDER BY po.code
            """,
            (student[0],),
        )
        rows = rows_to_dicts(cur)

    skills = []
    for row in rows:
        earned = float(row["earned_points"])
        possible = float(row["total_possible_points"])
        percentage = (earned / possible * 100) if possible > 0 else 0
        skills.append({
            "code": row["code"],
            "title": row["title"],
            "earned": round(earned, 1),
            "possible": round(possible, 1),
            "percentage": int(percentage),
        })
    return {"student": student_data, "skills": skills}


@app.get("/api/reports/student-portfolio/{student_no}/detailed", dependencies=[Depends(get_current_user)])
def get_student_portfolio_detailed(student_no: str):
    """
    Detaylı öğrenci yetkinlik karnesi.

    Her ders için:
      - Öğrencinin o dersteki genel başarı yüzdesi (cevapladığı sorular üzerinden)
      - DÖÇ (ders öğrenim çıktıları) başarı yüzdeleri — ders bazlı
      - PÇ (program çıktıları) katkı yüzdeleri — outcome_matrix üzerinden DÖÇ→PÇ ağırlıklandırma

    Ayrıca tüm dersler üzerinden ağırlıklı ortalama PÇ başarısı döndürülür.
    """
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, student_no, name FROM students WHERE student_no = %s",
            (student_no,),
        )
        student = cur.fetchone()
        if not student:
            raise HTTPException(404, "Öğrenci bulunamadı")
        student_id = student[0]
        student_data = {"id": student_id, "student_no": student[1], "name": student[2]}

        # Öğrencinin cevap verdiği tüm ders-açılışları (course_offerings)
        cur.execute(
            """
            SELECT DISTINCT co.id, co.term, c.id AS course_id, c.code, c.name
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            JOIN exams e ON q.exam_id = e.id
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            WHERE r.student_id = %s
            ORDER BY co.term, c.code
            """,
            (student_id,),
        )
        offerings = cur.fetchall()

        courses = []
        total_exams = 0

        # Her ders-açılışı için detaylı hesap
        for off_id, term, course_id, course_code, course_name in offerings:
            # Bu dersteki toplam başarı yüzdesi (alınan puan / olası puan)
            cur.execute(
                """
                SELECT COALESCE(SUM(r.score), 0) AS earned,
                       COALESCE(SUM(q.points), 0) AS possible,
                       COUNT(DISTINCT e.id) AS exam_count
                FROM responses r
                JOIN questions q ON r.question_id = q.id
                JOIN exams e ON q.exam_id = e.id
                WHERE e.offering_id = %s AND r.student_id = %s
                """,
                (off_id, student_id),
            )
            earned, possible, exam_count = cur.fetchone()
            earned = float(earned or 0)
            possible = float(possible or 0)
            overall_pct = (earned / possible * 100) if possible > 0 else 0
            total_exams += int(exam_count or 0)

            # DÖÇ başarı yüzdeleri (ders bazlı)
            cur.execute(
                """
                SELECT clo.id, clo.sequence_number, clo.description,
                       SUM(r.score * qo.weight) AS earned,
                       SUM(q.points * qo.weight) AS possible
                FROM responses r
                JOIN questions q ON r.question_id = q.id
                JOIN exams e ON q.exam_id = e.id
                JOIN question_outcomes qo ON q.id = qo.question_id
                JOIN course_learning_outcomes clo ON qo.outcome_id = clo.id
                WHERE e.offering_id = %s
                  AND r.student_id = %s
                  AND clo.course_id = %s
                GROUP BY clo.id, clo.sequence_number, clo.description
                ORDER BY clo.sequence_number
                """,
                (off_id, student_id, course_id),
            )
            clo_scores = []
            for clo_id, seq, desc, ce, cp in cur.fetchall():
                ce = float(ce or 0)
                cp = float(cp or 0)
                pct = (ce / cp * 100) if cp > 0 else 0
                clo_scores.append({
                    "id": clo_id,
                    "code": f"DÖÇ{seq}",
                    "sequence_number": seq,
                    "description": desc,
                    "earned": round(ce, 1),
                    "possible": round(cp, 1),
                    "percentage": round(pct, 1),
                })

            # PÇ katkıları (DÖÇ → outcome_matrix → PÇ)
            cur.execute(
                """
                SELECT po.id, po.code, po.title,
                       SUM(r.score * qo.weight * om.value) AS earned,
                       SUM(q.points * qo.weight * om.value) AS possible
                FROM responses r
                JOIN questions q ON r.question_id = q.id
                JOIN exams e ON q.exam_id = e.id
                JOIN question_outcomes qo ON q.id = qo.question_id
                JOIN outcome_matrix om ON qo.outcome_id = om.outcome_id
                JOIN program_outcomes po ON om.program_outcome_id = po.id
                WHERE e.offering_id = %s AND r.student_id = %s
                GROUP BY po.id, po.code, po.title
                ORDER BY po.code
                """,
                (off_id, student_id),
            )
            po_scores = []
            for po_id, code, title, pe, pp in cur.fetchall():
                pe = float(pe or 0)
                pp = float(pp or 0)
                pct = (pe / pp * 100) if pp > 0 else 0
                po_scores.append({
                    "id": po_id,
                    "code": code,
                    "title": title,
                    "earned": round(pe, 1),
                    "possible": round(pp, 1),
                    "percentage": round(pct, 1),
                })

            courses.append({
                "offering_id": off_id,
                "course_id": course_id,
                "course_code": course_code,
                "course_name": course_name,
                "term": term,
                "overall_percentage": round(overall_pct, 1),
                "earned": round(earned, 1),
                "possible": round(possible, 1),
                "exam_count": int(exam_count or 0),
                "clo_scores": clo_scores,
                "po_scores": po_scores,
            })

        # Toplam PÇ başarısı (tüm dersler birlikte, ağırlıklı)
        cur.execute(
            """
            SELECT po.id, po.code, po.title,
                   SUM(r.score * qo.weight * om.value) AS earned,
                   SUM(q.points * qo.weight * om.value) AS possible,
                   COUNT(DISTINCT co.id) AS course_count
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            JOIN exams e ON q.exam_id = e.id
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN question_outcomes qo ON q.id = qo.question_id
            JOIN outcome_matrix om ON qo.outcome_id = om.outcome_id
            JOIN program_outcomes po ON om.program_outcome_id = po.id
            WHERE r.student_id = %s
            GROUP BY po.id, po.code, po.title
            ORDER BY po.code
            """,
            (student_id,),
        )
        overall_po = []
        for po_id, code, title, pe, pp, cc in cur.fetchall():
            pe = float(pe or 0)
            pp = float(pp or 0)
            pct = (pe / pp * 100) if pp > 0 else 0
            overall_po.append({
                "id": po_id,
                "code": code,
                "title": title,
                "earned": round(pe, 1),
                "possible": round(pp, 1),
                "percentage": round(pct, 1),
                "courses_count": int(cc or 0),
            })

    overall_success = 0
    if overall_po:
        overall_success = round(sum(p["percentage"] for p in overall_po) / len(overall_po), 1)

    return {
        "student": student_data,
        "summary": {
            "overall_success_percentage": overall_success,
            "total_courses": len(courses),
            "total_exams": total_exams,
            "total_program_outcomes": len(overall_po),
        },
        "program_outcomes": overall_po,
        "courses": courses,
    }


@app.get("/api/my-grades")
def get_my_grades(user: dict = Depends(require_role("student"))):
    user_id = user["user_id"]
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM students WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            return []
        cur.execute(
            """
            SELECT c.code, c.name as course_name, e.title as exam_title, e.date,
                   SUM(r.score) as my_score,
                   (SELECT SUM(points) FROM questions WHERE exam_id = e.id) as max_score
            FROM responses r
            JOIN questions q ON r.question_id = q.id
            JOIN exams e ON q.exam_id = e.id
            JOIN course_offerings co ON e.offering_id = co.id
            JOIN courses c ON co.course_id = c.id
            WHERE r.student_id = %s
            GROUP BY e.id, c.code, c.name, e.title, e.date
            ORDER BY e.date DESC
            """,
            (row[0],),
        )
        return rows_to_dicts(cur)


# ======================================================
# Dönem Karşılaştırma / Trend Analizi
# ======================================================

@app.get("/api/reports/pc-trend")
def get_pc_trend(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Program Çıktıları (PÇ) dönem bazlı trend analizi.
    Her dönem için tüm derslerin PÇ başarı ortalamasını hesaplar.

    Dönüş formatı:
    {
        "terms": ["2023-Güz", "2024-Bahar", ...],
        "program_outcomes": [
            {"id": 1, "code": "PÇ1", "title": "...", "scores": [0.72, 0.75, null, ...]},
            ...
        ],
        "course_details": [
            {"term": "2024-Güz", "course_code": "BIL201", "course_name": "...", "pc_scores": {"1": 0.73, ...}},
            ...
        ]
    }
    """
    decode_jwt(credentials.credentials)

    from mudek_service import calculate_course_attainment, MissingDataError

    with pool.connection() as conn, conn.cursor() as cur:
        # 1. Tüm dönemleri al (sıralı)
        cur.execute("""
            SELECT DISTINCT co.term
            FROM course_offerings co
            JOIN exams e ON e.offering_id = co.id
            WHERE co.term IS NOT NULL AND co.term != ''
            ORDER BY co.term
        """)
        terms = [r[0] for r in cur.fetchall()]

        if not terms:
            return {"terms": [], "program_outcomes": [], "course_details": []}

        # 2. Program çıktılarını al
        cur.execute("SELECT id, code, title FROM program_outcomes ORDER BY id")
        po_rows = cur.fetchall()
        po_map = {r[0]: {"id": r[0], "code": r[1], "title": r[2]} for r in po_rows}

        # 3. Dönem × Ders × Offering kombinasyonlarını al
        cur.execute("""
            SELECT co.term, co.course_id, c.code, c.name, co.id AS offering_id
            FROM course_offerings co
            JOIN courses c ON c.id = co.course_id
            JOIN exams e ON e.offering_id = co.id
            WHERE co.term IS NOT NULL AND co.term != ''
            GROUP BY co.term, co.course_id, c.code, c.name, co.id
            ORDER BY co.term, c.code
        """)
        term_course_offerings = cur.fetchall()

    # Offering'leri term×course bazında grupla
    from collections import defaultdict
    tco_map: dict[tuple, list[int]] = defaultdict(list)
    for term, course_id_row, ccode, cname, oid in term_course_offerings:
        tco_map[(term, course_id_row, ccode, cname)].append(oid)

    # 4. Her dönem-ders çifti için PÇ hesapla — offering_ids ile dönem filtreleyerek
    term_pc_agg: dict[str, dict[int, list[float]]] = {t: {} for t in terms}
    course_details = []

    for (term, course_id, course_code, course_name), oids in tco_map.items():
        try:
            with pool.connection() as conn:
                result = calculate_course_attainment(
                    conn=conn, course_id=course_id, offering_ids=oids
                )

                if result.pc_attainment:
                    pc_dict = {}
                    for po_id, score in result.pc_attainment.items():
                        term_pc_agg[term].setdefault(po_id, []).append(score)
                        pc_dict[str(po_id)] = round(score, 4)

                    course_details.append({
                        "term": term,
                        "course_id": course_id,
                        "course_code": course_code,
                        "course_name": course_name,
                        "pc_scores": pc_dict,
                        "students_total": result.students_total,
                        "students_passing": result.students_passing,
                    })
        except Exception:
            continue

    # 5. Dönem ortalamaları → PÇ trend verisi
    program_outcomes = []
    for po_id, po_info in po_map.items():
        scores = []
        for term in terms:
            vals = term_pc_agg[term].get(po_id)
            if vals:
                scores.append(round(sum(vals) / len(vals) * 100, 1))  # % olarak
            else:
                scores.append(None)

        # En az bir dönemde skoru varsa listeye ekle
        if any(s is not None for s in scores):
            program_outcomes.append({
                "id": po_id,
                "code": po_info["code"],
                "title": po_info["title"],
                "scores": scores,
            })

    return {
        "terms": terms,
        "program_outcomes": program_outcomes,
        "course_details": course_details,
    }


@app.get("/api/reports/course-trend/{course_id}")
def get_course_trend(
    course_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Tek bir dersin DÖÇ/PÇ başarısını dönem bazında takip eder.
    """
    decode_jwt(credentials.credentials)

    from mudek_service import calculate_course_attainment, MissingDataError

    with pool.connection() as conn, conn.cursor() as cur:
        # Bu derse ait dönem + offering bilgilerini al
        cur.execute("""
            SELECT co.term, co.id AS offering_id
            FROM course_offerings co
            JOIN exams e ON e.offering_id = co.id
            WHERE co.course_id = %s AND co.term IS NOT NULL
            GROUP BY co.term, co.id
            ORDER BY co.term
        """, (course_id,))
        term_offering_rows = cur.fetchall()

        cur.execute("SELECT code, name FROM courses WHERE id = %s", (course_id,))
        course_row = cur.fetchone()
        if not course_row:
            raise HTTPException(404, "Ders bulunamadı")

        # DÖÇ bilgilerini al
        cur.execute("""
            SELECT id, sequence_number, description
            FROM course_learning_outcomes
            WHERE course_id = %s
            ORDER BY sequence_number
        """, (course_id,))
        doc_rows = cur.fetchall()
        doc_map = {r[0]: {"id": r[0], "seq": r[1], "desc": r[2]} for r in doc_rows}

    # Dönem → offering_ids eşlemesi
    from collections import defaultdict as _defaultdict
    term_oids: dict[str, list[int]] = _defaultdict(list)
    for term_val, oid in term_offering_rows:
        term_oids[term_val].append(oid)
    terms = sorted(term_oids.keys())

    # Her dönem için hesapla — yalnızca o dönemin offering'leriyle
    doc_trend: dict[int, list] = {d: [] for d in doc_map}
    pc_trend: dict[int, list] = {}

    for term in terms:
        try:
            with pool.connection() as conn:
                result = calculate_course_attainment(
                    conn=conn, course_id=course_id, offering_ids=term_oids[term]
                )
                for doc_id in doc_map:
                    score = result.doc_attainment.get(doc_id)
                    doc_trend[doc_id].append(round(score * 100, 1) if score is not None else None)

                for po_id, score in result.pc_attainment.items():
                    pc_trend.setdefault(po_id, [None] * len(terms))
                    idx = terms.index(term)
                    pc_trend[po_id][idx] = round(score * 100, 1)
        except Exception:
            for doc_id in doc_map:
                doc_trend[doc_id].append(None)

    # PÇ isimlerini al
    po_names = {}
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, code, title FROM program_outcomes")
        for r in cur.fetchall():
            po_names[r[0]] = {"code": r[1], "title": r[2]}

    return {
        "course_code": course_row[0],
        "course_name": course_row[1],
        "terms": terms,
        "doc_outcomes": [
            {
                "id": doc_id,
                "sequence_number": info["seq"],
                "description": info["desc"],
                "scores": doc_trend[doc_id],
            }
            for doc_id, info in doc_map.items()
        ],
        "pc_outcomes": [
            {
                "id": po_id,
                "code": po_names.get(po_id, {}).get("code", f"PÇ{po_id}"),
                "title": po_names.get(po_id, {}).get("title", ""),
                "scores": scores,
            }
            for po_id, scores in pc_trend.items()
        ],
    }


# ======================================================
# Ders Dönem Değerlendirmesi (A5 / B / C)
# ======================================================
# SQL migration (bir kez çalıştır):
# CREATE TABLE IF NOT EXISTS offering_reflections (
#     id            SERIAL PRIMARY KEY,
#     offering_id   INTEGER UNIQUE NOT NULL REFERENCES course_offerings(id) ON DELETE CASCADE,
#     a5_text       TEXT,
#     b_text        TEXT,
#     c_text        TEXT,
#     instructor_id INTEGER REFERENCES users(id),
#     updated_at    TIMESTAMP DEFAULT NOW()
# );

class OfferingReflectionIn(BaseModel):
    a5_text: Optional[str] = None   # Anket sonuçlarının tartışılması
    b_text:  Optional[str] = None   # PÇ karşılanma düzeyleri yorumu
    c_text:  Optional[str] = None   # Dersin işleyişi genel değerlendirmesi


@app.get("/api/offerings/{offering_id}/reflection")
def get_offering_reflection(
    offering_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Bir ders şubesinin dönem sonu değerlendirmesini döndürür."""
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT a5_text, b_text, c_text, updated_at FROM offering_reflections WHERE offering_id = %s",
            (offering_id,),
        )
        row = cur.fetchone()

    if row:
        return {
            "exists":       True,
            "a5_text":      row[0],
            "b_text":       row[1],
            "c_text":       row[2],
            "last_updated": row[3],
        }
    return {"exists": False}


@app.post("/api/offerings/{offering_id}/reflection")
def save_offering_reflection(
    offering_id: int,
    data: OfferingReflectionIn,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Ders şubesi dönem sonu değerlendirmesini kaydeder / günceller."""
    token_data = decode_jwt(credentials.credentials)
    user_id = int(token_data["user_id"])

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO offering_reflections
                (offering_id, a5_text, b_text, c_text, instructor_id, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (offering_id) DO UPDATE SET
                a5_text       = EXCLUDED.a5_text,
                b_text        = EXCLUDED.b_text,
                c_text        = EXCLUDED.c_text,
                instructor_id = EXCLUDED.instructor_id,
                updated_at    = NOW()
            """,
            (offering_id, data.a5_text, data.b_text, data.c_text, user_id),
        )
        conn.commit()
    return {"success": True, "message": "✅ Ders değerlendirmesi kaydedildi."}


# ======================================================
# Offering Hazırlık Durumu (Status Dashboard)
# ======================================================

@app.get("/api/offerings/{offering_id}/status")
def get_offering_status(
    offering_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Bir ders şubesinin MÜDEK hazırlık durumunu döndürür.
    Her adım tamamlandı mı yoksa eksik mi bilgisini verir.

    Kontrol edilen adımlar:
      1. Sınavlar var mı?
      2. Sorular tanımlı mı?
      3. Soru→DÖÇ ağırlıkları ayarlandı mı?
      4. DÖÇ tanımlı mı?
      5. DÖÇ→PÇ matrisi dolu mu?
      6. Not yüklemeleri yapıldı mı (response var mı)?
      7. Dönem değerlendirmesi (reflection) yazıldı mı?
      8. PUKÖ A5: Baraj altında DÖÇ varsa eylem planı yazıldı mı?
    """
    decode_jwt(credentials.credentials)
    course_id_for_attainment: int | None = None
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT course_id FROM course_offerings WHERE id = %s", (offering_id,))
        offering_row = cur.fetchone()
        if not offering_row:
            raise HTTPException(404, "Offering bulunamadı")
        course_id_for_attainment = int(offering_row[0])

        # 1. Sınavlar
        cur.execute("SELECT COUNT(*) FROM exams WHERE offering_id = %s", (offering_id,))
        exam_count = cur.fetchone()[0]

        # 2. Sorular
        cur.execute(
            "SELECT COUNT(*) FROM questions WHERE exam_id IN (SELECT id FROM exams WHERE offering_id = %s)",
            (offering_id,),
        )
        question_count = cur.fetchone()[0]

        # 3. Soru→DÖÇ ağırlıkları
        cur.execute(
            """
            SELECT COUNT(DISTINCT q.id) as total_q,
                   COUNT(DISTINCT qo.question_id) as mapped_q
            FROM questions q
            JOIN exams e ON q.exam_id = e.id
            LEFT JOIN question_outcomes qo ON q.id = qo.question_id
            WHERE e.offering_id = %s
            """,
            (offering_id,),
        )
        row = cur.fetchone()
        total_q, mapped_q = (row[0] or 0), (row[1] or 0)

        # 4. DÖÇ
        cur.execute(
            """
            SELECT COUNT(*) FROM course_learning_outcomes
            WHERE course_id = (SELECT course_id FROM course_offerings WHERE id = %s)
            """,
            (offering_id,),
        )
        doc_count = cur.fetchone()[0]

        # 5. DÖÇ→PÇ matrisi
        cur.execute(
            """
            SELECT COUNT(*) FROM outcome_matrix om
            JOIN course_learning_outcomes clo ON om.outcome_id = clo.id
            WHERE clo.course_id = (SELECT course_id FROM course_offerings WHERE id = %s)
            """,
            (offering_id,),
        )
        matrix_count = cur.fetchone()[0]

        # 6. Notlar yüklenmiş mi
        cur.execute(
            """
            SELECT COUNT(*) FROM responses r
            JOIN questions q ON r.question_id = q.id
            JOIN exams e ON q.exam_id = e.id
            WHERE e.offering_id = %s
            """,
            (offering_id,),
        )
        response_count = cur.fetchone()[0]

        # 7. Reflection
        cur.execute(
            "SELECT 1 FROM offering_reflections WHERE offering_id = %s",
            (offering_id,),
        )
        has_reflection = cur.fetchone() is not None

        # 8. PUKÖ Eylem Planı (A5):
        # mudek_service ile bu offering'in DÖÇ başarı durumunu hesapla;
        # baraj altında kalan DÖÇ varsa offering_reflections.a5_text dolu olmalı.
        not_met_count = 0
        attainment_ok = True
        try:
            from mudek_service import calculate_course_attainment
            att = calculate_course_attainment(
                conn=conn,
                course_id=course_id_for_attainment,
                offering_ids=[offering_id],
            )
            not_met_count = sum(1 for s in att.doc_status.values() if s == "not_met")
        except Exception as e:
            # Henüz hesaplama yapılamıyorsa (eksik veri vb.) eylem planı kontrolü
            # zaten anlamlı değil; bu adımı "gerekmiyor" olarak işaretle.
            attainment_ok = False
            logging.info(f"Offering {offering_id} attainment hesaplanamadı: {e}")

        needs_action_plan = attainment_ok and not_met_count > 0
        has_a5 = False
        has_exam_plan = False
        if needs_action_plan:
            # (a) Offering-level A5
            cur.execute(
                "SELECT 1 FROM offering_reflections "
                "WHERE offering_id = %s AND COALESCE(TRIM(a5_text), '') <> '' LIMIT 1",
                (offering_id,),
            )
            has_a5 = cur.fetchone() is not None
            # (b) Bu offering'e bağlı herhangi bir sınavın exam_reflections.action_plan'ı dolu mu?
            if not has_a5:
                cur.execute(
                    "SELECT 1 FROM exam_reflections er "
                    "JOIN exams e ON er.exam_id = e.id "
                    "WHERE e.offering_id = %s "
                    "  AND COALESCE(TRIM(er.action_plan), '') <> '' LIMIT 1",
                    (offering_id,),
                )
                has_exam_plan = cur.fetchone() is not None
        plan_satisfied = has_a5 or has_exam_plan
        action_plan_ok = (not needs_action_plan) or plan_satisfied
        if not attainment_ok:
            action_plan_detail = "Hesaplama yapılamadı"
        elif not needs_action_plan:
            action_plan_detail = "Gerekmiyor (tüm DÖÇ baraj üstünde)"
        elif has_a5:
            action_plan_detail = "Tamamlandı (offering A5)"
        elif has_exam_plan:
            action_plan_detail = "Tamamlandı (sınav eylem planı)"
        else:
            action_plan_detail = f"Eksik: Eylem Planı Bekleniyor ({not_met_count} DÖÇ baraj altı)"

    steps = [
        {"key": "exams",       "label": "Sınavlar tanımlı",           "ok": exam_count > 0,     "detail": f"{exam_count} sınav"},
        {"key": "questions",   "label": "Sorular girilmiş",            "ok": question_count > 0, "detail": f"{question_count} soru"},
        {"key": "doc_weights", "label": "Soru→DÖÇ ağırlıkları atandı", "ok": mapped_q == total_q and total_q > 0, "detail": f"{mapped_q}/{total_q} soru eşlendi"},
        {"key": "doc",         "label": "DÖÇ tanımlı",                 "ok": doc_count > 0,      "detail": f"{doc_count} DÖÇ"},
        {"key": "matrix",      "label": "DÖÇ→PÇ matrisi dolu",         "ok": matrix_count > 0,   "detail": f"{matrix_count} matris girişi"},
        {"key": "responses",   "label": "Notlar yüklendi",              "ok": response_count > 0, "detail": f"{response_count} yanıt"},
        {"key": "reflection",  "label": "Dönem değerlendirmesi yazıldı","ok": has_reflection,     "detail": "Tamamlandı" if has_reflection else "Eksik"},
        {"key": "action_plan", "label": "Eylem Planı (PUKÖ A5)",        "ok": action_plan_ok,     "detail": action_plan_detail},
    ]
    completed = sum(1 for s in steps if s["ok"])
    return {
        "offering_id": offering_id,
        "completed_steps": completed,
        "total_steps": len(steps),
        "ready": completed == len(steps),
        "steps": steps,
    }


# ======================================================
# Öğrenci Bazlı DÖÇ Başarısı
# ======================================================

@app.get("/api/offerings/{offering_id}/student-attainment")
def get_student_attainment(
    offering_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Bir ders şubesindeki her öğrencinin DÖÇ bazında başarı puanını döndürür.
    Öğrenci puanı = Σ(soru_puanı × DÖÇ_ağırlığı) / Σ(max_puan × DÖÇ_ağırlığı) → 0..1 aralığı.
    """
    decode_jwt(credentials.credentials)
    with pool.connection() as conn, conn.cursor() as cur:
        # Dersin DÖÇ listesi
        cur.execute(
            """
            SELECT clo.id, clo.sequence_number, clo.description
            FROM course_learning_outcomes clo
            JOIN course_offerings co ON clo.course_id = co.course_id
            WHERE co.id = %s
            ORDER BY clo.sequence_number
            """,
            (offering_id,),
        )
        docs = cur.fetchall()
        doc_map = {r[0]: {"seq": r[1], "desc": r[2]} for r in docs}

        if not doc_map:
            return {"offering_id": offering_id, "students": [], "doc_outcomes": []}

        # Öğrenci × DÖÇ skoru — ağırlıklı
        cur.execute(
            """
            SELECT r.student_id,
                   qo.outcome_id,
                   SUM(r.score * qo.weight)     AS earned,
                   SUM(q.points * qo.weight)    AS possible
            FROM responses r
            JOIN questions q   ON q.id = r.question_id
            JOIN exams e       ON e.id = q.exam_id
            JOIN question_outcomes qo ON qo.question_id = q.id
            WHERE e.offering_id = %s
              AND qo.outcome_id = ANY(%s)
            GROUP BY r.student_id, qo.outcome_id
            """,
            (offering_id, list(doc_map.keys())),
        )
        rows = cur.fetchall()

        # Öğrenci bilgileri
        student_ids = list({r[0] for r in rows})
        if not student_ids:
            return {"offering_id": offering_id, "students": [], "doc_outcomes": list(doc_map.values())}

        cur.execute(
            "SELECT id, student_no, name FROM students WHERE id = ANY(%s) ORDER BY student_no",
            (student_ids,),
        )
        student_info = {r[0]: {"student_no": r[1], "name": r[2]} for r in cur.fetchall()}

    # Öğrenci × DÖÇ matrisini oluştur
    attainment: dict[int, dict[int, float]] = {}
    for sid, oid, earned, possible in rows:
        if possible and float(possible) > 0:
            attainment.setdefault(int(sid), {})[int(oid)] = round(float(earned) / float(possible), 4)

    students_out = []
    for sid, info in student_info.items():
        doc_scores = attainment.get(sid, {})
        students_out.append({
            "student_id":  sid,
            "student_no":  info["student_no"],
            "name":        info["name"],
            "doc_scores":  {str(oid): doc_scores.get(oid) for oid in doc_map},
        })

    return {
        "offering_id":  offering_id,
        "doc_threshold": 0.60,
        "doc_outcomes": [
            {"id": oid, "sequence_number": info["seq"], "description": info["desc"]}
            for oid, info in doc_map.items()
        ],
        "students": students_out,
    }
