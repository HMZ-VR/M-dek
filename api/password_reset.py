"""
Self-servis şifre sıfırlama (Şifremi Unuttum).

Akış:
  1) POST /api/forgot-password {identifier}  — kullanıcı adı veya e-posta.
     Hesap varsa tek kullanımlık token üretir, sha256'sını DB'ye yazar ve
     kullanıcının okul e-postasına sıfırlama bağlantısı gönderir.
     Hesap enumeration'ı önlemek için her durumda aynı genel yanıt döner.
  2) POST /api/reset-password {token, new_password} — token doğrulanır,
     parola güncellenir, must_change_password temizlenir, password_changed_at
     güncellenir (bu, kullanıcının tüm eski JWT'lerini geçersiz kılar).

Kod main.py yerine burada; main.py `router`'ı include_router ile bağlar ve
`init_password_reset(pool)` ile DB pool'unu verir.

E-posta gönderimi stdlib smtplib ile yapılır (ek bağımlılık yok). SMTP_HOST
tanımlı değilse gönderim atlanır ama yanıt yine de geneldir — sayfa "kırık"
görünmez; o aşamada admin panelinden sıfırlama yedek yoldur.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from auth_utils import _hash_password, _validate_password_policy
from security_ext import audit_log, client_ip, LoginLimiter

log = logging.getLogger("mudek")
router = APIRouter()

# Token geçerlilik süresi (dakika)
RESET_TTL_MINUTES = 30

# DB pool — init_password_reset ile main.py'dan verilir
_pool = None

# IP başına dakikada en fazla 5 sıfırlama talebi (nginx'e ek savunma katmanı;
# API doğrudan 8000'den erişilse bile koruma sağlar).
_limiter = LoginLimiter(max_per_minute=5)

# Hesap olsun olmasın hep aynı yanıt — enumeration koruması.
_GENERIC_MESSAGE = (
    "Hesabınız varsa, şifre sıfırlama bağlantısı e-posta adresinize gönderildi. "
    "Lütfen gelen kutunuzu (ve spam klasörünü) kontrol edin."
)


def init_password_reset(pool) -> None:
    """main.py tarafından bir kez çağrılır; modüle DB pool'unu tanıtır."""
    global _pool
    _pool = pool


# ---------------------------------------------------------------------------
# E-posta gönderimi
# ---------------------------------------------------------------------------

def _public_base_url(request: Request) -> str:
    """Sıfırlama bağlantısındaki kök URL. Öncelik: PUBLIC_BASE_URL → ilk
    CORS origin → isteğin kendi base_url'i."""
    base = os.getenv("PUBLIC_BASE_URL", "").strip()
    if not base:
        origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
        if origins and origins[0] != "*":
            base = origins[0]
    if not base:
        base = str(request.base_url)
    return base.rstrip("/")


def _send_reset_email(to_email: str, reset_link: str) -> bool:
    """Sıfırlama e-postasını gönderir. SMTP yapılandırılmamışsa False döner
    (hata fırlatmaz). Gönderim başarılıysa True."""
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        log.warning("SMTP_HOST tanımlı değil — şifre sıfırlama e-postası gönderilemedi "
                    "(admin paneli yedek yol olarak kullanılabilir).")
        return False

    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", "").strip() or "mudek@ktun.edu.tr"
    use_ssl = os.getenv("SMTP_SSL", "").strip().lower() in ("1", "true", "yes")
    use_starttls = os.getenv("SMTP_STARTTLS", "true").strip().lower() in ("1", "true", "yes")

    msg = EmailMessage()
    msg["Subject"] = "MÜDEK – Şifre Sıfırlama"
    msg["From"] = sender
    msg["To"] = to_email
    plain = (
        "Merhaba,\n\n"
        "MÜDEK Akreditasyon sistemi için bir şifre sıfırlama talebi aldık. "
        "Yeni şifrenizi belirlemek için aşağıdaki bağlantıya tıklayın:\n\n"
        f"{reset_link}\n\n"
        f"Bu bağlantı {RESET_TTL_MINUTES} dakika boyunca geçerlidir ve yalnızca bir kez kullanılabilir.\n\n"
        "Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz; şifreniz değişmez.\n\n"
        "Konya Teknik Üniversitesi – MÜDEK Akreditasyon"
    )
    html = (
        '<div style="font-family:Arial,sans-serif;font-size:14px;color:#1a1a1a;line-height:1.6">'
        "<p>Merhaba,</p>"
        "<p>MÜDEK Akreditasyon sistemi için bir <strong>şifre sıfırlama</strong> talebi aldık. "
        "Yeni şifrenizi belirlemek için aşağıdaki butona tıklayın:</p>"
        f'<p style="margin:24px 0"><a href="{reset_link}" '
        'style="background:#0b1f45;color:#fff;padding:12px 22px;border-radius:6px;'
        'text-decoration:none;font-weight:600">Şifremi Sıfırla</a></p>'
        f'<p style="font-size:12px;color:#666">Buton çalışmazsa bu bağlantıyı tarayıcınıza '
        f'yapıştırın:<br><a href="{reset_link}">{reset_link}</a></p>'
        f"<p>Bu bağlantı <strong>{RESET_TTL_MINUTES} dakika</strong> geçerlidir ve yalnızca bir kez kullanılabilir.</p>"
        "<p style=\"font-size:12px;color:#666\">Bu talebi siz yapmadıysanız bu e-postayı yok sayabilirsiniz; "
        "şifreniz değişmez.</p>"
        '<hr style="border:none;border-top:1px solid #e5e5e5;margin:20px 0">'
        '<p style="font-size:12px;color:#888">Konya Teknik Üniversitesi – MÜDEK Akreditasyon</p>'
        "</div>"
    )
    msg.set_content(plain)
    msg.add_alternative(html, subtype="html")

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                if use_starttls:
                    smtp.starttls()
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        return True
    except Exception:
        log.exception("Şifre sıfırlama e-postası gönderilemedi (to=%s)", to_email)
        return False


# ---------------------------------------------------------------------------
# Endpoint'ler
# ---------------------------------------------------------------------------

class ForgotRequest(BaseModel):
    identifier: str


class ResetRequest(BaseModel):
    token: str
    new_password: str


@router.post("/api/forgot-password")
def forgot_password(req: ForgotRequest, request: Request):
    ident = (req.identifier or "").strip()
    generic = {"success": True, "message": _GENERIC_MESSAGE}
    ip = client_ip(request)

    # Rate limit — başarısız olsa da genel yanıt davranışını bozmamak için
    # 429 yerine sessizce genel yanıt döneriz (enumeration/oracle önleme).
    if not _limiter.check(ip):
        audit_log(_pool, user_id=None, username=ident, ip=ip,
                  action="password.reset_rate_limited", target=None, status_code=429)
        return generic
    if not ident:
        return generic

    try:
        with _pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, email, is_active FROM users "
                "WHERE username = %s OR lower(email) = lower(%s) LIMIT 1",
                (ident, ident),
            )
            row = cur.fetchone()
            if not row:
                audit_log(_pool, user_id=None, username=ident, ip=ip,
                          action="password.reset_requested", target="unknown_user", status_code=200)
                return generic
            user_id, username, email, is_active = row
            if not is_active or not email:
                audit_log(_pool, user_id=user_id, username=username, ip=ip,
                          action="password.reset_requested", target="no_email_or_inactive", status_code=200)
                return generic

            # Aynı kullanıcının önceki kullanılmamış token'larını geçersiz kıl.
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = NOW() "
                "WHERE user_id = %s AND used_at IS NULL",
                (user_id,),
            )
            raw = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TTL_MINUTES)
            cur.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip) "
                "VALUES (%s, %s, %s, %s)",
                (user_id, token_hash, expires_at, ip),
            )
            conn.commit()

        reset_link = f"{_public_base_url(request)}/reset-password.html?token={raw}"
        sent = _send_reset_email(email, reset_link)
        audit_log(_pool, user_id=user_id, username=username, ip=ip,
                  action="password.reset_requested",
                  target="email_sent" if sent else "email_unconfigured",
                  status_code=200)
    except Exception:
        # Beklenmedik hata kullanıcıya yansımasın; genel yanıt korunur.
        log.exception("forgot-password işlenemedi")
    return generic


@router.post("/api/reset-password")
def reset_password(req: ResetRequest, request: Request):
    raw = (req.token or "").strip()
    if not raw:
        raise HTTPException(400, "Bağlantı geçersiz veya süresi dolmuş. Lütfen yeniden talep edin.")
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    ip = client_ip(request)

    with _pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT prt.id, prt.user_id, u.username "
            "FROM password_reset_tokens prt JOIN users u ON u.id = prt.user_id "
            "WHERE prt.token_hash = %s AND prt.used_at IS NULL AND prt.expires_at > NOW() "
            "LIMIT 1",
            (token_hash,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(400, "Bağlantı geçersiz veya süresi dolmuş. Lütfen yeniden talep edin.")
        token_id, user_id, username = row

        # Parola politikası (min 8, en az 1 harf + 1 rakam — change-password ile aynı kural)
        _validate_password_policy(req.new_password)

        new_hash = _hash_password(req.new_password)
        cur.execute(
            "UPDATE users SET password_hash = %s, must_change_password = FALSE, "
            "password_changed_at = NOW() WHERE id = %s",
            (new_hash, user_id),
        )
        # Token'ı tek kullanımlık yap.
        cur.execute(
            "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = %s",
            (token_id,),
        )
        # password_changed_at = NOW() → decode_jwt bu kullanıcının eski tüm
        # JWT'lerini (iat < password_changed_at) reddeder. Ayrıca süresi geçmiş
        # token kayıtlarını fırsat buldukça temizle.
        cur.execute("DELETE FROM password_reset_tokens WHERE expires_at < NOW() AND used_at IS NULL")
        conn.commit()

    audit_log(_pool, user_id=user_id, username=username, ip=ip,
              action="password.reset_completed", target=None, status_code=200)
    return {
        "success": True,
        "message": "✅ Şifreniz güncellendi. Yeni şifrenizle giriş yapabilirsiniz.",
    }
