-- 011_password_reset_tokens.sql
-- Self-servis "Şifremi Unuttum" akışı için tek kullanımlık sıfırlama token'ları.
--
-- Token ham hâliyle saklanmaz; yalnızca sha256 özeti (token_hash) tutulur.
-- used_at NULL → henüz kullanılmamış; expires_at → kısa ömür (vars. 30 dk).
--
-- İdempotent (CREATE ... IF NOT EXISTS). Aynı şema api/security_ext.py
-- ensure_hardening_tables içinde de garanti altına alınır; migration unutulsa
-- bile özellik çalışır.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip         TEXT
);

CREATE INDEX IF NOT EXISTS prt_token_hash_idx ON password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS prt_user_idx       ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS prt_expires_idx    ON password_reset_tokens (expires_at);
