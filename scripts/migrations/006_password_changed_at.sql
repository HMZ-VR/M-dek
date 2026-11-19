-- Migration 006: password_changed_at kolonu
-- Şifre değiştirildiğinde mevcut tüm JWT'lerin geçersiz kılınması için
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
UPDATE users SET password_changed_at = NOW() WHERE password_changed_at IS NULL;
