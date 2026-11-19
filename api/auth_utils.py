"""
Paylaşılan parola yardımcıları (hashing, doğrulama, politika, rastgele üretim).

main.py çok büyüdüğü için bu güvenlik-kritik yardımcılar buraya çıkarıldı;
hem main.py hem password_reset.py buradan import eder. Davranış main.py'daki
önceki implementasyonla bire bir aynıdır (saf taşıma).
"""
from __future__ import annotations

import secrets
import string

import bcrypt as _bcrypt
from fastapi import HTTPException

__all__ = [
    "_hash_password",
    "_is_bcrypt_hash",
    "_verify_password",
    "generate_random_password",
    "_validate_password_policy",
]


def _hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode("utf-8")[:72], _bcrypt.gensalt(rounds=12)).decode()


def _is_bcrypt_hash(value: str | None) -> bool:
    return bool(value) and (
        value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$")
    )


def _verify_password(plain: str, hashed: str) -> bool:
    if not plain or not _is_bcrypt_hash(hashed):
        return False
    try:
        return _bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except ValueError:
        return False


def generate_random_password(length: int = 12) -> str:
    if length < 8:
        length = 8
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*-_=+?"
    alphabet = lowers + uppers + digits + symbols
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c in lowers for c in pw) and any(c in uppers for c in pw)
                and any(c in digits for c in pw) and any(c in symbols for c in pw)):
            return pw


def _validate_password_policy(pw: str) -> None:
    if len(pw) < 8:
        raise HTTPException(400, "Yeni şifre en az 8 karakter olmalıdır")
    if len(pw) > 128:
        raise HTTPException(400, "Yeni şifre en fazla 128 karakter olabilir")
    if pw.strip() != pw:
        raise HTTPException(400, "Şifrenin başında veya sonunda boşluk olamaz")
    has_letter = any(c.isalpha() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    if not (has_letter and has_digit):
        raise HTTPException(400, "Yeni şifre en az bir harf ve bir rakam içermelidir")
