"""
Tek seferlik backfill: users tablosundaki düz metin password_hash değerlerini
bcrypt ile hash'ler. $2a$/$2b$/$2y$ ile başlayan satırlar atlanır.

Kullanım:
    # docker
    docker compose exec api python /app/scripts/migrations/003_hash_legacy_passwords.py

    # yerel (PYTHONPATH api klasörünü içermeli)
    DATABASE_URL=postgresql://postgres@localhost:5432/mudek_db \
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))') \
    python3 -c "import sys; sys.path.insert(0,'api'); exec(open('scripts/migrations/003_hash_legacy_passwords.py').read())"

NOT: Backfill sonrası kullanıcılar mevcut parolalarıyla giriş yapmaya devam eder;
yalnızca DB'de düz metin saklanmaz.
"""
import os
import sys

import bcrypt
import psycopg


def _is_bcrypt(value: str | None) -> bool:
    return bool(value) and (
        value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$")
    )


def main() -> int:
    db_url = os.getenv("DATABASE_URL", "postgresql://postgres@localhost:5432/mudek_db")
    converted = 0
    skipped = 0
    skipped_empty = 0

    with psycopg.connect(db_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, username, password_hash FROM users")
        rows = cur.fetchall()

        for user_id, username, stored in rows:
            if stored is None or stored == "":
                skipped_empty += 1
                continue
            if _is_bcrypt(stored):
                skipped += 1
                continue
            new_hash = bcrypt.hashpw(stored.encode("utf-8")[:72], bcrypt.gensalt(rounds=12)).decode()
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (new_hash, user_id),
            )
            converted += 1
            print(f"  [migrate] id={user_id} username={username}")
        conn.commit()

    print(f"\nDone. converted={converted} already_bcrypt={skipped} empty={skipped_empty}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
