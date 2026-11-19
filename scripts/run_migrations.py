#!/usr/bin/env python3
"""DB migration'larını sıralı uygular — psql gerektirmez, psycopg yeterli.

Birincil kullanım (api container içinden; DATABASE_URL zaten ortamda):
    docker compose exec api python scripts/run_migrations.py

Host'tan kullanım (DSN'de host.docker.internal DEĞİL, localhost kullanın):
    DATABASE_URL='postgresql://user:pass@localhost:5432/mudek_db' \
        python3 scripts/run_migrations.py

.sql dosyaları psycopg ile, .py dosyaları (örn. 003_hash_legacy_passwords.py)
alt süreç olarak sıra numarasına göre çalıştırılır. Tüm migration'lar
idempotent yazıldığı için zincir tekrar tekrar çalıştırılabilir.
"""
import os
import pathlib
import subprocess
import sys

import psycopg

MIG_DIR = pathlib.Path(__file__).resolve().parent / "migrations"


def main() -> int:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("❌ DATABASE_URL set edilmemiş.", file=sys.stderr)
        return 1
    if not MIG_DIR.is_dir():
        print(f"❌ Migration klasörü bulunamadı: {MIG_DIR}", file=sys.stderr)
        return 1

    files = sorted(
        p for p in MIG_DIR.iterdir()
        if p.suffix in (".sql", ".py") and p.name[:1].isdigit()
    )
    if not files:
        print("ℹ️  Migration dosyası yok.")
        return 0

    print(f"📦 {len(files)} migration uygulanıyor: {MIG_DIR}", flush=True)
    for f in files:
        print(f"▶︎  {f.name}", flush=True)
        if f.suffix == ".sql":
            # Parametre verilmediği için psycopg çok-ifadeli (multi-statement)
            # SQL dosyalarını tek seferde çalıştırabilir.
            with psycopg.connect(dsn) as conn:
                conn.execute(f.read_text())
                conn.commit()
        else:
            subprocess.run([sys.executable, str(f)], check=True)

    print("✅ Tüm migration'lar başarıyla uygulandı.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
