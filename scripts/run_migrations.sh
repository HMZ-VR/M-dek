#!/usr/bin/env bash
# DB migration'larını sıralı çalıştırır.
# Kullanım: DATABASE_URL='postgresql://...' bash scripts/run_migrations.sh
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
    echo "❌ DATABASE_URL set edilmemiş." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIG_DIR="$SCRIPT_DIR/migrations"

if [[ ! -d "$MIG_DIR" ]]; then
    echo "❌ Migration klasörü bulunamadı: $MIG_DIR" >&2
    exit 1
fi

echo "📦 Migration'lar çalıştırılıyor: $MIG_DIR"

shopt -s nullglob
files=("$MIG_DIR"/[0-9]*.sql "$MIG_DIR"/[0-9]*.py)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "ℹ️  Migration dosyası yok"
    exit 0
fi

# Sıra numarasına göre tek listede sırala (.sql ve .py karışık)
while IFS= read -r f; do
    echo "▶︎  $(basename "$f")"
    case "$f" in
        *.sql) psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f" ;;
        *.py)  python3 "$f" ;;
    esac
done < <(printf '%s\n' "${files[@]}" | sort)

echo "✅ Tüm migration'lar başarıyla uygulandı."
