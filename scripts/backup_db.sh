#!/usr/bin/env bash
# Daily PostgreSQL backup for Mudek.
#
# Usage:
#   ./scripts/backup_db.sh                     # writes to ./backups/
#   BACKUP_DIR=/var/backups/mudek ./scripts/backup_db.sh
#
# Cron example (keep 14 days of backups, run daily at 03:00):
#   0 3 * * * /opt/mudek/scripts/backup_db.sh >> /var/log/mudek-backup.log 2>&1
#
# Restore with:
#   gunzip < mudek-YYYY-MM-DD.sql.gz | psql "$DATABASE_URL"

set -euo pipefail

# Load .env so DATABASE_URL is available
if [ -f "$(dirname "$0")/../.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$(dirname "$0")/../.env"; set +a
fi

: "${DATABASE_URL:?DATABASE_URL must be set (in .env or environment)}"

BACKUP_DIR="${BACKUP_DIR:-$(dirname "$0")/../backups}"
RETAIN_DAYS="${BACKUP_RETAIN_DAYS:-14}"

mkdir -p "$BACKUP_DIR"

STAMP=$(date +%Y-%m-%d_%H%M)
OUT="$BACKUP_DIR/mudek-$STAMP.sql.gz"

echo "[$(date -Iseconds)] backing up -> $OUT"
pg_dump --no-owner --no-privileges "$DATABASE_URL" | gzip -9 > "$OUT"

# verify the dump is non-empty and gzip-valid
if [ ! -s "$OUT" ] || ! gzip -t "$OUT" 2>/dev/null; then
  echo "[$(date -Iseconds)] backup verification FAILED for $OUT" >&2
  rm -f "$OUT"
  exit 1
fi

# prune old backups
find "$BACKUP_DIR" -name 'mudek-*.sql.gz' -type f -mtime +"$RETAIN_DAYS" -delete

echo "[$(date -Iseconds)] backup ok ($(du -h "$OUT" | cut -f1))"
