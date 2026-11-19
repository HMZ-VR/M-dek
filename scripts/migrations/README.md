# DB Migrations

Bu klasördeki SQL dosyaları sıralı (`001_`, `002_`, ...) olarak çalıştırılmalıdır.
Her migration **idempotent** (yeniden çalıştırılınca hata vermez) yazılmıştır:
`ADD COLUMN IF NOT EXISTS`, `CREATE TABLE IF NOT EXISTS` vb. kullanır.

## Çalıştırma

Production veya test DB'sinde:

```bash
DATABASE_URL='postgresql://user@host:5432/mudek_db' \
    bash scripts/run_migrations.sh
```

Tek dosya çalıştırma:

```bash
psql "$DATABASE_URL" -f scripts/migrations/001_add_exam_project_weight.sql
```

## Migration Listesi

| # | Dosya | Açıklama |
|---|-------|----------|
| 001 | `001_add_exam_project_weight.sql` | exams.project_weight + exam_project_scores tablosu (Excel uyumu) |

`revoked_tokens` ve `audit_log` tabloları `api/security_ext.py:ensure_hardening_tables`
tarafından startup'ta otomatik oluşturulur — ayrı migration gerektirmez.
