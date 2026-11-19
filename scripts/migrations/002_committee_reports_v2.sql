-- 002_committee_reports_v2.sql
-- Komite raporlarını "tek dosya" modelinden "metin + N ek + onay akışı" modeline genişletir.
--
-- Geriye dönük uyumluluk:
--   * Mevcut committee_reports satırlarındaki file_path kaybolmadan
--     committee_report_attachments tablosuna kopyalanır.
--   * Eski POST /committees/{id}/upload endpoint'i çalışmaya devam eder
--     (otomatik draft rapor + tek ek olarak kaydeder).

-- ── Rapor metni & onay akışı kolonları ────────────────────────────────
ALTER TABLE committee_reports
    ADD COLUMN IF NOT EXISTS content       TEXT,
    ADD COLUMN IF NOT EXISTS report_type   VARCHAR(50),
    ADD COLUMN IF NOT EXISTS period        VARCHAR(20),
    ADD COLUMN IF NOT EXISTS status        VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','submitted','approved','rejected')),
    ADD COLUMN IF NOT EXISTS submitted_at  TIMESTAMP,
    ADD COLUMN IF NOT EXISTS reviewed_at   TIMESTAMP,
    ADD COLUMN IF NOT EXISTS reviewer_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS review_note   TEXT,
    ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMP NOT NULL DEFAULT NOW();

-- file_path artık nullable (rapor sadece metinden ibaret olabilir)
ALTER TABLE committee_reports
    ALTER COLUMN file_path DROP NOT NULL;

CREATE INDEX IF NOT EXISTS committee_reports_committee_status_idx
    ON committee_reports (committee_id, status);

CREATE INDEX IF NOT EXISTS committee_reports_uploader_idx
    ON committee_reports (uploader_id);

-- ── Ekler tablosu ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS committee_report_attachments (
    id             SERIAL PRIMARY KEY,
    report_id      INTEGER NOT NULL REFERENCES committee_reports(id) ON DELETE CASCADE,
    file_path      VARCHAR NOT NULL,
    original_name  VARCHAR NOT NULL,
    file_size      BIGINT,
    content_type   VARCHAR(120),
    uploaded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS committee_report_attachments_report_idx
    ON committee_report_attachments (report_id);

-- ── Mevcut tek-dosyalı raporları attachments'a taşı ───────────────────
-- Bir defaya mahsus, idempotent: aynı (report_id, file_path) tekrar eklenmez.
INSERT INTO committee_report_attachments
    (report_id, file_path, original_name, uploaded_by, uploaded_at)
SELECT r.id,
       r.file_path,
       COALESCE(NULLIF(SPLIT_PART(r.file_path, '/', -1), ''), 'attachment'),
       r.uploader_id,
       r.created_at
FROM committee_reports r
WHERE r.file_path IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM committee_report_attachments a
      WHERE a.report_id = r.id AND a.file_path = r.file_path
  );
