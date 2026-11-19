-- 005_exam_artifacts.sql
-- MÜDEK denetçileri için sınav/proje kanıt kağıtları (en iyi / orta / en kötü)
-- yüklemek üzere exam_artifacts tablosunu oluşturur.
--
-- Pattern: committee_report_attachments (002_committee_reports_v2.sql) aynalanır.

DO $$ BEGIN
    CREATE TYPE exam_artifact_type AS ENUM ('best','average','worst');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS exam_artifacts (
    id             SERIAL PRIMARY KEY,
    exam_id        INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    artifact_type  exam_artifact_type NOT NULL,
    file_path      VARCHAR NOT NULL,
    original_name  VARCHAR NOT NULL,
    file_size      BIGINT,
    content_type   VARCHAR(120),
    description    TEXT,
    uploaded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS exam_artifacts_exam_idx
    ON exam_artifacts (exam_id);

CREATE INDEX IF NOT EXISTS exam_artifacts_exam_type_idx
    ON exam_artifacts (exam_id, artifact_type);
