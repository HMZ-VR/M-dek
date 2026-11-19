-- 001_add_exam_project_weight.sql
-- Excel şablonundaki "soru ağırlığı + proje/ödev ağırlığı" mantığını destekler.
-- exam_total = SUM(soru_puan) × (1 - project_weight) + project_score × project_weight
--
-- Geri uyumluluk: project_weight = 0 (default) → eski davranış aynen korunur.

ALTER TABLE exams
    ADD COLUMN IF NOT EXISTS project_weight     NUMERIC(4,3) NOT NULL DEFAULT 0
        CHECK (project_weight >= 0 AND project_weight <= 1);

ALTER TABLE exams
    ADD COLUMN IF NOT EXISTS project_max_points NUMERIC(6,2) NOT NULL DEFAULT 0
        CHECK (project_max_points >= 0);

-- Öğrenci başına proje/ödev puanı
CREATE TABLE IF NOT EXISTS exam_project_scores (
    exam_id    INTEGER NOT NULL REFERENCES exams(id)    ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    score      NUMERIC(6,2) NOT NULL DEFAULT 0,
    PRIMARY KEY (exam_id, student_id)
);

CREATE INDEX IF NOT EXISTS exam_project_scores_exam_idx
    ON exam_project_scores (exam_id);
