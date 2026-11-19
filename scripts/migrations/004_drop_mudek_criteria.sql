-- 004_drop_mudek_criteria.sql
-- mudek_criteria tablosunu kaldırır; survey_questions.criterion_code yerine
-- doğrudan program_outcomes (PÇ) referansı kullanılır.
--
-- Karar: Eski criterion_code (Ö1..Ö11) değerleri global MÜDEK kriterleridir ve
-- bölüm-bazlı PÇ'lere birebir eşlenemez. Kolon silinir; hocalar custom soruları
-- survey-management UI'dan manuel olarak PÇ'ye yeniden bağlar.

ALTER TABLE survey_questions
    ADD COLUMN IF NOT EXISTS program_outcome_id INTEGER
        REFERENCES program_outcomes(id) ON DELETE SET NULL;

ALTER TABLE survey_questions
    DROP COLUMN IF EXISTS criterion_code;

DROP TABLE IF EXISTS mudek_criteria;

CREATE INDEX IF NOT EXISTS survey_questions_po_idx
    ON survey_questions (program_outcome_id);
