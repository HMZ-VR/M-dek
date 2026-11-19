-- ============================================================================
-- clear_demo_data.sql — seed_demo_data.sql ile eklenen demo/sunum verisini siler
-- ============================================================================
-- Gerçek kullanıma (production) geçmeden ÖNCE, demo verisi yüklendiyse çalıştırın.
-- Yalnızca demo olduğu kesin olan kayıtları hedefler; gerçek verilere dokunmaz.
--
-- Siler:
--   • Örnek komite raporu (başlığı sabit)
--   • 3 demo dersi (244201, 311402, 322501) → FK CASCADE ile bağlı offering,
--     sınav, soru, cevap, anket, DÖÇ, matris vb. otomatik temizlenir
--   • Demo öğrencileri (öğrenci no '2026%') ve onların kullanıcı hesapları
--
-- Kullanım (api container içinden):
--   docker compose exec -T api python -c "
--   import os, psycopg
--   with psycopg.connect(os.environ['DATABASE_URL']) as c:
--       c.execute(open('scripts/clear_demo_data.sql').read()); c.commit()
--   "
-- ============================================================================

BEGIN;

-- 1) Örnek komite raporu (komitenin kendisine dokunmaz)
DELETE FROM committee_reports
WHERE title = 'MÜDEK Komisyonu 2025-2026 Güz Dönemi Değerlendirme Raporu';

-- 2) Demo dersleri — offering/exam/question/response/survey/DÖÇ CASCADE ile gider
DELETE FROM courses
WHERE code IN ('244201', '311402', '322501');

-- 3) Demo öğrencilerinin kullanıcı hesapları (user_roles CASCADE ile gider).
--    students.user_id ON DELETE SET NULL olduğundan önce kullanıcıyı sileriz.
DELETE FROM users
WHERE id IN (
    SELECT user_id FROM students
    WHERE student_no LIKE '2026%' AND user_id IS NOT NULL
);

-- 4) Demo öğrenci kayıtları — enrollment/response/survey_response CASCADE ile gider
DELETE FROM students
WHERE student_no LIKE '2026%';

COMMIT;
