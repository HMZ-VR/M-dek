-- Migration 007: course_offerings tekillik güvencesi
-- Aynı ders + dönem + şube kombinasyonu mükerrer açılamasın.
-- term/section NULL olabildiği için düz UNIQUE constraint NULL'ları ayrı sayar;
-- COALESCE'li unique index ile NULL'lar da tekilliğe dahil edilir.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM course_offerings
        GROUP BY course_id, COALESCE(term, ''), COALESCE(section, '')
        HAVING COUNT(*) > 1
    ) THEN
        RAISE WARNING 'course_offerings içinde mükerrer (course_id, term, section) kayıtları var — tekillik index''i EKLENMEDİ. Önce mükerrer kayıtları birleştirin/silin, sonra bu migration''ı tekrar çalıştırın.';
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS course_offerings_course_term_section_uniq
            ON course_offerings (course_id, COALESCE(term, ''), COALESCE(section, ''));
    END IF;
END $$;
