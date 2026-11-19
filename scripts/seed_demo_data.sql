-- ============================================================================
-- seed_demo_data.sql — Sunum/demo verisi
-- ============================================================================
-- 3 yeni ders (DÖÇ'leri, DÖÇ-PÇ matrisi, 2 dönemlik offering'ler, vize+final,
-- sorular, soru-DÖÇ ağırlıkları, kayıtlar, gerçekçi dağılımlı cevaplar,
-- proje bileşenli bir final, kapatılmış bir anket ve bir komite raporu) ekler.
--
-- GÜVENLİ: Mevcut verilere dokunmaz; tüm INSERT'ler idempotent
-- (ON CONFLICT DO NOTHING veya WHERE NOT EXISTS). Tekrar çalıştırılabilir.
--
-- Kullanım (api container içinden):
--   docker compose exec -T api python -c "
--   import os, psycopg, sys
--   with psycopg.connect(os.environ['DATABASE_URL']) as c:
--       c.execute(open('scripts/seed_demo_data.sql').read()); c.commit()
--   "
-- ============================================================================

BEGIN;

-- ── 1. Dersler ──────────────────────────────────────────────────────────────
INSERT INTO courses (code, name)
SELECT v.code, v.name
FROM (VALUES
    ('244201', 'Veri Yapıları ve Algoritmalar'),
    ('311402', 'Veritabanı Yönetim Sistemleri'),
    ('322501', 'Yazılım Mühendisliği')
) AS v(code, name)
ON CONFLICT (code) DO NOTHING;

-- ── 2. DÖÇ'ler (ders öğrenme çıktıları) ────────────────────────────────────
INSERT INTO course_learning_outcomes (course_id, sequence_number, description)
SELECT c.id, v.seq, v.descr
FROM (VALUES
    ('244201', 1, 'Temel veri yapılarını (dizi, bağlı liste, yığın, kuyruk) tanımlar ve uygular.'),
    ('244201', 2, 'Ağaç ve graf yapılarını problem çözümünde kullanır.'),
    ('244201', 3, 'Algoritmaların zaman ve bellek karmaşıklığını analiz eder.'),
    ('244201', 4, 'Sıralama ve arama algoritmalarını karşılaştırır ve probleme uygun olanı seçer.'),
    ('244201', 5, 'Verilen bir probleme uygun veri yapısını seçerek özgün çözüm tasarlar.'),
    ('311402', 1, 'İlişkisel veri modelini ve normalizasyon ilkelerini açıklar.'),
    ('311402', 2, 'SQL ile karmaşık sorgular yazar ve sorgu performansını değerlendirir.'),
    ('311402', 3, 'Kurumsal bir senaryo için kavramsal ve mantıksal veri modeli tasarlar.'),
    ('311402', 4, 'Hareket (transaction) yönetimi ve eşzamanlılık denetimini uygular.'),
    ('311402', 5, 'Veritabanı güvenliği ve yedekleme stratejilerini değerlendirir.'),
    ('322501', 1, 'Yazılım geliştirme yaşam döngüsü modellerini karşılaştırır.'),
    ('322501', 2, 'Gereksinim analizi yapar ve standartlara uygun belgeler.'),
    ('322501', 3, 'UML diyagramlarıyla yazılım mimarisini modeller.'),
    ('322501', 4, 'Birim ve entegrasyon testi tekniklerini uygular.'),
    ('322501', 5, 'Takım içinde sürüm kontrolü ve proje yönetim araçlarını etkin kullanır.')
) AS v(code, seq, descr)
JOIN courses c ON c.code = v.code
ON CONFLICT (course_id, sequence_number) DO NOTHING;

-- ── 3. DÖÇ-PÇ matrisi (katkı: 10 = yüksek, 5 = orta — mevcut ölçekle uyumlu) ─
INSERT INTO outcome_matrix (outcome_id, program_outcome_id, value)
SELECT lo.id, po.id, v.val
FROM (VALUES
    -- Veri Yapıları ve Algoritmalar
    ('244201', 1, 'PÇ-1', 10), ('244201', 1, 'PÇ-2', 5),
    ('244201', 2, 'PÇ-2', 10), ('244201', 2, 'PÇ-5', 5),
    ('244201', 3, 'PÇ-1', 10), ('244201', 3, 'PÇ-5', 10),
    ('244201', 4, 'PÇ-2', 10), ('244201', 4, 'PÇ-4', 5),
    ('244201', 5, 'PÇ-3', 10), ('244201', 5, 'PÇ-4', 10),
    -- Veritabanı Yönetim Sistemleri
    ('311402', 1, 'PÇ-1', 10), ('311402', 1, 'PÇ-2', 5),
    ('311402', 2, 'PÇ-4', 10), ('311402', 2, 'PÇ-2', 5),
    ('311402', 3, 'PÇ-3', 10), ('311402', 3, 'PÇ-2', 10),
    ('311402', 4, 'PÇ-4', 10), ('311402', 4, 'PÇ-5', 5),
    ('311402', 5, 'PÇ-9', 10), ('311402', 5, 'PÇ-11', 5),
    -- Yazılım Mühendisliği
    ('322501', 1, 'PÇ-10', 10), ('322501', 1, 'PÇ-8', 5),
    ('322501', 2, 'PÇ-7', 10),  ('322501', 2, 'PÇ-2', 5),
    ('322501', 3, 'PÇ-3', 10),  ('322501', 3, 'PÇ-4', 5),
    ('322501', 4, 'PÇ-5', 10),  ('322501', 4, 'PÇ-4', 5),
    ('322501', 5, 'PÇ-6', 10),  ('322501', 5, 'PÇ-10', 5)
) AS v(code, seq, pc, val)
JOIN courses c  ON c.code = v.code
JOIN course_learning_outcomes lo ON lo.course_id = c.id AND lo.sequence_number = v.seq
JOIN program_outcomes po ON po.code = v.pc
WHERE NOT EXISTS (
    SELECT 1 FROM outcome_matrix om
    WHERE om.outcome_id = lo.id AND om.program_outcome_id = po.id
);

-- ── 4. Offering'ler: her ders 2 dönem (trend raporları için) ────────────────
-- Öğretim üyesi ID’leri (26, 29, 40) mevcut instructors tablosundan gelir
INSERT INTO course_offerings (course_id, term, section, instructor_id)
SELECT c.id, v.term, 'A', v.instr
FROM (VALUES
    ('244201', '2024-Güz', 26), ('244201', '2025-Güz', 26),
    ('311402', '2024-Güz', 29), ('311402', '2025-Güz', 29),
    ('322501', '2024-Güz', 40), ('322501', '2025-Güz', 40)
) AS v(code, term, instr)
JOIN courses c ON c.code = v.code
WHERE NOT EXISTS (
    SELECT 1 FROM course_offerings co
    WHERE co.course_id = c.id AND co.term = v.term AND co.section = 'A'
);

-- ── 5. Kayıtlar: mevcut 20 demo öğrencisi tüm yeni offering'lere ────────────
INSERT INTO enrollments (student_id, offering_id)
SELECT s.id, co.id
FROM students s
CROSS JOIN course_offerings co
JOIN courses c ON c.id = co.course_id
WHERE s.student_no LIKE '2026%'
  AND c.code IN ('244201', '311402', '322501')
ON CONFLICT DO NOTHING;

-- ── 6. Sınavlar: her offering'e vize + final ────────────────────────────────
-- Yazılım Mühendisliği finallerinde proje bileşeni (%40, 100 üzerinden)
INSERT INTO exams (offering_id, title, exam_type, date, project_weight, project_max_points)
SELECT co.id, v.title, v.etype,
       CASE WHEN co.term = '2024-Güz' THEN v.d2024 ELSE v.d2025 END,
       CASE WHEN v.etype = 'final' AND c.code = '322501' THEN 0.400 ELSE 0 END,
       CASE WHEN v.etype = 'final' AND c.code = '322501' THEN 100 ELSE 0 END
FROM (VALUES
    ('Vize',  'midterm', DATE '2024-11-13', DATE '2025-11-12'),
    ('Final', 'final',   DATE '2025-01-08', DATE '2026-01-07')
) AS v(title, etype, d2024, d2025)
CROSS JOIN course_offerings co
JOIN courses c ON c.id = co.course_id
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz')
  AND NOT EXISTS (
      SELECT 1 FROM exams e
      WHERE e.offering_id = co.id AND e.exam_type = v.etype
  );

-- ── 7. Sorular: her sınava 5 soru × 20 puan (mevcut düzenle uyumlu) ─────────
INSERT INTO questions (exam_id, q_no, text, points)
SELECT e.id, n, 'Soru ' || n, 20
FROM exams e
JOIN course_offerings co ON co.id = e.offering_id
JOIN courses c ON c.id = co.course_id
CROSS JOIN generate_series(1, 5) AS n
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz')
ON CONFLICT (exam_id, q_no) DO NOTHING;

-- ── 8. Soru-DÖÇ ağırlıkları: soru n → DÖÇ n (0.6667) + DÖÇ (n mod 5)+1 (0.3333)
INSERT INTO question_outcomes (question_id, outcome_id, weight)
SELECT q.id, lo.id, w.weight
FROM questions q
JOIN exams e             ON e.id = q.exam_id
JOIN course_offerings co ON co.id = e.offering_id
JOIN courses c           ON c.id = co.course_id
JOIN LATERAL (VALUES
    (q.q_no,             0.6667),
    ((q.q_no % 5) + 1,   0.3333)
) AS w(seq, weight) ON TRUE
JOIN course_learning_outcomes lo
     ON lo.course_id = c.id AND lo.sequence_number = w.seq
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz')
ON CONFLICT DO NOTHING;

-- ── 9. Cevaplar: deterministik, gerçekçi dağılım ────────────────────────────
-- Öğrenci bazlı taban (8-18) + soru bazlı sapma (-3..+3); finalde +1;
-- 2025 döneminde +1 / 2024'te -1 (PUKÖ "sürekli iyileştirme" trendi görünsün);
-- ~%8 sıfır (boş bırakılan soru). Ortalama ≈ 13/20 (mevcut veriyle uyumlu).
INSERT INTO responses (question_id, student_id, score, is_correct)
SELECT q.id, s.id, sc.score, sc.score > 0
FROM questions q
JOIN exams e             ON e.id = q.exam_id
JOIN course_offerings co ON co.id = e.offering_id
JOIN courses c           ON c.id = co.course_id
JOIN students s          ON s.student_no LIKE '2026%'
CROSS JOIN LATERAL (
    SELECT CASE
        WHEN (s.id * 5 + q.q_no * 11) % 12 = 0 THEN 0
        ELSE GREATEST(0, LEAST(20,
             8 + (s.id % 11)
               + ((s.id * 7 + q.q_no * 13) % 7) - 3
               + CASE WHEN e.exam_type = 'final' THEN 1 ELSE 0 END
               + CASE WHEN co.term = '2025-Güz' THEN 1 ELSE -1 END))
    END AS score
) sc
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz')
ON CONFLICT (question_id, student_id) DO NOTHING;

-- ── 10. Proje puanları (Yazılım Müh. finalleri) ─────────────────────────────
INSERT INTO exam_project_scores (exam_id, student_id, score)
SELECT e.id, s.id, 50 + (s.id * 13 % 46)
FROM exams e
JOIN course_offerings co ON co.id = e.offering_id
JOIN courses c           ON c.id = co.course_id
JOIN students s          ON s.student_no LIKE '2026%'
WHERE c.code = '322501' AND e.exam_type = 'final'
  AND co.term IN ('2024-Güz', '2025-Güz')
ON CONFLICT (exam_id, student_id) DO NOTHING;

-- ── 11. Kapatılmış anketler: tüm yeni offering'lere ─────────────────────────
INSERT INTO surveys (offering_id, is_active)
SELECT co.id, FALSE
FROM course_offerings co
JOIN courses c ON c.id = co.course_id
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz') AND co.section = 'A'
  AND NOT EXISTS (SELECT 1 FROM surveys sv WHERE sv.offering_id = co.id);

-- DÖÇ bazlı Likert cevapları (3-5 arası)
INSERT INTO survey_responses (survey_id, student_id, outcome_id, score)
SELECT sv.id, s.id, lo.id, 3 + ((s.id + lo.sequence_number) % 3)
FROM surveys sv
JOIN course_offerings co ON co.id = sv.offering_id
JOIN courses c           ON c.id = co.course_id
JOIN course_learning_outcomes lo ON lo.course_id = c.id
JOIN students s          ON s.student_no LIKE '2026%'
WHERE c.code IN ('244201', '311402', '322501')
  AND co.term IN ('2024-Güz', '2025-Güz')
  AND NOT EXISTS (
      SELECT 1 FROM survey_responses sr
      WHERE sr.survey_id = sv.id AND sr.student_id = s.id AND sr.outcome_id = lo.id
  );

-- PÇ'ye bağlı 2 özel Likert sorusu + cevapları
INSERT INTO survey_questions (survey_id, q_type, q_text, q_order, program_outcome_id)
SELECT sv.id, 'likert', v.q_text, v.q_order, po.id
FROM surveys sv
JOIN course_offerings co ON co.id = sv.offering_id
JOIN courses c           ON c.id = co.course_id AND c.code = '244201'
JOIN (VALUES
    ('Bu ders, yazılı ve sözlü iletişim becerime katkı sağladı.', 1, 'PÇ-7'),
    ('Bu ders, yeni teknolojileri kendi başıma öğrenme becerimi geliştirdi.', 2, 'PÇ-8')
) AS v(q_text, q_order, pc) ON TRUE
JOIN program_outcomes po ON po.code = v.pc
WHERE co.term = '2025-Güz'
  AND NOT EXISTS (
      SELECT 1 FROM survey_questions sq
      WHERE sq.survey_id = sv.id AND sq.q_text = v.q_text
  );

INSERT INTO survey_question_responses (question_id, student_id, score)
SELECT sq.id, s.id, 3 + ((s.id + sq.q_order) % 3)
FROM survey_questions sq
JOIN surveys sv          ON sv.id = sq.survey_id
JOIN course_offerings co ON co.id = sv.offering_id
JOIN courses c           ON c.id = co.course_id AND c.code = '244201'
JOIN students s          ON s.student_no LIKE '2026%'
WHERE co.term = '2025-Güz' AND sq.q_type = 'likert'
ON CONFLICT (question_id, student_id) DO NOTHING;

-- ── 12. Komite raporu örneği (MÜDEK KOMİSYON, onaylanmış) ───────────────────
INSERT INTO committee_reports
    (committee_id, uploader_id, reviewer_id, title, content, report_type,
     period, status, submitted_at, reviewed_at, review_note)
SELECT cm.committee_id, cm.user_id, adm.id,
       'MÜDEK Komisyonu 2025-2026 Güz Dönemi Değerlendirme Raporu',
       'Dönem içinde yürütülen DÖÇ-PÇ ölçümleri gözden geçirilmiştir. ' ||
       'Veri Yapıları ve Algoritmalar ile Veritabanı Yönetim Sistemleri derslerinde ' ||
       'PÇ-2 ve PÇ-4 başarı düzeyleri hedefin üzerindedir. Yazılım Mühendisliği ' ||
       'dersinde proje bileşeninin PÇ-6 (takım çalışması) katkısı izlenmeye devam ' ||
       'edilecektir. PUKÖ döngüsü kapsamında bir sonraki dönem için soru-DÖÇ ' ||
       'eşleme ağırlıklarının gözden geçirilmesi kararlaştırılmıştır.',
       'Dönem Değerlendirme', '2025-2026 Güz', 'approved', NOW(), NOW(),
       'Rapor incelendi, uygun bulundu.'
FROM committee_members cm
JOIN (SELECT u.id FROM users u
      JOIN user_roles ur ON ur.user_id = u.id
      JOIN roles r ON r.id = ur.role_id
      WHERE r.code = 'admin' ORDER BY u.id LIMIT 1) adm ON TRUE
WHERE cm.committee_id = 2
  AND NOT EXISTS (
      SELECT 1 FROM committee_reports cr
      WHERE cr.title = 'MÜDEK Komisyonu 2025-2026 Güz Dönemi Değerlendirme Raporu'
  )
LIMIT 1;

COMMIT;
