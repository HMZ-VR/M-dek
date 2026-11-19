-- 000_initial_schema.sql
-- KTU MÜDEK akreditasyon sistemi — başlangıç şeması.
-- IF NOT EXISTS ile mevcut DB'lere zarar vermez. Sırayla 001/002/003 takip eder.
-- Bu dosya kod tabanından (SELECT/INSERT sorguları) çıkarılarak yazılmıştır.

BEGIN;

-- =====================================================
-- 1. Kullanıcı / Yetki
-- =====================================================

CREATE TABLE IF NOT EXISTS users (
    id                    SERIAL PRIMARY KEY,
    username              VARCHAR(150) UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    full_name             VARCHAR(255),
    email                 VARCHAR(255),
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS users_username_idx ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS roles (
    id    SERIAL PRIMARY KEY,
    code  VARCHAR(50) UNIQUE NOT NULL,
    name  VARCHAR(150) NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id    SERIAL PRIMARY KEY,
    code  VARCHAR(80) UNIQUE NOT NULL,
    name  VARCHAR(150)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id  INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id        INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id  INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Default roller (idempotent)
INSERT INTO roles (code, name) VALUES
    ('admin',                'Yönetici'),
    ('bolum_baskani',        'Bölüm Başkanı'),
    ('ogretim_uyesi',        'Öğretim Üyesi'),
    ('mudek_kurul_uyesi',    'MÜDEK Kurul Üyesi'),
    ('arastirma_gorevlisi',  'Araştırma Görevlisi'),
    ('komisyon_uyesi',       'Komisyon Üyesi'),
    ('student',              'Öğrenci')
ON CONFLICT (code) DO NOTHING;

-- =====================================================
-- 2. Akademik Yapı
-- =====================================================

CREATE TABLE IF NOT EXISTS courses (
    id    SERIAL PRIMARY KEY,
    code  VARCHAR(50) NOT NULL,
    name  VARCHAR(255) NOT NULL,
    UNIQUE (code)
);

CREATE TABLE IF NOT EXISTS instructors (
    id       SERIAL PRIMARY KEY,
    title    VARCHAR(60),
    name     VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL,
    user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS instructors_user_idx ON instructors (user_id);

CREATE TABLE IF NOT EXISTS students (
    id          SERIAL PRIMARY KEY,
    student_no  VARCHAR(50) UNIQUE NOT NULL,
    name        VARCHAR(255),
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS students_user_idx ON students (user_id);

CREATE TABLE IF NOT EXISTS course_offerings (
    id             SERIAL PRIMARY KEY,
    course_id      INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    term           VARCHAR(40),
    section        VARCHAR(20),
    instructor_id  INTEGER NOT NULL REFERENCES instructors(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS course_offerings_course_idx     ON course_offerings (course_id);
CREATE INDEX IF NOT EXISTS course_offerings_instructor_idx ON course_offerings (instructor_id);

CREATE TABLE IF NOT EXISTS enrollments (
    student_id   INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    offering_id  INTEGER NOT NULL REFERENCES course_offerings(id) ON DELETE CASCADE,
    PRIMARY KEY (student_id, offering_id)
);
CREATE INDEX IF NOT EXISTS enrollments_offering_idx ON enrollments (offering_id);

-- =====================================================
-- 3. Sınavlar / Sorular / Cevaplar
-- =====================================================

CREATE TABLE IF NOT EXISTS exams (
    id           SERIAL PRIMARY KEY,
    offering_id  INTEGER NOT NULL REFERENCES course_offerings(id) ON DELETE CASCADE,
    title        VARCHAR(255),
    exam_type    VARCHAR(40),
    date         TIMESTAMP
    -- 001 migration adds: project_weight, project_max_points
);
CREATE INDEX IF NOT EXISTS exams_offering_idx ON exams (offering_id);

CREATE TABLE IF NOT EXISTS questions (
    id       SERIAL PRIMARY KEY,
    exam_id  INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    q_no     INTEGER NOT NULL,
    text     TEXT,
    points   NUMERIC(8,2) NOT NULL DEFAULT 0,
    UNIQUE (exam_id, q_no)
);

CREATE TABLE IF NOT EXISTS responses (
    id           SERIAL PRIMARY KEY,
    question_id  INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    student_id   INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    score        NUMERIC(8,2) NOT NULL DEFAULT 0,
    is_correct   BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (question_id, student_id)
);
CREATE INDEX IF NOT EXISTS responses_student_idx  ON responses (student_id);
CREATE INDEX IF NOT EXISTS responses_question_idx ON responses (question_id);

-- =====================================================
-- 4. DÖÇ / PÇ / Matrisler
-- =====================================================

CREATE TABLE IF NOT EXISTS course_learning_outcomes (
    id               SERIAL PRIMARY KEY,
    course_id        INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    sequence_number  INTEGER NOT NULL,
    description      TEXT,
    UNIQUE (course_id, sequence_number)
);

CREATE TABLE IF NOT EXISTS program_outcomes (
    id     SERIAL PRIMARY KEY,
    code   VARCHAR(20) UNIQUE NOT NULL,
    title  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outcome_matrix (
    outcome_id          INTEGER NOT NULL REFERENCES course_learning_outcomes(id) ON DELETE CASCADE,
    program_outcome_id  INTEGER NOT NULL REFERENCES program_outcomes(id) ON DELETE CASCADE,
    value               NUMERIC(6,3) NOT NULL DEFAULT 0,
    PRIMARY KEY (outcome_id, program_outcome_id)
);

CREATE TABLE IF NOT EXISTS question_outcomes (
    question_id  INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    outcome_id   INTEGER NOT NULL REFERENCES course_learning_outcomes(id) ON DELETE CASCADE,
    weight       NUMERIC(6,3) NOT NULL DEFAULT 0,
    PRIMARY KEY (question_id, outcome_id)
);
CREATE INDEX IF NOT EXISTS question_outcomes_outcome_idx ON question_outcomes (outcome_id);

-- =====================================================
-- 5. Anketler
-- =====================================================

CREATE TABLE IF NOT EXISTS surveys (
    id           SERIAL PRIMARY KEY,
    offering_id  INTEGER NOT NULL REFERENCES course_offerings(id) ON DELETE CASCADE,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS survey_responses (
    id          SERIAL PRIMARY KEY,
    survey_id   INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    student_id  INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    outcome_id  INTEGER REFERENCES course_learning_outcomes(id) ON DELETE SET NULL,
    score       NUMERIC(4,2),
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS survey_responses_survey_idx  ON survey_responses (survey_id);
CREATE INDEX IF NOT EXISTS survey_responses_student_idx ON survey_responses (student_id);

-- =====================================================
-- 6. Komiteler
-- =====================================================

CREATE TABLE IF NOT EXISTS committees (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS committee_members (
    id            SERIAL PRIMARY KEY,
    committee_id  INTEGER NOT NULL REFERENCES committees(id) ON DELETE CASCADE,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (committee_id, user_id)
);

CREATE TABLE IF NOT EXISTS committee_reports (
    id            SERIAL PRIMARY KEY,
    committee_id  INTEGER NOT NULL REFERENCES committees(id) ON DELETE CASCADE,
    uploader_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    title         VARCHAR(255) NOT NULL,
    file_path     VARCHAR,                         -- 002 migration ALTER TABLE DROP NOT NULL
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
    -- 002 migration adds: content, report_type, period, status, submitted_at, reviewed_at, reviewer_id, review_note, updated_at
);
CREATE INDEX IF NOT EXISTS committee_reports_committee_idx ON committee_reports (committee_id);
CREATE INDEX IF NOT EXISTS committee_reports_uploader_idx  ON committee_reports (uploader_id);

-- =====================================================
-- 7. Sınav Refleksiyonu (Hoca analizi + kurul feedback)
-- =====================================================

CREATE TABLE IF NOT EXISTS exam_reflections (
    exam_id        INTEGER PRIMARY KEY REFERENCES exams(id) ON DELETE CASCADE,
    instructor_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    analysis_text  TEXT,
    action_plan    TEXT,
    feedback_text  TEXT,
    reviewer_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =====================================================
-- 8. Raporlama VIEW'leri
-- =====================================================
-- Bu view'ler reports.html (Sekme 3 — Sınav Detayı) için kullanılır.

-- DROP+CREATE: CREATE OR REPLACE mevcut bir view'ın kolon adlarını/sırasını
-- değiştiremez; zincirin var olan DB'lerde de yeniden çalıştırılabilmesi için
-- view'lar önce düşürülür (view veri tutmaz, kayıp olmaz).
DROP VIEW IF EXISTS exam_header;
CREATE VIEW exam_header AS
SELECT e.id          AS exam_id,
       e.title       AS exam_title,
       e.exam_type,
       e.date        AS exam_date,
       co.id         AS offering_id,
       co.term,
       co.section,
       c.id          AS course_id,
       c.code        AS course_code,
       c.name        AS course_name,
       i.title       AS instructor_title,
       i.name        AS instructor_name,
       i.email       AS instructor_email
FROM exams e
JOIN course_offerings co ON co.id = e.offering_id
JOIN courses c           ON c.id  = co.course_id
LEFT JOIN instructors i  ON i.id  = co.instructor_id;

DROP VIEW IF EXISTS question_stats;
CREATE VIEW question_stats AS
SELECT q.exam_id,
       q.id           AS question_id,
       q.q_no,
       q.points,
       COUNT(r.id)                                                    AS attempts,
       COUNT(*) FILTER (WHERE r.is_correct)                           AS correct_count,
       CASE WHEN COUNT(r.id) > 0
            THEN ROUND(100.0 * COUNT(*) FILTER (WHERE r.is_correct) / COUNT(r.id), 2)
            ELSE 0 END                                                AS correct_rate_pct,
       COALESCE(ROUND(AVG(r.score)::numeric, 2), 0)                   AS avg_score
FROM questions q
LEFT JOIN responses r ON r.question_id = q.id
GROUP BY q.exam_id, q.id, q.q_no, q.points;

-- po_attainment: sınav bazında PÇ başarı yüzdesi
-- (mudek_service.calculate_course_attainment kanonik kaynak; bu view yalnız hızlı görüntüleme için.)
DROP VIEW IF EXISTS po_attainment;
CREATE VIEW po_attainment AS
SELECT q.exam_id,
       po.code                                              AS po_code,
       ROUND(
         CASE WHEN SUM(om.value * qo.weight * q.points) > 0
              THEN 100.0 * SUM(om.value * qo.weight * COALESCE(rs.avg_score, 0))
                         / SUM(om.value * qo.weight * q.points)
              ELSE 0 END, 2
       )                                                    AS attainment_pct
FROM questions q
JOIN question_outcomes qo  ON qo.question_id = q.id
JOIN outcome_matrix om     ON om.outcome_id  = qo.outcome_id
JOIN program_outcomes po   ON po.id          = om.program_outcome_id
LEFT JOIN (
    SELECT r.question_id, AVG(r.score) AS avg_score
    FROM responses r GROUP BY r.question_id
) rs ON rs.question_id = q.id
GROUP BY q.exam_id, po.code;

COMMIT;
