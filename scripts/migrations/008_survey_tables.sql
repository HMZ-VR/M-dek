-- Migration 008: genişletilmiş anket tabloları
-- Bu tablolar bugüne kadar API startup'ında _ensure_survey_tables() ile
-- oluşturuluyordu (api/main.py). Şemanın tek kaynaktan (migration zinciri)
-- yönetilebilmesi için aynı DDL buraya taşındı. Startup'taki IF NOT EXISTS
-- güvencesi davranış değişmeden fallback olarak kodda durmaya devam eder.

-- Özel anket soruları (DÖÇ sorularının yanına eklenen ek sorular).
-- Anket soruları doğrudan program_outcomes (PÇ) tablosuna referans verir;
-- eski mudek_criteria tablosu kaldırıldı (bkz. migration 004).
CREATE TABLE IF NOT EXISTS survey_questions (
    id          SERIAL PRIMARY KEY,
    survey_id   INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    q_type      VARCHAR(20) NOT NULL DEFAULT 'likert',  -- 'likert', 'multiple_choice', 'open_ended'
    q_text      TEXT NOT NULL,
    q_order     INTEGER NOT NULL DEFAULT 0,
    options     TEXT,                                   -- JSON string (MC seçenekleri), diğerlerinde NULL
    program_outcome_id INTEGER REFERENCES program_outcomes(id) ON DELETE SET NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Özel soru yanıtları
CREATE TABLE IF NOT EXISTS survey_question_responses (
    id            SERIAL PRIMARY KEY,
    question_id   INTEGER NOT NULL REFERENCES survey_questions(id) ON DELETE CASCADE,
    student_id    INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    score         INTEGER,          -- Likert (1-5) veya MC index
    text_answer   TEXT,             -- Açık uçlu cevap
    created_at    TIMESTAMP DEFAULT NOW(),
    UNIQUE (question_id, student_id)
);

-- Ders dönem değerlendirme (offering_reflections)
CREATE TABLE IF NOT EXISTS offering_reflections (
    id            SERIAL PRIMARY KEY,
    offering_id   INTEGER UNIQUE NOT NULL
                  REFERENCES course_offerings(id) ON DELETE CASCADE,
    a5_text       TEXT,
    b_text        TEXT,
    c_text        TEXT,
    instructor_id INTEGER REFERENCES users(id),
    updated_at    TIMESTAMP DEFAULT NOW()
);
