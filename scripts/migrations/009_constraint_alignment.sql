-- Migration 009: şema kayması düzeltmesi — eksik UNIQUE kısıtlar
-- Eski şema neslinden kurulan veritabanlarında 000_initial_schema.sql'in ilan
-- ettiği bazı tekillik kısıtları yok (CREATE TABLE IF NOT EXISTS mevcut tabloya
-- kısıt eklemez). Bu migration eksikleri kapatır; 000 ile kurulmuş taze
-- veritabanlarında kısıt zaten varsa hiçbir şey yapmaz.
-- Her blok önce mükerrer veri kontrolü yapar; mükerrer varsa kısıtı eklemek
-- yerine WARNING basar (veri kaybı riski alınmaz).

-- courses(code)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'courses_code_key')
       OR EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'courses_code_uniq') THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM courses GROUP BY code HAVING COUNT(*) > 1) THEN
        RAISE WARNING 'courses.code içinde mükerrer değerler var — tekillik index''i EKLENMEDİ.';
    ELSE
        CREATE UNIQUE INDEX courses_code_uniq ON courses (code);
    END IF;
END $$;

-- course_learning_outcomes(course_id, sequence_number)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'course_learning_outcomes_course_id_sequence_number_key')
       OR EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'clo_course_seq_uniq') THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM course_learning_outcomes
               GROUP BY course_id, sequence_number HAVING COUNT(*) > 1) THEN
        RAISE WARNING 'course_learning_outcomes içinde mükerrer (course_id, sequence_number) var — tekillik index''i EKLENMEDİ.';
    ELSE
        CREATE UNIQUE INDEX clo_course_seq_uniq
            ON course_learning_outcomes (course_id, sequence_number);
    END IF;
END $$;

-- questions(exam_id, q_no)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'questions_exam_id_q_no_key')
       OR EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'questions_exam_qno_uniq') THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM questions GROUP BY exam_id, q_no HAVING COUNT(*) > 1) THEN
        RAISE WARNING 'questions içinde mükerrer (exam_id, q_no) var — tekillik index''i EKLENMEDİ.';
    ELSE
        CREATE UNIQUE INDEX questions_exam_qno_uniq ON questions (exam_id, q_no);
    END IF;
END $$;

-- survey_responses: eski UNIQUE(student_id, outcome_id) kısıtı survey_id'yi
-- kapsamadığı için aynı öğrencinin aynı DÖÇ'ü FARKLI dönem anketlerinde
-- cevaplamasını engelliyordu (ders tekrarı senaryosu). Doğrusu anket bazında
-- tekillik: UNIQUE(survey_id, student_id, outcome_id).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'survey_responses_student_id_outcome_id_key') THEN
        ALTER TABLE survey_responses
            DROP CONSTRAINT survey_responses_student_id_outcome_id_key;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE indexname = 'survey_responses_survey_student_outcome_uniq') THEN
        IF EXISTS (SELECT 1 FROM survey_responses
                   GROUP BY survey_id, student_id, outcome_id HAVING COUNT(*) > 1) THEN
            RAISE WARNING 'survey_responses içinde mükerrer (survey_id, student_id, outcome_id) var — tekillik index''i EKLENMEDİ.';
        ELSE
            CREATE UNIQUE INDEX survey_responses_survey_student_outcome_uniq
                ON survey_responses (survey_id, student_id, outcome_id);
        END IF;
    END IF;
END $$;
