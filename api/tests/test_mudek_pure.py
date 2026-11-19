"""Pure-function tests for mudek_service — no DB required."""
import pytest

from mudek_service import (
    ExamAttainment,
    PASSING_THRESHOLD,
    VIZE_WEIGHT,
    FINAL_WEIGHT,
    _avg_doc_scores,
    _combine_question_and_project,
    _exam_category,
    compute_letter_grade,
)


class TestLetterGrade:
    @pytest.mark.parametrize("score,expected", [
        (None, None),
        (0, "FF"),
        (34.99, "FF"),
        (35, "DD"),
        (39.9, "DD"),
        (39.99, "DD"),
        (40, "DC"),
        (49.9, "DC"),
        (49.99, "DC"),
        (50, "CC"),
        (57.9, "CC"),
        (57.99, "CC"),
        (58, "CB"),
        (64.9, "CB"),
        (64.99, "CB"),
        (65, "BB"),
        (73.9, "BB"),
        (73.99, "BB"),
        (74, "BA"),
        (81.9, "BA"),
        (81.99, "BA"),
        (82, "AA"),
        (100, "AA"),
    ])
    def test_boundaries(self, score, expected):
        assert compute_letter_grade(score) == expected


class TestExamCategory:
    @pytest.mark.parametrize("exam_type,expected", [
        ("Vize", "vize"),
        ("ara sınav", "vize"),
        ("quiz 1", "vize"),
        (None, "vize"),
        ("", "vize"),
        ("Final", "final"),
        ("FINAL SINAVI", "final"),
        ("final exam", "final"),
        ("Bütünleme", "butunleme"),
        ("butunleme", "butunleme"),
        ("Makeup Exam", "butunleme"),
        ("resit", "butunleme"),
        ("Final Bütünleme", "butunleme"),  # butunleme takes precedence
    ])
    def test_categories(self, exam_type, expected):
        assert _exam_category(exam_type) == expected


class TestAvgDocScores:
    def test_single_exam(self):
        atts = [ExamAttainment(1, "V", "vize", "vize", doc_scores={1: 0.8, 2: 0.6})]
        assert _avg_doc_scores(atts) == {1: 0.8, 2: 0.6}

    def test_multi_exam_average(self):
        atts = [
            ExamAttainment(1, "V", "vize", "vize", doc_scores={1: 0.8, 2: 0.6}),
            ExamAttainment(2, "F", "final", "final", doc_scores={1: 0.4, 2: 0.2}),
        ]
        result = _avg_doc_scores(atts)
        assert result[1] == pytest.approx(0.6)
        assert result[2] == pytest.approx(0.4)

    def test_missing_outcome_in_one_exam(self):
        """Only averages the outcomes that appear in each exam."""
        atts = [
            ExamAttainment(1, "V", "vize", "vize", doc_scores={1: 0.8}),
            ExamAttainment(2, "F", "final", "final", doc_scores={1: 0.4, 2: 0.9}),
        ]
        result = _avg_doc_scores(atts)
        assert result[1] == pytest.approx(0.6)
        assert result[2] == pytest.approx(0.9)

    def test_empty(self):
        assert _avg_doc_scores([]) == {}


class TestConstants:
    def test_weights_sum_to_one(self):
        assert VIZE_WEIGHT + FINAL_WEIGHT == pytest.approx(1.0)

    def test_passing_threshold(self):
        assert PASSING_THRESHOLD == 40.0


class TestBasariNotuFormula:
    """Verifies the 40/60 başarı notu formula used by _get_passing_student_ids."""

    def _basari(self, vize, terminal):
        return round(VIZE_WEIGHT * vize + FINAL_WEIGHT * terminal, 2)

    def test_known_values(self):
        assert self._basari(100, 100) == 100.0
        assert self._basari(0, 0) == 0.0
        assert self._basari(50, 50) == 50.0
        assert self._basari(80, 60) == pytest.approx(68.0)
        assert self._basari(40, 40) == 40.0  # exactly the passing threshold

    def test_just_below_passing(self):
        # 0.40*40 + 0.60*39 = 16 + 23.4 = 39.4
        assert self._basari(40, 39) < PASSING_THRESHOLD

    def test_just_above_passing(self):
        assert self._basari(40, 40) >= PASSING_THRESHOLD


class TestProjectWeightFormula:
    """
    Excel şablonu formülü: exam_total = q_norm × (1 - pw) + p_norm × pw
    """

    def test_zero_weight_returns_q_norm(self):
        assert _combine_question_and_project(0.8, 0.5, 0.0) == 0.8
        assert _combine_question_and_project(0.8, None, 0.0) == 0.8

    def test_full_project_weight_returns_p_norm(self):
        assert _combine_question_and_project(0.2, 0.9, 1.0) == 0.9

    def test_classic_excel_example_60q_40p(self):
        # Excel rapor: %60 sorular + %40 proje, q=80%, p=100% → 88%
        assert _combine_question_and_project(0.80, 1.00, 0.40) == pytest.approx(0.88)

    def test_missing_project_treated_as_zero(self):
        # %40 proje ağırlığı ama öğrenci proje vermemiş
        # 0.80 × 0.6 + 0 × 0.4 = 0.48
        assert _combine_question_and_project(0.80, None, 0.40) == pytest.approx(0.48)

    def test_clamps_out_of_range(self):
        # negatif weight ve >1 değerler clamp edilir
        assert _combine_question_and_project(0.5, 0.5, -0.1) == 0.5  # pw clamped to 0
        assert _combine_question_and_project(0.5, 1.5, 0.5) == pytest.approx(0.75)  # p clamped to 1

    @pytest.mark.parametrize("q,p,pw,expected", [
        (1.0, 1.0, 0.0, 1.0),
        (1.0, 1.0, 0.5, 1.0),
        (1.0, 0.0, 0.5, 0.5),
        (0.0, 1.0, 0.5, 0.5),
        (0.6, 0.8, 0.25, 0.65),
    ])
    def test_table(self, q, p, pw, expected):
        assert _combine_question_and_project(q, p, pw) == pytest.approx(expected)


class TestStudentEmailUsername:
    """Öğrenci e-posta/kullanıcı adı türetimi (okul standardı f<no>@ktun.edu.tr).

    main import edilir; pool open=False olduğundan import DB'ye bağlanmaz.
    """

    def test_email_format(self):
        from main import student_email
        assert student_email("2026001") == "f2026001@ktun.edu.tr"

    def test_username_is_email_local_part(self):
        from main import create_username, student_email
        email = student_email("2026001")
        assert create_username("Öğrenci 2026001", email) == "f2026001"

    def test_double_f_guard(self):
        # Numara zaten 'f' ile başlıyorsa ikinci 'f' eklenmez (idempotent).
        from main import student_email
        assert student_email("f2026001") == "f2026001@ktun.edu.tr"

    def test_strips_whitespace(self):
        from main import student_email
        assert student_email("  2026001  ") == "f2026001@ktun.edu.tr"


class TestNormalizeStudentNo:
    """Öğrenci no normalizasyonu — aynı öğrencinin farklı derslerde çift kayıt
    olmasını önler (pandas float artefaktı + boşluk temizliği)."""

    def test_plain(self):
        from main import _normalize_student_no
        assert _normalize_student_no("2026001") == "2026001"

    def test_pandas_float_artifact(self):
        # pandas, boş hücreli sütunda sayıyı float okur: '2026001.0'
        from main import _normalize_student_no
        assert _normalize_student_no("2026001.0") == "2026001"
        assert _normalize_student_no(2026001.0) == "2026001"
        assert _normalize_student_no("2026001.00") == "2026001"

    def test_whitespace(self):
        from main import _normalize_student_no
        assert _normalize_student_no("  2026001  ") == "2026001"

    def test_none_and_empty(self):
        from main import _normalize_student_no
        assert _normalize_student_no(None) == ""
        assert _normalize_student_no("") == ""

    def test_two_formats_resolve_equal(self):
        # Asıl senaryo: aynı öğrenci iki derste farklı formatta → aynı kanonik no
        from main import _normalize_student_no
        assert _normalize_student_no("2026001") == _normalize_student_no("2026001.0")

    def test_non_numeric_preserved(self):
        from main import _normalize_student_no
        assert _normalize_student_no("f2026001") == "f2026001"
