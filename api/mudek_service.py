# mudek_service.py
"""
MÜDEK Ders Değerlendirme Servisi
=================================

Hesaplama zinciri (Excel şablonu "Müdek Ders Değerlendirme Şablonu.xlsx"
ile birebir uyumlu — DOC!AR, DOC!AV ve PC!W sütunlarındaki formüller):
  Ham soru puanları (responses)
      → Her sorunun normalize ortalama puanı  (öğrenci ort. / max puan → 0..1)
      → Ağırlıklı sınav-DÖÇ skorları          (question_outcomes ağırlıkları,
                                               her sorunun toplamı = 1)
                                               DÖÇ_exam = Σ(w×avg)/Σw
      → Ders-DÖÇ ortalaması                   DÖÇ_course = AVERAGE(
                                                 DÖÇ_vize, DÖÇ_final,
                                                 DÖÇ_butunleme)
      → Ağırlıklı PÇ skorları                 (outcome_matrix ağırlıkları)
                                               PÇ = Σ(w×DÖÇ)/Σw

Geçme notu zinciri:
  Vize notu (0–100)
  + Final veya Bütünleme notu (0–100)
      → Başarı notu  (%40 vize, %60 final/bütünleme)
      → Harf notu    (bağıl değerlendirme — Excel şablonundaki sabit eşikler)

Bütünleme kuralı (Excel şablonuyla birebir):
  Öğrenci bütünlemeye girdiyse → Başarı = %40 × vize + %60 × bütünleme
  Bütünlemeye girmediyse       → Başarı = %40 × vize + %60 × final
  DÖÇ hesabında da aynı kural geçerli:
    - Bütünlemeye giren öğrencilerin yanıtları bütünleme sınavından,
    - Girmeyen öğrencilerin yanıtları final sınavından alınır.

Geçen öğrenci filtresi (Excel şablonundaki vizey/finaly/butunlemey mantığı):
  DÖÇ ve PÇ başarı hesabına yalnızca Başarı Notu >= PASSING_THRESHOLD olan
  öğrenciler dahil edilir. Bu davranış `passing_only=True` (varsayılan) ile
  kontrol edilebilir.

DB şeması (ilgili tablolar):
  students                 : id, student_no, name
  course_offerings         : id, course_id, term, section, instructor_id
  exams                    : id, offering_id, title, exam_type, date
  questions                : id, exam_id, q_no, text, points
  responses                : id, question_id, student_id, score, is_correct
  course_learning_outcomes : id, course_id, sequence_number, description  ← DÖÇ tablosu
  outcome_matrix           : id, outcome_id, program_outcome_id, value
  question_outcomes        : question_id, outcome_id, weight
  program_outcomes         : id, code, title
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import psycopg


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


VIZE_WEIGHT       = _env_float("MUDEK_VIZE_WEIGHT", 0.40)
FINAL_WEIGHT      = _env_float("MUDEK_FINAL_WEIGHT", 0.60)
PASSING_THRESHOLD = _env_float("MUDEK_PASSING_THRESHOLD", 40.0)

# DÖÇ karşılanma eşiği (0..1): sınıf ortalaması bu değerin üzerindeyse DÖÇ "karşılandı"
DOC_ATTAINMENT_THRESHOLD: float = _env_float("MUDEK_DOC_ATTAINMENT_THRESHOLD", 0.60)

# Harf notu eşikleri — büyükten küçüğe, ilk eşleşen döner.
# Override via MUDEK_LETTER_THRESHOLDS="AA:82,BA:74,BB:65,CB:58,CC:50,DC:40,DD:35,FF:0"
_DEFAULT_LETTER_THRESHOLDS: list[tuple[float, str]] = [
    (82, "AA"),
    (74, "BA"),
    (65, "BB"),
    (58, "CB"),
    (50, "CC"),
    (40, "DC"),
    (35, "DD"),
    ( 0, "FF"),
]


def _parse_letter_thresholds(raw: str | None) -> list[tuple[float, str]]:
    if not raw:
        return _DEFAULT_LETTER_THRESHOLDS
    try:
        pairs: list[tuple[float, str]] = []
        for item in raw.split(","):
            letter, threshold = item.split(":")
            pairs.append((float(threshold.strip()), letter.strip().upper()))
        pairs.sort(key=lambda p: p[0], reverse=True)
        return pairs or _DEFAULT_LETTER_THRESHOLDS
    except (ValueError, AttributeError):
        return _DEFAULT_LETTER_THRESHOLDS


LETTER_GRADE_THRESHOLDS: list[tuple[float, str]] = _parse_letter_thresholds(
    os.getenv("MUDEK_LETTER_THRESHOLDS")
)

_BUTUNLEME_KEYWORDS = {"butunleme", "bütünleme", "makeup", "resit"}
_FINAL_KEYWORDS     = {"final"}


# ---------------------------------------------------------------------------
# Özel exception sınıfları
# ---------------------------------------------------------------------------

class MudekError(Exception):
    """Tüm MÜDEK servis hatalarının base sınıfı."""


class MissingDataError(MudekError):
    """Gerekli veri DB'de bulunamadığında fırlatılır."""


class InvalidWeightError(MudekError):
    """DÖÇ ağırlıkları geçersiz olduğunda fırlatılır."""


# ---------------------------------------------------------------------------
# Yardımcı: exam_type → kategori
# ---------------------------------------------------------------------------

def _exam_category(exam_type: str | None) -> str:
    """DB'deki exam_type değerini 'vize' | 'final' | 'butunleme' kategorisine çevirir."""
    t = (exam_type or "").lower().strip()
    if any(k in t for k in _BUTUNLEME_KEYWORDS):
        return "butunleme"
    if any(k in t for k in _FINAL_KEYWORDS):
        return "final"
    return "vize"


# ---------------------------------------------------------------------------
# Veri sınıfları
# ---------------------------------------------------------------------------

@dataclass
class DocQuestionEvidence:
    """Bir DÖÇ skoruna tek bir sorunun katkısı (sınav-bazlı)."""
    exam_id:          int
    exam_title:       str
    category:         str                # 'vize' | 'final' | 'butunleme'
    question_id:      int
    q_no:             int
    q_text:           str | None
    q_norm:           float               # 0..1 — sınıf ortalaması / max puan
    weight:           float               # question_outcomes.weight
    contribution_pct: float               # 0..100 — bu sınavda DÖÇ skoruna katkı %


@dataclass
class PcDocEvidence:
    """Bir PÇ skoruna tek bir DÖÇ'nin katkısı (ders düzeyinde)."""
    outcome_id:       int
    outcome_seq:      int | None
    doc_score:        float               # 0..1 — ders-bazlı DÖÇ ortalaması
    matrix_value:     float               # outcome_matrix.value
    contribution_pct: float               # 0..100 — bu DÖÇ'nin PÇ skoruna katkı %


@dataclass
class ExamAttainment:
    """Tek bir sınavın DÖÇ ve PÇ başarı sonuçları (0..1 aralığında)."""
    exam_id:    int
    exam_title: str
    exam_type:  str | None
    category:   str                    # 'vize' | 'final' | 'butunleme'
    doc_scores: dict[int, float] = field(default_factory=dict)
    pc_scores:  dict[int, float] = field(default_factory=dict)
    # outcome_id -> [DocQuestionEvidence, ...] (yalnızca collect_evidence=True ile dolar)
    doc_evidence: dict[int, list[DocQuestionEvidence]] = field(default_factory=dict)


@dataclass
class CourseAttainment:
    """Bir dersin tüm dönem/şube sonuçlarını birleştiren nihai MÜDEK raporu."""
    course_id:        int
    exam_results:     list[ExamAttainment] = field(default_factory=list)
    doc_attainment:   dict[int, float]     = field(default_factory=dict)
    pc_attainment:    dict[int, float]     = field(default_factory=dict)
    # DÖÇ karşılanma durumu: {outcome_id: "met" | "not_met"}
    doc_status:       dict[int, str]       = field(default_factory=dict)
    # Kaç öğrenci hesaba dahil edildi, kaç öğrenci toplam vardı
    students_total:   int = 0
    students_passing: int = 0
    warnings:         list[str] = field(default_factory=list)
    # Sınıfın harf notu dağılımı (AA, BA, BB, CB, CC, DC, DD, FF). Tüm offering'ler agregue edilir.
    letter_grade_distribution: dict[str, int] = field(default_factory=dict)
    # Kanıt zincirleri (collect_evidence=True ile dolar)
    doc_evidence:     dict[int, list[DocQuestionEvidence]] = field(default_factory=dict)
    pc_evidence:      dict[int, list[PcDocEvidence]]       = field(default_factory=dict)


@dataclass
class StudentGrade:
    """Tek bir öğrencinin dönem sonu not bilgisi."""
    student_id:      int
    student_no:      str
    name:            str | None
    vize_score:      float | None   # 0–100
    final_score:     float | None   # 0–100
    butunleme_score: float | None   # 0–100
    basari_notu:     float | None   # 0–100  (%40 vize + %60 terminal)
    harf_notu:       str  | None
    passed:          bool = False   # basari_notu >= PASSING_THRESHOLD


@dataclass
class WeightValidationResult:
    ok:      bool
    details: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def compute_letter_grade(score: float | None) -> str | None:
    """100 üzerinden başarı notunu harf notuna çevirir."""
    if score is None:
        return None
    for threshold, letter in LETTER_GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "FF"


def _upsert_student(cur, student_no: str, name: str | None) -> int:
    """Öğrenciyi bul ya da oluştur; id döndür."""
    cur.execute("SELECT id FROM students WHERE student_no = %s", (student_no,))
    row = cur.fetchone()
    if row:
        sid = int(row[0])
        if name:
            cur.execute(
                "UPDATE students SET name = COALESCE(%s, name) WHERE id = %s",
                (name, sid),
            )
        return sid
    cur.execute(
        "INSERT INTO students (student_no, name) VALUES (%s, %s) RETURNING id",
        (student_no, name),
    )
    return int(cur.fetchone()[0])


def _avg_doc_scores(atts: list[ExamAttainment]) -> dict[int, float]:
    """Birden fazla sınavın DÖÇ skorlarının basit ortalaması."""
    combined: dict[int, list[float]] = {}
    for a in atts:
        for oid, score in a.doc_scores.items():
            combined.setdefault(oid, []).append(score)
    return {oid: sum(v) / len(v) for oid, v in combined.items()}


def _get_students_of_exams(cur, exam_ids: list[int]) -> list[int]:
    """Verilen sınavlara yanıt girmiş tüm öğrenci id'lerini döndürür."""
    if not exam_ids:
        return []
    cur.execute(
        """
        SELECT DISTINCT r.student_id
        FROM responses r
        JOIN questions q ON q.id = r.question_id
        WHERE q.exam_id = ANY(%s)
        """,
        (exam_ids,),
    )
    return [int(row[0]) for row in cur.fetchall()]


def _combine_question_and_project(
    q_norm: float,
    p_norm: float | None,
    project_weight: float,
) -> float:
    """
    Excel şablonu formülü (saf, DB'ye dokunmaz — test edilebilir):

        exam_total_norm = q_norm × (1 - project_weight) + p_norm × project_weight

    project_weight = 0 ise sonuç = q_norm (proje yok).
    p_norm None ise proje girilmemiş kabul edilir (0 olarak alınır).
    """
    pw = max(0.0, min(1.0, project_weight))
    if pw <= 0:
        return q_norm
    p = 0.0 if p_norm is None else max(0.0, min(1.0, p_norm))
    return q_norm * (1.0 - pw) + p * pw


def _compute_student_totals(cur, exam_ids: list[int]) -> dict[int, float]:
    """
    Verilen sınav(lar)daki her öğrencinin normalize toplam puanı (0–100).

    Excel şablonu mantığı (per exam):
        exam_total = q_norm × (1 - project_weight) + p_norm × project_weight
        burada:
          q_norm = SUM(soru_puanları) / SUM(soru_max)        ∈ [0, 1]
          p_norm = project_score      / project_max_points   ∈ [0, 1]

    project_weight = 0 (default) ise eski davranışla birebir aynı:
        exam_total = SUM(score) / SUM(points) × 100

    Birden fazla sınav id'si verilirse her sınavın normalize toplamı ayrı
    hesaplanır, sonra basit aritmetik ortalama alınır.
    """
    if not exam_ids:
        return {}

    # Sınav meta-verisi (proje ağırlığı + max puan)
    try:
        cur.execute(
            "SELECT id, COALESCE(project_weight, 0), COALESCE(project_max_points, 0) "
            "FROM exams WHERE id = ANY(%s)",
            (exam_ids,),
        )
        exam_meta = {
            int(eid): (float(pw), float(pmp))
            for eid, pw, pmp in cur.fetchall()
        }
    except psycopg.errors.UndefinedColumn:
        # Migration henüz uygulanmamış — transaction'ı temizle, eski davranışa dön
        cur.connection.rollback()
        exam_meta = {int(eid): (0.0, 0.0) for eid in exam_ids}

    # Soru-bazlı toplamlar (per exam, per student)
    cur.execute(
        """
        SELECT q.exam_id, r.student_id,
               SUM(r.score)  AS earned,
               SUM(q.points) AS max_pts
        FROM responses r
        JOIN questions q ON q.id = r.question_id
        WHERE q.exam_id = ANY(%s)
        GROUP BY q.exam_id, r.student_id
        """,
        (exam_ids,),
    )
    q_norms: dict[tuple[int, int], float] = {}
    for eid, sid, earned, max_pts in cur.fetchall():
        mp = float(max_pts)
        if mp > 0:
            q_norms[(int(eid), int(sid))] = min(float(earned) / mp, 1.0)

    # Proje skorları (per exam, per student) — tablo yoksa boş geç
    p_scores: dict[tuple[int, int], float] = {}
    try:
        cur.execute(
            "SELECT exam_id, student_id, score FROM exam_project_scores "
            "WHERE exam_id = ANY(%s)",
            (exam_ids,),
        )
        for eid, sid, sc in cur.fetchall():
            p_scores[(int(eid), int(sid))] = float(sc)
    except psycopg.errors.UndefinedTable:
        cur.connection.rollback()

    # Per-exam total normalize → öğrenci başına liste → ortalama
    per_student: dict[int, list[float]] = {}
    for (eid, sid), q_norm in q_norms.items():
        pw, pmp = exam_meta.get(eid, (0.0, 0.0))
        p_norm: float | None = None
        if pw > 0 and pmp > 0:
            p_score = p_scores.get((eid, sid), 0.0)
            p_norm = min(p_score / pmp, 1.0)
        total_norm = _combine_question_and_project(q_norm, p_norm, pw)
        per_student.setdefault(int(sid), []).append(total_norm * 100.0)

    return {sid: round(sum(v) / len(v), 4) for sid, v in per_student.items()}


def _get_passing_student_ids(
    cur,
    exam_by_cat: dict[str, list[int]],
) -> tuple[set[int], int, int]:
    """
    Bir offering'deki öğrencilerin başarı notunu hesaplar ve
    PASSING_THRESHOLD'u geçenlerin id setini döndürür.

    Bütünleme kuralı (Excel ile birebir):
      - Öğrenci bütünlemeye girdiyse → %40 × vize + %60 × bütünleme
      - Bütünlemeye girmediyse       → %40 × vize + %60 × final

    Not (DZ paydası): all_sids `_compute_student_totals` çıktısının
    birleşimidir; bu fonksiyon yalnızca `responses` tablosundan okur, yani
    derse/sınava hiç yanıt vermemiş (DZ — devamsız) öğrenciler `enrollments`'ta
    kayıtlı olsa bile burada görünmez. Sonuç olarak DZ öğrenciler MÜDEK başarı
    yüzdesi paydasına dahil edilmez.

    Returns:
        (passing_ids: set[int], total: int, passing: int)
    """
    vize_scores      = _compute_student_totals(cur, exam_by_cat["vize"])
    final_scores     = _compute_student_totals(cur, exam_by_cat["final"])
    butunleme_scores = _compute_student_totals(cur, exam_by_cat["butunleme"])

    all_sids = set(vize_scores) | set(final_scores) | set(butunleme_scores)
    passing_ids: set[int] = set()

    for sid in all_sids:
        vize_s      = vize_scores.get(sid)
        butunleme_s = butunleme_scores.get(sid)
        final_s     = final_scores.get(sid)

        # Bütünlemeye girdiyse terminal = bütünleme, yoksa final
        terminal = butunleme_s if butunleme_s is not None else final_s

        if vize_s is not None and terminal is not None:
            basari = round(VIZE_WEIGHT * vize_s + FINAL_WEIGHT * terminal, 2)
        elif terminal is not None:
            basari = round(terminal, 2)
        elif vize_s is not None:
            basari = round(vize_s, 2)
        else:
            basari = None

        if basari is not None and basari >= PASSING_THRESHOLD:
            passing_ids.add(sid)

    return passing_ids, len(all_sids), len(passing_ids)


# ---------------------------------------------------------------------------
# Soru → DÖÇ ağırlık yönetimi
# ---------------------------------------------------------------------------

def save_question_outcome_weights(
    *,
    conn: psycopg.Connection,
    question_id: int,
    weights: list[dict[str, Any]],
    tolerance: float = 0.01,
) -> None:
    """
    Bir sorunun DÖÇ ağırlıklarını kaydeder (eski kayıtlar silinir).

    weights: [{"outcome_id": 5, "weight": 0.6}, {"outcome_id": 6, "weight": 0.4}]
    Toplam ağırlık 1.0 olmalı (±tolerance).

    Raises:
        InvalidWeightError: ağırlıklar geçersizse
        MissingDataError:   question_id DB'de yoksa
    """
    if not weights:
        raise InvalidWeightError(f"Soru {question_id}: En az bir DÖÇ ağırlığı girilmeli")

    if any(float(w["weight"]) < 0 for w in weights):
        raise InvalidWeightError(f"Soru {question_id}: Negatif ağırlık girilemez")

    total = sum(float(w["weight"]) for w in weights)
    if not (1.0 - tolerance <= total <= 1.0 + tolerance):
        raise InvalidWeightError(
            f"Soru {question_id}: Ağırlıklar toplamı 1.0 olmalı, şu an {total:.4f}"
        )

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM questions WHERE id = %s", (question_id,))
        if cur.fetchone() is None:
            raise MissingDataError(f"Soru bulunamadı: question_id={question_id}")

        outcome_ids = [int(w["outcome_id"]) for w in weights]
        cur.execute(
            "SELECT id FROM course_learning_outcomes WHERE id = ANY(%s)",
            (outcome_ids,),
        )
        found_ids = {int(row[0]) for row in cur.fetchall()}
        missing = set(outcome_ids) - found_ids
        if missing:
            raise MissingDataError(f"Şu DÖÇ id'leri bulunamadı: {sorted(missing)}")

        cur.execute(
            "DELETE FROM question_outcomes WHERE question_id = %s",
            (question_id,),
        )
        cur.executemany(
            "INSERT INTO question_outcomes (question_id, outcome_id, weight) VALUES (%s, %s, %s)",
            [(question_id, int(w["outcome_id"]), float(w["weight"])) for w in weights],
        )


def validate_question_outcome_weights(
    *,
    conn: psycopg.Connection,
    exam_id: int,
    tolerance: float = 0.01,
) -> WeightValidationResult:
    """
    Bir sınavdaki tüm soruların DÖÇ ağırlık toplamlarını doğrular.
    Her sorunun toplamı 1.0 olmalı.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, q_no FROM questions WHERE exam_id = %s ORDER BY q_no",
            (exam_id,),
        )
        questions = cur.fetchall()
        if not questions:
            return WeightValidationResult(
                ok=False,
                details=[{"error": "Bu sınavda soru bulunamadı"}],
            )

        q_ids = [int(qid) for qid, _ in questions]
        cur.execute(
            """
            SELECT question_id, COALESCE(SUM(weight), 0)
            FROM question_outcomes
            WHERE question_id = ANY(%s)
            GROUP BY question_id
            """,
            (q_ids,),
        )
        sums = {int(qid): float(s) for qid, s in cur.fetchall()}

    details: list[dict[str, Any]] = []
    all_ok = True
    for qid, q_no in questions:
        total = sums.get(int(qid), 0.0)
        ok = (1.0 - tolerance) <= total <= (1.0 + tolerance)
        if not ok:
            all_ok = False
        details.append({
            "question_id": int(qid),
            "q_no":        int(q_no),
            "weight_sum":  round(total, 6),
            "ok":          ok,
        })

    return WeightValidationResult(ok=all_ok, details=details)


# ---------------------------------------------------------------------------
# Tek sınav: DÖÇ ve PÇ başarı hesabı
# ---------------------------------------------------------------------------

def compute_exam_attainment(
    *,
    conn: psycopg.Connection,
    exam_id: int,
    student_ids: list[int] | None = None,
    collect_evidence: bool = False,
) -> ExamAttainment:
    """
    Bir sınavın DÖÇ ve PÇ başarı puanlarını hesaplar.

    student_ids:
      None  → tüm öğrenciler üzerinden hesap yapılır
      [...] → yalnızca listedeki öğrenciler üzerinden hesap yapılır
      []    → boş ExamAttainment döner (hesap yapılmaz)

    Bu parametre şu iki senaryoda kullanılır:
      1. Bütünleme ayrımı:
         - Final      → bütünlemeye GİRMEYEN, GEÇEN öğrenciler
         - Bütünleme  → bütünlemeye GİREN, GEÇEN öğrenciler
      2. Geçen öğrenci filtresi (passing_only):
         Sadece Başarı Notu >= PASSING_THRESHOLD olan öğrenciler

    Raises:
        MissingDataError: sınav, soru veya yanıt verisi yoksa
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT title, exam_type FROM exams WHERE id = %s", (exam_id,)
        )
        row = cur.fetchone()
        if not row:
            raise MissingDataError(f"Sınav bulunamadı: exam_id={exam_id}")
        exam_title, exam_type = row
        category = _exam_category(exam_type)

        # Boş öğrenci listesi → hesap yapma, boş döndür
        if student_ids is not None and len(student_ids) == 0:
            return ExamAttainment(
                exam_id=exam_id,
                exam_title=str(exam_title),
                exam_type=exam_type,
                category=category,
            )

        # Soruların max puanları (+ q_no/text — kanıt için)
        cur.execute(
            "SELECT id, points, q_no, text FROM questions WHERE exam_id = %s",
            (exam_id,),
        )
        q_rows = cur.fetchall()
        if not q_rows:
            raise MissingDataError(f"Sınav {exam_id} için soru bulunamadı")

        q_max: dict[int, float] = {}
        q_meta: dict[int, tuple[int, str | None]] = {}
        for qid, pts, q_no, q_text in q_rows:
            pts_f = float(pts)
            if pts_f <= 0:
                raise MissingDataError(
                    f"Soru {qid} (exam_id={exam_id}): max puan 0 veya negatif olamaz"
                )
            q_max[int(qid)] = pts_f
            q_meta[int(qid)] = (int(q_no) if q_no is not None else 0, q_text)

        q_id_list = list(q_max.keys())

        # Soru bazında öğrenci ortalamaları (filtreli ya da tüm öğrenciler)
        if student_ids is not None:
            cur.execute(
                """
                SELECT question_id, AVG(score)
                FROM responses
                WHERE question_id = ANY(%s)
                  AND student_id  = ANY(%s)
                GROUP BY question_id
                """,
                (q_id_list, student_ids),
            )
        else:
            cur.execute(
                """
                SELECT question_id, AVG(score)
                FROM responses
                WHERE question_id = ANY(%s)
                GROUP BY question_id
                """,
                (q_id_list,),
            )

        avg_rows = cur.fetchall()
        if not avg_rows:
            raise MissingDataError(
                f"Sınav {exam_id} için yanıt verisi bulunamadı"
                + (" (filtreli öğrenciler)" if student_ids is not None else "")
            )

        # Normalize: öğrenci ort. / max puan → 0..1
        q_avg_norm: dict[int, float] = {
            int(qid): min(float(avg) / q_max[int(qid)], 1.0)
            for qid, avg in avg_rows
            if int(qid) in q_max
        }

        # Soru–DÖÇ ağırlıkları
        cur.execute(
            """
            SELECT question_id, outcome_id, weight
            FROM question_outcomes
            WHERE question_id = ANY(%s)
            """,
            (q_id_list,),
        )
        qo_rows = cur.fetchall()
        if not qo_rows:
            raise MissingDataError(
                f"Sınav {exam_id} için Soru→DÖÇ eşlemesi bulunamadı. "
                "Önce soru ağırlıklarını kaydedin."
            )

        # DÖÇ skorları: ağırlıklı ortalama
        # Yanıt olmayan sorular pay+paydadan birlikte düşülür.
        doc_sum:  dict[int, float] = {}
        doc_wsum: dict[int, float] = {}
        # outcome_id -> [(question_id, q_norm, weight), ...] — kanıt için
        doc_contribs: dict[int, list[tuple[int, float, float]]] = {}
        for qid, oid, w in qo_rows:
            qid, oid = int(qid), int(oid)
            w = float(w)
            norm = q_avg_norm.get(qid)
            if norm is None:
                continue
            doc_sum[oid]  = doc_sum.get(oid, 0.0)  + norm * w
            doc_wsum[oid] = doc_wsum.get(oid, 0.0) + w
            if collect_evidence:
                doc_contribs.setdefault(oid, []).append((qid, norm, w))

        doc_scores: dict[int, float] = {
            oid: doc_sum[oid] / doc_wsum[oid]
            for oid in doc_sum
            if doc_wsum.get(oid, 0.0) > 0
        }

        # Soru-bazlı kanıt: katkı_pct = (q_norm × w) / Σ_q(w) × 100
        doc_evidence: dict[int, list[DocQuestionEvidence]] = {}
        if collect_evidence:
            for oid, contribs in doc_contribs.items():
                wsum = doc_wsum.get(oid, 0.0)
                if wsum <= 0:
                    continue
                ev_list: list[DocQuestionEvidence] = []
                for qid, norm, w in contribs:
                    q_no, q_text = q_meta.get(qid, (0, None))
                    ev_list.append(DocQuestionEvidence(
                        exam_id=exam_id,
                        exam_title=str(exam_title),
                        category=category,
                        question_id=qid,
                        q_no=q_no,
                        q_text=q_text,
                        q_norm=norm,
                        weight=w,
                        contribution_pct=round((norm * w) / wsum * 100.0, 4),
                    ))
                ev_list.sort(key=lambda e: e.q_no)
                doc_evidence[oid] = ev_list

        # DÖÇ–PÇ matrisi → PÇ skorları
        pc_sum:  dict[int, float] = {}
        pc_wsum: dict[int, float] = {}
        if doc_scores:
            cur.execute(
                """
                SELECT outcome_id, program_outcome_id, value
                FROM outcome_matrix
                WHERE outcome_id = ANY(%s)
                """,
                (list(doc_scores.keys()),),
            )
            for oid, po_id, val in cur.fetchall():
                oid, po_id = int(oid), int(po_id)
                val = float(val)
                if val <= 0:
                    continue
                score = doc_scores.get(oid)
                if score is None:
                    continue
                pc_sum[po_id]  = pc_sum.get(po_id, 0.0)  + score * val
                pc_wsum[po_id] = pc_wsum.get(po_id, 0.0) + val

        pc_scores: dict[int, float] = {
            po_id: pc_sum[po_id] / pc_wsum[po_id]
            for po_id in pc_sum
            if pc_wsum.get(po_id, 0.0) > 0
        }

    return ExamAttainment(
        exam_id=exam_id,
        exam_title=str(exam_title),
        exam_type=exam_type,
        category=category,
        doc_scores=doc_scores,
        pc_scores=pc_scores,
        doc_evidence=doc_evidence if collect_evidence else {},
    )


# ---------------------------------------------------------------------------
# Öğrenci geçme notları
# ---------------------------------------------------------------------------

def compute_student_grades(
    *,
    conn: psycopg.Connection,
    offering_id: int,
) -> list[StudentGrade]:
    """
    Bir ders şubesindeki (offering_id) tüm öğrencilerin geçme notunu hesaplar.

    Bütünleme kuralı (Excel ile birebir):
      - Öğrenci bütünlemeye girdiyse  → %40 vize + %60 bütünleme
      - Bütünlemeye girmediyse        → %40 vize + %60 final
      - Yalnızca vize varsa           → vize notu
      - Hiç sınava girmemişse         → basari_notu=None, harf_notu=None

    Raises:
        MissingDataError: offering_id bulunamazsa
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM course_offerings WHERE id = %s", (offering_id,)
        )
        if cur.fetchone() is None:
            raise MissingDataError(f"Ders şubesi bulunamadı: offering_id={offering_id}")

        cur.execute(
            "SELECT id, exam_type FROM exams WHERE offering_id = %s",
            (offering_id,),
        )
        exams = cur.fetchall()
        if not exams:
            return []

        exam_by_cat: dict[str, list[int]] = {"vize": [], "final": [], "butunleme": []}
        for eid, etype in exams:
            exam_by_cat[_exam_category(etype)].append(int(eid))

        vize_scores      = _compute_student_totals(cur, exam_by_cat["vize"])
        final_scores     = _compute_student_totals(cur, exam_by_cat["final"])
        butunleme_scores = _compute_student_totals(cur, exam_by_cat["butunleme"])

        all_student_ids = set(vize_scores) | set(final_scores) | set(butunleme_scores)
        if not all_student_ids:
            return []

        cur.execute(
            "SELECT id, student_no, name FROM students WHERE id = ANY(%s)",
            (list(all_student_ids),),
        )
        student_info: dict[int, tuple[str, str | None]] = {
            int(sid): (sno, sname) for sid, sno, sname in cur.fetchall()
        }

    grades: list[StudentGrade] = []
    for sid in all_student_ids:
        vize_s      = vize_scores.get(sid)
        final_s     = final_scores.get(sid)
        butunleme_s = butunleme_scores.get(sid)

        # Bütünlemeye girdiyse terminal = bütünleme, yoksa final
        terminal = butunleme_s if butunleme_s is not None else final_s

        if vize_s is not None and terminal is not None:
            basari = round(VIZE_WEIGHT * vize_s + FINAL_WEIGHT * terminal, 2)
        elif terminal is not None:
            basari = round(terminal, 2)
        elif vize_s is not None:
            basari = round(vize_s, 2)
        else:
            basari = None

        sno, sname = student_info.get(sid, ("", None))
        grades.append(StudentGrade(
            student_id=sid,
            student_no=sno,
            name=sname,
            vize_score=round(vize_s, 2) if vize_s is not None else None,
            final_score=round(final_s, 2) if final_s is not None else None,
            butunleme_score=round(butunleme_s, 2) if butunleme_s is not None else None,
            basari_notu=basari,
            harf_notu=compute_letter_grade(basari),
            passed=(basari is not None and basari >= PASSING_THRESHOLD),
        ))

    return sorted(grades, key=lambda g: g.student_no)


# ---------------------------------------------------------------------------
# Ders genelinde DÖÇ / PÇ başarı hesabı  (ana fonksiyon)
# ---------------------------------------------------------------------------

def calculate_course_attainment(
    *,
    conn: psycopg.Connection,
    course_id: int,
    passing_only: bool = True,
    offering_ids: list[int] | None = None,
    collect_evidence: bool = False,
) -> CourseAttainment:
    """
    Bir dersin tüm offering'leri üzerinden DÖÇ ve PÇ başarısını hesaplar.

    Excel şablonuyla birebir uyumlu mantık:

    1. Geçen öğrenci filtresi (passing_only=True, varsayılan):
       Her offering için önce başarı notları hesaplanır.
       Başarı Notu >= PASSING_THRESHOLD (varsayılan: 40) olan öğrenciler
       DÖÇ/PÇ hesabına dahil edilir. Bu, Excel'deki vizey/finaly/butunlemey
       sayfalarının mantığıyla birebir aynıdır.

    2. Bütünleme ayrımı:
       Bütünlemeye giren (geçen) öğrenciler final DÖÇ hesabından çıkarılır;
       bu öğrencilerin yanıtları bütünleme sınavından alınır.

    3. DÖÇ ders ortalaması (Excel DOC!AV formülüyle birebir):
       DÖÇ_course = AVERAGE(DÖÇ_vize, DÖÇ_final, DÖÇ_butunleme)
       Eksik sınav kategorisi (ör. bütünleme yoksa) ortalamadan düşülür.
       Not: 40/60 vize/final ağırlıklandırması yalnızca öğrenci başarı
       notunda kullanılır; DÖÇ/PÇ hesabında kullanılmaz.

    4. Birden fazla offering varsa dönem ortalaması alınır.

    Args:
        course_id:    Dersin DB id'si
        passing_only: True → sadece geçen öğrenciler (Excel uyumlu, varsayılan)
                      False → tüm öğrenciler dahil edilir
        offering_ids: Belirtilirse yalnızca bu offering'ler dahil edilir
                      (dönem bazlı trend analizi için kullanılır)

    Raises:
        MissingDataError: gerekli veri yoksa
    """
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM courses WHERE id = %s", (course_id,))
        if cur.fetchone() is None:
            raise MissingDataError(f"Ders bulunamadı: course_id={course_id}")

        if offering_ids is not None:
            cur.execute(
                """
                SELECT e.id, e.title, e.exam_type, e.offering_id
                FROM exams e
                JOIN course_offerings co ON co.id = e.offering_id
                WHERE co.course_id = %s AND co.id = ANY(%s)
                ORDER BY co.id, e.date NULLS LAST, e.id
                """,
                (course_id, offering_ids),
            )
        else:
            cur.execute(
                """
                SELECT e.id, e.title, e.exam_type, e.offering_id
                FROM exams e
                JOIN course_offerings co ON co.id = e.offering_id
                WHERE co.course_id = %s
                ORDER BY co.id, e.date NULLS LAST, e.id
                """,
                (course_id,),
            )
        exam_rows = cur.fetchall()

    if not exam_rows:
        raise MissingDataError(f"course_id={course_id} için sınav bulunamadı")

    # Offering bazında sınavları grupla
    offerings: dict[int, dict[str, list[tuple[int, str, str | None]]]] = {}
    for eid, etitle, etype, oid in exam_rows:
        oid = int(oid)
        offerings.setdefault(oid, {"vize": [], "final": [], "butunleme": []})
        offerings[oid][_exam_category(etype)].append((int(eid), str(etitle), etype))

    all_exam_attainments: list[ExamAttainment] = []
    all_offering_doc:     list[dict[int, float]] = []
    errors:               list[str] = []
    warnings:             list[str] = []
    total_students_all  = 0
    total_students_pass = 0
    letter_dist: dict[str, int] = {l: 0 for _, l in LETTER_GRADE_THRESHOLDS}

    for oid, groups in offerings.items():
        try:
            for g in compute_student_grades(conn=conn, offering_id=oid):
                if g.harf_notu:
                    letter_dist[g.harf_notu] = letter_dist.get(g.harf_notu, 0) + 1
        except MissingDataError:
            pass
        exam_by_cat_ids: dict[str, list[int]] = {
            "vize":      [eid for eid, _, _ in groups["vize"]],
            "final":     [eid for eid, _, _ in groups["final"]],
            "butunleme": [eid for eid, _, _ in groups["butunleme"]],
        }

        # ── Adım 1: Geçen öğrencileri belirle ──────────────────────────────
        with conn.cursor() as cur:
            if passing_only:
                passing_ids, n_total, n_pass = _get_passing_student_ids(
                    cur, exam_by_cat_ids
                )
                total_students_all  += n_total
                total_students_pass += n_pass
                if n_total > 0 and n_pass == 0:
                    warnings.append(
                        f"offering={oid}: {n_total} öğrenciden hiçbiri geçemedi, "
                        "DÖÇ hesabı tüm öğrencilerle yapıldı"
                    )
                    # Hiç kimse geçmemişse tüm öğrencilerle devam et
                    passing_ids = None  # type: ignore[assignment]
                    n_pass = n_total
            else:
                passing_ids = None   # tüm öğrenciler
                n_total = n_pass = 0  # sayaç kullanılmıyor

        # ── Adım 2: Bütünlemeye giren (geçen) öğrencileri bul ──────────────
        with conn.cursor() as cur:
            butunleme_sids_all = _get_students_of_exams(cur, exam_by_cat_ids["butunleme"])

        # Geçen öğrenci filtresiyle kesişim
        if passing_ids is not None and butunleme_sids_all:
            butunleme_sids = [s for s in butunleme_sids_all if s in passing_ids]
        else:
            butunleme_sids = butunleme_sids_all

        # Final filtresi: bütünlemeciler hariç, geçenler
        if butunleme_sids and exam_by_cat_ids["final"]:
            with conn.cursor() as cur:
                all_final_sids = _get_students_of_exams(cur, exam_by_cat_ids["final"])
            butunleme_set = set(butunleme_sids)
            if passing_ids is not None:
                final_filter: list[int] | None = [
                    s for s in all_final_sids
                    if s not in butunleme_set and s in passing_ids
                ]
            else:
                final_filter = [s for s in all_final_sids if s not in butunleme_set]
        elif passing_ids is not None and exam_by_cat_ids["final"]:
            # Bütünleme yok ama filtre var
            final_filter = list(passing_ids)
        else:
            final_filter = None  # filtre yok, tüm öğrenciler

        # Vize filtresi: geçenler (bütünleme ayrımı yok)
        vize_filter: list[int] | None = list(passing_ids) if passing_ids is not None else None

        # ── Adım 3: Sınav başarılarını hesapla ─────────────────────────────

        # Vize
        vize_atts: list[ExamAttainment] = []
        for eid, _, _ in groups["vize"]:
            try:
                att = compute_exam_attainment(
                    conn=conn, exam_id=eid, student_ids=vize_filter,
                    collect_evidence=collect_evidence,
                )
                vize_atts.append(att)
                all_exam_attainments.append(att)
            except MissingDataError as e:
                errors.append(f"offering={oid}, vize exam={eid}: {e}")

        # Final (bütünlemeciler + başarısızlar hariç)
        final_atts: list[ExamAttainment] = []
        for eid, _, _ in groups["final"]:
            try:
                att = compute_exam_attainment(
                    conn=conn, exam_id=eid, student_ids=final_filter,
                    collect_evidence=collect_evidence,
                )
                final_atts.append(att)
                all_exam_attainments.append(att)
            except MissingDataError as e:
                errors.append(f"offering={oid}, final exam={eid}: {e}")

        # Bütünleme (sadece bütünlemeye giren geçen öğrenciler)
        butunleme_atts: list[ExamAttainment] = []
        for eid, _, _ in groups["butunleme"]:
            try:
                att = compute_exam_attainment(
                    conn=conn,
                    exam_id=eid,
                    student_ids=butunleme_sids if butunleme_sids else [],
                    collect_evidence=collect_evidence,
                )
                butunleme_atts.append(att)
                all_exam_attainments.append(att)
            except MissingDataError as e:
                errors.append(f"offering={oid}, butunleme exam={eid}: {e}")

        # ── Adım 4: Vize / Final / Bütünleme DÖÇ'lerini birleştir ─────────
        # Excel şablonu (DOC!AV sütunu): DÖÇ_course = AVERAGE(DÖÇ_vize,
        # DÖÇ_final, DÖÇ_butunleme).  Eksik olan sınav kategorisi (ör.
        # bütünleme yapılmamışsa) ortalamadan düşülür.
        vize_doc      = _avg_doc_scores(vize_atts)
        final_doc     = _avg_doc_scores(final_atts)
        butunleme_doc = _avg_doc_scores(butunleme_atts)

        if not vize_doc and not final_doc and not butunleme_doc:
            errors.append(
                f"offering={oid}: hesaplanabilir sınav verisi yok, bu offering atlandı"
            )
            continue

        all_oids = set(vize_doc) | set(final_doc) | set(butunleme_doc)
        offering_doc: dict[int, float] = {}
        for oid_key in all_oids:
            vals = [
                d[oid_key] for d in (vize_doc, final_doc, butunleme_doc)
                if oid_key in d
            ]
            if vals:
                offering_doc[oid_key] = sum(vals) / len(vals)
        all_offering_doc.append(offering_doc)

    if not all_offering_doc:
        detail = "; ".join(errors) if errors else "bilinmeyen sebep"
        raise MissingDataError(
            f"DÖÇ hesabı için yeterli veri bulunamadı. Detaylar: {detail}"
        )

    # ── Adım 5: Dönem ortalaması ────────────────────────────────────────────
    combined_doc: dict[int, list[float]] = {}
    for od in all_offering_doc:
        for oid_key, score in od.items():
            combined_doc.setdefault(oid_key, []).append(score)

    doc_attainment: dict[int, float] = {
        oid_key: round(sum(v) / len(v), 6)
        for oid_key, v in combined_doc.items()
    }

    # ── Defansif kontrol: PÇ hesabından önce tüm tanımlı DÖÇ'ler puanlanmış
    # olmalı — eksik DÖÇ ile PÇ hesaplamak akademik olarak geçersizdir (MÜDEK).
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, sequence_number FROM course_learning_outcomes "
            "WHERE course_id = %s ORDER BY sequence_number",
            (course_id,),
        )
        defined_docs = cur.fetchall()

    if not defined_docs:
        raise MissingDataError(
            "Bu ders için DÖÇ tanımlanmamış. "
            "Öncelikle DÖÇ puanlarını eksiksiz girmeniz gerekmektedir."
        )

    missing = [str(seq) for doc_id, seq in defined_docs if int(doc_id) not in doc_attainment]
    if missing:
        raise MissingDataError(
            "Öncelikle DÖÇ puanlarını eksiksiz girmeniz gerekmektedir. "
            "Puanı hesaplanamayan DÖÇ'ler: DÖÇ " + ", DÖÇ ".join(missing)
        )

    # ── Adım 6: PÇ başarısı ────────────────────────────────────────────────
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT outcome_id, program_outcome_id, value
            FROM outcome_matrix
            WHERE outcome_id = ANY(%s)
            """,
            (list(doc_attainment.keys()),),
        )
        om_rows = cur.fetchall()

    pc_sum:  dict[int, float] = {}
    pc_wsum: dict[int, float] = {}
    # po_id -> [(outcome_id, doc_score, matrix_value), ...]
    pc_contribs: dict[int, list[tuple[int, float, float]]] = {}
    for oid_key, po_id, val in om_rows:
        oid_key, po_id = int(oid_key), int(po_id)
        val = float(val)
        if val <= 0:
            continue
        score = doc_attainment.get(oid_key)
        if score is None:
            continue
        pc_sum[po_id]  = pc_sum.get(po_id, 0.0)  + score * val
        pc_wsum[po_id] = pc_wsum.get(po_id, 0.0) + val
        if collect_evidence:
            pc_contribs.setdefault(po_id, []).append((oid_key, score, val))

    pc_attainment: dict[int, float] = {
        po_id: round(pc_sum[po_id] / pc_wsum[po_id], 6)
        for po_id in pc_sum
        if pc_wsum.get(po_id, 0.0) > 0
    }

    # DÖÇ karşılanma durumu (met / not_met)
    doc_status: dict[int, str] = {
        oid: ("met" if score >= DOC_ATTAINMENT_THRESHOLD else "not_met")
        for oid, score in doc_attainment.items()
    }

    # ── Kanıt zincirleri ─────────────────────────────────────────────────
    doc_evidence_agg: dict[int, list[DocQuestionEvidence]] = {}
    pc_evidence_agg:  dict[int, list[PcDocEvidence]]       = {}
    if collect_evidence:
        # DÖÇ kanıtı: tüm exam_results'tan flat olarak topla
        for ea in all_exam_attainments:
            for oid_key, ev_list in ea.doc_evidence.items():
                doc_evidence_agg.setdefault(oid_key, []).extend(ev_list)

        # PÇ kanıtı: outcome_seq lookup için DB'den çek
        outcome_seq_map: dict[int, int | None] = {}
        if pc_contribs:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, sequence_number FROM course_learning_outcomes "
                    "WHERE id = ANY(%s)",
                    (list(doc_attainment.keys()),),
                )
                outcome_seq_map = {
                    int(oid): (int(seq) if seq is not None else None)
                    for oid, seq in cur.fetchall()
                }

        for po_id, contribs in pc_contribs.items():
            wsum = pc_wsum.get(po_id, 0.0)
            if wsum <= 0:
                continue
            ev_list_pc: list[PcDocEvidence] = []
            for oid_key, doc_score, mv in contribs:
                ev_list_pc.append(PcDocEvidence(
                    outcome_id=oid_key,
                    outcome_seq=outcome_seq_map.get(oid_key),
                    doc_score=doc_score,
                    matrix_value=mv,
                    contribution_pct=round((doc_score * mv) / wsum * 100.0, 4),
                ))
            ev_list_pc.sort(key=lambda e: (e.outcome_seq if e.outcome_seq is not None else 9999, e.outcome_id))
            pc_evidence_agg[po_id] = ev_list_pc

    if errors:
        warnings.extend(errors)

    return CourseAttainment(
        course_id=course_id,
        exam_results=all_exam_attainments,
        doc_attainment=doc_attainment,
        pc_attainment=pc_attainment,
        doc_status=doc_status,
        students_total=total_students_all,
        students_passing=total_students_pass,
        warnings=warnings,
        letter_grade_distribution=letter_dist,
        doc_evidence=doc_evidence_agg,
        pc_evidence=pc_evidence_agg,
    )


# ---------------------------------------------------------------------------
# main.py ile uyumluluk katmanı
# ---------------------------------------------------------------------------

def calculate_mudek_results(
    *,
    course_id: int,
    conn: psycopg.Connection,
) -> dict:
    """
    main.py'daki mevcut API endpoint'leriyle geriye dönük uyumluluk için
    calculate_course_attainment'ı dict formatında döndürür.

    Dönen yapı:
    {
        "course_id": int,
        "exam_results": [...],
        "doc_attainment": {outcome_id: float, ...},
        "pc_attainment":  {program_outcome_id: float, ...},
        "students_total":   int,
        "students_passing": int,
        "warning": str | None,
    }
    """
    try:
        result = calculate_course_attainment(conn=conn, course_id=course_id)
        return {
            "course_id":        result.course_id,
            "exam_results": [
                {
                    "exam_id":    ea.exam_id,
                    "exam_title": ea.exam_title,
                    "exam_type":  ea.exam_type,
                    "category":   ea.category,
                    "doc_scores": {str(k): v for k, v in ea.doc_scores.items()},
                    "pc_scores":  {str(k): v for k, v in ea.pc_scores.items()},
                }
                for ea in result.exam_results
            ],
            "doc_attainment":   {str(k): v for k, v in result.doc_attainment.items()},
            "pc_attainment":    {str(k): v for k, v in result.pc_attainment.items()},
            "doc_status":       {str(k): v for k, v in result.doc_status.items()},
            "students_total":   result.students_total,
            "students_passing": result.students_passing,
            "warning": "; ".join(result.warnings) if result.warnings else None,
        }
    except MissingDataError as e:
        return {"error": str(e)}
    except MudekError as e:
        return {"error": f"Hesaplama hatası: {e}"}
