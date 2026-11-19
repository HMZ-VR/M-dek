"""
Komisyon Konsolide Rapor PDF Üreteci
=====================================

Onaylanmış (status='approved') raporları tek bir PDF dosyasında birleştirir.
MÜDEK denetiminde sabit URL ile erişilebilir kanıt çıktısı sağlar.

Kullanım:
    pdf_bytes = build_committee_consolidated_pdf(conn, committee_id, period=None, report_type=None)
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from typing import Any

import psycopg
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak,
)


# ── Türkçe karakter desteği için DejaVuSans ───────────────────────────
_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]
_BASE_FONT = "Helvetica"
_BOLD_FONT = "Helvetica-Bold"


def _register_fonts() -> None:
    global _BASE_FONT, _BOLD_FONT
    reg = "DejaVuSans"
    bold = "DejaVuSans-Bold"
    try:
        if os.path.isfile(_FONT_CANDIDATES[0]):
            pdfmetrics.registerFont(TTFont(reg, _FONT_CANDIDATES[0]))
            _BASE_FONT = reg
        if os.path.isfile(_FONT_CANDIDATES[1]):
            pdfmetrics.registerFont(TTFont(bold, _FONT_CANDIDATES[1]))
            _BOLD_FONT = bold
    except Exception:
        # Font kayıt hatası → Helvetica fallback (Türkçe karakter sorun çıkarabilir)
        pass


_register_fonts()


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "TitleX", parent=ss["Title"],
            fontName=_BOLD_FONT, fontSize=22, leading=26,
            textColor=colors.HexColor("#0b1f45"), alignment=1, spaceAfter=12,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=ss["Normal"],
            fontName=_BASE_FONT, fontSize=12, textColor=colors.HexColor("#555"),
            alignment=1, spaceAfter=20,
        ),
        "h1": ParagraphStyle(
            "H1", parent=ss["Heading1"],
            fontName=_BOLD_FONT, fontSize=16, leading=20,
            textColor=colors.HexColor("#0b1f45"), spaceBefore=10, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2", parent=ss["Heading2"],
            fontName=_BOLD_FONT, fontSize=13, leading=16,
            textColor=colors.HexColor("#c9a84c"), spaceBefore=6, spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "Meta", parent=ss["Normal"],
            fontName=_BASE_FONT, fontSize=9, leading=12,
            textColor=colors.HexColor("#666"), spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=ss["Normal"],
            fontName=_BASE_FONT, fontSize=10.5, leading=15,
            textColor=colors.HexColor("#222"), spaceAfter=4,
        ),
        "kv_label": ParagraphStyle(
            "KvLabel", parent=ss["Normal"],
            fontName=_BOLD_FONT, fontSize=9, textColor=colors.HexColor("#0b1f45"),
        ),
    }


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _draw_header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(colors.HexColor("#0b1f45"))
    canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
    canvas.setFont(_BOLD_FONT, 9)
    canvas.setFillColor(colors.white)
    canvas.drawString(1.5 * cm, h - 0.8 * cm, "MÜDEK · Komisyon Konsolide Raporu")
    canvas.drawRightString(w - 1.5 * cm, h - 0.8 * cm,
                           datetime.now().strftime("%d.%m.%Y"))
    canvas.setFont(_BASE_FONT, 8)
    canvas.setFillColor(colors.HexColor("#888"))
    canvas.drawCentredString(w / 2, 0.8 * cm, f"Sayfa {doc.page}")
    canvas.restoreState()


def _fetch_committee(cur, committee_id: int) -> dict | None:
    cur.execute(
        "SELECT id, name, description, created_at FROM committees WHERE id = %s",
        (committee_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return {"id": row[0], "name": row[1], "description": row[2], "created_at": row[3]}


def _fetch_members(cur, committee_id: int) -> list[dict]:
    cur.execute(
        """
        SELECT u.full_name, u.username
        FROM committee_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.committee_id = %s
        ORDER BY u.full_name
        """,
        (committee_id,),
    )
    return [{"name": r[0], "username": r[1]} for r in cur.fetchall()]


def _fetch_approved_reports(
    cur,
    committee_id: int,
    period: str | None,
    report_type: str | None,
) -> list[dict]:
    where = ["r.committee_id = %s", "r.status = 'approved'"]
    params: list[Any] = [committee_id]
    if period:
        where.append("r.period = %s")
        params.append(period)
    if report_type:
        where.append("r.report_type = %s")
        params.append(report_type)

    cur.execute(
        f"""
        SELECT r.id, r.title, r.content, r.report_type, r.period,
               r.submitted_at, r.reviewed_at, r.review_note,
               u.full_name AS uploader_name,
               ru.full_name AS reviewer_name
        FROM committee_reports r
        JOIN users u ON u.id = r.uploader_id
        LEFT JOIN users ru ON ru.id = r.reviewer_id
        WHERE {" AND ".join(where)}
        ORDER BY COALESCE(r.report_type, 'zzz'), r.reviewed_at
        """,
        params,
    )
    cols = [d[0] for d in cur.description]
    reports = [dict(zip(cols, r)) for r in cur.fetchall()]

    if reports:
        ids = [r["id"] for r in reports]
        cur.execute(
            """
            SELECT report_id, original_name, file_size
            FROM committee_report_attachments
            WHERE report_id = ANY(%s)
            ORDER BY uploaded_at
            """,
            (ids,),
        )
        atts: dict[int, list[dict]] = {}
        for rid, name, size in cur.fetchall():
            atts.setdefault(int(rid), []).append({
                "name": name, "size": size,
            })
        for r in reports:
            r["attachments"] = atts.get(r["id"], [])
    return reports


def _fmt_dt(dt) -> str:
    if not dt:
        return "—"
    if isinstance(dt, datetime):
        return dt.strftime("%d.%m.%Y")
    return str(dt)[:10]


def _fmt_size(b) -> str:
    if not b:
        return "—"
    b = int(b)
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.0f} KB"
    return f"{b / 1024 / 1024:.1f} MB"


def build_committee_consolidated_pdf(
    conn: psycopg.Connection,
    committee_id: int,
    period: str | None = None,
    report_type: str | None = None,
) -> bytes:
    """
    Komitenin onaylı raporlarından konsolide PDF üretir, byte cinsinden döner.
    period / report_type ile filtreleme opsiyoneldir.
    """
    with conn.cursor() as cur:
        committee = _fetch_committee(cur, committee_id)
        if not committee:
            raise ValueError(f"Komisyon bulunamadı: {committee_id}")
        members = _fetch_members(cur, committee_id)
        reports = _fetch_approved_reports(cur, committee_id, period, report_type)

    styles = _styles()
    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"Konsolide Rapor — {committee['name']}",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="normal")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame],
                                       onPage=_draw_header_footer)])

    story: list = []

    # ── Kapak ─────────────────────────────────────
    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph("MÜDEK Komisyon Konsolide Raporu", styles["title"]))
    story.append(Paragraph(_esc(committee["name"]), styles["subtitle"]))

    cover_data = [
        ["Komisyon", _esc(committee["name"])],
        ["Açıklama", _esc(committee.get("description") or "—")],
        ["Oluşturulma", _fmt_dt(committee.get("created_at"))],
        ["Üye Sayısı", str(len(members))],
        ["Onaylı Rapor Sayısı", str(len(reports))],
    ]
    if period:
        cover_data.append(["Dönem Filtresi", _esc(period)])
    if report_type:
        cover_data.append(["Tip Filtresi", _esc(report_type)])
    cover_data.append(["Üretim Tarihi", datetime.now().strftime("%d.%m.%Y %H:%M")])

    tbl = Table(cover_data, colWidths=[5 * cm, 11 * cm])
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _BASE_FONT),
        ("FONTNAME", (0, 0), (0, -1), _BOLD_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0b1f45")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f5f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#eee")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)

    if members:
        story.append(Spacer(1, 0.7 * cm))
        story.append(Paragraph("Komisyon Üyeleri", styles["h2"]))
        for m in members:
            story.append(Paragraph(f"• {_esc(m['name'])}", styles["body"]))

    if not reports:
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            "Bu filtreyle eşleşen onaylı rapor bulunamadı.",
            styles["body"],
        ))
        doc.build(story)
        return buf.getvalue()

    story.append(PageBreak())

    # ── İçindekiler ───────────────────────────────
    story.append(Paragraph("İçindekiler", styles["h1"]))
    toc_rows = [["#", "Tip", "Başlık", "Yazar", "Onay Tarihi"]]
    for idx, r in enumerate(reports, 1):
        toc_rows.append([
            str(idx),
            _esc(r.get("report_type") or "—"),
            _esc(r["title"])[:60],
            _esc(r["uploader_name"]),
            _fmt_dt(r.get("reviewed_at")),
        ])
    toc = Table(toc_rows, colWidths=[1 * cm, 4 * cm, 7 * cm, 3.5 * cm, 2.5 * cm])
    toc.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _BASE_FONT),
        ("FONTNAME", (0, 0), (-1, 0), _BOLD_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f45")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f7f5f0")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#eee")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(toc)

    # ── Her rapor ──────────────────────────────────
    for idx, r in enumerate(reports, 1):
        story.append(PageBreak())
        story.append(Paragraph(f"{idx}. {_esc(r['title'])}", styles["h1"]))

        meta_data = [
            ["Tip",      _esc(r.get("report_type") or "—")],
            ["Dönem",    _esc(r.get("period") or "—")],
            ["Yazar",    _esc(r["uploader_name"])],
            ["Gönderim", _fmt_dt(r.get("submitted_at"))],
            ["Onaylayan", _esc(r.get("reviewer_name") or "—")],
            ["Onay",     _fmt_dt(r.get("reviewed_at"))],
        ]
        meta_tbl = Table(meta_data, colWidths=[3.5 * cm, 12.5 * cm])
        meta_tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), _BASE_FONT),
            ("FONTNAME", (0, 0), (0, -1), _BOLD_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0b1f45")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f5f0")),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#ddd")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 0.4 * cm))

        if r.get("review_note"):
            story.append(Paragraph("Kurul Notu", styles["h2"]))
            story.append(Paragraph(_esc(r["review_note"]), styles["body"]))
            story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Rapor İçeriği", styles["h2"]))
        content = r.get("content") or "— İçerik girilmemiş —"
        for para in str(content).split("\n\n"):
            line = _esc(para).replace("\n", "<br/>")
            story.append(Paragraph(line, styles["body"]))
            story.append(Spacer(1, 0.1 * cm))

        atts = r.get("attachments") or []
        if atts:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph(f"Ekler ({len(atts)})", styles["h2"]))
            att_rows = [["#", "Dosya Adı", "Boyut"]]
            for i, a in enumerate(atts, 1):
                att_rows.append([str(i), _esc(a["name"]), _fmt_size(a["size"])])
            att_tbl = Table(att_rows, colWidths=[0.8 * cm, 12 * cm, 3 * cm])
            att_tbl.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), _BASE_FONT),
                ("FONTNAME", (0, 0), (-1, 0), _BOLD_FONT),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c9a84c")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#ddd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#eee")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(att_tbl)

    doc.build(story)
    return buf.getvalue()
