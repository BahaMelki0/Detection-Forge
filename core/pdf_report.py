"""Portable PDF export for the current persisted investigation state."""

from __future__ import annotations

from io import BytesIO
import re
import unicodedata
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _text(value: object) -> str:
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    return escape(re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)).replace("\n", "<br/>")


def render_case_pdf(investigation) -> bytes:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CaseTitle", parent=styles["Title"], textColor=colors.HexColor("#be2535"), spaceAfter=6))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=colors.HexColor("#be2535"), spaceBefore=14, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], fontSize=8.5, leading=12, spaceAfter=5))
    story = [Paragraph(_text(investigation.name), styles["CaseTitle"]),
             Paragraph(f"Case {investigation.id} | Status: {_text(investigation.status)}", styles["SmallBody"]),
             Paragraph(f"Created: {_text(investigation.created_at)} | Updated: {_text(investigation.updated_at)}", styles["SmallBody"])]
    if investigation.description:
        story.append(Paragraph(_text(investigation.description), styles["SmallBody"]))
    if investigation.resolution_notes:
        story += [Paragraph("Resolution", styles["Section"]), Paragraph(_text(investigation.resolution_notes), styles["SmallBody"])]
    summary = [
        ["Files", str(len(investigation.files)), "Events", str(len(investigation.events)), "Alerts", str(len(investigation.alerts))],
    ]
    table = Table(summary, colWidths=[20 * mm, 16 * mm, 22 * mm, 16 * mm, 20 * mm, 16 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f1f4")),
                               ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#191c22")),
                               ("BOX", (0, 0), (-1, -1), .4, colors.HexColor("#c6c8cf")),
                               ("INNERGRID", (0, 0), (-1, -1), .3, colors.HexColor("#c6c8cf")),
                               ("PADDING", (0, 0), (-1, -1), 8)]))
    story += [Spacer(1, 6 * mm), table, Paragraph("Detection alerts", styles["Section"])]
    if investigation.alerts:
        for alert in investigation.alerts:
            files = sorted({name for event in alert.events for name in (event.get("origin_files") or [event.get("origin_file") or "Unknown"])})
            story.append(Paragraph(f"{_text(alert.severity.upper())} | {_text(alert.rule_id)} | {_text(alert.timestamp)}", styles["SmallBody"]))
            story.append(Paragraph(f"<b>{_text(alert.rule_title)}</b>", styles["BodyText"]))
            story.append(Paragraph(_text(alert.description), styles["SmallBody"]))
            review = investigation.alert_reviews.get(alert.id, {})
            story.append(Paragraph(f"Analyst disposition: {_text(review.get('disposition', 'new'))} | Notes: {_text(review.get('notes', 'Not recorded'))}", styles['SmallBody']))
            story.append(Paragraph(f"Sources: {_text(', '.join(alert.sources))} | Input files: {_text(', '.join(files))}", styles["SmallBody"]))
            story.append(Paragraph(f"ATT&amp;CK: {_text(alert.attack.get('id'))} - {_text(alert.attack.get('name'))}", styles["SmallBody"]))
            story.append(Paragraph(f"Recommended response: {_text(alert.remediation)}", styles["SmallBody"]))
            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Paragraph("No alerts have been generated for this case.", styles["SmallBody"]))
    story.append(Paragraph("Evidence inventory", styles["Section"]))
    if investigation.files:
        rows = [["File", "Profile", "Events", "Uploaded"]]
        rows.extend([[ _text(item.filename), _text(item.profile), str(item.event_count), _text(item.uploaded_at)] for item in investigation.files])
        rows = [[Paragraph(str(cell), styles['SmallBody']) for cell in row] for row in rows]
        inventory = Table(rows, repeatRows=1, colWidths=[65 * mm, 35 * mm, 16 * mm, 60 * mm])
        inventory.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9e9ed")),
                                       ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                       ("GRID", (0, 0), (-1, -1), .3, colors.HexColor("#c6d2d8")),
                                       ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                       ("PADDING", (0, 0), (-1, -1), 5)]))
        story.append(inventory)
    else:
        story.append(Paragraph("No files ingested.", styles["SmallBody"]))
    if investigation.ai_analysis:
        story += [Paragraph("AI correlation and analysis", styles["Section"]),
                  Paragraph(_text(investigation.ai_analysis), styles["SmallBody"]),
                  Paragraph(f"Local model analysis generated: {_text(investigation.ai_analyzed_at)}. Analyst review required.", styles["SmallBody"])]
    buffer = BytesIO()
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#686d78'))
        canvas.drawString(17 * mm, 9 * mm, 'Detection Forge | Analyst review required')
        canvas.drawRightString(193 * mm, 9 * mm, f'Page {document.page}')
        canvas.restoreState()
    SimpleDocTemplate(buffer, pagesize=A4, rightMargin=17 * mm, leftMargin=17 * mm,
                      topMargin=16 * mm, bottomMargin=16 * mm, title=investigation.name).build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
