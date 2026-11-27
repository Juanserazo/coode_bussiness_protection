"""Portrait PDF rendering for the Base diagnostic."""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from functools import partial
from importlib.resources import files
from io import BytesIO
from textwrap import shorten
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

from .models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


PROJECT_NAME = "COODE BUSSINES PROTECTION"
REGULAR_FONT = "VeraSans"
BOLD_FONT = "VeraSans-Bold"

# Embed the fonts shipped with ReportLab for consistent viewing across platforms.
font_directory = files("reportlab").joinpath("fonts")
for font_name, filename in ((REGULAR_FONT, "Vera.ttf"), (BOLD_FONT, "VeraBd.ttf")):
    with font_directory.joinpath(filename).open("rb") as font_file:
        pdfmetrics.registerFont(TTFont(font_name, font_file))

PAGE_WIDTH, PAGE_HEIGHT = letter
MARGIN = 46
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN
OVERVIEW_HEIGHT = PAGE_HEIGHT - 249
NAVY = colors.HexColor("#0D1B2A")
NAVY_PANEL = colors.HexColor("#142838")
INK = colors.HexColor("#102B3C")
MUTED = colors.HexColor("#425D70")
LIGHT_TEXT = colors.HexColor("#D3E4EB")
TEAL = colors.HexColor("#13C6AE")
TEAL_DARK = colors.HexColor("#00796F")
PAPER = colors.HexColor("#F0F5F6")
RULE = colors.HexColor("#D8E4E8")
WHITE = colors.white

STATUS_COLORS = {
    VERIFIED: (colors.HexColor("#D5F0E8"), colors.HexColor("#087463")),
    NEEDS_REVIEW: (colors.HexColor("#FFF0D4"), colors.HexColor("#8B5100")),
    UNVERIFIED: (colors.HexColor("#E1EBEF"), colors.HexColor("#40596A")),
}
STATUS_DESCRIPTIONS = {
    VERIFIED: "Se obtuvo evidencia según el criterio del control.",
    NEEDS_REVIEW: "Se encontró una condición que conviene revisar.",
    UNVERIFIED: "La consulta o conexión quedó inconclusa.",
}
CONTROL_NAMES = {
    "MX": "Servidores de correo",
    "SPF": "Remitentes autorizados",
    "DMARC": "Política contra suplantación",
    "TLS": "Certificado del sitio",
    "HTTPS": "Respuesta del sitio",
}
MAIL_CONTROLS = {"MX", "SPF", "DMARC"}

REVIEW_ORDER = {"DMARC": 0, "SPF": 1, "MX": 2, "TLS": 3, "HTTPS": 4}
REVIEW_IMPACT = {
    "DMARC": "Afecta la política contra la suplantación del remitente.",
    "SPF": "Afecta la identificación de remitentes autorizados.",
    "MX": "Puede afectar la recepción del correo.",
    "TLS": "Puede afectar la confianza de los visitantes en la conexión.",
    "HTTPS": "Puede afectar el acceso a la página principal.",
}


def describe_controls(domain: str, web_host: str) -> dict[str, tuple[str, str]]:
    return {
        "MX": (
            f"Consulta DNS MX de {domain}.",
            "Identifica los servidores publicados para recibir correo o un MX nulo. "
            "La entrega de mensajes requiere una comprobación aparte.",
        ),
        "SPF": (
            f"Consulta DNS TXT de {domain} en busca de registros v=spf1.",
            "Comprueba si se publicó una política y si hay registros duplicados. "
            "La prueba no evalúa sus mecanismos ni autentica mensajes.",
        ),
        "DMARC": (
            f"Consulta DNS TXT de _dmarc.{domain} en busca de registros v=DMARC1.",
            "Comprueba si hay una política publicada y lee su etiqueta p. "
            "p=none expresa monitoreo y requiere revisar los remitentes antes de cambiarla. "
            "La prueba no evalúa la alineación SPF o DKIM de mensajes reales.",
        ),
        "TLS": (
            f"Conexión TLS a {web_host} por el puerto 443.",
            "Comprueba la confianza y el nombre del certificado. Si es válido, "
            "lee su vencimiento y marca para revisión los que vencen en 30 días o menos.",
        ),
        "HTTPS": (
            f"Solicitud GET a https://{web_host}/.",
            "Registra el primer código HTTP observado sin seguir redirecciones. "
            "Una respuesta describe ese momento y esa ruta.",
        ),
    }


def _style(name, size, leading, ink=INK, bold=False, **options):
    return ParagraphStyle(
        name, fontName=BOLD_FONT if bold else REGULAR_FONT,
        fontSize=size, leading=leading, textColor=ink, **options,
    )


BODY = _style("Body", 10.5, 14, MUTED)
SMALL = _style("Small", 9, 12, MUTED)
FIELD = _style("Field", 10, 14, TEAL_DARK, bold=True)
PRIORITY_LABEL = _style("Priority label", 9, 12, TEAL_DARK, bold=True)
VALUE = _style("Value", 11, 14, bold=True)
HEADING = _style("Heading", 21, 25, bold=True, keepWithNext=True)
SUBHEADING = _style("Subheading", 14, 18, bold=True, keepWithNext=True)
COLUMN = _style("Column", 9, 12, WHITE, bold=True)
CARD_TITLE = _style("Card title", 13, 17, bold=True)
COUNT = _style("Count", 29, 31, bold=True)
STATUS = {
    status: _style(f"Status {status}", 10, 13, foreground, bold=True)
    for status, (_, foreground) in STATUS_COLORS.items()
}
STATUS_RIGHT = {
    status: _style(f"Right status {status}", 10, 14, foreground, bold=True, alignment=TA_RIGHT)
    for status, (_, foreground) in STATUS_COLORS.items()
}


def _paragraph(value: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(" ".join(value.split())), style)


def _page_background(canvas, document, *, overview):
    header_height = 184 if overview else 112
    header_bottom = PAGE_HEIGHT - header_height
    canvas.saveState()
    canvas.setFillColor(PAPER)
    canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
    canvas.setFillColor(NAVY)
    canvas.rect(0, header_bottom, PAGE_WIDTH, header_height, stroke=0, fill=1)

    panel_left = PAGE_WIDTH - 132
    canvas.setFillColor(NAVY_PANEL)
    canvas.rect(panel_left, header_bottom, 132, header_height, stroke=0, fill=1)
    canvas.saveState()
    clip = canvas.beginPath()
    clip.rect(panel_left, header_bottom, 132, header_height)
    canvas.clipPath(clip, stroke=0, fill=0)
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(3)
    canvas.arc(panel_left - 68, header_bottom - 65, PAGE_WIDTH + 24,
               header_bottom + 78, startAng=0, extent=90)
    canvas.restoreState()

    canvas.setFillColor(TEAL)
    canvas.setFont(BOLD_FONT, 10)
    canvas.drawString(MARGIN, PAGE_HEIGHT - 40, PROJECT_NAME)
    canvas.setFillColor(WHITE)
    if overview:
        canvas.setFont(BOLD_FONT, 33)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 92, "Diagnóstico de dominio")
        canvas.drawString(MARGIN, PAGE_HEIGHT - 130, "y sitio web")
        canvas.setFont(REGULAR_FONT, 11)
        canvas.setFillColor(LIGHT_TEXT)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 157, "MX, SPF, DMARC, TLS y HTTPS")
    else:
        canvas.setFont(BOLD_FONT, 28)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 83, "Detalle de controles")

    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.7)
    canvas.line(MARGIN, 35, PAGE_WIDTH - MARGIN, 35)
    canvas.setFillColor(MUTED)
    canvas.setFont(BOLD_FONT, 8)
    canvas.drawString(MARGIN, 21, PROJECT_NAME)
    canvas.setFont(REGULAR_FONT, 8)
    canvas.drawRightString(PAGE_WIDTH - MARGIN, 21, f"{document.page:02}")
    canvas.restoreState()


def _overview_background(canvas, document):
    _page_background(canvas, document, overview=True)


def _details_background(canvas, document):
    _page_background(canvas, document, overview=False)


def _metadata(domain: str, web_host: str, timestamp: datetime) -> Table:
    rows = [
        [_paragraph("Dominio de correo", FIELD), _paragraph(domain, VALUE)],
        [_paragraph("Nombre web", FIELD), _paragraph(web_host, VALUE)],
        [_paragraph("Fecha de revisión", FIELD), _paragraph(f"{timestamp:%Y-%m-%d %H:%M} UTC", VALUE)],
    ]
    table = Table(rows, colWidths=[135, CONTENT_WIDTH - 135], splitInRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("LINEBEFORE", (0, 0), (0, -1), 3, TEAL),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _status_cards(findings: Sequence[Finding]) -> Table:
    counts = Counter(finding.status for finding in findings)
    cells = []
    styles = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]
    for index, (status, (background, foreground)) in enumerate(STATUS_COLORS.items()):
        column = index * 2
        if index:
            cells.append("")
        cells.append([
            _paragraph(status.capitalize(), STATUS[status]),
            _paragraph(str(counts[status]), COUNT),
            Spacer(1, 3),
            _paragraph(STATUS_DESCRIPTIONS[status], SMALL),
        ])
        styles.extend([
            ("BACKGROUND", (column, 0), (column, 0), background),
            ("LINEABOVE", (column, 0), (column, 0), 2, foreground),
        ])
    width = (CONTENT_WIDTH - 20) / 3
    table = Table([cells], colWidths=[width, 10, width, 10, width])
    table.setStyle(TableStyle(styles))
    return table


def _control_summary(findings: Sequence[Finding]) -> Table:
    rows = [[_paragraph(label, COLUMN) for label in ("CONTROL", "QUÉ REVISA", "ESTADO")]]
    styles = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PAPER]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, -1), (-1, -1), 0.7, RULE),
    ]
    for row_index, finding in enumerate(findings, start=1):
        rows.append([
            _paragraph(finding.control, VALUE),
            _paragraph(CONTROL_NAMES[finding.control], BODY),
            _paragraph(finding.status.capitalize(), STATUS[finding.status]),
        ])
        styles.append(
            ("BACKGROUND", (2, row_index), (2, row_index), STATUS_COLORS[finding.status][0])
        )
    table = Table(rows, colWidths=[88, CONTENT_WIDTH - 224, 136], repeatRows=1)
    table.setStyle(TableStyle(styles))
    return table


def _prioritized_findings(findings: Sequence[Finding]) -> list[Finding]:
    actionable = [
        finding for finding in findings
        if finding.status == NEEDS_REVIEW and finding.action
    ]
    return sorted(
        actionable,
        key=lambda finding: (
            finding.reason_code != "tls_certificate_invalid",
            REVIEW_ORDER[finding.control],
        ),
    )[:3]


def _priority_card(finding: Finding) -> Table:
    rows = [[
        _paragraph(finding.control, PRIORITY_LABEL),
        _paragraph(REVIEW_IMPACT[finding.control], SMALL),
    ]]
    for label, value in (
        ("Evidencia", finding.evidence),
        ("Acción", finding.action),
        ("Verificación", finding.verification),
    ):
        if value:
            summary = shorten(value, width=92, placeholder="...")
            rows.append([_paragraph(label, PRIORITY_LABEL), _paragraph(summary, SMALL)])
    table = Table(rows, colWidths=[82, CONTENT_WIDTH - 82], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("BACKGROUND", (0, 0), (-1, 0), STATUS_COLORS[NEEDS_REVIEW][0]),
        ("LINEBEFORE", (0, 0), (0, 0), 3, STATUS_COLORS[NEEDS_REVIEW][1]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def _control_details(finding: Finding, target: str, criterion: str) -> Table:
    fields = [
        ("Qué se consultó", target),
        ("Qué comprueba", criterion),
        ("Evidencia", finding.evidence),
    ]
    if finding.action:
        fields.append(("Acción sugerida", finding.action))
    if finding.verification:
        fields.append(("Cómo comprobar el cambio", finding.verification))
    if finding.status == UNVERIFIED:
        fields.append(("Siguiente paso", "Revisar la conectividad y repetir la consulta."))

    rows = [[
        _paragraph(finding.control, CARD_TITLE),
        _paragraph(finding.status.capitalize(), STATUS_RIGHT[finding.status]),
    ]]
    rows.extend([_paragraph(label, FIELD), _paragraph(value, BODY)] for label, value in fields)
    background, foreground = STATUS_COLORS[finding.status]
    table = Table(rows, colWidths=[144, CONTENT_WIDTH - 144], repeatRows=1, splitInRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 1), (-1, -1), WHITE),
        ("BACKGROUND", (0, 0), (-1, 0), background),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#EAF2F4")),
        ("LINEBEFORE", (0, 0), (0, 0), 3, foreground),
        ("LINEBELOW", (0, -1), (-1, -1), 0.7, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def render_pdf(
    domain: str, web_host: str, timestamp: datetime, findings: Sequence[Finding]
) -> bytes:
    """Render the Spanish diagnostic as a portrait PDF."""
    buffer = BytesIO()
    document = BaseDocTemplate(
        buffer, pagesize=letter, title=f"{PROJECT_NAME} - {domain}", author=PROJECT_NAME,
    )
    frames = [
        Frame(MARGIN, 44, CONTENT_WIDTH, OVERVIEW_HEIGHT,
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        Frame(MARGIN, 44, CONTENT_WIDTH, PAGE_HEIGHT - 174,
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
    ]
    document.addPageTemplates([
        PageTemplate("overview", frames[0], onPage=_overview_background, autoNextPageTemplate="details"),
        PageTemplate("details", frames[1], onPage=_details_background),
    ])
    story = [
        _metadata(domain, web_host, timestamp),
        Spacer(1, 18),
        _paragraph("Resumen del diagnóstico", HEADING),
        Spacer(1, 8),
        _status_cards(findings),
    ]
    summary = []
    if findings:
        summary = [
            Spacer(1, 14),
            _paragraph("Estado por control", SUBHEADING),
            Spacer(1, 7),
            _control_summary(findings),
        ]
    priorities = _prioritized_findings(findings)
    if priorities:
        story.extend([
            Spacer(1, 12),
            _paragraph("Acciones prioritarias", SUBHEADING),
            Spacer(1, 6),
        ])
        for finding in priorities:
            story.extend([_priority_card(finding), Spacer(1, 4)])
    note = [
        Spacer(1, 7),
        _paragraph("El diagnóstico refleja la configuración pública observada en esta ejecución.", SMALL),
    ]
    move_summary = bool(priorities) and (
        sum(item.wrap(CONTENT_WIDTH, OVERVIEW_HEIGHT)[1] for item in story + summary + note)
        > OVERVIEW_HEIGHT
    )
    if not move_summary:
        story.extend(summary)
    story.extend(note)

    scope = describe_controls(domain, web_host)
    mail = [finding for finding in findings if finding.control in MAIL_CONTROLS]
    web = [finding for finding in findings if finding.control not in MAIL_CONTROLS]
    for title, group in (("Correo y autenticación", mail), ("Sitio web", web)):
        if group:
            story.append(PageBreak())
            story.extend([_paragraph(title, HEADING), Spacer(1, 13)])
            for finding in group:
                story.extend([_control_details(finding, *scope[finding.control]), Spacer(1, 14)])

    if move_summary:
        story.extend(summary)

    document.build(story, canvasmaker=partial(Canvas, initialFontName=REGULAR_FONT))
    return buffer.getvalue()
