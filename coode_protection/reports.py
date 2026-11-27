"""Rendering and file output for Base diagnostic reports."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


def escape_markdown(value):
    return re.sub(r"[^\w\s.,:/+;=@()-]", lambda m: f"&#{ord(m[0])};",
                  " ".join(value.split()))


def describe_controls(domain, web_host):
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


def render_markdown(
    domain: str, web_host: str, timestamp: datetime, findings: Sequence[Finding]
) -> str:
    scope = describe_controls(domain, web_host)
    status_descriptions = {
        VERIFIED: "Se obtuvo evidencia según el criterio del control.",
        NEEDS_REVIEW: "Se encontró una condición que conviene revisar.",
        UNVERIFIED: "La consulta o conexión quedó inconclusa.",
    }
    lines = [
        "# COODE BUSSINES PROTECTION", "",
        "## Diagnóstico de dominio y sitio web", "",
        f"**Dominio de correo** · `{domain}`  ",
        f"**Sitio web** · `{web_host}`  ",
        f"**Fecha de revisión** · {timestamp:%Y-%m-%d %H:%M UTC}", "",
        "### Resumen", "",
        "| Estado | Controles | Cómo leerlo |", "|---|---:|---|",
    ]
    for status, description in status_descriptions.items():
        count = sum(h.status == status for h in findings)
        lines.append(f"| {status.capitalize()} | {count} | {description} |")

    needs_review = [h.control for h in findings if h.status == NEEDS_REVIEW]
    unverified = [h.control for h in findings if h.status == UNVERIFIED]
    if needs_review:
        lines.extend(["", f"**Controles para revisar** · {', '.join(needs_review)}"])
    if unverified:
        lines.extend(["", f"**Controles sin verificar** · {', '.join(unverified)}"])

    lines.extend(["", "### Detalle de los controles", ""])
    for finding in findings:
        target, criterion = scope[finding.control]
        lines.extend([
            f"#### {finding.control} · {finding.status.capitalize()}", "",
            f"- **Qué se consultó.** {target}",
            f"- **Qué comprueba.** {criterion}",
            f"- **Evidencia.** {escape_markdown(finding.evidence)}",
        ])
        if finding.action:
            lines.append(f"- **Acción sugerida.** {escape_markdown(finding.action)}")
        if finding.verification:
            lines.append(f"- **Cómo comprobar el cambio.** {escape_markdown(finding.verification)}")
        if finding.status == UNVERIFIED:
            lines.append("- **Siguiente paso.** Revisar la conectividad y repetir la consulta.")
        lines.extend(["", "---", ""])
    lines.append("El diagnóstico refleja la configuración pública observada en esta ejecución.")
    return "\n".join(lines) + "\n"


def write_reports(
    domain: str, web_host: str, findings: Sequence[Finding], folder: Path
) -> tuple[Path, Path]:
    """Write JSON and Markdown without overwriting existing reports."""
    timestamp = datetime.now(timezone.utc)
    # Preserve the JSON field names used by existing reports.
    data = {
        "dominio": domain,
        "sitio": web_host,
        "fecha_utc": timestamp.isoformat(),
        "hallazgos": [
            {
                "control": finding.control,
                "estado": finding.status,
                "evidencia": finding.evidence,
                "accion": finding.action,
                "verificacion": finding.verification,
            }
            for finding in findings
        ],
    }
    folder.mkdir(parents=True, exist_ok=True)
    base = f"{domain}_{timestamp:%Y%m%dT%H%M%S%fZ}"
    json_path = folder / f"{base}.json"
    markdown_path = folder / f"{base}.md"
    contents = (
        (json_path, json.dumps(data, ensure_ascii=False, indent=2) + "\n"),
        (markdown_path, render_markdown(domain, web_host, timestamp, findings)),
    )
    created = []
    try:
        for path, content in contents:
            with path.open("x", encoding="utf-8") as file:
                created.append(path)
                file.write(content)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return json_path, markdown_path
