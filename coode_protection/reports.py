"""Output the Base diagnostic reports as PDF and JSON."""

import json
import os
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding
from .pdf_report import render_pdf


def write_reports(
    domain: str, web_host: str, findings: Sequence[Finding], folder: Path
) -> tuple[Path, Path]:
    """Write JSON and PDF without overwriting existing reports."""
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
    json_text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    pdf_content = render_pdf(domain, web_host, timestamp, findings)
    base = f"{domain}_{timestamp:%Y%m%dT%H%M%S%fZ}"
    json_path = folder / f"{base}.json"
    pdf_path = folder / f"{base}.pdf"
    contents = (
        (json_path, json_text.replace("\n", os.linesep).encode("utf-8")),
        (pdf_path, pdf_content),
    )
    folder.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for path, content in contents:
            with path.open("xb") as file:
                created.append(path)
                file.write(content)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return json_path, pdf_path
