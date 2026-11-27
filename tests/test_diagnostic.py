import argparse
import io
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call, patch

import dns.exception
import dns.resolver
import httpx
import pytest
from pypdf import PdfReader

import coode_diagnostic
from coode_protection import dns_checks, reports, web_checks
from coode_protection.diagnostic import run_diagnostic
from coode_protection.models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


DOMAIN = "example.com"
WEB_HOST = "www.example.com"
CONTROLS = ["MX", "SPF", "DMARC", "TLS", "HTTPS"]


@patch.object(web_checks.httpx, "Client")
@patch.object(web_checks.ssl, "create_default_context")
@patch.object(web_checks.socket, "create_connection")
@patch.object(dns_checks.dns.resolver, "Resolver")
def test_checks_all_five_controls_on_the_expected_targets(
    resolver_factory, connect, context_factory, client_factory
):
    mx = Mock()
    mx.to_text.return_value = "10 mail.example.com."
    resolver = resolver_factory.return_value
    resolver.resolve.side_effect = [
        [mx],
        [SimpleNamespace(strings=[b"v=spf1 ", b"-all"])],
        [SimpleNamespace(strings=[b"v=DMARC1; p=reject"])],
    ]
    context = context_factory.return_value
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2099 GMT"}
    client = client_factory.return_value.__enter__.return_value
    response = client.stream.return_value.__enter__.return_value
    response.status_code = 302

    findings = run_diagnostic(DOMAIN, WEB_HOST, timeout=3)

    assert [finding.control for finding in findings] == CONTROLS
    assert [finding.status for finding in findings] == [VERIFIED] * 5
    assert findings[1].evidence == "v=spf1 -all"
    assert [finding.target for finding in findings] == [
        DOMAIN, DOMAIN, f"_dmarc.{DOMAIN}", WEB_HOST, f"https://{WEB_HOST}/",
    ]
    assert all(finding.reason_code for finding in findings)
    assert "HTTP 302" in findings[4].evidence
    assert resolver.resolve.call_args_list == [
        call(DOMAIN, "MX", search=False),
        call(DOMAIN, "TXT", search=False),
        call(f"_dmarc.{DOMAIN}", "TXT", search=False),
    ]
    assert resolver.lifetime == 3
    connect.assert_called_once_with((WEB_HOST, 443), timeout=3)
    context.wrap_socket.assert_called_once_with(
        connect.return_value.__enter__.return_value, server_hostname=WEB_HOST
    )
    client.stream.assert_called_once_with("GET", f"https://{WEB_HOST}/")
    assert client_factory.call_args.kwargs["follow_redirects"] is False


@patch.object(web_checks.httpx, "Client", side_effect=httpx.ConnectError("connection failed"))
@patch.object(web_checks.socket, "create_connection", side_effect=socket.gaierror())
@patch.object(dns_checks.dns.resolver, "Resolver")
def test_records_evidence_when_checks_cannot_complete(
    resolver_factory, _connect, _client_factory
):
    resolver_factory.return_value.resolve.side_effect = dns.exception.Timeout()

    findings = run_diagnostic(DOMAIN, WEB_HOST, timeout=2)

    assert [finding.control for finding in findings] == CONTROLS
    assert [finding.status for finding in findings] == [UNVERIFIED] * 5
    expected_errors = ["Timeout"] * 3 + ["gaierror", "ConnectError"]
    for finding, error in zip(findings, expected_errors, strict=True):
        assert error in finding.evidence, finding.control


def test_marks_monitoring_only_dmarc_for_review():
    resolver = MagicMock()
    resolver.resolve.return_value = [SimpleNamespace(strings=[b"v=DMARC1; p=none"])]

    finding = dns_checks.check_txt(resolver, DOMAIN, "DMARC")

    assert finding.status == NEEDS_REVIEW
    assert finding.reason_code == "dmarc_monitoring_only"
    assert finding.action
    assert finding.verification


@pytest.mark.parametrize(
    ("failure", "status", "reason_code", "evidence"),
    [
        (dns.resolver.NXDOMAIN, NEEDS_REVIEW, "dns_name_not_found", "NXDOMAIN"),
        (dns.resolver.NoAnswer, NEEDS_REVIEW, "dns_record_not_found", "NoAnswer"),
        (dns.exception.Timeout, UNVERIFIED, "dns_timeout", "Timeout"),
        (dns.resolver.NoNameservers, UNVERIFIED, "dns_query_failed", "NoNameservers"),
    ],
    ids=["missing-name", "missing-record", "timeout", "resolver-failure"],
)
def test_dmarc_distinguishes_missing_records_and_dns_failures(failure, status, reason_code, evidence):
    resolver = Mock()
    resolver.resolve.side_effect = failure()

    finding = dns_checks.check_txt(resolver, DOMAIN, "DMARC")

    assert finding.target == f"_dmarc.{DOMAIN}"
    assert finding.status == status
    assert finding.reason_code == reason_code
    assert evidence in finding.evidence
    assert bool(finding.action) == (status == NEEDS_REVIEW)


@pytest.mark.parametrize(
    ("records", "reason_code"),
    [
        ([b"unrelated TXT"], "policy_not_found"),
        ([b"v=DMARC2; p=reject"], "invalid_policy_version"),
        ([b"v=DMARC1; p=reject", b"v=DMARC1; p=none"], "multiple_policy_records"),
        ([b"v=DMARC1; rua=mailto:dmarc@example.com"], "invalid_dmarc_policy"),
        ([b"v=DMARC1; p=reject; p=none"], "invalid_dmarc_policy"),
        ([b"v=DMARC1; p=unexpected"], "invalid_dmarc_policy"),
    ],
    ids=["unrelated-txt", "version", "duplicates", "missing-p", "duplicate-p", "invalid-p"],
)
def test_dmarc_explains_missing_or_malformed_policy(records, reason_code):
    resolver = Mock()
    resolver.resolve.return_value = [SimpleNamespace(strings=[record]) for record in records]

    finding = dns_checks.check_txt(resolver, DOMAIN, "DMARC")

    assert finding.status == NEEDS_REVIEW
    assert finding.reason_code == reason_code
    assert finding.verification


def test_writes_portrait_pdf_and_json_with_the_existing_schema(tmp_path):
    findings = [
        Finding("MX", VERIFIED, "10 mail.example.com."),
        Finding(
            "SPF", NEEDS_REVIEW, "Sin política detectada.",
            "Consultar al administrador.", "Repetir la prueba.",
            target=DOMAIN, reason_code="policy_not_found",
        ),
        Finding("DMARC", UNVERIFIED, "Consulta DNS inconclusa."),
        Finding("TLS", VERIFIED, "Certificado válido."),
        Finding("HTTPS", VERIFIED, "HTTP 200."),
    ]

    json_path, pdf_path = reports.write_reports(
        DOMAIN, WEB_HOST, findings, tmp_path / "reports"
    )

    assert json_path.stem == pdf_path.stem
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert set(data) == {"dominio", "sitio", "fecha_utc", "hallazgos"}
    assert data["dominio"] == DOMAIN
    assert data["sitio"] == WEB_HOST
    assert data["fecha_utc"].endswith("+00:00")
    assert [finding["control"] for finding in data["hallazgos"]] == CONTROLS
    assert data["hallazgos"][1] == {
        "control": "SPF",
        "estado": NEEDS_REVIEW,
        "evidencia": "Sin política detectada.",
        "accion": "Consultar al administrador.",
        "verificacion": "Repetir la prueba.",
        "control_id": "spf",
        "objetivo": DOMAIN,
        "codigo_motivo": "policy_not_found",
    }
    pdf = PdfReader(pdf_path)
    assert pdf_path.suffix == ".pdf"
    assert len(pdf.pages) == 3
    assert all((page.mediabox.width, page.mediabox.height) == (612, 792) for page in pdf.pages)
    overview = " ".join(pdf.pages[0].extract_text().split())
    assert "COODE BUSSINES PROTECTION" in overview
    assert DOMAIN in overview and WEB_HOST in overview
    assert "Fecha de revisión" in overview and "UTC" in overview
    assert "Acciones prioritarias" in overview
    assert "Consultar al administrador." in overview
    assert "Repetir la prueba." in overview
    assert "Verificado 3" in overview
    assert "Requiere revisión 1" in overview
    assert "No verificado 1" in overview
    assert all(control in overview.split() for control in CONTROLS)
    mail_page, web_page = [page.extract_text() for page in pdf.pages[1:]]
    assert "Correo y autenticación" in mail_page
    assert "Sitio web" in web_page
    assert f"_dmarc.{DOMAIN}" in mail_page
    assert f"https://{WEB_HOST}/" in web_page
    details = mail_page + web_page
    for field in ("Qué se consultó", "Qué comprueba", "Evidencia"):
        assert details.count(field) == len(CONTROLS)
    assert "Acción sugerida" in details
    assert "Cómo comprobar el" in details
    assert "Consultar al administrador." in details
    assert "Siguiente paso" in details


def test_pdf_limits_priorities_and_keeps_unverified_checks_out_of_the_shortlist(tmp_path):
    findings = [
        Finding("MX", NEEDS_REVIEW, "MX evidence", "MX action", "MX verification"),
        Finding("SPF", NEEDS_REVIEW, "SPF evidence", "SPF action", "SPF verification"),
        Finding("DMARC", NEEDS_REVIEW, "DMARC evidence", "DMARC action", "DMARC verification"),
        Finding("TLS", NEEDS_REVIEW, "TLS evidence", "TLS action", "TLS verification",
                reason_code="tls_certificate_invalid"),
        Finding("HTTPS", UNVERIFIED, "HTTPS evidence", "HTTPS action", "HTTPS verification"),
    ]

    _, pdf_path = reports.write_reports(DOMAIN, WEB_HOST, findings, tmp_path)

    pdf = PdfReader(pdf_path)
    overview = pdf.pages[0].extract_text()
    assert "Acciones prioritarias" in overview
    assert overview.index("TLS action") < overview.index("DMARC action") < overview.index("SPF action")
    assert "MX action" not in overview
    assert "HTTPS action" not in overview
    details = " ".join(page.extract_text() for page in pdf.pages[1:])
    assert "MX action" in details and "HTTPS action" in details
    assert "Estado por control" in overview + details


def test_long_evidence_spans_pdf_pages_without_truncation(tmp_path):
    evidence = "<first> " + " ".join(f"record-{n:03}" for n in range(600)) + " <last>"
    _, pdf_path = reports.write_reports(
        DOMAIN, WEB_HOST, [Finding("SPF", VERIFIED, evidence)], tmp_path
    )

    pdf = PdfReader(pdf_path)
    assert len(pdf.pages) > 2
    details = " ".join(page.extract_text() for page in pdf.pages[1:])
    assert "<first>" in details
    assert "<last>" in details
    assert all(f"record-{n:03}" in details for n in range(600))


def test_collision_preserves_existing_report_and_removes_partial_output(tmp_path, monkeypatch):
    timestamp = datetime(2026, 11, 27, tzinfo=timezone.utc)
    clock = Mock()
    clock.now.return_value = timestamp
    monkeypatch.setattr(reports, "datetime", clock)
    existing = tmp_path / f"{DOMAIN}_{timestamp:%Y%m%dT%H%M%S%fZ}.pdf"
    existing.write_bytes(b"existing PDF")

    with pytest.raises(FileExistsError):
        reports.write_reports(DOMAIN, WEB_HOST, [], tmp_path)

    assert existing.read_bytes() == b"existing PDF"
    assert list(tmp_path.iterdir()) == [existing]


@pytest.fixture
def mock_diagnostic(monkeypatch):
    run = Mock(return_value=[])
    monkeypatch.setattr(coode_diagnostic, "run_diagnostic", run)
    return run


def test_cli_accepts_web_host_output_and_timeout(tmp_path, monkeypatch, capsys, mock_diagnostic):
    folder = tmp_path / "output"
    args = [
        "coode_diagnostic.py", DOMAIN, "--web-host", WEB_HOST,
        "--output", str(folder), "--timeout", "2",
    ]
    monkeypatch.setattr(sys, "argv", args)

    coode_diagnostic.main()

    paths = [Path(line) for line in capsys.readouterr().out.splitlines()]
    assert [path.suffix for path in paths] == [".json", ".pdf"]
    assert all(path.parent == folder and path.is_file() for path in paths)
    mock_diagnostic.assert_called_once_with(DOMAIN, WEB_HOST, 2)


@pytest.fixture
def mock_report_writer(monkeypatch):
    save = Mock(return_value=[])
    monkeypatch.setattr(coode_diagnostic, "write_reports", save)
    return save


def test_cli_without_arguments_prompts_with_defaults(
    monkeypatch, capsys, mock_diagnostic, mock_report_writer
):
    monkeypatch.setattr(sys, "argv", ["coode_diagnostic.py"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n\n"))

    coode_diagnostic.main()

    output = capsys.readouterr().out
    assert "Dominio de correo [example.com]" in output
    assert "Nombre web [example.com]" in output
    mock_diagnostic.assert_called_once_with(DOMAIN, DOMAIN, 5)
    mock_report_writer.assert_called_once_with(DOMAIN, DOMAIN, [], Path("reports"))


def test_interactive_cli_retries_invalid_names_and_preserves_options(
    monkeypatch, capsys, mock_diagnostic, mock_report_writer
):
    args = ["coode_diagnostic.py", "--interactive", "--timeout", "3", "--output", "output"]
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"https://{DOMAIN}\n{DOMAIN}\n{WEB_HOST}\n"))

    coode_diagnostic.main()

    captured = capsys.readouterr()
    assert captured.out.count("Dominio de correo") == 2
    assert "sin URL ni puerto" in captured.err
    mock_diagnostic.assert_called_once_with(DOMAIN, WEB_HOST, 3)
    mock_report_writer.assert_called_once_with(DOMAIN, WEB_HOST, [], Path("output"))


def test_guided_cli_exits_without_running_when_input_ends(monkeypatch, capsys, mock_diagnostic):
    monkeypatch.setattr(sys, "argv", ["coode_diagnostic.py"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    with pytest.raises(SystemExit) as exit_context:
        coode_diagnostic.main()

    assert exit_context.value.code == 2
    assert "No se recibió la entrada" in capsys.readouterr().err
    mock_diagnostic.assert_not_called()


def test_normalizes_domain():
    assert coode_diagnostic.parse_dns_name(" Example.COM. ") == DOMAIN


@pytest.mark.parametrize("value", ["https://example.com", "127.0.0.1"], ids=["url", "ip-address"])
def test_rejects_invalid_domain(value):
    with pytest.raises(argparse.ArgumentTypeError):
        coode_diagnostic.parse_dns_name(value)
