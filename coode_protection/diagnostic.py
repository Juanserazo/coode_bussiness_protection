"""Orchestration for the Base diagnostic."""

from .dns_checks import check_mail
from .models import Finding
from .web_checks import check_https, check_tls


def run_diagnostic(domain: str, web_host: str, timeout: float) -> list[Finding]:
    """Run the five controls and return their findings in report order."""
    return [
        *check_mail(domain, timeout),
        check_tls(web_host, timeout),
        check_https(web_host, timeout),
    ]
