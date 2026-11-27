"""DNS checks for email domains."""

import re

import dns.exception
import dns.resolver

from .models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


def query_dns(resolver, name, record_type):
    try:
        return list(resolver.resolve(name, record_type, search=False)), None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as error:
        return [], type(error).__name__


def check_mx(resolver, domain):
    records, error = query_dns(resolver, domain, "MX")
    if error:
        return Finding("MX", UNVERIFIED, f"Consulta DNS inconclusa: {error}.")
    if len(records) == 1 and records[0].to_text() == "0 .":
        return Finding("MX", VERIFIED, "MX nulo: el dominio declara que no recibe correo.")
    if records:
        return Finding("MX", VERIFIED, ", ".join(sorted(r.to_text() for r in records)))
    return Finding("MX", NEEDS_REVIEW, "Sin MX explícito.",
                    "Confirmar si el dominio debe recibir correo.",
                    "Consultar nuevamente los registros MX y confirmar con el administrador.")


def check_txt(resolver, domain, control):
    name = f"_dmarc.{domain}" if control == "DMARC" else domain
    records, error = query_dns(resolver, name, "TXT")
    if error:
        return Finding(control, UNVERIFIED, f"Consulta DNS inconclusa: {error}.")
    texts = [b"".join(r.strings).decode("utf-8", errors="replace").strip()
              for r in records]
    prefix = r"^v=dmarc1(?:\s*;|$)" if control == "DMARC" else r"^v=spf1(?:\s|$)"
    policies = sorted(t for t in texts if re.match(prefix, t, re.IGNORECASE))
    verification = f"Volver a ejecutar el diagnóstico y revisar el registro {control} publicado."
    if len(policies) != 1:
        evidence = "Sin política detectada." if not policies else "Múltiples políticas detectadas."
        return Finding(control, NEEDS_REVIEW, evidence,
                        "Confirmar el uso del dominio y revisar la publicación con su administrador.",
                        verification)
    policy = policies[0]
    if control == "DMARC":
        match = re.search(r"(?:^|;)\s*p\s*=\s*([^;\s]+)", policy, re.IGNORECASE)
        value = match[1].lower() if match else ""
        if value not in {"quarantine", "reject"}:
            return Finding(control, NEEDS_REVIEW, policy,
                            "Validar remitentes legítimos antes de ajustar la política DMARC.",
                            verification)
    return Finding(control, VERIFIED, policy)


def check_mail(domain: str, timeout: float) -> list[Finding]:
    try:
        resolver = dns.resolver.Resolver()
    except (OSError, dns.exception.DNSException):
        resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = timeout
    return [
        check_mx(resolver, domain),
        check_txt(resolver, domain, "SPF"),
        check_txt(resolver, domain, "DMARC"),
    ]
