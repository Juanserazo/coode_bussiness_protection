"""DNS checks for email domains."""

import re

import dns.exception
import dns.resolver

from .models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


REVIEW_ACTIONS = {
    "MX": "Confirmar con el administrador si el dominio debe recibir correo.",
    "SPF": "Confirmar los servicios que envían correo y revisar el registro SPF con el administrador.",
    "DMARC": "Identificar los remitentes legítimos y revisar DKIM antes de publicar o ajustar DMARC.",
}
VERIFICATION_STEPS = {
    "MX": "Consultar los MX y contrastar los destinos con el proveedor de correo.",
    "SPF": "Confirmar un único TXT SPF que cubra a los remitentes autorizados.",
    "DMARC": "Consultar _dmarc y confirmar una única política con el valor p acordado.",
}


def query_dns(resolver, name, record_type):
    try:
        return list(resolver.resolve(name, record_type, search=False)), None
    except dns.exception.DNSException as error:
        return [], error


def _review(control: str, target: str, evidence: str, reason_code: str) -> Finding:
    return Finding(
        control, NEEDS_REVIEW, evidence, REVIEW_ACTIONS[control], VERIFICATION_STEPS[control],
        target=target, reason_code=reason_code,
    )


def _lookup_issue(control, target, record_type, error):
    if isinstance(error, dns.resolver.NXDOMAIN):
        return _review(
            control, target, "DNS indica que el nombre consultado no existe (NXDOMAIN).",
            "dns_name_not_found",
        )
    if isinstance(error, dns.resolver.NoAnswer):
        return _review(
            control, target, f"DNS no devolvió registros {record_type} para el nombre consultado (NoAnswer).",
            "dns_record_not_found",
        )
    reason_code = "dns_timeout" if isinstance(error, dns.exception.Timeout) else "dns_query_failed"
    return Finding(
        control, UNVERIFIED, f"Consulta DNS inconclusa: {type(error).__name__}.",
        target=target, reason_code=reason_code,
    )


def check_mx(resolver, domain):
    records, error = query_dns(resolver, domain, "MX")
    if error is not None:
        return _lookup_issue("MX", domain, "MX", error)
    if len(records) == 1 and records[0].to_text() == "0 .":
        return Finding(
            "MX", VERIFIED, "MX nulo: el dominio declara que no recibe correo.",
            target=domain, reason_code="null_mx",
        )
    if records:
        return Finding(
            "MX", VERIFIED, ", ".join(sorted(record.to_text() for record in records)),
            target=domain, reason_code="mx_records_found",
        )
    return _review("MX", domain, "DNS no devolvió registros MX para el dominio.", "dns_record_not_found")


def check_txt(resolver, domain, control):
    name = f"_dmarc.{domain}" if control == "DMARC" else domain
    records, error = query_dns(resolver, name, "TXT")
    if error is not None:
        return _lookup_issue(control, name, "TXT", error)
    texts = [
        b"".join(record.strings).decode("utf-8", errors="replace").strip()
        for record in records
    ]
    version = "dmarc" if control == "DMARC" else "spf"
    prefix = r"^v=dmarc1(?:\s*;|$)" if control == "DMARC" else r"^v=spf1(?:\s|$)"
    candidates = sorted(text for text in texts if re.match(rf"^v\s*=\s*{version}", text, re.IGNORECASE))
    policies = [text for text in candidates if re.match(prefix, text, re.IGNORECASE)]
    if len(policies) > 1:
        evidence = f"DNS devolvió {len(policies)} registros de política {control}."
        return _review(control, name, evidence, "multiple_policy_records")
    if len(candidates) > len(policies):
        evidence = f"Se encontró un TXT con formato de versión {control} inválido."
        return _review(control, name, evidence, "invalid_policy_version")
    if not policies:
        evidence = f"DNS respondió, pero no se encontró una política {control} en los registros TXT."
        return _review(control, name, evidence, "policy_not_found")
    policy = policies[0]
    if control == "DMARC":
        values = re.findall(r"(?:^|;)\s*p\s*=\s*([^;]*)", policy, re.IGNORECASE)
        values = [value.strip().lower() for value in values]
        if len(values) != 1 or values[0] not in {"none", "quarantine", "reject"}:
            evidence = f"La etiqueta p de la política DMARC falta, se repite o tiene un valor inválido. TXT: {policy}"
            return _review(control, name, evidence, "invalid_dmarc_policy")
        if values[0] == "none":
            evidence = f"Política DMARC de monitoreo (p=none). TXT: {policy}"
            return _review(control, name, evidence, "dmarc_monitoring_only")
    return Finding(control, VERIFIED, policy, target=name, reason_code="policy_found")


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
