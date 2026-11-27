"""Command-line entry point for the Base diagnostic."""

import argparse
import ipaddress
import re
import sys
from pathlib import Path

from coode_protection.diagnostic import run_diagnostic
from coode_protection.reports import write_reports


def parse_dns_name(value: str) -> str:
    try:
        name = value.strip().removesuffix(".").encode("idna").decode().lower()
    except UnicodeError as error:
        raise argparse.ArgumentTypeError("Nombre DNS inválido.") from error
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(name) > 253 or not re.fullmatch(rf"(?:{label}\.)+{label}", name):
        raise argparse.ArgumentTypeError("Indica un dominio completo sin URL ni puerto.")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise argparse.ArgumentTypeError("Indica un nombre de dominio.")


def prompt_for_dns_name(label: str, default: str) -> str:
    while True:
        value = input(f"{label} [{default}]: ").strip()
        try:
            return parse_dns_name(value or default)
        except argparse.ArgumentTypeError as error:
            print(error, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Diagnóstico de solo lectura sobre dominios autorizados.")
    parser.add_argument("domain", metavar="DOMAIN", nargs="?", type=parse_dns_name,
                        help="dominio autorizado para MX, SPF y DMARC")
    parser.add_argument("--interactive", action="store_true",
                        help="pedir en consola el dominio y el nombre web que falten")
    parser.add_argument("--web-host", type=parse_dns_name, help="nombre autorizado para TLS y HTTPS")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument("--timeout", type=float, default=5, help="tiempo de espera en segundos")
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error("--timeout debe ser mayor que 0 y menor o igual a 60.")
    domain = args.domain
    web_host = args.web_host
    if args.interactive or len(sys.argv) == 1:
        try:
            domain = domain or prompt_for_dns_name("Dominio de correo", "example.com")
            web_host = web_host or prompt_for_dns_name("Nombre web", domain)
        except EOFError:
            parser.exit(2, "\nNo se recibió la entrada del diagnóstico.\n")
        except KeyboardInterrupt:
            parser.exit(130, "\nDiagnóstico cancelado.\n")
    if domain is None:
        parser.error("indica un dominio o usa --interactive.")
    web_host = web_host or domain

    try:
        findings = run_diagnostic(domain, web_host, args.timeout)
        for path in write_reports(domain, web_host, findings, args.output):
            print(path)
    except OSError as error:
        parser.exit(1, f"No fue posible generar los informes: {error}\n")


if __name__ == "__main__":
    main()
