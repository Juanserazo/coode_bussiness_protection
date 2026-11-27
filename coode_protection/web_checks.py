"""TLS and HTTPS checks for the website."""

import socket
import ssl
from datetime import datetime, timezone

import httpx

from .models import Finding, NEEDS_REVIEW, UNVERIFIED, VERIFIED


def check_tls(web_host, timeout):
    context = ssl.create_default_context()
    verification = "Repetir la conexión HTTPS y comprobar nombre, confianza y vigencia."
    try:
        with socket.create_connection((web_host, 443), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=web_host) as tls:
                expiration = tls.getpeercert()["notAfter"]
    except ssl.SSLCertVerificationError as error:
        return Finding("TLS", NEEDS_REVIEW, error.verify_message,
                        "Revisar el certificado y su cadena con el administrador.", verification)
    except OSError as error:
        return Finding("TLS", UNVERIFIED, f"Conexión inconclusa: {type(error).__name__}.")
    timestamp = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiration), timezone.utc)
    days = (timestamp - datetime.now(timezone.utc)).total_seconds() / 86400
    evidence = f"Certificado válido para {web_host}. Vence el {timestamp:%Y-%m-%d %H:%M UTC}."
    if days <= 30:
        return Finding("TLS", NEEDS_REVIEW, evidence,
                        "Confirmar o programar la renovación del certificado.", verification)
    return Finding("TLS", VERIFIED, evidence)


def check_https(web_host, timeout):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                          verify=ssl.create_default_context()) as client:
            with client.stream("GET", f"https://{web_host}/") as response:
                code = response.status_code
    except httpx.RequestError as error:
        return Finding("HTTPS", UNVERIFIED, f"Solicitud inconclusa: {type(error).__name__}.")
    if 300 <= code < 400:
        return Finding("HTTPS", VERIFIED,
                        f"HTTP {code}. El servidor respondió con una redirección; se comprobó el origen.")
    if 200 <= code < 300:
        return Finding("HTTPS", VERIFIED, f"HTTP {code}. El sitio respondió.")
    return Finding("HTTPS", NEEDS_REVIEW, f"HTTP {code} al consultar la página principal.",
                    "Confirmar si la respuesta es esperada con el administrador.",
                    "Repetir la consulta y comparar el código esperado.")
