"""Finding and status definitions shared by checks and reports."""

from dataclasses import dataclass


VERIFIED = "verificado"
NEEDS_REVIEW = "requiere revisión"
UNVERIFIED = "no verificado"


@dataclass
class Finding:
    control: str
    status: str
    evidence: str
    action: str = ""
    verification: str = ""
