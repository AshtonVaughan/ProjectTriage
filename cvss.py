"""CVSS 3.1 scoring - computes severity scores from attack metrics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CVSS:
    """CVSS 3.1 metrics for a vulnerability."""
    AV: str = "N"   # Attack Vector: N=Network, A=Adjacent, L=Local, P=Physical
    AC: str = "L"   # Attack Complexity: L=Low, H=High
    PR: str = "N"   # Privileges Required: N=None, L=Low, H=High
    UI: str = "N"   # User Interaction: N=None, R=Required
    S: str = "U"    # Scope: U=Unchanged, C=Changed
    C: str = "N"    # Confidentiality: N=None, L=Low, H=High
    I: str = "N"    # Integrity: N=None, L=Low, H=High
    A: str = "N"    # Availability: N=None, L=Low, H=High

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/"
            f"UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )


# CVSS 3.1 metric weights per the specification
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}

# PR depends on Scope
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}


def compute_cvss_score(cvss: CVSS) -> float:
    """Compute CVSS 3.1 base score. Returns 0.0-10.0."""
    # Impact sub-score
    isc_base = 1.0 - (
        (1.0 - _IMPACT[cvss.C])
        * (1.0 - _IMPACT[cvss.I])
        * (1.0 - _IMPACT[cvss.A])
    )

    if isc_base <= 0:
        return 0.0

    if cvss.S == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    # Exploitability sub-score
    pr_weights = _PR_CHANGED if cvss.S == "C" else _PR_UNCHANGED
    exploitability = (
        8.22
        * _AV[cvss.AV]
        * _AC[cvss.AC]
        * pr_weights[cvss.PR]
        * _UI[cvss.UI]
    )

    if impact <= 0:
        return 0.0

    if cvss.S == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    # Round up to 1 decimal
    return _roundup(score)


def _roundup(value: float) -> float:
    """CVSS spec requires rounding up to 1 decimal place."""
    import math
    return math.ceil(value * 10) / 10


def cvss_from_technique(technique: str) -> CVSS:
    """Generate a reasonable default CVSS from a vulnerability technique name.

    Provides starting values the LLM or validator can override.
    """
    t = technique.lower()

    if "rce" in t or "command injection" in t or "remote code" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")

    if "sqli" in t or "sql injection" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")

    if "ssrf" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N")

    if "xss" in t and "stored" in t:
        return CVSS(AV="N", AC="L", PR="L", UI="R", S="C", C="L", I="L", A="N")

    if "xss" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N")

    if "idor" in t or "insecure direct" in t:
        return CVSS(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="L", A="N")

    if "auth" in t and "bypass" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")

    if "csrf" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N")

    if "open redirect" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N")

    if "info" in t and ("disclos" in t or "leak" in t):
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N")

    if "header" in t and "missing" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N")

    if "dos" in t or "denial" in t:
        return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H")

    # Default: medium severity network vuln
    return CVSS(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N")
