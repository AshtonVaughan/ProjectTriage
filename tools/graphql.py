"""GraphQL security scanner - introspection, auth, DoS, and batch probing."""

from __future__ import annotations

import json
import re
from typing import Any

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Introspection queries
# ---------------------------------------------------------------------------

_INTROSPECTION_PROBE = '{"query":"{__schema{types{name}}}"}'

_FULL_INTROSPECTION = (
    '{"query":"{__schema{queryType{name}mutationType{name}'
    "types{name kind fields{name type{name kind ofType{name kind}}}}"
    '}}"}'
)

_SUGGESTION_PROBE = '{"query":"{__typena}"}'

_NESTED_DOS_QUERY = (
    '{"query":"{__typename ...on Query{__typename '
    "...on Query{__typename ...on Query{__typename "
    '...on Query{__typename}}}}}"}'
)

_BATCH_PAYLOAD = (
    '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
)

# Mutation names that signal sensitive operations
_SENSITIVE_MUTATION_RE = re.compile(
    r"^(delete|create|update|admin|user|password|role|token)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _curl_post(url: str, body: str, extra_headers: str = "", timeout: int = 30) -> dict[str, Any]:
    """Send a POST request with JSON content-type via curl."""
    cmd = ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json"]

    if extra_headers:
        for hdr in extra_headers.split("\\n"):
            hdr = hdr.strip()
            if hdr:
                cmd.extend(["-H", sanitize_subprocess_arg(hdr, "generic")])

    cmd.extend(["-d", body, url])
    return run_cmd(cmd, timeout=timeout)


def _parse_json_body(raw: str) -> dict | list | None:
    """Try to extract JSON from a curl response (may include HTTP headers)."""
    # If the response starts with HTTP/ strip headers
    if raw.lstrip().startswith("HTTP/"):
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) == 2:
            raw = parts[1]

    # Find first { or [ to handle any leading whitespace/noise
    for i, ch in enumerate(raw):
        if ch in ("{", "["):
            try:
                return json.loads(raw[i:])
            except json.JSONDecodeError:
                break
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


def graphql_scan(url: str, flags: str = "") -> dict[str, Any]:
    """Probe a GraphQL endpoint for security misconfigurations.

    Checks: introspection, suggestion leaking, sensitive mutations,
    query depth limiting, and batch query support.
    """
    url = sanitize_subprocess_arg(url, "url")
    flags = sanitize_subprocess_arg(flags, "flags")

    findings: list[str] = []
    parsed: dict[str, Any] = {
        "introspection_enabled": False,
        "suggestion_leak": False,
        "schema": None,
        "sensitive_mutations": [],
        "depth_limit_missing": False,
        "batch_enabled": False,
        "findings": findings,
    }

    # ---- a) Introspection probe ----
    intro_result = _curl_post(url, _INTROSPECTION_PROBE)
    intro_body = _parse_json_body(intro_result.get("stdout", ""))

    if isinstance(intro_body, dict):
        data = intro_body.get("data") or {}
        schema_types = (data.get("__schema") or {}).get("types")
        if schema_types and isinstance(schema_types, list):
            parsed["introspection_enabled"] = True
            findings.append(
                f"INTROSPECTION ENABLED - {len(schema_types)} types exposed"
            )

    # ---- b) Suggestion leak probe (when introspection is off) ----
    if not parsed["introspection_enabled"]:
        suggest_result = _curl_post(url, _SUGGESTION_PROBE)
        suggest_body = _parse_json_body(suggest_result.get("stdout", ""))

        if suggest_body and "Did you mean" in json.dumps(suggest_body):
            parsed["suggestion_leak"] = True
            findings.append(
                "SUGGESTION LEAK - server returns field suggestions "
                "(schema enumerable without introspection)"
            )

    # ---- c) Full schema dump ----
    if parsed["introspection_enabled"]:
        schema_result = _curl_post(url, _FULL_INTROSPECTION, timeout=60)
        schema_body = _parse_json_body(schema_result.get("stdout", ""))

        if isinstance(schema_body, dict):
            schema_data = (schema_body.get("data") or {}).get("__schema")
            if schema_data:
                parsed["schema"] = schema_data
                type_count = len(schema_data.get("types", []))
                query_type = (schema_data.get("queryType") or {}).get("name", "?")
                mutation_type = (schema_data.get("mutationType") or {}).get("name")
                findings.append(
                    f"FULL SCHEMA DUMPED - {type_count} types, "
                    f"queryType={query_type}, "
                    f"mutationType={mutation_type or 'none'}"
                )

    # ---- d) Mutation enumeration ----
    if parsed["schema"]:
        mutation_type_name = (parsed["schema"].get("mutationType") or {}).get("name")
        if mutation_type_name:
            for t in parsed["schema"].get("types", []):
                if t.get("name") == mutation_type_name and t.get("fields"):
                    for field in t["fields"]:
                        fname = field.get("name", "")
                        if _SENSITIVE_MUTATION_RE.match(fname):
                            parsed["sensitive_mutations"].append(fname)

        if parsed["sensitive_mutations"]:
            findings.append(
                f"SENSITIVE MUTATIONS - {len(parsed['sensitive_mutations'])} found: "
                + ", ".join(parsed["sensitive_mutations"][:15])
            )

    # ---- e) Nested query DoS check ----
    dos_result = _curl_post(url, _NESTED_DOS_QUERY, timeout=15)
    dos_body = _parse_json_body(dos_result.get("stdout", ""))

    if dos_result.get("returncode", -1) == 0 and dos_body is not None:
        errors = []
        if isinstance(dos_body, dict):
            errors = dos_body.get("errors", [])

        # If we got data back without errors, depth limiting is likely absent
        has_data = isinstance(dos_body, dict) and dos_body.get("data") is not None
        depth_blocked = any(
            "depth" in json.dumps(e).lower() or "complexity" in json.dumps(e).lower()
            for e in errors
        ) if errors else False

        if has_data and not depth_blocked:
            parsed["depth_limit_missing"] = True
            findings.append(
                "NO DEPTH LIMIT - 5-level nested query succeeded "
                "(vulnerable to query complexity DoS)"
            )
    elif dos_result.get("returncode", 0) == -1:
        # Timeout could indicate the server is struggling but not rejecting
        parsed["depth_limit_missing"] = True
        findings.append(
            "POSSIBLE DEPTH ISSUE - nested query caused timeout "
            "(no explicit depth rejection, possible DoS vector)"
        )

    # ---- f) Batch query check ----
    batch_result = _curl_post(url, _BATCH_PAYLOAD)
    batch_body = _parse_json_body(batch_result.get("stdout", ""))

    if isinstance(batch_body, list) and len(batch_body) >= 2:
        parsed["batch_enabled"] = True
        findings.append(
            f"BATCH QUERIES ENABLED - server processed {len(batch_body)} "
            "queries in one request (amplification vector)"
        )

    # ---- Build output ----
    if not findings:
        findings.append("No GraphQL misconfigurations detected")

    summary = f"[graphql_scan] {url}\n" + "\n".join(f"  [!] {f}" for f in findings)

    return {
        "stdout": summary,
        "stderr": "",
        "returncode": 0,
        "parsed": parsed,
    }


# ---------------------------------------------------------------------------
# Auth test
# ---------------------------------------------------------------------------


def graphql_auth_test(
    url: str,
    query: str,
    headers_authed: str = "",
    headers_unauthed: str = "",
) -> dict[str, Any]:
    """Test whether a GraphQL query/mutation enforces authentication.

    Sends the same query with and without auth headers and compares results.
    If both return data (not errors), the resolver likely lacks auth checks.
    """
    url = sanitize_subprocess_arg(url, "url")
    payload = json.dumps({"query": query})

    authed = _curl_post(url, payload, extra_headers=headers_authed)
    unauthed = _curl_post(url, payload, extra_headers=headers_unauthed)

    authed_body = _parse_json_body(authed.get("stdout", ""))
    unauthed_body = _parse_json_body(unauthed.get("stdout", ""))

    def _has_data(body: Any) -> bool:
        if isinstance(body, dict):
            return body.get("data") is not None and not body.get("errors")
        return False

    authed_ok = _has_data(authed_body)
    unauthed_ok = _has_data(unauthed_body)
    missing_auth = authed_ok and unauthed_ok

    result: dict[str, Any] = {
        "missing_auth": missing_auth,
        "authed_has_data": authed_ok,
        "unauthed_has_data": unauthed_ok,
        "authed_response": authed.get("stdout", "")[:1000],
        "unauthed_response": unauthed.get("stdout", "")[:1000],
    }

    if missing_auth:
        summary = (
            f"[graphql_auth_test] AUTH MISSING - query returned data "
            f"without authentication\n"
            f"  Query: {query[:200]}\n"
            f"  Unauthed response (truncated): "
            f"{unauthed.get('stdout', '')[:300]}"
        )
    elif unauthed_ok and not authed_ok:
        summary = (
            f"[graphql_auth_test] UNEXPECTED - unauthed succeeded but "
            f"authed failed (check auth headers)"
        )
    else:
        summary = (
            f"[graphql_auth_test] OK - query properly requires authentication"
        )

    return {
        "stdout": summary,
        "stderr": "",
        "returncode": 0,
        "parsed": result,
    }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_graphql_tools(config: Config) -> list[Tool]:
    """Register GraphQL security tools if curl is available."""
    if "curl" not in config.tool_paths:
        return []

    return [
        Tool(
            name="graphql_scan",
            description=(
                "Probe a GraphQL endpoint for security misconfigurations: "
                "introspection leaks, suggestion enumeration, sensitive mutations, "
                "missing depth limits, and batch query amplification."
            ),
            parameters={
                "url": "GraphQL endpoint URL (e.g. https://target.com/graphql)",
                "flags": "Additional flags (optional)",
            },
            example='graphql_scan(url="https://target.com/graphql")',
            phase_tags=["discovery", "vulnerability_scan"],
            execute=graphql_scan,
        ),
        Tool(
            name="graphql_auth_test",
            description=(
                "Test if a GraphQL query or mutation enforces authentication "
                "by comparing responses with and without auth headers."
            ),
            parameters={
                "url": "GraphQL endpoint URL",
                "query": "GraphQL query or mutation to test",
                "headers_authed": "Auth headers (e.g. 'Authorization: Bearer TOKEN') (optional)",
                "headers_unauthed": "Headers for unauthed request (optional, default none)",
            },
            example=(
                'graphql_auth_test(url="https://target.com/graphql", '
                'query="{users{id email}}", '
                'headers_authed="Authorization: Bearer eyJ...")'
            ),
            phase_tags=["vulnerability_scan", "exploitation"],
            execute=graphql_auth_test,
        ),
    ]
