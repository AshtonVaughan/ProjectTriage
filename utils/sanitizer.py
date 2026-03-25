"""Output sanitizer - bulletproof layer between LLM output and tool execution.

Handles every known model quirk: wrong case, wrong params, wrong types,
garbled JSON, missing fields, hallucinated tools, and unparseable output.
Zero errors should reach the user.
"""

from __future__ import annotations

import json
import re
from difflib import get_close_matches
from typing import Any


# Canonical tool names and their required/optional params with types
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "subfinder": {
        "required": {"target": str},
        "optional": {"flags": str},
        "aliases": {"domain": "target", "url": "target", "host": "target"},
    },
    "nmap": {
        "required": {"target": str},
        "optional": {"ports": str, "flags": str},
        "aliases": {"host": "target", "ip": "target", "domain": "target", "url": "target"},
    },
    "httpx": {
        "required": {"targets": str},
        "optional": {"flags": str},
        "aliases": {"target": "targets", "url": "targets", "domain": "targets", "host": "targets"},
    },
    "nuclei": {
        "required": {"target": str},
        "optional": {"templates": str, "flags": str},
        "aliases": {"url": "target", "domain": "target"},
    },
    "curl": {
        "required": {"url": str},
        "optional": {"method": str, "headers": (str, dict), "data": str, "flags": str, "timeout": int},
        "aliases": {"target": "url", "domain": "url", "host": "url"},
    },
    "sqlmap": {
        "required": {"url": str},
        "optional": {"data": str, "flags": str},
        "aliases": {"target": "url"},
    },
    "http_payload": {
        "required": {"url": str},
        "optional": {"method": str, "headers": (str, dict), "body": str, "follow_redirects": bool},
        "aliases": {"target": "url", "data": "body"},
    },
    "analyze_headers": {
        "required": {"response": str},
        "optional": {"check_security": bool},
        "aliases": {"headers": "response", "raw": "response", "output": "response"},
    },
    "parse_nmap": {
        "required": {"output": str},
        "optional": {},
        "aliases": {"raw": "output", "stdout": "output", "data": "output"},
    },
}

# Common model hallucinations mapped to real tools
TOOL_ALIASES: dict[str, str] = {
    "gobuster": "curl",       # No gobuster, use curl for manual probing
    "dirb": "curl",
    "ffuf": "curl",
    "dirbuster": "curl",
    "wfuzz": "curl",
    "wget": "curl",
    "nikto": "nuclei",        # Use nuclei instead
    "burp": "curl",
    "hydra": "curl",
    "dig": "nmap",            # DNS via nmap
    "whois": "subfinder",
    "amass": "subfinder",
    "masscan": "nmap",
    "rustscan": "nmap",
    "shodan": "nmap",
    "censys": "subfinder",
}


def sanitize_action(raw_action: str, available_tools: list[str]) -> str:
    """Clean and resolve the action name to a valid tool.

    Handles: uppercase, trailing garbage, hallucinated tools, fuzzy matching.
    Returns a valid tool name or the original (for ADVANCE/DONE).
    """
    if not raw_action:
        return ""

    # Preserve special actions
    action_upper = raw_action.upper().strip()
    if action_upper in ("ADVANCE", "DONE"):
        return action_upper

    # Lowercase and strip non-alpha chars
    clean = re.sub(r"[^a-z_].*", "", raw_action.lower().strip())
    if not clean:
        clean = re.sub(r"[^a-zA-Z_]", "", raw_action).lower()

    # Direct match
    if clean in available_tools:
        return clean

    # Check hallucinated tool aliases
    if clean in TOOL_ALIASES:
        replacement = TOOL_ALIASES[clean]
        if replacement in available_tools:
            return replacement

    # Fuzzy match (typos like "subinder" -> "subfinder")
    matches = get_close_matches(clean, available_tools, n=1, cutoff=0.6)
    if matches:
        return matches[0]

    # Last resort: partial match ("sub" -> "subfinder")
    for tool in available_tools:
        if clean.startswith(tool[:3]) or tool.startswith(clean[:3]):
            return tool

    return clean


def sanitize_inputs(tool_name: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    """Clean and normalize tool inputs.

    Handles: wrong param names, wrong types, missing required params,
    extra params, nested dicts, list-instead-of-string.
    """
    spec = TOOL_SPECS.get(tool_name)
    if not spec:
        # Unknown tool - pass through, strip obviously bad params
        return {k: _coerce_to_str(v) for k, v in raw_inputs.items()
                if not isinstance(v, (list, dict)) or k in ("headers",)}

    aliases = spec.get("aliases", {})
    required = spec.get("required", {})
    optional = spec.get("optional", {})
    all_params = {**required, **optional}

    result: dict[str, Any] = {}

    for key, value in raw_inputs.items():
        # Map aliases
        canonical = aliases.get(key, key)

        # Skip params not in spec
        if canonical not in all_params:
            continue

        # Type coercion
        expected_type = all_params[canonical]
        result[canonical] = _coerce(value, expected_type)

    # Ensure required params exist
    for param, ptype in required.items():
        if param not in result:
            # Try to find it under any alias
            for alias, canonical in aliases.items():
                if canonical == param and alias in raw_inputs:
                    result[param] = _coerce(raw_inputs[alias], ptype)
                    break

    return result


def sanitize_json(raw: str) -> dict[str, Any]:
    """Extract valid JSON from garbled model output.

    Handles: nested braces, trailing commas, single quotes, unquoted keys.
    """
    if not raw:
        return {}

    # Try direct parse
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # Find the outermost JSON object
    depth = 0
    start = -1
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = raw[start:i + 1]
                try:
                    return json.loads(candidate)
                except (json.JSONDecodeError, ValueError):
                    # Try fixing common issues
                    fixed = _fix_json(candidate)
                    try:
                        return json.loads(fixed)
                    except (json.JSONDecodeError, ValueError):
                        pass
                start = -1

    # Last resort: extract key=value pairs
    pairs = re.findall(r"['\"]?(\w+)['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", raw)
    if pairs:
        return {k: v for k, v in pairs}

    return {}


def _fix_json(s: str) -> str:
    """Fix common JSON issues from LLM output."""
    # Replace single quotes with double quotes
    s = re.sub(r"(?<!\\)'", '"', s)
    # Remove trailing commas before }
    s = re.sub(r",\s*}", "}", s)
    # Remove trailing commas before ]
    s = re.sub(r",\s*]", "]", s)
    # Quote unquoted keys
    s = re.sub(r"(\{|,)\s*(\w+)\s*:", r'\1 "\2":', s)
    return s


def _coerce(value: Any, expected_type: Any) -> Any:
    """Coerce a value to the expected type."""
    # Handle tuple of types (e.g., (str, dict) for headers)
    if isinstance(expected_type, tuple):
        if isinstance(value, expected_type):
            return value
        return _coerce_to_str(value)

    if expected_type == str:
        return _coerce_to_str(value)
    if expected_type == int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    if expected_type == bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)

    return value


def _coerce_to_str(value: Any) -> str:
    """Convert any value to a clean string."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)
