"""Shared utilities for NPUHacker v2."""

from __future__ import annotations

import re
import subprocess
from typing import Any


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------

# Flags that could write files, execute code, or exfiltrate data
_DANGEROUS_FLAG_PATTERNS = re.compile(
    r"(?:^|\s)(?:"
    r"-oN|-oX|-oG|-oA|-oS"           # nmap output to file
    r"|--os-shell|--os-cmd|--os-pwn"  # sqlmap OS execution
    r"|--file-read|--file-write"      # sqlmap file access
    r"|--priv-esc"                    # sqlmap privilege escalation
    r"|--sql-shell"                   # sqlmap interactive shell
    r"|-O\s"                          # curl output to file (uppercase)
    r"|-o\s"                          # curl output to file
    r"|--output\s"                    # curl output to file
    r"|--upload-file"                 # curl upload
    r"|-T\s"                          # curl upload
    r"|-K\s|--config\s"              # curl load config file
    r")"
)

# Characters that should never appear in a target/URL argument
_SHELL_METACHAR_RE = re.compile(r"[;&|`$(){}\n\r]")


def sanitize_subprocess_arg(value: str, arg_type: str = "generic") -> str:
    """Strip dangerous characters from a subprocess argument.

    arg_type: 'url', 'flags', 'target', or 'generic'
    """
    # Strip shell metacharacters from all arg types
    value = _SHELL_METACHAR_RE.sub("", value)

    if arg_type == "flags":
        # Block dangerous flags
        if _DANGEROUS_FLAG_PATTERNS.search(value):
            # Remove the dangerous flags, keep the rest
            parts = value.split()
            safe_parts = []
            skip_next = False
            for i, part in enumerate(parts):
                if skip_next:
                    skip_next = False
                    continue
                if _DANGEROUS_FLAG_PATTERNS.match(part):
                    # If this flag takes an argument, skip the next part too
                    if part in ("-oN", "-oX", "-oG", "-oA", "-oS", "-O", "-o",
                                "--output", "-T", "--upload-file", "-K", "--config",
                                "--file-read", "--file-write"):
                        skip_next = True
                    continue
                safe_parts.append(part)
            value = " ".join(safe_parts)

    return value.strip()


def run_cmd(cmd: list[str], timeout: int = 120, stdin_data: str = "") -> dict[str, Any]:
    """Run a subprocess with timeout and return structured output.

    Shared implementation used by all tool wrappers.
    """
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data or None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout[:4000],  # Cap output to prevent context explosion
            "stderr": result.stderr[:1000],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"Tool not found: {cmd[0]}",
            "returncode": -1,
        }


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = int(minutes // 60)
    mins = int(minutes % 60)
    return f"{hours}h {mins}m {secs}s"
