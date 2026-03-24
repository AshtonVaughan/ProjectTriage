"""Wordlist Manager - curated built-in wordlists for security testing.

No external files are required. All lists ship with the module.
Custom wordlists can be loaded from disk to supplement the built-ins.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Built-in wordlists
# ---------------------------------------------------------------------------

_API_PATHS: List[str] = [
    "/api/v1/users",
    "/api/v1/user",
    "/api/v1/accounts",
    "/api/v1/account",
    "/api/v1/profile",
    "/api/v1/me",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/settings",
    "/api/v1/tokens",
    "/api/v1/keys",
    "/api/v1/secrets",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/metrics",
    "/api/v2/users",
    "/api/v2/accounts",
    "/api/v2/admin",
    "/api/v2/health",
    "/api/v2/me",
    "/api/health",
    "/api/status",
    "/api/admin",
    "/api/debug",
    "/api/config",
    "/api/ping",
    "/graphql",
    "/graphiql",
    "/graphql/console",
    "/graphql/playground",
    "/admin",
    "/admin/api",
    "/internal",
    "/internal/api",
    "/swagger",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/v1",
    "/v2",
    "/v3",
    "/_api",
    "/_internal",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/service",
]

_COMMON_PARAMETERS: List[str] = [
    "id",
    "user_id",
    "userId",
    "account_id",
    "accountId",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return_url",
    "returnUrl",
    "next",
    "url",
    "uri",
    "link",
    "file",
    "filename",
    "path",
    "filepath",
    "page",
    "template",
    "view",
    "include",
    "load",
    "ref",
]

_COMMON_SUBDOMAINS: List[str] = [
    "api",
    "admin",
    "dev",
    "develop",
    "development",
    "staging",
    "stage",
    "stg",
    "test",
    "testing",
    "qa",
    "uat",
    "internal",
    "intranet",
    "portal",
    "dashboard",
    "console",
    "manage",
    "management",
    "cms",
    "backend",
    "app",
    "apps",
    "static",
    "cdn",
    "media",
    "assets",
    "files",
    "uploads",
    "mail",
]

_DIRECTORY_PATHS: List[str] = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin/panel",
    "/backup",
    "/backups",
    "/bak",
    "/.git",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/config",
    "/config.php",
    "/config.yml",
    "/configuration.php",
    "/database",
    "/db",
    "/dump",
    "/debug",
    "/info.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/.well-known",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.htaccess",
    "/web.config",
    "/install.php",
]

_FILE_EXTENSIONS: List[str] = [
    ".bak",
    ".old",
    ".orig",
    ".copy",
    ".sql",
    ".dump",
    ".env",
    ".config",
    ".cfg",
    ".conf",
    ".log",
    ".swp",
    ".tmp",
    ".zip",
    ".tar.gz",
]

# Registry mapping category name to its list
_REGISTRY: Dict[str, List[str]] = {
    "api_paths": _API_PATHS,
    "parameters": _COMMON_PARAMETERS,
    "subdomains": _COMMON_SUBDOMAINS,
    "directories": _DIRECTORY_PATHS,
    "extensions": _FILE_EXTENSIONS,
}

VALID_CATEGORIES = list(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get(category: str) -> List[str]:
    """Return a copy of the built-in wordlist for the given category.

    Args:
        category: One of 'api_paths', 'parameters', 'subdomains',
                  'directories', or 'extensions'.

    Returns:
        List of wordlist entries.

    Raises:
        KeyError: If the category name is not recognised.
    """
    if category not in _REGISTRY:
        raise KeyError(
            f"Unknown wordlist category '{category}'. "
            f"Valid categories: {VALID_CATEGORIES}"
        )
    return list(_REGISTRY[category])


def combine(*categories: str) -> List[str]:
    """Merge one or more wordlist categories into a single deduplicated list.

    Preserves insertion order (first occurrence wins).

    Args:
        *categories: One or more category names to merge.

    Returns:
        Deduplicated list combining all requested categories.
    """
    seen: set[str] = set()
    result: List[str] = []
    for category in categories:
        for entry in get(category):
            if entry not in seen:
                seen.add(entry)
                result.append(entry)
    return result


def load_file(path: str, deduplicate: bool = True) -> List[str]:
    """Load a custom wordlist from a plain-text file (one entry per line).

    Blank lines and lines beginning with '#' are ignored.

    Args:
        path: Absolute or relative path to the wordlist file.
        deduplicate: Remove duplicate entries while preserving order.

    Returns:
        List of entries from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Wordlist file not found: {path}")

    entries: List[str] = []
    seen: set[str] = set()

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if deduplicate:
                if line not in seen:
                    seen.add(line)
                    entries.append(line)
            else:
                entries.append(line)

    return entries


def combine_with_file(
    path: str,
    *categories: str,
    deduplicate: bool = True,
) -> List[str]:
    """Combine built-in categories with entries loaded from a custom file.

    The file entries are appended after the built-in entries.

    Args:
        path: Path to the custom wordlist file.
        *categories: Built-in category names to include first.
        deduplicate: Remove duplicates across the combined result.

    Returns:
        Combined list.
    """
    base = combine(*categories) if categories else []
    custom = load_file(path, deduplicate=False)

    if not deduplicate:
        return base + custom

    seen: set[str] = set(base)
    result = list(base)
    for entry in custom:
        if entry not in seen:
            seen.add(entry)
            result.append(entry)
    return result


def all_categories() -> List[str]:
    """Return the list of available built-in category names."""
    return list(VALID_CATEGORIES)


def summary() -> Dict[str, int]:
    """Return a dict mapping each category to its entry count."""
    return {cat: len(lst) for cat, lst in _REGISTRY.items()}
