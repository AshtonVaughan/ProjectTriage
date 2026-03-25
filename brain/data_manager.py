"""
data_manager.py - Technology-aware data asset management for Project Triage.

Selects wordlists, payloads, and patterns based on the detected tech stack.
All data is loaded from data/wordlists/tech_routes.json and data/payloads/.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


# Tech fingerprint keys that map to framework names in tech_routes.json
_FRAMEWORK_ALIASES: dict[str, str] = {
    # Rails
    "rails": "rails",
    "ruby on rails": "rails",
    "ror": "rails",
    # Django
    "django": "django",
    # Next.js
    "next.js": "nextjs",
    "nextjs": "nextjs",
    "next": "nextjs",
    # Spring / Spring Boot
    "spring": "spring",
    "spring boot": "spring",
    "springboot": "spring",
    # Express
    "express": "express",
    "express.js": "express",
    "expressjs": "express",
    # Laravel
    "laravel": "laravel",
    # Flask
    "flask": "flask",
    # FastAPI
    "fastapi": "fastapi",
    "fast api": "fastapi",
    # WordPress
    "wordpress": "wordpress",
    "wp": "wordpress",
    # ASP.NET
    "asp.net": "asp_net",
    "asp_net": "asp_net",
    "aspnet": "asp_net",
    "asp.net core": "asp_net",
    ".net": "asp_net",
    "dotnet": "asp_net",
}

# WAF detection strings mapped to waf_bypass keys
_WAF_ALIASES: dict[str, str] = {
    "cloudflare": "cloudflare",
    "cf": "cloudflare",
    "akamai": "akamai",
    "aws waf": "aws_waf",
    "aws": "aws_waf",
    "waf_aws": "aws_waf",
    "modsecurity": "modsecurity",
    "mod_security": "modsecurity",
    "modsec": "modsecurity",
}


class DataManager:
    """Selects and provides technology-specific wordlists and payloads.

    Loads all data from JSON files in data_dir at construction time. All
    public methods are pure (no I/O after __init__) and operate on the
    in-memory representation, so callers can call them freely in hot loops.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.wordlists_dir = data_dir / "wordlists"
        self.payloads_dir = data_dir / "payloads"

        self._tech_routes: dict = {}
        self._extra_payloads: dict[str, list[str]] = {}

        self._load_tech_routes()
        self._load_extra_payloads()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _load_tech_routes(self) -> None:
        """Load the main tech_routes.json data file."""
        path = self.wordlists_dir / "tech_routes.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                self._tech_routes = json.load(fh)
        else:
            self._tech_routes = {
                "frameworks": {},
                "api_patterns": {},
                "sensitive_paths": [],
                "backup_extensions": [],
                "common_params": {},
                "waf_bypass": {},
            }

    def _load_extra_payloads(self) -> None:
        """Load any supplemental payload files from data/payloads/."""
        if not self.payloads_dir.exists():
            return
        for payload_file in self.payloads_dir.glob("*.json"):
            try:
                with open(payload_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        self._extra_payloads.update(data)
                    elif isinstance(data, list):
                        key = payload_file.stem
                        self._extra_payloads[key] = data
            except (json.JSONDecodeError, OSError):
                pass

    # ------------------------------------------------------------------
    # Internal resolution helpers
    # ------------------------------------------------------------------

    def _resolve_frameworks(self, tech_stack: dict) -> list[str]:
        """Return a deduplicated list of canonical framework keys from a tech_stack dict.

        The tech_stack dict may come from the fingerprinter and can contain
        keys such as 'framework', 'language', 'cms', 'server', or free-form
        technology names as top-level keys with truthy values.
        """
        candidates: list[str] = []

        # Check common structured keys
        for field in ("framework", "cms", "platform"):
            value = tech_stack.get(field, "")
            if isinstance(value, str) and value:
                candidates.append(value.lower())
            elif isinstance(value, list):
                candidates.extend(str(v).lower() for v in value if v)

        # Accept top-level string keys that map to known aliases
        for key, val in tech_stack.items():
            if isinstance(key, str) and (val is True or val == 1 or isinstance(val, str)):
                candidates.append(key.lower())

        resolved: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            canonical = _FRAMEWORK_ALIASES.get(candidate)
            if canonical and canonical not in seen:
                resolved.append(canonical)
                seen.add(canonical)
        return resolved

    def _resolve_waf(self, waf: str) -> Optional[str]:
        """Normalise a WAF name to a key present in waf_bypass data."""
        return _WAF_ALIASES.get(waf.lower().strip())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_routes_for_tech(self, tech_stack: dict) -> list[str]:
        """Return technology-specific route patterns for the given tech stack.

        Covers routes for Rails, Django, Next.js, Spring Boot, Express,
        Laravel, Flask, FastAPI, WordPress, and ASP.NET.

        When multiple frameworks are detected the route lists are merged and
        deduplicated while preserving insertion order (most specific first).

        Args:
            tech_stack: Dict produced by the tech fingerprinter. Expected
                keys include 'framework', 'cms', 'platform', and/or any
                free-form technology name as a key with a truthy value.

        Returns:
            Deduplicated list of URL paths to probe.
        """
        frameworks = self._resolve_frameworks(tech_stack)
        fw_data: dict = self._tech_routes.get("frameworks", {})

        routes: list[str] = []
        seen: set[str] = set()

        for fw_key in frameworks:
            fw_routes: list[str] = fw_data.get(fw_key, {}).get("routes", [])
            for route in fw_routes:
                if route not in seen:
                    routes.append(route)
                    seen.add(route)

        # Fall back to sensitive paths when no framework was matched
        if not routes:
            routes = list(self.get_sensitive_paths())

        return routes

    def get_params_for_tech(self, tech_stack: dict) -> list[str]:
        """Return technology-specific parameter names for the given tech stack.

        Merges framework-specific parameters with the common parameter sets
        (injection, auth, debug) from the data file.

        Args:
            tech_stack: Dict produced by the tech fingerprinter.

        Returns:
            Deduplicated list of parameter names to fuzz.
        """
        frameworks = self._resolve_frameworks(tech_stack)
        fw_data: dict = self._tech_routes.get("frameworks", {})

        params: list[str] = []
        seen: set[str] = set()

        # Framework-specific params first (highest signal)
        for fw_key in frameworks:
            fw_params: list[str] = fw_data.get(fw_key, {}).get("params", [])
            for p in fw_params:
                if p not in seen:
                    params.append(p)
                    seen.add(p)

        # Append common parameter buckets
        common: dict = self._tech_routes.get("common_params", {})
        for bucket in ("injection", "auth", "debug"):
            for p in common.get(bucket, []):
                if p not in seen:
                    params.append(p)
                    seen.add(p)

        return params

    def get_payloads_for_vuln(
        self,
        vuln_type: str,
        tech_stack: dict,
        waf: str = "",
    ) -> list[str]:
        """Return payloads for a vulnerability type, filtered by tech and WAF.

        Payload selection priority:
        1. WAF-specific bypass payloads (when WAF is detected)
        2. Extra payloads loaded from data/payloads/<vuln_type>.json
        3. Generic payloads embedded in tech_routes.json waf_bypass section
           using the first available WAF bucket as a generic source

        Args:
            vuln_type: Vulnerability class. Supported values: 'xss', 'sqli',
                'ssti', 'ssrf', 'xxe', 'open_redirect', 'cmd_injection',
                'path_traversal', 'cors', 'crlf', 'proto_pollution'.
            tech_stack: Dict produced by the tech fingerprinter (used for
                future tech-aware payload selection).
            waf: Detected WAF name (e.g. 'cloudflare', 'akamai'). Empty
                string means no WAF or unknown WAF.

        Returns:
            List of payload strings ordered from most evasive to simplest.
        """
        norm_vuln = vuln_type.lower().strip()
        payloads: list[str] = []
        seen: set[str] = set()

        def _add(items: list[str]) -> None:
            for item in items:
                if item not in seen:
                    payloads.append(item)
                    seen.add(item)

        waf_data: dict = self._tech_routes.get("waf_bypass", {})

        # 1. WAF-specific payloads
        if waf:
            canonical_waf = self._resolve_waf(waf)
            if canonical_waf:
                waf_bucket = waf_data.get(canonical_waf, {})
                _add(waf_bucket.get(norm_vuln, []))

        # 2. Extra payloads from supplemental files
        extra_key = f"{norm_vuln}_payloads"
        _add(self._extra_payloads.get(extra_key, []))
        _add(self._extra_payloads.get(norm_vuln, []))

        # 3. Generic payloads from all WAF buckets (deduplicated)
        for waf_bucket in waf_data.values():
            _add(waf_bucket.get(norm_vuln, []))

        return payloads

    def get_api_patterns(self, api_type: str) -> list[str]:
        """Return API-specific route patterns.

        Args:
            api_type: One of 'rest', 'graphql', 'grpc_web', 'soap'.
                Case-insensitive. Partial matches are supported (e.g. 'grpc'
                will match 'grpc_web').

        Returns:
            List of URL path patterns for the given API style.
        """
        api_data: dict = self._tech_routes.get("api_patterns", {})
        norm = api_type.lower().strip().replace("-", "_").replace(" ", "_")

        # Exact match first
        if norm in api_data:
            return list(api_data[norm])

        # Partial match (e.g. 'grpc' -> 'grpc_web')
        for key, patterns in api_data.items():
            if norm in key or key in norm:
                return list(patterns)

        # Return all patterns merged when api_type is 'all' or empty
        if norm in ("all", ""):
            merged: list[str] = []
            seen: set[str] = set()
            for patterns in api_data.values():
                for p in patterns:
                    if p not in seen:
                        merged.append(p)
                        seen.add(p)
            return merged

        return []

    def get_sensitive_paths(self) -> list[str]:
        """Return paths that commonly expose sensitive data.

        Includes git repos, environment files, config files, log files,
        database dumps, admin interfaces, and debug endpoints.

        Returns:
            List of URL paths worth probing on any target.
        """
        return list(self._tech_routes.get("sensitive_paths", []))

    def get_backup_extensions(self) -> list[str]:
        """Return backup and temporary file extensions to test.

        These are appended to discovered filenames to check whether backup
        copies have been left accessible (e.g. config.php -> config.php.bak).

        Returns:
            List of extension strings including the leading dot (or tilde).
        """
        return list(self._tech_routes.get("backup_extensions", []))

    def get_tech_files(self, tech_stack: dict) -> list[str]:
        """Return known build/config files for the detected framework.

        These are typically located at the web root and may expose framework
        version, dependencies, or environment configuration.

        Args:
            tech_stack: Dict produced by the tech fingerprinter.

        Returns:
            Deduplicated list of file paths to probe.
        """
        frameworks = self._resolve_frameworks(tech_stack)
        fw_data: dict = self._tech_routes.get("frameworks", {})

        files: list[str] = []
        seen: set[str] = set()

        for fw_key in frameworks:
            fw_files: list[str] = fw_data.get(fw_key, {}).get("files", [])
            for f in fw_files:
                if f not in seen:
                    files.append(f)
                    seen.add(f)

        return files

    def get_all_routes(self) -> dict[str, list[str]]:
        """Return all framework routes keyed by framework name.

        Useful when the tech stack is unknown and a broad sweep is needed.

        Returns:
            Dict mapping framework name to its route list.
        """
        fw_data: dict = self._tech_routes.get("frameworks", {})
        return {fw: list(data.get("routes", [])) for fw, data in fw_data.items()}

    def get_framework_names(self) -> list[str]:
        """Return the list of framework keys available in the data file."""
        return list(self._tech_routes.get("frameworks", {}).keys())

    def get_waf_names(self) -> list[str]:
        """Return the list of WAF keys available in the data file."""
        return list(self._tech_routes.get("waf_bypass", {}).keys())

    def get_common_params(self, bucket: Optional[str] = None) -> list[str]:
        """Return common parameter names, optionally filtered by category.

        Args:
            bucket: One of 'injection', 'auth', 'debug'. When None, all
                buckets are returned merged and deduplicated.

        Returns:
            List of parameter name strings.
        """
        common: dict = self._tech_routes.get("common_params", {})
        if bucket:
            return list(common.get(bucket.lower(), []))

        merged: list[str] = []
        seen: set[str] = set()
        for items in common.values():
            for p in items:
                if p not in seen:
                    merged.append(p)
                    seen.add(p)
        return merged

    def get_waf_bypass_payloads(self, waf_name: str, vuln_type: str) -> list[str]:
        """Return WAF-specific bypass payloads directly.

        Thin convenience wrapper around get_payloads_for_vuln for callers
        that already know exactly which WAF they are dealing with.

        Args:
            waf_name: Canonical WAF name (e.g. 'cloudflare', 'akamai').
            vuln_type: Vulnerability type (e.g. 'xss', 'sqli').

        Returns:
            List of bypass payload strings.
        """
        waf_data: dict = self._tech_routes.get("waf_bypass", {})
        canonical = self._resolve_waf(waf_name) or waf_name.lower()
        bucket = waf_data.get(canonical, {})
        return list(bucket.get(vuln_type.lower(), []))

    def reload(self) -> None:
        """Reload all data files from disk.

        Call this if data files have been updated at runtime.
        """
        self._tech_routes = {}
        self._extra_payloads = {}
        self._load_tech_routes()
        self._load_extra_payloads()

    def summary(self) -> dict:
        """Return a summary of loaded data for diagnostic purposes.

        Returns:
            Dict with counts of routes, params, sensitive paths, payloads, etc.
        """
        fw_data: dict = self._tech_routes.get("frameworks", {})
        route_counts = {fw: len(d.get("routes", [])) for fw, d in fw_data.items()}
        param_counts = {fw: len(d.get("params", [])) for fw, d in fw_data.items()}
        waf_data: dict = self._tech_routes.get("waf_bypass", {})
        payload_counts: dict = {}
        for waf, vuln_map in waf_data.items():
            payload_counts[waf] = {vuln: len(plist) for vuln, plist in vuln_map.items()}

        return {
            "frameworks": list(fw_data.keys()),
            "route_counts": route_counts,
            "param_counts": param_counts,
            "sensitive_paths": len(self._tech_routes.get("sensitive_paths", [])),
            "backup_extensions": len(self._tech_routes.get("backup_extensions", [])),
            "common_params": {
                k: len(v)
                for k, v in self._tech_routes.get("common_params", {}).items()
            },
            "waf_bypass": payload_counts,
            "extra_payload_keys": list(self._extra_payloads.keys()),
            "api_pattern_types": list(self._tech_routes.get("api_patterns", {}).keys()),
        }


# ---------------------------------------------------------------------------
# Quick smoke test - run this file directly to verify loading
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import pprint

    project_root = Path(__file__).parent
    dm = DataManager(project_root / "data")

    print("=== DataManager summary ===")
    pprint.pprint(dm.summary())
    print()

    rails_stack = {"framework": "Rails"}
    print(f"Rails routes ({len(dm.get_routes_for_tech(rails_stack))}):")
    for r in dm.get_routes_for_tech(rails_stack)[:10]:
        print(f"  {r}")
    print("  ...")
    print()

    print("Sensitive paths (first 10):")
    for p in dm.get_sensitive_paths()[:10]:
        print(f"  {p}")
    print()

    print("Cloudflare XSS bypass payloads:")
    for payload in dm.get_waf_bypass_payloads("cloudflare", "xss")[:5]:
        print(f"  {payload}")
    print()

    print("GraphQL routes:")
    for r in dm.get_api_patterns("graphql"):
        print(f"  {r}")
