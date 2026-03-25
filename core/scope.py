"""Scope parser and enforcement - prevents testing out-of-scope assets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass
class ScopeRule:
    """A single scope rule: domain pattern + in/out flag."""
    pattern: str
    in_scope: bool
    asset_type: str = "domain"  # domain, ip, url, wildcard


@dataclass
class Scope:
    """Parsed scope for a target program."""
    rules: list[ScopeRule] = field(default_factory=list)
    out_of_scope_patterns: list[str] = field(default_factory=list)
    notes: str = ""
    last_verified: str = ""

    STALENESS_DAYS = 30

    @property
    def is_stale(self) -> bool:
        """True if scope hasn't been verified in over 30 days."""
        if not self.last_verified:
            return True
        try:
            verified = datetime.fromisoformat(self.last_verified)
            return datetime.now() - verified > timedelta(days=self.STALENESS_DAYS)
        except (ValueError, TypeError):
            return True

    @property
    def staleness_warning(self) -> str:
        """Warning message if scope is stale, empty string if fresh."""
        if not self.is_stale:
            return ""
        if not self.last_verified:
            return "Scope has never been verified. Consider checking the program policy."
        return f"Scope was last verified {self.last_verified}. Re-check program policy for changes."

    def is_in_scope(self, url_or_domain: str) -> bool:
        """Check if a URL or domain is in scope. Conservative: deny if unsure."""
        if not self.rules:
            # No scope defined - allow (user didn't set restrictions)
            return True

        normalized = self._normalize(url_or_domain)

        # Check out-of-scope patterns first (deny takes priority)
        for pattern in self.out_of_scope_patterns:
            if self._matches(normalized, pattern):
                return False

        # Check in-scope rules
        for rule in self.rules:
            if rule.in_scope and self._matches(normalized, rule.pattern):
                return True

        return False

    def add_in_scope(self, pattern: str, asset_type: str = "domain") -> None:
        """Add an in-scope pattern."""
        self.rules.append(ScopeRule(pattern=pattern, in_scope=True, asset_type=asset_type))

    def add_out_of_scope(self, pattern: str) -> None:
        """Add an out-of-scope pattern."""
        self.out_of_scope_patterns.append(pattern)

    def _normalize(self, url_or_domain: str) -> str:
        """Strip protocol and path for domain matching."""
        url_or_domain = url_or_domain.lower().strip()
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            return parsed.hostname or url_or_domain
        return url_or_domain.split("/")[0].split(":")[0]

    def _matches(self, domain: str, pattern: str) -> bool:
        """Match domain against pattern. Supports wildcards (*.example.com)."""
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com and example.com
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern

    def save(self, target_dir: Path) -> None:
        """Save scope to target memory directory."""
        memory_dir = target_dir / "memory"
        memory_dir.mkdir(parents=True, exist_ok=True)
        scope_file = memory_dir / "scope.md"

        lines = [
            f"# Scope - last verified {self.last_verified or 'never'}",
            "",
            "## In Scope",
        ]
        for rule in self.rules:
            if rule.in_scope:
                lines.append(f"- {rule.pattern} ({rule.asset_type})")

        lines.extend(["", "## Out of Scope"])
        for pattern in self.out_of_scope_patterns:
            lines.append(f"- {pattern}")

        if self.notes:
            lines.extend(["", "## Notes", self.notes])

        scope_file.write_text("\n".join(lines), encoding="utf-8")

    @classmethod
    def load(cls, target_dir: Path) -> "Scope":
        """Load scope from target memory directory."""
        scope_file = target_dir / "memory" / "scope.md"
        scope = cls()

        if not scope_file.exists():
            return scope

        content = scope_file.read_text(encoding="utf-8")
        section = ""
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("# Scope"):
                # Extract last_verified date
                match = re.search(r"last verified (.+)", line)
                if match and match.group(1) != "never":
                    scope.last_verified = match.group(1)
            elif line == "## In Scope":
                section = "in"
            elif line == "## Out of Scope":
                section = "out"
            elif line == "## Notes":
                section = "notes"
            elif line.startswith("- ") and section == "in":
                pattern = line[2:].split("(")[0].strip()
                scope.add_in_scope(pattern)
            elif line.startswith("- ") and section == "out":
                scope.add_out_of_scope(line[2:])
            elif section == "notes":
                scope.notes += line + "\n"

        return scope

    @classmethod
    def from_target(cls, target: str) -> "Scope":
        """Create a basic scope from a target URL/domain.

        Only scopes the exact domain provided (and its subdomains),
        NOT the entire root domain. For example, if target is
        'app.staging.example.com', only '*.app.staging.example.com'
        and 'app.staging.example.com' are in scope - not '*.example.com'.
        """
        scope = cls()
        scope.last_verified = datetime.now().isoformat()

        # Extract exact domain from target URL
        normalized = target.lower().replace("https://", "").replace("http://", "")
        domain = normalized.split("/")[0].split(":")[0]

        # Add the exact target domain and its subdomains
        scope.add_in_scope(domain, "domain")
        scope.add_in_scope(f"*.{domain}", "wildcard")

        return scope
