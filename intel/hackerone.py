"""HackerOne Program Importer - structured program data for Project Triage v4.

Fetches HackerOne (and Bugcrowd) program scope, bounty tables, and policy
details, then persists them as structured JSON files the agent references
during hunts.

Supports three data acquisition paths with graceful fallback:
  1. HackerOne API v1 (requires HACKERONE_USERNAME + HACKERONE_API_TOKEN env vars)
  2. Public undocumented JSON endpoints (/{handle}.json, /policy_scopes.json)
  3. HTML scraping of the public program page via curl

Usage:
    importer = HackerOneImporter(data_dir=Path("data"))
    profile  = importer.import_program("shopify")
    print(importer.generate_scope_context(profile))
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# User-agent used for all requests
# ---------------------------------------------------------------------------

_UA = "Project-Triage/4.0 (security-research; authorized)"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BountyTable:
    """Bounty payout ranges by severity."""

    critical_min: int = 0
    critical_max: int = 0
    high_min: int = 0
    high_max: int = 0
    medium_min: int = 0
    medium_max: int = 0
    low_min: int = 0
    low_max: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "critical_min": self.critical_min,
            "critical_max": self.critical_max,
            "high_min": self.high_min,
            "high_max": self.high_max,
            "medium_min": self.medium_min,
            "medium_max": self.medium_max,
            "low_min": self.low_min,
            "low_max": self.low_max,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BountyTable":
        return cls(
            critical_min=int(data.get("critical_min", 0)),
            critical_max=int(data.get("critical_max", 0)),
            high_min=int(data.get("high_min", 0)),
            high_max=int(data.get("high_max", 0)),
            medium_min=int(data.get("medium_min", 0)),
            medium_max=int(data.get("medium_max", 0)),
            low_min=int(data.get("low_min", 0)),
            low_max=int(data.get("low_max", 0)),
        )

    def severity_value(self, severity: str) -> int:
        """Return the max payout for a given severity. Used to weight hypotheses."""
        mapping = {
            "critical": self.critical_max,
            "high": self.high_max,
            "medium": self.medium_max,
            "low": self.low_max,
        }
        return mapping.get(severity.lower(), 0)

    def is_empty(self) -> bool:
        """True when no bounty data has been parsed yet."""
        return not any([
            self.critical_max, self.high_max, self.medium_max, self.low_max,
        ])


@dataclass
class ScopeAsset:
    """A single in-scope or out-of-scope asset."""

    asset_type: str           # URL, CIDR, DOMAIN, WILDCARD, IOS_APP, ANDROID_APP, SOURCE_CODE, HARDWARE, OTHER
    identifier: str           # *.example.com, 192.168.1.0/24, com.example.app
    eligible_for_bounty: bool
    eligible_for_submission: bool
    instruction: str          # Program-specific notes for this asset
    max_severity: str         # critical, high, medium, low, none
    created_at: str           # ISO date - recent = zero-competition window
    confidentiality_requirement: str  # none, low, medium, high

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "identifier": self.identifier,
            "eligible_for_bounty": self.eligible_for_bounty,
            "eligible_for_submission": self.eligible_for_submission,
            "instruction": self.instruction,
            "max_severity": self.max_severity,
            "created_at": self.created_at,
            "confidentiality_requirement": self.confidentiality_requirement,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeAsset":
        return cls(
            asset_type=data.get("asset_type", "URL"),
            identifier=data.get("identifier", ""),
            eligible_for_bounty=bool(data.get("eligible_for_bounty", False)),
            eligible_for_submission=bool(data.get("eligible_for_submission", True)),
            instruction=data.get("instruction", ""),
            max_severity=data.get("max_severity", "critical"),
            created_at=data.get("created_at", ""),
            confidentiality_requirement=data.get("confidentiality_requirement", ""),
        )

    def matches_url(self, url: str) -> bool:
        """Check whether url falls under this asset's identifier."""
        from urllib.parse import urlparse

        url_lower = url.lower()
        ident = self.identifier.lower()

        if ident.startswith("*."):
            # Wildcard: *.example.com matches api.example.com and example.com
            # Extract only the hostname portion of the URL for comparison
            try:
                host = urlparse(url_lower).hostname or url_lower
            except Exception:
                host = url_lower
            suffix = ident[2:]  # "example.com" (strip the "*.")
            return host == suffix or host.endswith("." + suffix)

        if ident.startswith("http://") or ident.startswith("https://"):
            return url_lower.startswith(ident)

        # Plain domain: match against the hostname of the URL
        try:
            host = urlparse(url_lower).hostname or ""
        except Exception:
            host = ""
        if host and (host == ident or host.endswith("." + ident)):
            return True

        # CIDR / identifier substring fallback
        return ident in url_lower


@dataclass
class ProgramProfile:
    """Complete HackerOne program profile."""

    handle: str
    name: str
    url: str                  # https://hackerone.com/{handle}
    platform: str             # hackerone, bugcrowd, intigriti

    state: str = "open"       # open, paused

    # Scope
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)

    # Bounty
    bounty_table: BountyTable = field(default_factory=BountyTable)
    offers_bounties: bool = False
    offers_swag: bool = False

    # Policy
    policy_text: str = ""
    out_of_scope_text: str = ""   # Explicit OOS rules (no DoS, no social engineering, etc.)
    safe_harbor: bool = False

    # Stats
    resolved_report_count: int = 0
    average_bounty: int = 0
    top_bounty: int = 0
    response_time_days: float = 0.0

    # Recent changes (zero-competition window)
    recent_scope_additions: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    fetched_at: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Serialisation
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-saveable dict."""
        return {
            "handle": self.handle,
            "name": self.name,
            "url": self.url,
            "platform": self.platform,
            "state": self.state,
            "in_scope": [a.to_dict() for a in self.in_scope],
            "out_of_scope": [a.to_dict() for a in self.out_of_scope],
            "bounty_table": self.bounty_table.to_dict(),
            "offers_bounties": self.offers_bounties,
            "offers_swag": self.offers_swag,
            "policy_text": self.policy_text,
            "out_of_scope_text": self.out_of_scope_text,
            "safe_harbor": self.safe_harbor,
            "resolved_report_count": self.resolved_report_count,
            "average_bounty": self.average_bounty,
            "top_bounty": self.top_bounty,
            "response_time_days": self.response_time_days,
            "recent_scope_additions": self.recent_scope_additions,
            "fetched_at": self.fetched_at,
            # Omit raw_data from serialisation - too large and not useful after parsing
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProgramProfile":
        """Deserialize from saved JSON."""
        profile = cls(
            handle=data["handle"],
            name=data.get("name", data["handle"]),
            url=data.get("url", f"https://hackerone.com/{data['handle']}"),
            platform=data.get("platform", "hackerone"),
            state=data.get("state", "open"),
            offers_bounties=bool(data.get("offers_bounties", False)),
            offers_swag=bool(data.get("offers_swag", False)),
            policy_text=data.get("policy_text", ""),
            out_of_scope_text=data.get("out_of_scope_text", ""),
            safe_harbor=bool(data.get("safe_harbor", False)),
            resolved_report_count=int(data.get("resolved_report_count", 0)),
            average_bounty=int(data.get("average_bounty", 0)),
            top_bounty=int(data.get("top_bounty", 0)),
            response_time_days=float(data.get("response_time_days", 0.0)),
            recent_scope_additions=data.get("recent_scope_additions", []),
            fetched_at=data.get("fetched_at", ""),
        )
        profile.bounty_table = BountyTable.from_dict(data.get("bounty_table", {}))
        profile.in_scope = [ScopeAsset.from_dict(a) for a in data.get("in_scope", [])]
        profile.out_of_scope = [ScopeAsset.from_dict(a) for a in data.get("out_of_scope", [])]
        return profile

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def scope_summary(self) -> str:
        """Human-readable scope summary for the agent's context window."""
        lines: list[str] = [
            f"{self.name} | {self.platform} | state={self.state}",
            f"Bounties: {'yes' if self.offers_bounties else 'no'} | "
            f"In-scope assets: {len(self.in_scope)} | "
            f"OOS assets: {len(self.out_of_scope)}",
        ]
        if not self.bounty_table.is_empty():
            bt = self.bounty_table
            lines.append(
                f"Payouts - Critical: ${bt.critical_min:,}-${bt.critical_max:,} | "
                f"High: ${bt.high_min:,}-${bt.high_max:,} | "
                f"Medium: ${bt.medium_min:,}-${bt.medium_max:,} | "
                f"Low: ${bt.low_min:,}-${bt.low_max:,}"
            )
        if self.recent_scope_additions:
            assets = ", ".join(r["asset"] for r in self.recent_scope_additions[:5])
            lines.append(f"RECENTLY ADDED ({len(self.recent_scope_additions)}): {assets}")
        return "\n".join(lines)

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL matches any in-scope asset."""
        if not self.in_scope:
            return True  # No scope data - assume in scope
        return any(a.matches_url(url) for a in self.in_scope)

    def is_out_of_scope(self, url: str) -> bool:
        """Check if a URL matches any explicit out-of-scope asset."""
        return any(a.matches_url(url) for a in self.out_of_scope)

    def bounty_eligible_assets(self) -> list[ScopeAsset]:
        """Return only assets that are eligible for a bounty payout."""
        return [a for a in self.in_scope if a.eligible_for_bounty]


# ---------------------------------------------------------------------------
# Bounty amount parsing helpers
# ---------------------------------------------------------------------------

# Matches "$1,000", "$20000", "$1.5k", etc.
_DOLLAR_AMOUNT_RE = re.compile(r"\$\s*([\d,]+(?:\.\d+)?)\s*[kK]?")
# Matches a range like "$500 - $5,000" or "$500-$5000"
_BOUNTY_RANGE_RE = re.compile(
    r"\$([\d,]+(?:\.\d+)?)\s*[kK]?\s*[-to]+\s*\$([\d,]+(?:\.\d+)?)\s*[kK]?",
    re.IGNORECASE,
)
# Severity label pattern
_SEVERITY_LABEL_RE = re.compile(
    r"(critical|high|medium|low|informational)\s*:?\s*"
    r"\$([\d,]+(?:\.\d+)?)\s*[kK]?\s*(?:[-to]+\s*\$([\d,]+(?:\.\d+)?)\s*[kK]?)?",
    re.IGNORECASE,
)


def _parse_dollar(value: str, is_k: bool = False) -> int:
    """Convert a dollar string like '5,000' to int. Handles k suffix."""
    try:
        n = float(value.replace(",", ""))
        if is_k:
            n *= 1000
        return int(n)
    except (ValueError, TypeError):
        return 0


def _extract_bounty_range(text: str, severity: str) -> tuple[int, int]:
    """Extract min/max dollar amounts for a specific severity from text.

    Searches line by line so adjacent lines for other severities do not bleed
    into each other's matches. Falls back to a relaxed multi-line pass if
    the per-line search finds nothing.
    """
    # Pass 1: line-by-line - most reliable
    for line in text.splitlines():
        if not re.search(rf"\b{severity}\b", line, re.IGNORECASE):
            continue
        # Try to find a range like $5,000 - $20,000 or $5k - $20k
        range_m = re.search(
            r"\$([\d,]+)\s*([kK])?\s*[-]\s*\$([\d,]+)\s*([kK])?",
            line,
        )
        if range_m:
            lo = _parse_dollar(range_m.group(1), bool(range_m.group(2)))
            hi = _parse_dollar(range_m.group(3), bool(range_m.group(4)))
            return lo, hi
        # Single amount
        single_m = re.search(r"\$([\d,]+)\s*([kK])?", line)
        if single_m:
            val = _parse_dollar(single_m.group(1), bool(single_m.group(2)))
            return val, val

    # Pass 2: relaxed multi-line search (handles "Critical:\n  $5,000 - $20,000")
    pattern = re.compile(
        rf"\b{severity}\b[^\n$]{{0,40}}\n?[^\n$]{{0,20}}\$([\d,]+)\s*([kK])?"
        rf"(?:[^\n$]{{0,20}}\$([\d,]+)\s*([kK])?)?",
        re.IGNORECASE,
    )
    m = pattern.search(text)
    if m:
        lo = _parse_dollar(m.group(1), bool(m.group(2)))
        hi = _parse_dollar(m.group(3), bool(m.group(4))) if m.group(3) else lo
        return lo, hi

    return 0, 0


# ---------------------------------------------------------------------------
# HTML extraction helpers
# ---------------------------------------------------------------------------

def _strip_tags(html: str) -> str:
    """Very lightweight HTML tag stripper - no external deps."""
    return re.sub(r"<[^>]+>", " ", html)


def _html_decode(text: str) -> str:
    """Decode basic HTML entities."""
    entities = {
        "&amp;": "&", "&lt;": "<", "&gt;": ">",
        "&quot;": '"', "&#39;": "'", "&nbsp;": " ",
        "&#x27;": "'", "&#x2F;": "/",
    }
    for entity, char in entities.items():
        text = text.replace(entity, char)
    return text


def _extract_json_blob(html: str, key: str) -> dict[str, Any] | None:
    """Extract a JSON blob assigned to a JS variable or data attribute in HTML."""
    # Try __NEXT_DATA__ pattern first (Next.js)
    patterns = [
        rf'id="{key}"[^>]*>(\{{.*?\}})</script>',
        rf'"{key}"\s*:\s*(\{{[^{{}}]{{0,50000}}\}})',
        rf"window\['{key}'\]\s*=\s*(\{{.*?\}});",
        rf"var\s+{key}\s*=\s*(\{{.*?\}});",
    ]
    for pat in patterns:
        m = re.search(pat, html, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return None


def _extract_next_data(html: str) -> dict[str, Any] | None:
    """Extract __NEXT_DATA__ from a Next.js-rendered page."""
    m = re.search(
        r'<script[^>]+id="__NEXT_DATA__"[^>]*>\s*(\{.*?\})\s*</script>',
        html,
        re.DOTALL,
    )
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return None


# ---------------------------------------------------------------------------
# Main importer
# ---------------------------------------------------------------------------

class HackerOneImporter:
    """Fetches and saves HackerOne (and Bugcrowd) program data."""

    def __init__(self, data_dir: Path = Path("data")) -> None:
        self.data_dir = data_dir
        self.programs_dir = data_dir / "programs"
        self.programs_dir.mkdir(parents=True, exist_ok=True)

        # HackerOne API credentials (optional)
        self.api_username: str = os.getenv("HACKERONE_USERNAME", "")
        self.api_token: str = os.getenv("HACKERONE_API_TOKEN", "")

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    @property
    def has_api_credentials(self) -> bool:
        return bool(self.api_username and self.api_token)

    def import_program(self, handle_or_url: str) -> ProgramProfile:
        """Import a program from HackerOne. Tries API first, falls back to scraping.

        Accepts:
        - Program handle: "shopify"
        - Full HackerOne URL: "https://hackerone.com/shopify"
        - Bugcrowd URL: "https://bugcrowd.com/shopify"
        """
        handle, platform = self._parse_input(handle_or_url)

        # Return cached profile if fresh
        saved = self.load_program(handle)
        if saved and not self._is_stale(saved):
            return saved

        if platform == "hackerone":
            profile = self._fetch_hackerone(handle)
        elif platform == "bugcrowd":
            profile = self._fetch_bugcrowd(handle)
        else:
            profile = self._fetch_hackerone(handle)  # default

        self.save_program(profile)
        return profile

    def refresh_program(self, handle: str) -> ProgramProfile:
        """Force-refresh a program, bypassing the staleness check."""
        handle, platform = self._parse_input(handle)
        if platform == "bugcrowd":
            profile = self._fetch_bugcrowd(handle)
        else:
            profile = self._fetch_hackerone(handle)
        self.save_program(profile)
        return profile

    # -----------------------------------------------------------------------
    # Input parsing
    # -----------------------------------------------------------------------

    def _parse_input(self, input_str: str) -> tuple[str, str]:
        """Parse handle or URL into (handle, platform)."""
        s = input_str.strip().rstrip("/")

        if "bugcrowd.com" in s:
            handle = s.rstrip("/").split("/")[-1]
            return handle, "bugcrowd"

        if "intigriti.com" in s:
            handle = s.rstrip("/").split("/")[-1]
            return handle, "intigriti"

        if "hackerone.com" in s:
            # e.g. https://hackerone.com/shopify or https://hackerone.com/shopify/policy_scopes
            parts = s.split("hackerone.com/", 1)
            handle = parts[1].split("/")[0] if len(parts) > 1 else s
            return handle, "hackerone"

        # Plain handle - no slashes, no dots
        if "/" not in s and "." not in s:
            return s, "hackerone"

        # Domain-style input: shopify.com - best-effort
        handle = s.replace("https://", "").replace("http://", "").split(".")[0]
        return handle, "hackerone"

    # -----------------------------------------------------------------------
    # HackerOne fetch orchestration
    # -----------------------------------------------------------------------

    def _fetch_hackerone(self, handle: str) -> ProgramProfile:
        """Fetch from HackerOne using API if credentials available, else scrape."""
        profile = ProgramProfile(
            handle=handle,
            name=handle,
            url=f"https://hackerone.com/{handle}",
            platform="hackerone",
        )

        if self.has_api_credentials:
            self._fetch_h1_api(profile)

        # Public undocumented endpoints (different data from the API)
        self._fetch_h1_public_json(profile)

        # HTML scrape as last resort / supplement
        self._fetch_h1_html(profile)

        # Post-processing
        self._parse_bounty_table(profile)
        self._detect_recent_additions(profile)

        profile.fetched_at = datetime.now().isoformat()
        return profile

    # -----------------------------------------------------------------------
    # HackerOne API v1
    # -----------------------------------------------------------------------

    def _fetch_h1_api(self, profile: ProgramProfile) -> None:
        """Fetch via HackerOne API v1 (requires credentials).

        Endpoint: GET https://api.hackerone.com/v1/hackers/programs/{handle}
        Auth: Basic auth with username:api_token
        """
        base = f"https://api.hackerone.com/v1/hackers/programs/{profile.handle}"
        auth = base64.b64encode(
            f"{self.api_username}:{self.api_token}".encode()
        ).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "User-Agent": _UA,
        }

        # Paginate structured scopes
        scope_url = (
            f"https://api.hackerone.com/v1/hackers/programs/{profile.handle}"
            f"/structured_scopes?page%5Bsize%5D=100"
        )

        for url in (base, scope_url):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
                    if url == base:
                        profile.raw_data = data
                        self._parse_h1_api_response(profile, data)
                    else:
                        self._parse_h1_scopes_api(profile, data)
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
                pass

    def _parse_h1_api_response(self, profile: ProgramProfile, data: dict[str, Any]) -> None:
        """Parse the HackerOne API v1 JSON:API response format."""
        # JSON:API format: {"data": {"type": "program", "attributes": {...}, "relationships": {...}}}
        node = data.get("data", {})
        attrs = node.get("attributes", {})

        profile.name = attrs.get("name", profile.handle)
        profile.state = attrs.get("state", "open")
        profile.offers_bounties = bool(attrs.get("offers_bounties", False))
        profile.offers_swag = bool(attrs.get("offers_swag", False))
        profile.policy_text = attrs.get("policy", "")

        # Response time (median_time_to_first_response in hours)
        mttfr = attrs.get("median_time_to_first_response")
        if mttfr is not None:
            try:
                profile.response_time_days = float(mttfr) / 24.0
            except (TypeError, ValueError):
                pass

        # Safe harbor
        sf = attrs.get("safe_harbor", "")
        profile.safe_harbor = bool(sf and sf != "none")

        # Parse any inline structured_scopes from included array
        for item in data.get("included", []):
            if item.get("type") == "structured-scope":
                self._parse_scope_item(profile, item.get("attributes", {}))

    def _parse_h1_scopes_api(self, profile: ProgramProfile, data: dict[str, Any]) -> None:
        """Parse structured scopes from the dedicated scopes API endpoint."""
        for item in data.get("data", []):
            if item.get("type") == "structured-scope":
                self._parse_scope_item(profile, item.get("attributes", {}))

    def _parse_scope_item(self, profile: ProgramProfile, scope_attrs: dict[str, Any]) -> None:
        """Convert a single scope attributes dict into a ScopeAsset."""
        asset = ScopeAsset(
            asset_type=scope_attrs.get("asset_type", "URL"),
            identifier=scope_attrs.get("asset_identifier", ""),
            eligible_for_bounty=bool(scope_attrs.get("eligible_for_bounty", False)),
            eligible_for_submission=bool(scope_attrs.get("eligible_for_submission", True)),
            instruction=(scope_attrs.get("instruction") or "")[:500],
            max_severity=scope_attrs.get("max_severity", "critical"),
            created_at=scope_attrs.get("created_at", ""),
            confidentiality_requirement=scope_attrs.get("confidentiality_requirement", ""),
        )

        # Avoid duplicates by identifier
        existing_ids = {a.identifier for a in profile.in_scope + profile.out_of_scope}
        if asset.identifier in existing_ids:
            return

        if asset.eligible_for_submission:
            profile.in_scope.append(asset)
        else:
            profile.out_of_scope.append(asset)

    # -----------------------------------------------------------------------
    # HackerOne public undocumented JSON endpoints
    # -----------------------------------------------------------------------

    def _fetch_h1_public_json(self, profile: ProgramProfile) -> None:
        """Fetch public program data from undocumented JSON endpoints.

        Tries:
          /{handle}/policy_scopes.json  - scope array
          /{handle}.json                - program info including payout ranges
        """
        endpoints = [
            f"https://hackerone.com/{profile.handle}/policy_scopes.json",
            f"https://hackerone.com/{profile.handle}.json",
        ]
        for url in endpoints:
            safe_url = sanitize_subprocess_arg(url, "url")
            result = run_cmd(
                ["curl", "-s", "-L", safe_url, "--max-time", "15",
                 "-H", f"User-Agent: {_UA}",
                 "-H", "Accept: application/json"],
                timeout=20,
            )
            if result.get("returncode") != 0:
                continue
            raw = (result.get("stdout") or "").strip()
            if not raw:
                continue

            if raw.startswith("["):
                self._parse_h1_scopes_json(profile, raw)
            elif raw.startswith("{"):
                self._parse_h1_info_json(profile, raw)

    def _parse_h1_scopes_json(self, profile: ProgramProfile, raw_json: str) -> None:
        """Parse the /{handle}/policy_scopes.json response (array format)."""
        try:
            scopes = json.loads(raw_json)
        except json.JSONDecodeError:
            return

        existing_ids = {a.identifier for a in profile.in_scope + profile.out_of_scope}
        for s in scopes:
            identifier = s.get("asset_identifier", "")
            if not identifier or identifier in existing_ids:
                continue

            asset = ScopeAsset(
                asset_type=s.get("asset_type", "URL"),
                identifier=identifier,
                eligible_for_bounty=bool(s.get("eligible_for_bounty", False)),
                eligible_for_submission=bool(s.get("eligible_for_submission", True)),
                instruction=(s.get("instruction") or "")[:500],
                max_severity=s.get("max_severity", "critical"),
                created_at=s.get("created_at", ""),
                confidentiality_requirement=s.get("confidentiality_requirement", ""),
            )
            existing_ids.add(identifier)
            if asset.eligible_for_submission:
                profile.in_scope.append(asset)
            else:
                profile.out_of_scope.append(asset)

    def _parse_h1_info_json(self, profile: ProgramProfile, raw_json: str) -> None:
        """Parse the /{handle}.json response (program info format)."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return

        # Programme name
        if not profile.name or profile.name == profile.handle:
            profile.name = data.get("name", profile.handle)

        # Bounty flags
        if "offers_bounties" in data:
            profile.offers_bounties = bool(data["offers_bounties"])

        # Top bounty stats
        top_lower = data.get("top_bounty_lower_range", 0)
        top_upper = data.get("top_bounty_upper_range", 0)
        if top_upper:
            profile.top_bounty = int(top_upper)
            # Use these as critical range hints if bounty table is empty
            if profile.bounty_table.critical_max == 0 and top_upper:
                profile.bounty_table.critical_min = int(top_lower or 0)
                profile.bounty_table.critical_max = int(top_upper)

        # Average bounty
        avg = data.get("average_bounty_lower_range", 0) or data.get("average_bounty", 0)
        if avg:
            profile.average_bounty = int(avg)

        # Policy text from nested profile key
        nested = data.get("profile", {})
        if nested and not profile.policy_text:
            profile.policy_text = nested.get("policy", "")[:5000]

        # Resolved report count
        rc = data.get("resolved_report_count", 0)
        if rc:
            profile.resolved_report_count = int(rc)

        # Response time (in hours)
        mttfr = data.get("median_time_to_first_response_in_minutes")
        if mttfr:
            try:
                profile.response_time_days = float(mttfr) / 60.0 / 24.0
            except (TypeError, ValueError):
                pass

    # -----------------------------------------------------------------------
    # HackerOne HTML scraping
    # -----------------------------------------------------------------------

    def _fetch_h1_html(self, profile: ProgramProfile) -> None:
        """Fetch the public program HTML page and extract embedded data."""
        safe_url = sanitize_subprocess_arg(
            f"https://hackerone.com/{profile.handle}", "url"
        )
        result = run_cmd(
            ["curl", "-s", "-L", safe_url, "--max-time", "20",
             "-H", f"User-Agent: {_UA}",
             "-H", "Accept: text/html,application/xhtml+xml"],
            timeout=25,
        )
        if result.get("returncode") != 0:
            return
        html = result.get("stdout") or ""
        if not html:
            return

        self._parse_h1_html(profile, html)

    def _parse_h1_html(self, profile: ProgramProfile, html: str) -> None:
        """Extract program data from the HackerOne program HTML page.

        Attempts to extract:
        - __NEXT_DATA__ JSON blob (highest fidelity)
        - Bounty ranges from visible text
        - Scope table entries
        - Policy text sections
        - Response statistics
        """
        # 1. Try __NEXT_DATA__ (Next.js embedded JSON - most reliable)
        next_data = _extract_next_data(html)
        if next_data:
            self._parse_next_data(profile, next_data)

        # 2. Parse visible text for bounty table if still empty
        if profile.bounty_table.is_empty():
            plain = _html_decode(_strip_tags(html))
            self._parse_bounty_from_text(profile, plain)

        # 3. Extract scope identifiers from HTML scope tables
        if not profile.in_scope:
            self._parse_scope_from_html(profile, html)

        # 4. Extract policy text from HTML if not already set
        if not profile.policy_text:
            self._parse_policy_from_html(profile, html)

        # 5. Pull response statistics from visible text
        self._parse_stats_from_html(profile, html)

    def _parse_next_data(self, profile: ProgramProfile, data: dict[str, Any]) -> None:
        """Parse the __NEXT_DATA__ JSON blob from a Next.js page."""
        # Navigate into the deeply nested structure - varies by page version
        props = data.get("props", {})
        page_props = props.get("pageProps", {})

        # Try multiple known key paths
        program_data = (
            page_props.get("program")
            or page_props.get("programProfile")
            or page_props.get("data", {}).get("program")
            or {}
        )

        if not program_data:
            # Fallback: search for "handle" key anywhere in the tree
            program_data = self._deep_find_program(data, profile.handle)

        if not program_data:
            return

        attrs = program_data.get("attributes", program_data)

        # Basic attributes
        name = attrs.get("name") or attrs.get("handle", "")
        if name and name != profile.handle:
            profile.name = name

        state = attrs.get("state", "")
        if state:
            profile.state = state

        offers = attrs.get("offers_bounties")
        if offers is not None:
            profile.offers_bounties = bool(offers)

        policy = attrs.get("policy", "")
        if policy and not profile.policy_text:
            profile.policy_text = policy[:5000]

        # Structured scopes nested in relationships
        rels = program_data.get("relationships", {})
        scopes_data = rels.get("structured_scopes", {}).get("data", [])
        included = data.get("props", {}).get("pageProps", {}).get("included", [])

        for scope_ref in scopes_data:
            scope_id = scope_ref.get("id", "")
            # Find in included array
            for item in included:
                if item.get("id") == scope_id and item.get("type") == "structured-scope":
                    self._parse_scope_item(profile, item.get("attributes", {}))
                    break

        # Some pages embed scopes directly
        direct_scopes = attrs.get("structured_scopes", [])
        for s in direct_scopes:
            s_attrs = s.get("attributes", s)
            self._parse_scope_item(profile, s_attrs)

    def _deep_find_program(
        self, obj: Any, handle: str, depth: int = 0
    ) -> dict[str, Any] | None:
        """Recursively search a JSON tree for a program node matching handle."""
        if depth > 6 or not isinstance(obj, dict):
            return None
        if obj.get("handle") == handle or obj.get("attributes", {}).get("handle") == handle:
            return obj
        for v in obj.values():
            if isinstance(v, dict):
                found = self._deep_find_program(v, handle, depth + 1)
                if found:
                    return found
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        found = self._deep_find_program(item, handle, depth + 1)
                        if found:
                            return found
        return None

    def _parse_scope_from_html(self, profile: ProgramProfile, html: str) -> None:
        """Extract scope entries from HTML scope tables.

        HackerOne renders scope as table rows with asset type, identifier, and
        bounty eligibility. We use regex to pull identifiers from common patterns.
        """
        # Pattern 1: data-* attributes on scope rows
        for m in re.finditer(
            r'data-type=["\']([^"\']+)["\'][^>]*data-identifier=["\']([^"\']+)["\']',
            html,
        ):
            identifier = _html_decode(m.group(2))
            if identifier and not self._scope_identifier_exists(profile, identifier):
                asset = ScopeAsset(
                    asset_type=m.group(1).upper(),
                    identifier=identifier,
                    eligible_for_bounty=True,
                    eligible_for_submission=True,
                    instruction="",
                    max_severity="critical",
                    created_at="",
                    confidentiality_requirement="",
                )
                profile.in_scope.append(asset)

        # Pattern 2: Domain/URL patterns in scope section
        # Look for the scope section div and extract domains from it
        scope_section_m = re.search(
            r'(?:In-?[Ss]cope|Scope\s+Information)(.{200,8000}?)(?:Out[- ]of[- ][Ss]cope|$)',
            _strip_tags(html),
            re.DOTALL,
        )
        if scope_section_m:
            scope_text = scope_section_m.group(1)
            for m in re.finditer(
                r"(?:\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*){1,4}",
                scope_text,
            ):
                identifier = m.group(0).lower()
                # Skip generic words that happen to look like domains
                if len(identifier) < 5 or identifier.endswith((".html", ".png", ".css", ".js")):
                    continue
                if not self._scope_identifier_exists(profile, identifier):
                    asset_type = "WILDCARD" if identifier.startswith("*.") else "URL"
                    profile.in_scope.append(ScopeAsset(
                        asset_type=asset_type,
                        identifier=identifier,
                        eligible_for_bounty=True,
                        eligible_for_submission=True,
                        instruction="(extracted from HTML)",
                        max_severity="critical",
                        created_at="",
                        confidentiality_requirement="",
                    ))

    def _scope_identifier_exists(self, profile: ProgramProfile, identifier: str) -> bool:
        """Check if identifier already exists in any scope list."""
        all_ids = {a.identifier.lower() for a in profile.in_scope + profile.out_of_scope}
        return identifier.lower() in all_ids

    def _parse_policy_from_html(self, profile: ProgramProfile, html: str) -> None:
        """Extract policy text from the rendered HTML."""
        # Look for policy section
        patterns = [
            r'<div[^>]+(?:class|id)=["\'][^"\']*policy[^"\']*["\'][^>]*>(.*?)</div>',
            r'<section[^>]+(?:class|id)=["\'][^"\']*policy[^"\']*["\'][^>]*>(.*?)</section>',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.DOTALL | re.IGNORECASE)
            if m:
                text = _html_decode(_strip_tags(m.group(1))).strip()
                if len(text) > 100:
                    profile.policy_text = text[:5000]
                    return

        # Fallback: look for the largest block of text after "Disclosure Policy" heading
        m = re.search(
            r'Disclosure Policy.{0,200}?(<p|<ul|<ol|<div)(.*?)(</section>|</article>)',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        if m:
            text = _html_decode(_strip_tags(m.group(2))).strip()
            if len(text) > 100:
                profile.policy_text = text[:5000]

    def _parse_stats_from_html(self, profile: ProgramProfile, html: str) -> None:
        """Parse response statistics from the rendered page."""
        plain = _html_decode(_strip_tags(html))

        # Resolved reports count
        m = re.search(r"([\d,]+)\s+(?:resolved\s+)?reports?\s+resolved", plain, re.IGNORECASE)
        if m and not profile.resolved_report_count:
            try:
                profile.resolved_report_count = int(m.group(1).replace(",", ""))
            except ValueError:
                pass

        # Average response time in days
        m = re.search(
            r"(?:average|median)\s+(?:first\s+)?response\s*:?\s*([\d.]+)\s*(day|hour|hr|d)",
            plain,
            re.IGNORECASE,
        )
        if m and not profile.response_time_days:
            try:
                val = float(m.group(1))
                unit = m.group(2).lower()
                if unit.startswith("h"):
                    val /= 24.0
                profile.response_time_days = val
            except ValueError:
                pass

        # Safe harbor mentions
        if re.search(r"safe\s+harbor", plain, re.IGNORECASE):
            profile.safe_harbor = True

    # -----------------------------------------------------------------------
    # Bounty table parsing
    # -----------------------------------------------------------------------

    def _parse_bounty_table(self, profile: ProgramProfile) -> None:
        """Parse bounty amounts from policy text and any other available text.

        Common patterns:
          - "Critical: $5,000 - $20,000"
          - "High: $1,000 - $5,000"
          - Table format with severity | bounty columns
          - Markdown table: | Critical | $5,000 | $20,000 |
        """
        if not profile.policy_text and not profile.out_of_scope_text:
            return

        text = profile.policy_text + "\n" + profile.out_of_scope_text

        # First pass: try markdown table format (most structured)
        self._parse_bounty_markdown_table(profile, text)

        # Second pass: line-by-line "Severity: $lo - $hi" format
        # This will override markdown results only where it finds richer data
        for severity in ("critical", "high", "medium", "low"):
            lo, hi = _extract_bounty_range(text, severity)
            current_max = getattr(profile.bounty_table, f"{severity}_max")
            # Only update if the range parse found a non-trivial range (lo != hi or better data)
            if (lo or hi) and (hi > current_max or current_max == 0):
                setattr(profile.bounty_table, f"{severity}_min", lo)
                setattr(profile.bounty_table, f"{severity}_max", hi)

    def _parse_bounty_markdown_table(self, profile: ProgramProfile, text: str) -> None:
        """Parse bounty amounts from markdown table format.

        e.g.  | Critical | $5,000 | $20,000 |
              | High     | $1,000 | $5,000  |
        """
        # Match rows with severity labels and dollar amounts
        row_re = re.compile(
            r"\|\s*(critical|high|medium|low)\s*\|[^|]*\$\s*([\d,]+)[^|]*"
            r"(?:\|\s*\$\s*([\d,]+))?[^|]*\|",
            re.IGNORECASE,
        )
        for m in row_re.finditer(text):
            severity = m.group(1).lower()
            lo = _parse_dollar(m.group(2))
            hi = _parse_dollar(m.group(3)) if m.group(3) else lo
            setattr(profile.bounty_table, f"{severity}_min", lo)
            setattr(profile.bounty_table, f"{severity}_max", hi)

    def _parse_bounty_from_text(self, profile: ProgramProfile, text: str) -> None:
        """Parse bounty ranges from plain text (stripped HTML)."""
        for severity in ("critical", "high", "medium", "low"):
            lo, hi = _extract_bounty_range(text, severity)
            if lo or hi:
                setattr(profile.bounty_table, f"{severity}_min", lo)
                setattr(profile.bounty_table, f"{severity}_max", hi)

    # -----------------------------------------------------------------------
    # Recent scope additions
    # -----------------------------------------------------------------------

    def _detect_recent_additions(self, profile: ProgramProfile, days: int = 30) -> None:
        """Flag scope assets added within the last N days.

        Recently added assets represent zero-competition windows - the highest
        ROI targets in bug bounty hunting. First 48 hours after addition has
        a near-zero duplicate rate.
        """
        cutoff = datetime.now() - timedelta(days=days)
        profile.recent_scope_additions = []  # Reset to avoid duplicates

        for asset in profile.in_scope:
            if not asset.created_at:
                continue
            try:
                created_str = asset.created_at.replace("Z", "+00:00")
                created = datetime.fromisoformat(created_str)
                created_naive = created.replace(tzinfo=None)
                if created_naive > cutoff:
                    days_ago = (datetime.now() - created_naive).days
                    profile.recent_scope_additions.append({
                        "asset": asset.identifier,
                        "type": asset.asset_type,
                        "added": asset.created_at,
                        "days_ago": days_ago,
                        "eligible_for_bounty": asset.eligible_for_bounty,
                        "max_severity": asset.max_severity,
                    })
            except (ValueError, TypeError):
                pass

        # Sort by most recent first
        profile.recent_scope_additions.sort(key=lambda r: r.get("days_ago", 999))

    # -----------------------------------------------------------------------
    # Bugcrowd
    # -----------------------------------------------------------------------

    def _fetch_bugcrowd(self, handle: str) -> ProgramProfile:
        """Fetch program data from Bugcrowd."""
        profile = ProgramProfile(
            handle=handle,
            name=handle,
            url=f"https://bugcrowd.com/{handle}",
            platform="bugcrowd",
        )

        # Bugcrowd public JSON endpoint
        for suffix in ("", ".json"):
            url = f"https://bugcrowd.com/{handle}{suffix}"
            safe_url = sanitize_subprocess_arg(url, "url")
            result = run_cmd(
                ["curl", "-s", "-L", safe_url, "--max-time", "15",
                 "-H", f"User-Agent: {_UA}",
                 "-H", "Accept: application/json"],
                timeout=20,
            )
            if result.get("returncode") != 0:
                continue
            raw = (result.get("stdout") or "").strip()
            if raw.startswith("{"):
                self._parse_bugcrowd_json(profile, raw)
                break

        # Bugcrowd targets endpoint
        targets_url = f"https://bugcrowd.com/{handle}/target_groups.json"
        safe_url = sanitize_subprocess_arg(targets_url, "url")
        result = run_cmd(
            ["curl", "-s", safe_url, "--max-time", "15",
             "-H", f"User-Agent: {_UA}"],
            timeout=20,
        )
        if result.get("returncode") == 0:
            raw = (result.get("stdout") or "").strip()
            if raw.startswith("{") or raw.startswith("["):
                self._parse_bugcrowd_targets(profile, raw)

        self._detect_recent_additions(profile)
        profile.fetched_at = datetime.now().isoformat()
        return profile

    def _parse_bugcrowd_json(self, profile: ProgramProfile, raw_json: str) -> None:
        """Parse the Bugcrowd program JSON response."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return

        profile.name = data.get("name", profile.handle)
        profile.offers_bounties = bool(data.get("maxPayout") or data.get("max_payout"))
        profile.policy_text = data.get("briefing_description", "")[:5000]

        # Target groups
        for group in data.get("target_groups", []):
            for target in group.get("targets", []):
                self._parse_bugcrowd_target(profile, target)

        # Flat targets array
        for target in data.get("targets", []):
            self._parse_bugcrowd_target(profile, target)

    def _parse_bugcrowd_targets(self, profile: ProgramProfile, raw: str) -> None:
        """Parse the Bugcrowd target_groups JSON endpoint."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return

        groups = data if isinstance(data, list) else data.get("groups", data.get("target_groups", []))
        for group in groups:
            targets = group.get("targets", [group]) if isinstance(group, dict) else []
            for t in targets:
                self._parse_bugcrowd_target(profile, t)

    def _parse_bugcrowd_target(self, profile: ProgramProfile, target: dict[str, Any]) -> None:
        """Parse a single Bugcrowd target into a ScopeAsset."""
        uri = (
            target.get("uri")
            or target.get("name")
            or target.get("identifier", "")
        )
        if not uri:
            return

        existing = {a.identifier for a in profile.in_scope + profile.out_of_scope}
        if uri in existing:
            return

        target_type = target.get("type", "url").upper()
        if target_type in ("WEBSITE", "URL", "WEB"):
            target_type = "URL"

        in_scope_flag = target.get("in_scope", target.get("eligible_for_submission", True))

        asset = ScopeAsset(
            asset_type=target_type,
            identifier=uri,
            eligible_for_bounty=bool(target.get("eligible_for_bounty", True)),
            eligible_for_submission=bool(in_scope_flag),
            instruction=(target.get("description") or "")[:500],
            max_severity=target.get("max_severity", "critical"),
            created_at=target.get("created_at", ""),
            confidentiality_requirement="",
        )

        if asset.eligible_for_submission:
            profile.in_scope.append(asset)
        else:
            profile.out_of_scope.append(asset)

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def save_program(self, profile: ProgramProfile) -> Path:
        """Save program profile to data/programs/{handle}.json."""
        path = self.programs_dir / f"{profile.handle}.json"
        path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
        return path

    def load_program(self, handle: str) -> ProgramProfile | None:
        """Load a saved program profile from disk."""
        path = self.programs_dir / f"{handle}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ProgramProfile.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def list_saved_programs(self) -> list[dict[str, Any]]:
        """List all saved program profiles with summary info."""
        programs: list[dict[str, Any]] = []
        for path in sorted(self.programs_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                programs.append({
                    "handle": data.get("handle", path.stem),
                    "name": data.get("name", ""),
                    "platform": data.get("platform", ""),
                    "state": data.get("state", ""),
                    "in_scope_count": len(data.get("in_scope", [])),
                    "out_of_scope_count": len(data.get("out_of_scope", [])),
                    "offers_bounties": data.get("offers_bounties", False),
                    "recent_additions": len(data.get("recent_scope_additions", [])),
                    "fetched_at": data.get("fetched_at", ""),
                    "file": str(path),
                })
            except Exception:
                pass
        return programs

    def delete_program(self, handle: str) -> bool:
        """Delete a saved program profile. Returns True if deleted."""
        path = self.programs_dir / f"{handle}.json"
        if path.exists():
            path.unlink()
            return True
        return False

    # -----------------------------------------------------------------------
    # Staleness check
    # -----------------------------------------------------------------------

    def _is_stale(self, profile: ProgramProfile, max_age_hours: int = 168) -> bool:
        """Return True if profile is older than max_age_hours (default 7 days)."""
        if not profile.fetched_at:
            return True
        try:
            fetched = datetime.fromisoformat(profile.fetched_at)
            return datetime.now() - fetched > timedelta(hours=max_age_hours)
        except (ValueError, TypeError):
            return True

    # -----------------------------------------------------------------------
    # Context generation for the agent
    # -----------------------------------------------------------------------

    def generate_scope_context(self, profile: ProgramProfile) -> str:
        """Generate a context string for the agent's system prompt.

        Produces a concise summary the LLM can use to:
        1. Know what is in scope and what is not
        2. Know what pays the most (guides hypothesis weighting)
        3. Know what was recently added (zero-competition priority targets)
        4. Know what techniques to avoid (OOS rules from policy)
        """
        lines: list[str] = [
            f"# Program: {profile.name} ({profile.platform})",
            f"URL: {profile.url}",
            f"State: {profile.state}",
            f"Bounties: {'Yes' if profile.offers_bounties else 'No'}"
            + (f" | Swag: Yes" if profile.offers_swag else ""),
        ]

        if profile.safe_harbor:
            lines.append("Safe Harbor: Yes")
        if profile.response_time_days:
            lines.append(f"Avg Response Time: {profile.response_time_days:.1f} days")

        # Bounty table
        bt = profile.bounty_table
        if not bt.is_empty():
            lines += ["", "## Bounty Table"]
            if bt.critical_max:
                lines.append(f"  Critical: ${bt.critical_min:,} - ${bt.critical_max:,}")
            if bt.high_max:
                lines.append(f"  High:     ${bt.high_min:,} - ${bt.high_max:,}")
            if bt.medium_max:
                lines.append(f"  Medium:   ${bt.medium_min:,} - ${bt.medium_max:,}")
            if bt.low_max:
                lines.append(f"  Low:      ${bt.low_min:,} - ${bt.low_max:,}")

        # In-scope assets
        lines += ["", "## In-Scope Assets"]
        if profile.in_scope:
            for asset in profile.in_scope:
                bounty_tag = " [BOUNTY]" if asset.eligible_for_bounty else ""
                severity_tag = (
                    f" [max:{asset.max_severity}]" if asset.max_severity else ""
                )
                lines.append(
                    f"  [{asset.asset_type}] {asset.identifier}{bounty_tag}{severity_tag}"
                )
                if asset.instruction:
                    lines.append(f"    Note: {asset.instruction[:120]}")
        else:
            lines.append("  (no structured scope data available)")

        # Out-of-scope assets
        if profile.out_of_scope:
            lines += ["", "## Out-of-Scope Assets"]
            for asset in profile.out_of_scope:
                lines.append(f"  [{asset.asset_type}] {asset.identifier}")

        # Out-of-scope rules from policy text
        if profile.out_of_scope_text:
            lines += ["", "## Out-of-Scope Activities"]
            lines.append(f"  {profile.out_of_scope_text[:500]}")
        elif profile.policy_text:
            # Extract OOS section from policy text if not already separated
            oos_m = re.search(
                r"out[- ]of[- ]scope.*?(?=\n#{1,3}\s|\Z)",
                profile.policy_text,
                re.IGNORECASE | re.DOTALL,
            )
            if oos_m:
                oos_snippet = oos_m.group(0).strip()[:400]
                lines += ["", "## Out-of-Scope Activities (from policy)"]
                lines.append(f"  {oos_snippet}")

        # Recent additions - highest priority for the agent
        if profile.recent_scope_additions:
            lines += ["", "## RECENTLY ADDED (priority targets - low competition)"]
            for r in profile.recent_scope_additions:
                bounty_flag = " [BOUNTY]" if r.get("eligible_for_bounty") else ""
                lines.append(
                    f"  [{r['type']}] {r['asset']}{bounty_flag}"
                    f" - added {r['days_ago']} days ago"
                )

        # Stats footer
        if profile.resolved_report_count or profile.top_bounty:
            lines += ["", "## Program Stats"]
            if profile.resolved_report_count:
                lines.append(f"  Resolved reports: {profile.resolved_report_count:,}")
            if profile.top_bounty:
                lines.append(f"  Top bounty: ${profile.top_bounty:,}")
            if profile.average_bounty:
                lines.append(f"  Average bounty: ${profile.average_bounty:,}")

        return "\n".join(lines)

    def generate_hypothesis_seeds(self, profile: ProgramProfile) -> list[dict[str, Any]]:
        """Generate program-aware hypothesis seeds for the MCTS planner.

        Priority order:
        1. Recently added assets (zero-competition window)
        2. High-bounty wildcard domains (max attack surface)
        3. Bounty-eligible assets with high max_severity
        4. Android/iOS apps (often under-tested)
        """
        seeds: list[dict[str, Any]] = []
        bt = profile.bounty_table

        # 1. Fresh scope additions get top priority
        for r in profile.recent_scope_additions:
            seeds.append({
                "endpoint": r["asset"],
                "technique": "fresh_scope_recon",
                "description": (
                    f"[FRESH TARGET] {r['asset']} added {r['days_ago']} days ago - "
                    f"zero-competition window."
                ),
                "novelty": 10,
                "exploitability": 7,
                "impact": 9,
                "effort": 2,
                "bounty_hint": bt.severity_value(r.get("max_severity", "critical")),
            })

        # 2. Wildcard domains
        for asset in profile.in_scope:
            if asset.identifier.startswith("*.") and asset.eligible_for_bounty:
                seeds.append({
                    "endpoint": f"https://{asset.identifier[2:]}",
                    "technique": "wildcard_subdomain_enum",
                    "description": (
                        f"Wildcard scope {asset.identifier} - enumerate subdomains "
                        f"for untested assets."
                    ),
                    "novelty": 6,
                    "exploitability": 6,
                    "impact": 7,
                    "effort": 2,
                    "bounty_hint": bt.severity_value(asset.max_severity),
                })

        # 3. Mobile apps (high ROI - often under-tested)
        for asset in profile.in_scope:
            if asset.asset_type in ("ANDROID_APP", "IOS_APP"):
                seeds.append({
                    "endpoint": asset.identifier,
                    "technique": "mobile_app_analysis",
                    "description": (
                        f"Mobile app in scope: {asset.identifier} "
                        f"({asset.asset_type}) - often under-tested."
                    ),
                    "novelty": 7,
                    "exploitability": 5,
                    "impact": 7,
                    "effort": 4,
                    "bounty_hint": bt.severity_value(asset.max_severity),
                })

        # 4. Source code repos
        for asset in profile.in_scope:
            if asset.asset_type == "SOURCE_CODE":
                seeds.append({
                    "endpoint": asset.identifier,
                    "technique": "source_code_review",
                    "description": f"Source code in scope: {asset.identifier}",
                    "novelty": 8,
                    "exploitability": 7,
                    "impact": 9,
                    "effort": 5,
                    "bounty_hint": bt.critical_max,
                })

        return seeds
