"""Program Intelligence - Bug bounty program-aware testing for Project Triage v4.

Reads, parses, and operationalizes bug bounty program policies before testing begins.
Elite hunters start here - know what pays, what's in scope, what was recently added.

Capabilities:
- Fetch and parse HackerOne/Bugcrowd program policy
- Extract in-scope assets, out-of-scope rules, severity minimums
- Detect recent scope additions (zero-competition window)
- Adjust MCTS reward weights based on program payout structure
- Track program-specific report preferences

Research basis: Gap analysis GAP-1, Jason Haddix methodology, XBOW program selection.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd


@dataclass
class ProgramScope:
    """Parsed bug bounty program scope and policy."""
    program_handle: str
    platform: str  # hackerone, bugcrowd, intigriti
    in_scope_assets: list[dict[str, str]] = field(default_factory=list)  # {type, identifier, instruction}
    out_of_scope: list[str] = field(default_factory=list)
    severity_minimum: str = "low"  # Minimum severity for payout
    response_sla: str = ""
    payout_ranges: dict[str, str] = field(default_factory=dict)  # {critical: "$5000-$20000", ...}
    report_preferences: list[str] = field(default_factory=list)
    recent_scope_additions: list[dict[str, Any]] = field(default_factory=list)
    last_updated: float = 0.0
    raw_policy: str = ""


@dataclass
class PayoutWeight:
    """MCTS reward weight adjustment based on program payouts."""
    technique_category: str
    weight_multiplier: float
    reason: str


# ---------------------------------------------------------------------------
# Known program payout patterns
# ---------------------------------------------------------------------------

DEFAULT_PAYOUT_WEIGHTS: dict[str, float] = {
    "rce": 10.0,
    "ssrf": 8.0,
    "sqli": 7.0,
    "auth_bypass": 9.0,
    "idor": 7.0,
    "xss_stored": 5.0,
    "xss_reflected": 3.0,
    "csrf": 2.0,
    "info_disclosure": 1.0,
    "open_redirect": 1.5,
    "race_condition": 6.0,
    "prototype_pollution": 7.0,
    "deserialization": 9.0,
    "subdomain_takeover": 4.0,
}

# Severity tier to MCTS reward mapping
SEVERITY_REWARDS: dict[str, int] = {
    "critical": 1000,
    "high": 500,
    "medium": 100,
    "low": 20,
    "none": 0,
}


class ProgramIntelligence:
    """Program-aware testing intelligence layer."""

    def __init__(self) -> None:
        self._cache: dict[str, ProgramScope] = {}

    def fetch_hackerone_program(self, handle: str) -> ProgramScope:
        """Fetch and parse a HackerOne program's policy."""
        if handle in self._cache:
            cached = self._cache[handle]
            if time.time() - cached.last_updated < 3600:
                return cached

        scope = ProgramScope(
            program_handle=handle,
            platform="hackerone",
            last_updated=time.time(),
        )

        # Fetch program policy page via curl
        try:
            policy_url = f"https://hackerone.com/{handle}/policy_scopes.json"
            raw = run_cmd(f"curl -s '{policy_url}' --max-time 10")
            if raw and raw.strip().startswith("["):
                self._parse_h1_scopes(scope, raw)
        except Exception:
            pass

        # Fetch program info
        try:
            info_url = f"https://hackerone.com/{handle}.json"
            raw = run_cmd(f"curl -s '{info_url}' --max-time 10")
            if raw and raw.strip().startswith("{"):
                self._parse_h1_info(scope, raw)
        except Exception:
            pass

        self._cache[handle] = scope
        return scope

    def _parse_h1_scopes(self, scope: ProgramScope, raw_json: str) -> None:
        """Parse HackerOne policy_scopes.json response."""
        try:
            scopes = json.loads(raw_json)
            for s in scopes:
                asset_type = s.get("asset_type", "")
                identifier = s.get("asset_identifier", "")
                instruction = s.get("instruction", "")
                eligible = s.get("eligible_for_bounty", False)
                eligible_submission = s.get("eligible_for_submission", True)

                if eligible_submission:
                    scope.in_scope_assets.append({
                        "type": asset_type,
                        "identifier": identifier,
                        "instruction": instruction[:200],
                        "bounty_eligible": eligible,
                    })

                # Check for recent additions (created_at within last 30 days)
                created = s.get("created_at", "")
                if created:
                    try:
                        # Simple date check - if year-month matches recent
                        if "2026-03" in created or "2026-02" in created:
                            scope.recent_scope_additions.append({
                                "asset": identifier,
                                "type": asset_type,
                                "added": created,
                            })
                    except Exception:
                        pass
        except json.JSONDecodeError:
            pass

    def _parse_h1_info(self, scope: ProgramScope, raw_json: str) -> None:
        """Parse HackerOne program info."""
        try:
            data = json.loads(raw_json)
            # Extract payout ranges if available
            if "top_bounty_lower_range" in data:
                scope.payout_ranges["max"] = str(data.get("top_bounty_upper_range", ""))
            if "profile" in data:
                profile = data["profile"]
                scope.raw_policy = profile.get("policy", "")[:2000]
        except json.JSONDecodeError:
            pass

    def fetch_bugcrowd_program(self, handle: str) -> ProgramScope:
        """Fetch and parse a Bugcrowd program's scope."""
        scope = ProgramScope(
            program_handle=handle,
            platform="bugcrowd",
            last_updated=time.time(),
        )

        try:
            url = f"https://bugcrowd.com/{handle}.json"
            raw = run_cmd(f"curl -s '{url}' --max-time 10")
            if raw and raw.strip().startswith("{"):
                data = json.loads(raw)
                # Extract targets
                for target in data.get("targets", data.get("target_groups", [])):
                    if isinstance(target, dict):
                        scope.in_scope_assets.append({
                            "type": target.get("type", "url"),
                            "identifier": target.get("uri", target.get("name", "")),
                            "instruction": target.get("description", "")[:200],
                            "bounty_eligible": True,
                        })
        except Exception:
            pass

        self._cache[handle] = scope
        return scope

    def extract_handle_from_url(self, target: str) -> tuple[str, str]:
        """Extract program handle and platform from a target URL or domain.

        Returns (handle, platform) tuple.
        """
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = domain.split(".")
        handle = parts[-2] if len(parts) >= 2 else domain
        # Default to HackerOne
        return handle, "hackerone"

    def get_scope_for_target(self, target: str) -> ProgramScope:
        """Auto-detect platform and fetch program scope."""
        handle, platform = self.extract_handle_from_url(target)
        if platform == "bugcrowd":
            return self.fetch_bugcrowd_program(handle)
        return self.fetch_hackerone_program(handle)

    def is_in_scope(self, scope: ProgramScope, url: str) -> bool:
        """Check if a URL is within the program's scope."""
        if not scope.in_scope_assets:
            return True  # No scope data = assume in scope

        url_lower = url.lower()
        for asset in scope.in_scope_assets:
            identifier = asset.get("identifier", "").lower()
            if not identifier:
                continue
            # Wildcard matching
            if identifier.startswith("*."):
                domain_suffix = identifier[1:]  # .example.com
                if domain_suffix in url_lower:
                    return True
            elif identifier in url_lower:
                return True
        return False

    def is_out_of_scope(self, scope: ProgramScope, technique: str) -> bool:
        """Check if a testing technique is explicitly out of scope."""
        technique_lower = technique.lower()
        for rule in scope.out_of_scope:
            rule_lower = rule.lower()
            if any(kw in technique_lower for kw in ["dos", "ddos", "brute"]):
                if any(kw in rule_lower for kw in ["denial", "dos", "brute", "rate limit"]):
                    return True
            if "social" in technique_lower and "social" in rule_lower:
                return True
            if "physical" in technique_lower and "physical" in rule_lower:
                return True
        return False

    def calculate_payout_weights(self, scope: ProgramScope) -> list[PayoutWeight]:
        """Calculate MCTS reward weight adjustments based on program payouts.

        If a program pays $20K for RCE but $200 for XSS, weight RCE hypothesis
        testing much higher than XSS.
        """
        weights = []

        # Parse payout ranges from policy text
        policy = scope.raw_policy.lower()

        # Detect payout emphasis from policy language
        high_value_signals = {
            "rce": ["remote code execution", "rce", "command injection"],
            "ssrf": ["ssrf", "server-side request"],
            "auth_bypass": ["authentication bypass", "access control", "authorization"],
            "idor": ["idor", "insecure direct object", "bola", "broken access"],
            "sqli": ["sql injection", "sqli"],
            "xss": ["cross-site scripting", "xss"],
        }

        for category, signals in high_value_signals.items():
            mentioned = any(s in policy for s in signals)
            base_weight = DEFAULT_PAYOUT_WEIGHTS.get(category, 5.0)

            if mentioned:
                # Mentioned in policy = program cares about this
                weights.append(PayoutWeight(
                    technique_category=category,
                    weight_multiplier=base_weight * 1.5,
                    reason=f"Explicitly mentioned in program policy",
                ))
            else:
                weights.append(PayoutWeight(
                    technique_category=category,
                    weight_multiplier=base_weight,
                    reason="Default weight",
                ))

        return weights

    def get_fresh_targets(self, scope: ProgramScope) -> list[dict[str, Any]]:
        """Get recently added scope targets (zero-competition window).

        New scope additions are the highest-ROI targets in bug bounty.
        First 48 hours after addition = near-zero duplicate rate.
        """
        return scope.recent_scope_additions

    def generate_hypotheses(
        self,
        scope: ProgramScope,
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Generate program-aware hypotheses."""
        hypotheses = []

        # Fresh targets get top priority
        for fresh in scope.recent_scope_additions:
            hypotheses.append({
                "endpoint": fresh.get("asset", base_url),
                "technique": "fresh_scope_recon",
                "description": (
                    f"[FRESH TARGET] Recently added to scope: {fresh['asset']} "
                    f"(added {fresh.get('added', 'recently')}). Zero competition window."
                ),
                "novelty": 10, "exploitability": 7, "impact": 8, "effort": 2,
            })

        # Bounty-eligible assets get boosted
        for asset in scope.in_scope_assets:
            if asset.get("bounty_eligible") and asset.get("identifier"):
                identifier = asset["identifier"]
                if identifier.startswith("*."):
                    hypotheses.append({
                        "endpoint": f"https://{identifier[2:]}",
                        "technique": "wildcard_subdomain_enum",
                        "description": f"Wildcard scope {identifier} - enumerate subdomains for untested assets",
                        "novelty": 6, "exploitability": 6, "impact": 7, "effort": 2,
                    })

        return hypotheses

    def format_scope_context(self, scope: ProgramScope, max_chars: int = 500) -> str:
        """Format scope info for LLM context injection."""
        parts = [f"Program: {scope.program_handle} ({scope.platform})"]

        if scope.in_scope_assets:
            assets_str = ", ".join(
                a["identifier"] for a in scope.in_scope_assets[:10]
            )
            parts.append(f"In-scope: {assets_str}")

        if scope.out_of_scope:
            parts.append(f"Out-of-scope: {'; '.join(scope.out_of_scope[:5])}")

        if scope.payout_ranges:
            parts.append(f"Payouts: {scope.payout_ranges}")

        if scope.recent_scope_additions:
            fresh = ", ".join(f["asset"] for f in scope.recent_scope_additions[:3])
            parts.append(f"FRESH TARGETS: {fresh}")

        result = " | ".join(parts)
        return result[:max_chars]
