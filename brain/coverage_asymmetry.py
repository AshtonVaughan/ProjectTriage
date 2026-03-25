"""Coverage Asymmetry Detector for Project Triage v4.

Based on research finding: "The best bugs live where nobody looks."
Frans Rosen hunts "boring/hard stuff other hackers won't."
Sam Curry finds employee admin portals.
The research is unambiguous: under-tested surfaces yield higher ROI.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SurfaceAssessment:
    surface: str
    category: str  # main_app, legacy_api, admin_portal, mobile_api, webhook, integration, staging, forgotten, internal
    estimated_coverage: str  # high, medium, low, untested
    priority_boost: float  # multiplier for hypothesis scores, 1.0 = normal, 2.0 = double priority
    reasoning: str  # why this coverage estimate
    signals: list[str] = field(default_factory=list)  # what signals indicate this coverage level


class CoverageAsymmetryDetector:
    """Estimates how much testing coverage a surface has received and
    prioritizes under-tested surfaces where the best bugs hide."""

    # Coverage level to default priority boost mapping
    COVERAGE_BOOSTS: dict[str, float] = {
        "high": 1.0,
        "medium": 1.3,
        "low": 1.7,
        "untested": 2.0,
    }

    def __init__(self) -> None:
        self.COVERAGE_SIGNALS: dict[str, list[dict[str, Any]]] = {
            "high": [
                {
                    "patterns": [r"^/$", r"^/index", r"^/home"],
                    "description": "Main web app at root domain",
                    "category": "main_app",
                },
                {
                    "patterns": [r"/login", r"/signin", r"/register", r"/signup", r"/auth"],
                    "description": "Login/registration pages",
                    "category": "main_app",
                },
                {
                    "patterns": [r"/swagger", r"/api-docs", r"/openapi"],
                    "sources": ["api_docs", "main_page"],
                    "description": "Common API endpoints documented in Swagger",
                    "category": "main_app",
                },
                {
                    "patterns": [
                        r"/api/users",
                        r"/api/auth",
                        r"/api/login",
                        r"/api/search",
                        r"/api/profile",
                    ],
                    "description": "Endpoints matching OWASP Top 10 patterns",
                    "category": "main_app",
                },
            ],
            "medium": [
                {
                    "patterns": [r"/mobile/", r"/app-api/", r"/m/api/"],
                    "description": "Mobile-specific API endpoints (different from web)",
                    "category": "mobile_api",
                },
                {
                    "patterns": [r"/beta/", r"/preview/", r"/new/", r"/v\d+-(beta|alpha|rc)"],
                    "description": "Newer features (less time in scope)",
                    "category": "main_app",
                },
                {
                    "patterns": [r"/api/"],
                    "sources": ["js_bundle"],
                    "description": "API endpoints not in official docs but in JS bundles",
                    "category": "main_app",
                },
            ],
            "low": [
                {
                    "patterns": [r"/v1/", r"/v1\b"],
                    "description": "Legacy API versions (v1 when current is v3)",
                    "category": "legacy_api",
                },
                {
                    "patterns": [r"/admin/", r"/internal/", r"/employee/", r"/staff/", r"/backoffice/"],
                    "description": "Employee/admin portals on subdomains",
                    "category": "admin_portal",
                },
                {
                    "patterns": [r"/webhook", r"/callback", r"/hook/", r"/hooks/", r"/notify"],
                    "description": "Webhook/callback endpoints",
                    "category": "webhook",
                },
                {
                    "patterns": [
                        r"/oauth/",
                        r"/slack/",
                        r"/zapier/",
                        r"/stripe/",
                        r"/integration",
                        r"/connect/",
                    ],
                    "description": "Third-party integration endpoints (OAuth, Slack, Zapier, Stripe)",
                    "category": "integration",
                },
                {
                    "patterns": [r".*"],
                    "sources": ["wayback"],
                    "description": "Deprecated but still live endpoints (found via Wayback)",
                    "category": "forgotten",
                },
                {
                    "patterns": [r"staging\.", r"stage\.", r"dev\.", r"test\.", r"internal\."],
                    "match_host": True,
                    "description": "Internal/staging subdomains accessible from internet",
                    "category": "staging",
                },
                {
                    "patterns": [r"/upload", r"/export", r"/import", r"/download", r"/file"],
                    "description": "File upload/export endpoints",
                    "category": "main_app",
                },
                {
                    "patterns": [r"/graphql.*subscription", r"/subscriptions"],
                    "description": "GraphQL subscriptions (vs queries/mutations)",
                    "category": "main_app",
                },
                {
                    "patterns": [r"/ws/", r"/websocket", r"/socket\.io", r"/wss"],
                    "description": "WebSocket endpoints",
                    "category": "main_app",
                },
            ],
            "untested": [
                {
                    "patterns": [r"/error", r"/404", r"/500", r"/error[-_]page"],
                    "description": "Error handling endpoints (/error, /404, custom error pages)",
                    "category": "forgotten",
                },
                {
                    "patterns": [r"/health", r"/status", r"/metrics", r"/ping", r"/ready", r"/alive"],
                    "description": "Health check/monitoring endpoints (/health, /status, /metrics)",
                    "category": "internal",
                },
                {
                    "patterns": [r"/api-docs", r"/swagger", r"/debug", r"/phpinfo", r"/server-status"],
                    "sources": ["subdomain_enum", "wayback", "cname_chain"],
                    "description": "Documentation endpoints with debug info",
                    "category": "internal",
                },
                {
                    "patterns": [r".*"],
                    "sources": ["cname_chain"],
                    "description": "Old CNAME-resolved internal hostnames",
                    "category": "forgotten",
                },
                {
                    "patterns": [r"backup\.", r"bak\.", r"archive\.", r"old\."],
                    "match_host": True,
                    "description": "Backup/archive subdomains",
                    "category": "forgotten",
                },
                {
                    "patterns": [r"/unsubscribe", r"/preferences", r"/email[-_]", r"/mail/"],
                    "description": "Email-related endpoints (unsubscribe, preferences)",
                    "category": "forgotten",
                },
            ],
        }

        # Specific source-based boost overrides
        self._source_overrides: dict[str, tuple[str, float]] = {
            "wayback": ("low", 1.8),
            "cname_chain": ("low", 2.0),
        }

        # URL pattern-based boost overrides (checked in order, first match wins)
        self._url_overrides: list[tuple[str, str, float, str]] = [
            # (regex, coverage, boost, category)
            (r"/admin/|/internal/|/employee/|/staff/", "low", 1.8, "admin_portal"),
            (r"/v1/|/v1\b", "low", 1.7, "legacy_api"),
            (r"/webhook/|/callback/|/hook/", "low", 1.6, "webhook"),
        ]

    def assess_surface(
        self, url: str, source: str = "", age_signal: str = ""
    ) -> SurfaceAssessment:
        """Analyze a URL/endpoint and estimate its testing coverage.

        Args:
            url: The URL or endpoint pattern to assess.
            source: Where this URL was discovered - "js_bundle", "wayback",
                    "subdomain_enum", "api_docs", "cname_chain", "main_page".
            age_signal: Any hints about how old this endpoint is.

        Returns:
            SurfaceAssessment with category, coverage estimate, and priority boost.
        """
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        path = parsed.path or "/"
        host = parsed.hostname or ""
        signals: list[str] = []
        reasoning_parts: list[str] = []

        # Check source-based overrides first
        if source in self._source_overrides:
            override_coverage, override_boost = self._source_overrides[source]
            signals.append(f"discovered via {source}")
            reasoning_parts.append(
                f"Found through {source} - indicates surface is likely under-tested"
            )

        # Check URL pattern overrides
        url_override_match: tuple[str, float, str] | None = None
        for pattern, cov, boost, cat in self._url_overrides:
            if re.search(pattern, path, re.IGNORECASE):
                url_override_match = (cov, boost, cat)
                signals.append(f"URL matches low-coverage pattern: {pattern}")
                reasoning_parts.append(
                    f"Path contains patterns typical of under-tested surfaces"
                )
                break

        # Check source + URL combo for js_bundle API endpoints
        if source == "js_bundle" and re.search(r"/api/", path, re.IGNORECASE):
            signals.append("API endpoint found in JS bundle, not in official docs")
            reasoning_parts.append(
                "Undocumented API endpoints in JS bundles receive medium coverage"
            )
            if not url_override_match and source not in self._source_overrides:
                # Only apply if no stronger override already matched
                best_coverage = "medium"
                best_boost = 1.4
                best_category = "main_app"
                best_description = "API endpoint discovered in JS bundle"
                return SurfaceAssessment(
                    surface=url,
                    category=best_category,
                    estimated_coverage=best_coverage,
                    priority_boost=best_boost,
                    reasoning=best_description + ". " + " ".join(reasoning_parts),
                    signals=signals,
                )

        # Walk through coverage signals from untested -> low -> medium -> high
        # Lower coverage takes precedence if matched
        best_match: tuple[str, float, str, str] | None = None

        for coverage_level in ["untested", "low", "medium", "high"]:
            for rule in self.COVERAGE_SIGNALS[coverage_level]:
                # Check source filter if present
                if "sources" in rule:
                    if source and source not in rule["sources"]:
                        continue
                    if not source:
                        continue

                # Check host-based patterns
                if rule.get("match_host"):
                    for pattern in rule["patterns"]:
                        if re.search(pattern, host, re.IGNORECASE):
                            signals.append(f"hostname matches: {rule['description']}")
                            reasoning_parts.append(rule["description"])
                            best_match = (
                                coverage_level,
                                self.COVERAGE_BOOSTS[coverage_level],
                                rule["category"],
                                rule["description"],
                            )
                            break
                else:
                    # Check path-based patterns
                    for pattern in rule["patterns"]:
                        if re.search(pattern, path, re.IGNORECASE):
                            signals.append(f"path matches: {rule['description']}")
                            if not best_match or self.COVERAGE_BOOSTS[coverage_level] > best_match[1]:
                                reasoning_parts.append(rule["description"])
                                best_match = (
                                    coverage_level,
                                    self.COVERAGE_BOOSTS[coverage_level],
                                    rule["category"],
                                    rule["description"],
                                )
                            break

                if best_match and best_match[0] in ("untested", "low"):
                    break
            if best_match and best_match[0] in ("untested", "low"):
                break

        # Apply age signal bonus
        if age_signal:
            old_keywords = ["old", "legacy", "deprecated", "archived", "2018", "2019", "2020"]
            if any(kw in age_signal.lower() for kw in old_keywords):
                signals.append(f"age signal indicates old endpoint: {age_signal}")
                reasoning_parts.append("Age signal suggests this is a legacy surface")

        # Determine final assessment - use overrides if they give lower coverage
        final_coverage = "medium"
        final_boost = 1.3
        final_category = "main_app"
        final_description = "No specific coverage signals matched"

        if best_match:
            final_coverage = best_match[0]
            final_boost = best_match[1]
            final_category = best_match[2]
            final_description = best_match[3]

        # Source overrides take precedence if they indicate lower coverage
        if source in self._source_overrides:
            src_cov, src_boost = self._source_overrides[source]
            if src_boost > final_boost:
                final_coverage = src_cov
                final_boost = src_boost

        # URL pattern overrides take precedence if they indicate lower coverage
        if url_override_match:
            uo_cov, uo_boost, uo_cat = url_override_match
            if uo_boost > final_boost:
                final_coverage = uo_cov
                final_boost = uo_boost
                final_category = uo_cat

        reasoning = final_description
        if reasoning_parts:
            reasoning = ". ".join(dict.fromkeys(reasoning_parts))

        return SurfaceAssessment(
            surface=url,
            category=final_category,
            estimated_coverage=final_coverage,
            priority_boost=final_boost,
            reasoning=reasoning,
            signals=signals,
        )

    def assess_all(self, endpoints: list[dict[str, str]]) -> list[SurfaceAssessment]:
        """Assess a batch of endpoints and sort by priority.

        Args:
            endpoints: List of dicts with keys: url, source (optional), method (optional).

        Returns:
            List of SurfaceAssessment sorted by priority_boost descending
            (lowest coverage = highest priority).
        """
        assessments: list[SurfaceAssessment] = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            source = ep.get("source", "")
            assessment = self.assess_surface(url, source=source)
            assessments.append(assessment)

        assessments.sort(key=lambda a: a.priority_boost, reverse=True)
        return assessments

    def boost_hypotheses(
        self,
        hypotheses: list[dict[str, Any]],
        assessments: list[SurfaceAssessment],
    ) -> list[dict[str, Any]]:
        """Multiply hypothesis scores by the matching surface's priority boost.

        Args:
            hypotheses: List of hypothesis dicts, each with at least
                        "url" or "target" and "score" keys.
            assessments: List of SurfaceAssessment from assess_all.

        Returns:
            Modified hypotheses with boosted scores.
        """
        # Build lookup from surface URL to boost
        boost_map: dict[str, float] = {}
        for a in assessments:
            boost_map[a.surface] = a.priority_boost

        boosted: list[dict[str, Any]] = []
        for hyp in hypotheses:
            hyp = dict(hyp)  # shallow copy
            target = hyp.get("url") or hyp.get("target", "")
            score = hyp.get("score", 1.0)

            # Try exact match first, then substring match
            boost = 1.0
            if target in boost_map:
                boost = boost_map[target]
            else:
                for surface_url, surface_boost in boost_map.items():
                    if surface_url in target or target in surface_url:
                        boost = surface_boost
                        break

            hyp["score"] = score * boost
            if boost > 1.0:
                hyp["coverage_boost_applied"] = boost
            boosted.append(hyp)

        return boosted

    def get_coverage_report(self, assessments: list[SurfaceAssessment]) -> str:
        """Format a human-readable coverage asymmetry report.

        Groups by category, shows coverage distribution, and highlights
        the highest-priority (lowest-coverage) surfaces.

        Args:
            assessments: List of SurfaceAssessment to report on.

        Returns:
            Formatted report string.
        """
        if not assessments:
            return "No surfaces assessed."

        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("COVERAGE ASYMMETRY REPORT")
        lines.append("=" * 60)
        lines.append("")

        # Coverage distribution summary
        coverage_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "untested": 0}
        for a in assessments:
            coverage_counts[a.estimated_coverage] = coverage_counts.get(a.estimated_coverage, 0) + 1

        lines.append("Coverage Distribution:")
        total = len(assessments)
        for level in ["untested", "low", "medium", "high"]:
            count = coverage_counts.get(level, 0)
            pct = (count / total * 100) if total > 0 else 0
            bar = "#" * int(pct / 2)
            lines.append(f"  {level:>10}: {count:3d} ({pct:5.1f}%) {bar}")
        lines.append("")

        # Group by category
        categories: dict[str, list[SurfaceAssessment]] = {}
        for a in assessments:
            categories.setdefault(a.category, []).append(a)

        lines.append("By Category:")
        lines.append("-" * 40)
        for cat, items in sorted(categories.items()):
            lines.append(f"\n  [{cat.upper()}] ({len(items)} surfaces)")
            for item in sorted(items, key=lambda x: x.priority_boost, reverse=True):
                boost_indicator = ""
                if item.priority_boost > 1.5:
                    boost_indicator = " *** HIGH PRIORITY"
                elif item.priority_boost > 1.0:
                    boost_indicator = " * boosted"
                lines.append(
                    f"    {item.estimated_coverage:>8} | {item.priority_boost:.1f}x | "
                    f"{item.surface}{boost_indicator}"
                )

        # Highlight top priority targets
        high_priority = [a for a in assessments if a.priority_boost >= 1.5]
        if high_priority:
            lines.append("")
            lines.append("=" * 60)
            lines.append("HIGHEST PRIORITY TARGETS (lowest coverage, highest ROI)")
            lines.append("=" * 60)
            high_priority.sort(key=lambda x: x.priority_boost, reverse=True)
            for a in high_priority[:10]:
                lines.append(f"  [{a.priority_boost:.1f}x] {a.surface}")
                lines.append(f"         Category: {a.category}")
                lines.append(f"         Coverage: {a.estimated_coverage}")
                lines.append(f"         Reason:   {a.reasoning}")
                lines.append("")

        return "\n".join(lines)

    def identify_forgotten_surfaces(
        self,
        all_urls: list[str],
        wayback_urls: list[str],
        current_urls: list[str],
    ) -> list[dict[str, Any]]:
        """Compare Wayback URLs against current sitemap to find forgotten surfaces.

        URLs present in Wayback but not in the current sitemap are potentially
        forgotten but may still be live - these are prime hunting targets.

        Args:
            all_urls: All known URLs for the target.
            wayback_urls: URLs found in the Wayback Machine.
            current_urls: URLs found in the current sitemap/crawl.

        Returns:
            List of dicts with url, last_seen_in_wayback, still_live, priority.
        """
        current_set = set(current_urls)
        all_set = set(all_urls)

        # Normalize URLs for comparison (strip trailing slashes, lowercase)
        def normalize(u: str) -> str:
            u = u.rstrip("/").lower()
            if "://" not in u:
                u = "https://" + u
            return u

        current_normalized = {normalize(u) for u in current_set}

        forgotten: list[dict[str, Any]] = []
        seen: set[str] = set()

        for wb_url in wayback_urls:
            norm = normalize(wb_url)
            if norm in current_normalized:
                continue
            if norm in seen:
                continue
            seen.add(norm)

            # Determine priority based on URL characteristics
            priority = "medium"
            if re.search(r"/admin|/internal|/employee|/staff", wb_url, re.IGNORECASE):
                priority = "critical"
            elif re.search(r"/api/|/v\d+/", wb_url, re.IGNORECASE):
                priority = "high"
            elif re.search(r"/upload|/export|/debug|/config", wb_url, re.IGNORECASE):
                priority = "high"

            # Check if URL appears in any known URL list (proxy for liveness)
            still_live = norm in {normalize(u) for u in all_set}

            forgotten.append({
                "url": wb_url,
                "last_seen_in_wayback": True,
                "still_live": still_live,
                "priority": priority,
            })

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        forgotten.sort(key=lambda x: priority_order.get(x["priority"], 99))

        return forgotten
