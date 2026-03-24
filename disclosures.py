"""Prior disclosure lookup - checks if similar bugs were already reported."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any


class DisclosureLookup:
    """Checks HackerOne disclosed reports to avoid submitting known duplicates.

    Uses HackerOne's public GraphQL API to search disclosed reports
    for a given program or domain.
    """

    H1_HACKTIVITY_URL = "https://hackerone.com/graphql"

    def search_disclosed(self, program_handle: str, max_results: int = 20) -> list[dict[str, Any]]:
        """Search HackerOne's public hacktivity for disclosed reports on a program.

        Returns list of dicts with: title, severity, disclosed_at, substate, url.
        Falls back to empty list if API is unavailable.
        """
        query = {
            "operationName": "HacktivityPageQuery",
            "variables": {
                "where": {
                    "report": {
                        "disclosed_at": {"_is_null": False},
                        "team": {"handle": {"_eq": program_handle}},
                    }
                },
                "first": max_results,
                "orderBy": {"field": "popular", "direction": "DESC"},
            },
            "query": """
                query HacktivityPageQuery($where: FiltersHacktivityItemFilterInput, $first: Int, $orderBy: HacktivityItemOrderInput) {
                    hacktivity_items(where: $where, first: $first, order_by: $orderBy) {
                        edges {
                            node {
                                ... on HacktivityItemInterface {
                                    id
                                    reporter { username }
                                    report {
                                        title
                                        substate
                                        severity_rating
                                        disclosed_at
                                        url
                                    }
                                    team { handle name }
                                }
                            }
                        }
                    }
                }
            """,
        }

        try:
            data = json.dumps(query).encode("utf-8")
            req = urllib.request.Request(
                self.H1_HACKTIVITY_URL,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "NPUHacker/2.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            edges = (
                result.get("data", {})
                .get("hacktivity_items", {})
                .get("edges", [])
            )

            disclosures = []
            for edge in edges:
                node = edge.get("node", {})
                report = node.get("report", {})
                if report:
                    disclosures.append({
                        "title": report.get("title", ""),
                        "severity": report.get("severity_rating", ""),
                        "disclosed_at": report.get("disclosed_at", ""),
                        "substate": report.get("substate", ""),
                        "url": report.get("url", ""),
                    })
            return disclosures

        except (urllib.error.URLError, json.JSONDecodeError, OSError, KeyError):
            return []

    def check_duplicate(
        self,
        program_handle: str,
        technique: str,
        endpoint: str,
    ) -> dict[str, Any] | None:
        """Check if a similar vulnerability was already disclosed.

        Returns the matching disclosure dict if found, None otherwise.
        """
        disclosures = self.search_disclosed(program_handle)
        technique_lower = technique.lower()
        endpoint_lower = endpoint.lower()

        for d in disclosures:
            title_lower = d.get("title", "").lower()
            # Match by technique keyword in title
            if technique_lower in title_lower:
                return d
            # Match by endpoint in title
            if endpoint_lower in title_lower:
                return d

        return None

    def format_disclosures(self, disclosures: list[dict[str, Any]]) -> str:
        """Format disclosures for display or prompt context."""
        if not disclosures:
            return "No prior disclosures found."

        lines = [f"Found {len(disclosures)} prior disclosures:"]
        for d in disclosures[:10]:
            severity = d.get("severity", "unknown")
            title = d.get("title", "untitled")
            lines.append(f"  [{severity}] {title}")
        return "\n".join(lines)
