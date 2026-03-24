"""Persistent target model - stores recon data as JSON, reused across hunts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


STALENESS_DAYS = 14


class TargetModel:
    """Persistent target intelligence. Saved to findings/{target}/target-model.json.

    Reused across hunt sessions if less than 14 days old. Stores subdomains,
    open ports, tech stack, endpoints, and recon observations.
    """

    def __init__(self, target: str, findings_dir: Path = Path("findings")) -> None:
        self.target = target
        # Sanitize target for filesystem: strip protocol, replace special chars
        self.safe_name = (
            target.replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
            .rstrip("_")
        )
        self.target_dir = findings_dir / self.safe_name
        self.model_path = self.target_dir / "target-model.json"
        self.data: dict[str, Any] = self._load_or_create()

    def _load_or_create(self) -> dict[str, Any]:
        """Load existing model or create a fresh one."""
        self.target_dir.mkdir(parents=True, exist_ok=True)
        (self.target_dir / "memory").mkdir(exist_ok=True)
        (self.target_dir / "reports").mkdir(exist_ok=True)
        (self.target_dir / "evidence").mkdir(exist_ok=True)

        if self.model_path.exists():
            try:
                return json.loads(self.model_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        return {
            "target": self.target,
            "domain": self._extract_domain(),
            "last_updated": datetime.now().isoformat(),
            "subdomains": [],
            "open_ports": [],
            "tech_stack": {},
            "endpoints": [],
            "headers_analysis": {},
            "recon_observations": [],
            "hypotheses_tested": [],
        }

    @property
    def is_stale(self) -> bool:
        """True if model is older than STALENESS_DAYS or doesn't exist."""
        last = self.data.get("last_updated")
        if not last:
            return True
        try:
            updated = datetime.fromisoformat(last)
            return datetime.now() - updated > timedelta(days=STALENESS_DAYS)
        except (ValueError, TypeError):
            return True

    @property
    def has_recon(self) -> bool:
        """True if any recon data has been collected."""
        return bool(
            self.data.get("subdomains")
            or self.data.get("open_ports")
            or self.data.get("endpoints")
        )

    def add_subdomains(self, subdomains: list[str]) -> None:
        """Merge new subdomains (dedup)."""
        existing = set(self.data.get("subdomains", []))
        existing.update(subdomains)
        self.data["subdomains"] = sorted(existing)

    def add_ports(self, ports: list[dict[str, str]]) -> None:
        """Add discovered open ports."""
        existing = self.data.get("open_ports", [])
        # Dedup by port+host
        seen = {(p.get("port"), p.get("host")) for p in existing}
        for port in ports:
            key = (port.get("port"), port.get("host"))
            if key not in seen:
                existing.append(port)
                seen.add(key)
        self.data["open_ports"] = existing

    def add_endpoint(self, url: str, method: str = "GET", notes: str = "") -> None:
        """Record a discovered endpoint."""
        endpoints = self.data.get("endpoints", [])
        # Dedup by url+method
        if not any(e.get("url") == url and e.get("method") == method for e in endpoints):
            endpoints.append({"url": url, "method": method, "notes": notes})
            self.data["endpoints"] = endpoints

    def add_observation(self, observation: str) -> None:
        """Add a recon observation (finding, tech detection, etc.)."""
        observations = self.data.get("recon_observations", [])
        observations.append({
            "text": observation,
            "timestamp": datetime.now().isoformat(),
        })
        # Keep last 50 observations
        self.data["recon_observations"] = observations[-50:]

    def set_tech_stack(self, key: str, value: str) -> None:
        """Record a tech stack component (e.g., 'server': 'nginx/1.18')."""
        tech = self.data.get("tech_stack", {})
        tech[key] = value
        self.data["tech_stack"] = tech

    def mark_hypothesis_tested(self, hypothesis_id: str) -> None:
        """Record that a hypothesis was tested (for dedup across sessions)."""
        tested = self.data.get("hypotheses_tested", [])
        if hypothesis_id not in tested:
            tested.append(hypothesis_id)
            self.data["hypotheses_tested"] = tested

    def was_hypothesis_tested(self, hypothesis_id: str) -> bool:
        """Check if a hypothesis was already tested in this target model."""
        return hypothesis_id in self.data.get("hypotheses_tested", [])

    def save(self) -> None:
        """Persist to disk."""
        self.data["last_updated"] = datetime.now().isoformat()
        self.model_path.write_text(
            json.dumps(self.data, indent=2, default=str),
            encoding="utf-8",
        )

    def summary(self) -> str:
        """One-paragraph summary for display."""
        subs = len(self.data.get("subdomains", []))
        ports = len(self.data.get("open_ports", []))
        endpoints = len(self.data.get("endpoints", []))
        tech = self.data.get("tech_stack", {})
        stale = "STALE" if self.is_stale else "FRESH"
        return (
            f"Target: {self.target} [{stale}] | "
            f"{subs} subdomains, {ports} ports, {endpoints} endpoints | "
            f"Tech: {', '.join(f'{k}={v}' for k, v in tech.items()) or 'unknown'}"
        )

    def _extract_domain(self) -> str:
        """Extract root domain from target URL."""
        domain = self.target.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0].split(":")[0]
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
