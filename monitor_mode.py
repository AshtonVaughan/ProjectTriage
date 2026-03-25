"""Monitor Mode - Continuous attack surface monitoring for Project Triage v4.

Runs persistent background monitoring to detect:
- New subdomains appearing (acquisition, new services)
- Endpoint changes (new features = untested code)
- Tech stack updates (framework upgrade = new vuln surface)
- Certificate transparency log new certs
- HTTP fingerprint changes (new server, CDN change)

New scope additions are zero-competition for 6-8 hours.
First hunter to test them has near-zero duplicate rate.

Research basis: Gap analysis GAP-8, NodeZero continuous mode, bionic hacker model.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from utils import run_cmd


@dataclass
class SurfaceSnapshot:
    """Point-in-time snapshot of the attack surface."""
    timestamp: float
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    http_fingerprints: dict[str, str] = field(default_factory=dict)  # subdomain -> hash(headers+status)
    content_hashes: dict[str, str] = field(default_factory=dict)  # url -> hash(body)
    certificates: list[str] = field(default_factory=list)  # CN values from crt.sh


@dataclass
class SurfaceChange:
    """A detected change in the attack surface."""
    change_type: str  # new_subdomain, new_endpoint, tech_change, cert_change, fingerprint_change
    detail: str
    url: str
    priority: str  # critical, high, medium, low
    timestamp: float
    first_seen: float = 0.0


class MonitorMode:
    """Continuous attack surface monitoring."""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._monitor_dir = os.path.join(data_dir, "monitor")
        Path(self._monitor_dir).mkdir(parents=True, exist_ok=True)

    def _snapshot_path(self, target: str) -> str:
        safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
        return os.path.join(self._monitor_dir, f"{safe}_snapshot.json")

    def _changes_path(self, target: str) -> str:
        safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
        return os.path.join(self._monitor_dir, f"{safe}_changes.json")

    def take_snapshot(self, target: str) -> SurfaceSnapshot:
        """Take a current snapshot of the attack surface."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        snapshot = SurfaceSnapshot(timestamp=time.time())

        # Subdomain enumeration (fast passive only)
        try:
            result = run_cmd(f"subfinder -d {domain} -silent -timeout 30 2>/dev/null")
            if result:
                snapshot.subdomains = sorted(set(
                    line.strip() for line in result.split("\n")
                    if line.strip() and "." in line.strip()
                ))
        except Exception:
            pass

        # Certificate transparency check
        try:
            result = run_cmd(
                f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' --max-time 15"
            )
            if result and result.strip().startswith("["):
                certs = json.loads(result)
                cn_values = set()
                for cert in certs[:100]:
                    cn = cert.get("common_name", "")
                    if cn and domain in cn:
                        cn_values.add(cn)
                snapshot.certificates = sorted(cn_values)
        except Exception:
            pass

        # HTTP fingerprint key subdomains
        for sub in snapshot.subdomains[:20]:
            try:
                result = run_cmd(
                    f"curl -s -o /dev/null -w '%{{http_code}}|%{{content_type}}' "
                    f"'https://{sub}/' --max-time 5 -k"
                )
                if result:
                    fp = hashlib.sha256(result.encode()).hexdigest()[:12]
                    snapshot.http_fingerprints[sub] = fp
            except Exception:
                pass

        return snapshot

    def save_snapshot(self, target: str, snapshot: SurfaceSnapshot) -> None:
        """Save a snapshot to disk."""
        path = self._snapshot_path(target)
        try:
            with open(path, "w") as f:
                json.dump({
                    "timestamp": snapshot.timestamp,
                    "subdomains": snapshot.subdomains,
                    "endpoints": snapshot.endpoints,
                    "tech_stack": snapshot.tech_stack,
                    "http_fingerprints": snapshot.http_fingerprints,
                    "content_hashes": snapshot.content_hashes,
                    "certificates": snapshot.certificates,
                }, f, indent=2)
        except Exception:
            pass

    def load_snapshot(self, target: str) -> SurfaceSnapshot | None:
        """Load the previous snapshot from disk."""
        path = self._snapshot_path(target)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            return SurfaceSnapshot(**data)
        except Exception:
            return None

    def diff_snapshots(
        self,
        old: SurfaceSnapshot,
        new: SurfaceSnapshot,
    ) -> list[SurfaceChange]:
        """Compare two snapshots and return detected changes."""
        changes: list[SurfaceChange] = []
        now = time.time()

        # New subdomains (highest priority - zero competition window)
        old_subs = set(old.subdomains)
        new_subs = set(new.subdomains)
        for sub in new_subs - old_subs:
            changes.append(SurfaceChange(
                change_type="new_subdomain",
                detail=f"New subdomain discovered: {sub}",
                url=f"https://{sub}",
                priority="critical",
                timestamp=now,
                first_seen=new.timestamp,
            ))

        # Removed subdomains (potential takeover)
        for sub in old_subs - new_subs:
            changes.append(SurfaceChange(
                change_type="removed_subdomain",
                detail=f"Subdomain disappeared: {sub} - check for dangling CNAME takeover",
                url=f"https://{sub}",
                priority="high",
                timestamp=now,
            ))

        # New certificates (new services being deployed)
        old_certs = set(old.certificates)
        new_certs = set(new.certificates)
        for cert in new_certs - old_certs:
            changes.append(SurfaceChange(
                change_type="cert_change",
                detail=f"New certificate issued for: {cert}",
                url=f"https://{cert}",
                priority="high",
                timestamp=now,
            ))

        # HTTP fingerprint changes (tech stack update, CDN change)
        for sub in set(old.http_fingerprints.keys()) & set(new.http_fingerprints.keys()):
            if old.http_fingerprints[sub] != new.http_fingerprints[sub]:
                changes.append(SurfaceChange(
                    change_type="fingerprint_change",
                    detail=f"HTTP fingerprint changed on {sub} - possible tech update",
                    url=f"https://{sub}",
                    priority="medium",
                    timestamp=now,
                ))

        # Tech stack changes
        for key in set(list(old.tech_stack.keys()) + list(new.tech_stack.keys())):
            old_val = old.tech_stack.get(key, "")
            new_val = new.tech_stack.get(key, "")
            if old_val != new_val and new_val:
                changes.append(SurfaceChange(
                    change_type="tech_change",
                    detail=f"Tech stack change: {key} '{old_val}' -> '{new_val}'",
                    url="",
                    priority="medium",
                    timestamp=now,
                ))

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        changes.sort(key=lambda c: priority_order.get(c.priority, 99))

        return changes

    def save_changes(self, target: str, changes: list[SurfaceChange]) -> None:
        """Append changes to the change log."""
        path = self._changes_path(target)
        existing = []
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    existing = json.load(f)
            except Exception:
                pass

        for change in changes:
            existing.append({
                "change_type": change.change_type,
                "detail": change.detail,
                "url": change.url,
                "priority": change.priority,
                "timestamp": change.timestamp,
            })

        # Keep last 500 changes
        existing = existing[-500:]

        try:
            with open(path, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception:
            pass

    def run_monitor_cycle(self, target: str) -> list[SurfaceChange]:
        """Run one monitoring cycle: snapshot, diff, save.

        Returns list of detected changes.
        """
        old_snapshot = self.load_snapshot(target)
        new_snapshot = self.take_snapshot(target)

        changes = []
        if old_snapshot:
            changes = self.diff_snapshots(old_snapshot, new_snapshot)
            if changes:
                self.save_changes(target, changes)

        self.save_snapshot(target, new_snapshot)
        return changes

    def generate_hypotheses_from_changes(
        self,
        changes: list[SurfaceChange],
    ) -> list[dict[str, Any]]:
        """Convert detected changes into high-priority hypotheses."""
        hypotheses = []

        for change in changes:
            if change.change_type == "new_subdomain":
                hypotheses.append({
                    "endpoint": change.url,
                    "technique": "fresh_subdomain_scan",
                    "description": f"[FRESH] {change.detail} - full scan, zero competition",
                    "novelty": 10, "exploitability": 7, "impact": 8, "effort": 2,
                })
            elif change.change_type == "removed_subdomain":
                hypotheses.append({
                    "endpoint": change.url,
                    "technique": "subdomain_takeover_check",
                    "description": f"[TAKEOVER?] {change.detail}",
                    "novelty": 8, "exploitability": 8, "impact": 8, "effort": 2,
                })
            elif change.change_type == "cert_change":
                hypotheses.append({
                    "endpoint": change.url,
                    "technique": "new_service_recon",
                    "description": f"[NEW CERT] {change.detail}",
                    "novelty": 8, "exploitability": 6, "impact": 7, "effort": 2,
                })
            elif change.change_type == "fingerprint_change":
                hypotheses.append({
                    "endpoint": change.url,
                    "technique": "tech_update_rescan",
                    "description": f"[UPDATED] {change.detail} - retest for new vulns",
                    "novelty": 7, "exploitability": 6, "impact": 7, "effort": 3,
                })

        return hypotheses
