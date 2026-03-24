from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class WorldModel:
    """Persistent structured fact store for the NPUHacker autonomous pentesting agent.

    Replaces lossy LLM context compression with an explicit, structured world
    model that the agent reads and writes on every step.  Backed by a JSON file
    on disk so nothing is lost between invocations.
    """

    # ------------------------------------------------------------------
    # Construction / persistence
    # ------------------------------------------------------------------

    def __init__(self, target: str, findings_dir: Path) -> None:
        self.target: str = target
        self.findings_dir: Path = findings_dir
        self._path: Path = findings_dir / target / "world_model.json"
        self._data: dict[str, Any] = self._load_or_create()

    # Convenience accessors so callers can read sections directly.
    @property
    def hosts(self) -> dict[str, Any]:
        return self._data["hosts"]

    @property
    def credentials(self) -> list[dict[str, Any]]:
        return self._data["credentials"]

    @property
    def access_levels(self) -> list[dict[str, Any]]:
        return self._data["access_levels"]

    @property
    def attack_paths(self) -> list[dict[str, Any]]:
        return self._data["attack_paths"]

    @property
    def findings(self) -> list[dict[str, Any]]:
        return self._data["findings"]

    @property
    def crown_jewels(self) -> list[dict[str, Any]]:
        return self._data["crown_jewels"]

    @property
    def tech_stack(self) -> dict[str, str]:
        return self._data["tech_stack"]

    @property
    def tested_surfaces(self) -> list[dict[str, Any]]:
        return self._data["tested_surfaces"]

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_host(
        self,
        host: str,
        port_info: dict[str, Any] | None = None,
        os: str | None = None,
    ) -> None:
        """Register or update a host entry."""
        if host not in self._data["hosts"]:
            self._data["hosts"][host] = {
                "ports": [],
                "os": "",
                "vulns_tested": [],
                "vulns_found": [],
                "notes": "",
            }
        entry = self._data["hosts"][host]
        if port_info is not None:
            # Avoid duplicate port records for the same port number.
            existing_ports = {p.get("port") for p in entry["ports"]}
            if port_info.get("port") not in existing_ports:
                entry["ports"].append(port_info)
        if os is not None:
            entry["os"] = os

    def add_credential(
        self,
        type: str,
        value: str,
        username: str = "",
        scope: str = "",
        source_step: int = 0,
    ) -> int:
        """Add a credential and return its index."""
        cred = {
            "type": type,
            "value": value,
            "username": username,
            "scope": scope,
            "source_step": source_step,
            "validated": False,
        }
        self._data["credentials"].append(cred)
        return len(self._data["credentials"]) - 1

    def add_access(
        self,
        host: str,
        level: str,
        method: str,
        credential_idx: int | None = None,
    ) -> None:
        self._data["access_levels"].append({
            "host": host,
            "level": level,
            "method": method,
            "credential_idx": credential_idx,
        })

    def add_attack_path(
        self,
        from_state: str,
        to_state: str,
        technique: str,
        status: str = "untested",
        step_tested: int | None = None,
    ) -> None:
        self._data["attack_paths"].append({
            "from_state": from_state,
            "to_state": to_state,
            "technique": technique,
            "status": status,
            "step_tested": step_tested,
        })

    def add_finding(
        self,
        id: str,
        title: str,
        severity: str,
        description: str,
        endpoint: str,
        technique: str,
        step_found: int,
        chain_potential: list[str] | None = None,
    ) -> None:
        self._data["findings"].append({
            "id": id,
            "title": title,
            "severity": severity,
            "description": description,
            "endpoint": endpoint,
            "technique": technique,
            "chain_potential": chain_potential or [],
            "validated": False,
            "step_found": step_found,
        })

    def add_crown_jewel(
        self,
        asset: str,
        value_type: str,
        priority: int,
        notes: str = "",
    ) -> None:
        self._data["crown_jewels"].append({
            "asset": asset,
            "value_type": value_type,
            "priority": max(1, min(10, priority)),
            "notes": notes,
        })

    def set_tech(self, key: str, value: str) -> None:
        self._data["tech_stack"][key] = value

    # ------------------------------------------------------------------
    # Surface tracking
    # ------------------------------------------------------------------

    def mark_surface_tested(self, surface: str, technique: str, step: int) -> None:
        for entry in self._data["tested_surfaces"]:
            if entry["surface"] == surface:
                if technique not in entry["techniques_tried"]:
                    entry["techniques_tried"].append(technique)
                entry["last_tested_step"] = step
                return
        self._data["tested_surfaces"].append({
            "surface": surface,
            "techniques_tried": [technique],
            "last_tested_step": step,
        })

    def is_surface_tested(self, surface: str, technique: str) -> bool:
        for entry in self._data["tested_surfaces"]:
            if entry["surface"] == surface and technique in entry.get("techniques_tried", []):
                return True
        return False

    def get_untested_surfaces(self) -> list[dict[str, Any]]:
        """Return surfaces that still have untested attack paths."""
        tested_map: dict[str, set[str]] = {}
        for entry in self._data["tested_surfaces"]:
            tested_map[entry["surface"]] = set(entry.get("techniques_tried", []))

        untested: list[dict[str, Any]] = []
        for path in self._data["attack_paths"]:
            if path.get("status") == "untested":
                surface = path.get("from_state", "")
                technique = path.get("technique", "")
                if technique not in tested_map.get(surface, set()):
                    untested.append(path)
        return untested

    # ------------------------------------------------------------------
    # Context generation for LLM injection
    # ------------------------------------------------------------------

    def get_attack_context(self, max_chars: int = 2000) -> str:
        """Build a compact text summary suitable for LLM context injection."""
        parts: list[str] = []

        # Hosts
        host_lines: list[str] = []
        for h, info in self._data["hosts"].items():
            ports_str = ", ".join(
                f"{p.get('port')}/{p.get('protocol', 'tcp')}({p.get('service', '?')})"
                for p in info.get("ports", [])
            )
            host_lines.append(f"  {h}: {ports_str or 'no ports'}"
                              + (f" OS={info['os']}" if info.get("os") else ""))
        if host_lines:
            parts.append("HOSTS:\n" + "\n".join(host_lines))

        # Access levels
        if self._data["access_levels"]:
            al_lines = [
                f"  {a['host']}: {a['level']} via {a['method']}"
                for a in self._data["access_levels"]
            ]
            parts.append("ACCESS:\n" + "\n".join(al_lines))

        # Credentials (redacted values)
        if self._data["credentials"]:
            cred_lines = [
                f"  [{i}] {c['type']} user={c.get('username', '?')} scope={c.get('scope', '?')} validated={c.get('validated', False)}"
                for i, c in enumerate(self._data["credentials"])
            ]
            parts.append("CREDS:\n" + "\n".join(cred_lines))

        # Untested attack paths
        untested = [p for p in self._data["attack_paths"] if p.get("status") == "untested"]
        if untested:
            ap_lines = [
                f"  {p['from_state']} -> {p['to_state']} via {p['technique']}"
                for p in untested[:10]
            ]
            remaining = len(untested) - 10
            parts.append(
                "UNTESTED PATHS:\n" + "\n".join(ap_lines)
                + (f"\n  ...and {remaining} more" if remaining > 0 else "")
            )

        # Tech stack
        if self._data["tech_stack"]:
            ts_line = ", ".join(f"{k}={v}" for k, v in self._data["tech_stack"].items())
            parts.append(f"TECH: {ts_line}")

        # Findings count
        if self._data["findings"]:
            parts.append(f"FINDINGS: {len(self._data['findings'])} total")

        text = "\n".join(parts)
        if len(text) > max_chars:
            text = text[: max_chars - 3] + "..."
        return text

    def get_findings_for_chain_analysis(self) -> list[dict[str, Any]]:
        """Return all findings that have non-empty chain_potential."""
        return [
            f for f in self._data["findings"]
            if f.get("chain_potential")
        ]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, default=str)
        tmp.replace(self._path)

    def _load_or_create(self) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "target": self.target,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hosts": {},
            "credentials": [],
            "access_levels": [],
            "attack_paths": [],
            "findings": [],
            "crown_jewels": [],
            "tech_stack": {},
            "tested_surfaces": [],
        }
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                # Back-fill any keys that older files might lack.
                for key, default in empty.items():
                    if key not in data:
                        data[key] = default
                return data
            except (json.JSONDecodeError, OSError):
                # Corrupt or unreadable - start fresh.
                return empty
        return empty

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def summary(self) -> str:
        h = len(self._data["hosts"])
        f = len(self._data["findings"])
        c = len(self._data["credentials"])
        a = len(self._data["access_levels"])
        s = len(self._data["tested_surfaces"])
        return (
            f"WorldModel({self.target}): "
            f"{h} hosts, {f} findings, {c} creds, {a} access, {s} surfaces tested"
        )

    def __repr__(self) -> str:
        return self.summary()
