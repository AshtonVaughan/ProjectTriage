"""Evidence capture - saves curl responses, tool output, and reproduction artifacts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class EvidenceCapture:
    """Captures and organizes evidence for findings.

    Saves to findings/{target}/evidence/ with timestamped filenames.
    Each piece of evidence links back to its finding via the hypothesis ID.
    """

    def __init__(self, target_dir: Path) -> None:
        self.evidence_dir = target_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_dir = target_dir / "tmp"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def save_response(
        self,
        tool_name: str,
        output: str,
        hypothesis_id: str = "",
        label: str = "",
    ) -> Path:
        """Save raw tool output as evidence."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{hypothesis_id}_" if hypothesis_id else ""
        suffix = f"_{label}" if label else ""
        filename = f"{prefix}{tool_name}{suffix}_{timestamp}.txt"
        path = self.evidence_dir / filename
        path.write_text(output, encoding="utf-8")
        return path

    def save_curl_chain(
        self,
        steps: list[dict[str, str]],
        hypothesis_id: str = "",
    ) -> Path:
        """Save a curl reproduction chain as a single file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{hypothesis_id}_" if hypothesis_id else ""
        filename = f"{prefix}curl_chain_{timestamp}.sh"
        path = self.evidence_dir / filename

        lines = [
            "#!/bin/bash",
            f"# Reproduction curl chain - {datetime.now().isoformat()}",
            "",
        ]
        for i, step in enumerate(steps, 1):
            title = step.get("title", f"Step {i}")
            curl = step.get("curl", "")
            lines.append(f"# Step {i}: {title}")
            if curl:
                lines.append(curl)
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def save_verbose_output(self, tool_name: str, output: str) -> Path:
        """Save verbose tool output to tmp/ (not evidence, just for reference)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{tool_name}_{timestamp}_verbose.txt"
        path = self.tmp_dir / filename
        path.write_text(output, encoding="utf-8")
        return path

    def list_evidence(self) -> list[Path]:
        """List all captured evidence files."""
        return sorted(self.evidence_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
