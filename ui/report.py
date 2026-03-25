"""Report generator - produces step-by-step reproduction reports with CVSS scoring."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from models.cvss import CVSS, compute_cvss_score


class ReportGenerator:
    """Generates HackerOne-style reports with curl reproduction steps.

    Every report follows BountyHound's first-try reproduction standard:
    a triager who has never seen the target can reproduce in one pass.
    """

    def generate(
        self,
        title: str,
        target: str,
        endpoint: str,
        technique: str,
        description: str,
        reproduction_steps: list[dict[str, str]],
        impact: str,
        cvss: CVSS,
        evidence_paths: list[str] | None = None,
        findings_dir: Path = Path("findings"),
    ) -> Path:
        """Generate a markdown report and reproduction script. Returns report path."""
        # Sanitize target for filesystem
        safe_target = (
            target.replace("https://", "").replace("http://", "")
            .replace("/", "_").replace(":", "_").rstrip("_")
        )
        target_dir = findings_dir / safe_target / "reports"
        target_dir.mkdir(parents=True, exist_ok=True)

        # Generate slug from title
        slug = title.lower().replace(" ", "-")[:60]
        slug = "".join(c for c in slug if c.isalnum() or c == "-")
        report_path = target_dir / f"{slug}.md"
        script_path = target_dir / f"{slug}_reproduce.py"

        cvss_score = compute_cvss_score(cvss)
        severity = self._severity_from_score(cvss_score)

        # Build report
        report = self._build_report(
            title=title,
            target=target,
            endpoint=endpoint,
            technique=technique,
            description=description,
            reproduction_steps=reproduction_steps,
            impact=impact,
            cvss=cvss,
            cvss_score=cvss_score,
            severity=severity,
            evidence_paths=evidence_paths,
        )

        # Build reproduction script
        script = self._build_reproduce_script(
            title=title,
            endpoint=endpoint,
            reproduction_steps=reproduction_steps,
        )

        report_path.write_text(report, encoding="utf-8")
        script_path.write_text(script, encoding="utf-8")

        return report_path

    def _build_report(
        self,
        title: str,
        target: str,
        endpoint: str,
        technique: str,
        description: str,
        reproduction_steps: list[dict[str, str]],
        impact: str,
        cvss: CVSS,
        cvss_score: float,
        severity: str,
        evidence_paths: list[str] | None,
    ) -> str:
        """Build markdown report content."""
        lines = [
            f"# {title}",
            "",
            f"**Target:** {target}",
            f"**Endpoint:** {endpoint}",
            f"**Technique:** {technique}",
            f"**Severity:** {severity} ({cvss_score:.1f})",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            "",
            "## Summary",
            "",
            description,
            "",
            "## CVSS 3.1",
            "",
            f"**Score:** {cvss_score:.1f} ({severity})",
            f"- Attack Vector: {cvss.AV}",
            f"- Attack Complexity: {cvss.AC}",
            f"- Privileges Required: {cvss.PR}",
            f"- User Interaction: {cvss.UI}",
            f"- Scope: {cvss.S}",
            f"- Confidentiality: {cvss.C}",
            f"- Integrity: {cvss.I}",
            f"- Availability: {cvss.A}",
            "",
            "## Steps to Reproduce",
            "",
        ]

        for i, step in enumerate(reproduction_steps, 1):
            step_title = step.get("title", f"Step {i}")
            curl_cmd = step.get("curl", "")
            expected = step.get("expected", "")
            notes = step.get("notes", "")

            lines.append(f"### Step {i}: {step_title}")
            lines.append("")
            if curl_cmd:
                lines.append("```bash")
                lines.append(curl_cmd)
                lines.append("```")
                lines.append("")
            if expected:
                lines.append(f"**Expected:** {expected}")
                lines.append("")
            if notes:
                lines.append(f"*{notes}*")
                lines.append("")

        lines.extend([
            "## Impact",
            "",
            impact,
            "",
        ])

        if evidence_paths:
            lines.extend([
                "## Evidence",
                "",
            ])
            for path in evidence_paths:
                lines.append(f"- {path}")
            lines.append("")

        return "\n".join(lines)

    def _build_reproduce_script(
        self,
        title: str,
        endpoint: str,
        reproduction_steps: list[dict[str, str]],
    ) -> str:
        """Build a self-contained Python reproduction script."""
        curl_commands = [s.get("curl", "") for s in reproduction_steps if s.get("curl")]
        expected_evidence = [s.get("expected", "") for s in reproduction_steps if s.get("expected")]

        lines = [
            '"""',
            f"Reproduction script: {title}",
            f"Endpoint: {endpoint}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "Run: python reproduce.py",
            "Output: VULNERABLE or NOT VULNERABLE",
            '"""',
            "",
            "import shlex",
            "import subprocess",
            "import sys",
            "",
            "",
            "def main() -> None:",
            f'    print("Testing: {title}")',
            f'    print("Endpoint: {endpoint}")',
            '    print("-" * 60)',
            '    print()',
            "",
        ]

        for i, curl_cmd in enumerate(curl_commands):
            # Use repr() to safely embed the command string, then shlex.split at runtime
            evidence = expected_evidence[i] if i < len(expected_evidence) else ""

            lines.extend([
                f'    # Step {i + 1}',
                f'    print("Step {i + 1}...")',
                f'    cmd_str = {repr(curl_cmd)}',
                '    cmd_parts = shlex.split(cmd_str)',
                '    result = subprocess.run(',
                '        cmd_parts,',
                '        capture_output=True, text=True, timeout=30,',
                '    )',
                '    output = result.stdout + result.stderr',
                "",
            ])

            if evidence:
                lines.extend([
                    f'    if {repr(evidence.lower())} in output.lower():',
                    f'        print("  [FOUND] Expected evidence: {evidence}")',
                    '    else:',
                    f'        print("  [MISS] Expected evidence not found: {evidence}")',
                    '        print("  RESULT: NOT VULNERABLE")',
                    '        sys.exit(1)',
                    "",
                ])

        lines.extend([
            '    print()',
            '    print("RESULT: VULNERABLE")',
            "",
            "",
            'if __name__ == "__main__":',
            '    main()',
            "",
        ])

        return "\n".join(lines)

    def _severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"
