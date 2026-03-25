"""Real-time terminal dashboard for Project Triage v4.

Streams LLM thoughts, tool executions, findings, hypotheses, and world model
state in a live-updating Rich layout. Thread-safe - the agent runs in the main
thread and pushes updates via callbacks; the Rich Live renderer pulls state on
each refresh cycle.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.spinner import Spinner
from rich.style import Style
from rich.table import Table
from rich.text import Text

from utils.utils import format_duration


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[str, Style] = {
    "critical": Style(color="red", bold=True),
    "high": Style(color="yellow", bold=True),
    "medium": Style(color="cyan"),
    "low": Style(color="bright_black"),
    "info": Style(color="bright_black", italic=True),
}

_SEVERITY_TAGS: dict[str, str] = {
    "critical": "[bold red]CRIT[/bold red]",
    "high": "[bold yellow]HIGH[/bold yellow]",
    "medium": "[cyan]MED[/cyan]",
    "low": "[dim]LOW[/dim]",
    "info": "[dim italic]INFO[/dim italic]",
}

_PHASE_COLORS: dict[str, str] = {
    "recon": "bright_blue",
    "enumeration": "blue",
    "analysis": "magenta",
    "exploitation": "red",
    "validation": "green",
    "reporting": "bright_green",
}


# ---------------------------------------------------------------------------
# LiveDisplay
# ---------------------------------------------------------------------------


class LiveDisplay:
    """Thread-safe live terminal dashboard powered by Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self.console: Console = console or Console()
        self.live: Live | None = None
        self._lock = threading.Lock()

        # Header
        self._target: str = ""
        self._model: str = ""
        self._start_time: float = 0.0
        self._step_count: int = 0
        self._total_steps: int = 0

        # Main panel - thought / action
        self._current_thought: str = ""
        self._current_action: str = ""
        self._current_phase: str = "recon"

        # Hypothesis panel
        self._hypothesis_queue: list[dict[str, Any]] = []
        self._active_hypothesis: dict[str, Any] | None = None

        # Findings panel
        self._findings: list[dict[str, Any]] = []

        # World model
        self._world_summary: str = "No data yet."

        # Stats
        self._tokens_used: int = 0
        self._llm_calls: int = 0
        self._cost: str = "A$0.00"

        # Tool execution state
        self._tool_running: str = ""
        self._tool_elapsed: float = 0.0
        self._tool_start: float = 0.0

        # Log messages
        self._messages: list[str] = []
        self._max_messages: int = 6

        # Misc
        self._verbose: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, target: str, model: str, total_steps: int) -> None:
        """Initialize and start the live display."""
        with self._lock:
            self._target = target
            self._model = model
            self._total_steps = total_steps
            self._start_time = time.time()
            self._step_count = 0

        self.live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            screen=False,
            transient=False,
        )
        self.live.start()

    def stop(self) -> None:
        """Stop the live display cleanly."""
        if self.live is not None:
            try:
                self.live.stop()
            except Exception:
                pass
            self.live = None

    # ------------------------------------------------------------------
    # State update methods (thread-safe)
    # ------------------------------------------------------------------

    def update_thought(self, thought: str) -> None:
        """Update the streaming thought text."""
        with self._lock:
            self._current_thought = thought
        self._refresh()

    def update_action(self, action: str, action_input: str) -> None:
        """Show the current tool being called."""
        with self._lock:
            self._current_action = f"{action}({_truncate(action_input, 120)})"
        self._refresh()

    def start_tool(self, tool_name: str) -> None:
        """Show a spinner while a tool is executing."""
        with self._lock:
            self._tool_running = tool_name
            self._tool_start = time.time()
            self._tool_elapsed = 0.0
        self._refresh()

    def finish_tool(
        self, tool_name: str, output: str, is_error: bool = False
    ) -> None:
        """Show tool completion with a one-line summary."""
        with self._lock:
            elapsed = time.time() - self._tool_start if self._tool_start else 0.0
            style = "red" if is_error else "green"
            status = "ERR" if is_error else "OK"
            summary = _truncate(output.replace("\n", " "), 80)
            self._messages.append(
                f"[{style}][{status}][/{style}] {tool_name} "
                f"[dim]({elapsed:.1f}s)[/dim] {summary}"
            )
            if len(self._messages) > self._max_messages:
                self._messages = self._messages[-self._max_messages :]
            self._tool_running = ""
            self._tool_elapsed = 0.0
            self._tool_start = 0.0
        self._refresh()

    def add_finding(
        self, title: str, severity: str, confidence: int, endpoint: str
    ) -> None:
        """Add a finding to the findings panel."""
        with self._lock:
            self._findings.append(
                {
                    "title": title,
                    "severity": severity.lower(),
                    "confidence": confidence,
                    "endpoint": endpoint,
                }
            )
        self._refresh()

    def update_hypothesis(
        self, active: dict[str, Any] | None, queue: list[dict[str, Any]]
    ) -> None:
        """Update the hypothesis panel with current + upcoming hypotheses."""
        with self._lock:
            self._active_hypothesis = active
            self._hypothesis_queue = queue[:5]
        self._refresh()

    def update_world(self, summary: str) -> None:
        """Update the world model summary panel."""
        with self._lock:
            self._world_summary = summary
        self._refresh()

    def update_stats(
        self,
        step: int,
        tokens: int,
        llm_calls: int,
        cost: str,
        phase: str,
    ) -> None:
        """Update the status bar metrics."""
        with self._lock:
            self._step_count = step
            self._tokens_used = tokens
            self._llm_calls = llm_calls
            self._cost = cost
            self._current_phase = phase.lower()
        self._refresh()

    def log(self, message: str, style: str = "") -> None:
        """Add a message to the log area."""
        with self._lock:
            entry = f"[{style}]{message}[/{style}]" if style else message
            self._messages.append(entry)
            if len(self._messages) > self._max_messages:
                self._messages = self._messages[-self._max_messages :]
        self._refresh()

    def show_finding_detail(self, finding: dict[str, Any]) -> None:
        """Show a detailed panel for a finding (outside live context)."""
        sev = finding.get("severity", "info").lower()
        tag = _SEVERITY_TAGS.get(sev, sev.upper())
        detail = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        detail.add_column("key", style="bold")
        detail.add_column("value")
        detail.add_row("Title", finding.get("title", ""))
        detail.add_row("Severity", tag)
        detail.add_row("Confidence", f"{finding.get('confidence', 0)}%")
        detail.add_row("Endpoint", finding.get("endpoint", ""))
        if finding.get("description"):
            detail.add_row("Description", finding["description"])
        panel = Panel(
            detail,
            title="[bold]Finding Detail[/bold]",
            border_style=_SEVERITY_STYLES.get(sev, Style()),
            box=box.ROUNDED,
        )
        self.console.print(panel)

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Push a new render to the live display."""
        if self.live is not None:
            try:
                self.live.update(self._render())
            except Exception:
                pass

    def _render(self) -> Panel:
        """Render the full dashboard."""
        layout = self._build_layout()
        return Panel(
            layout,
            box=box.HEAVY,
            border_style="bright_blue",
            padding=0,
        )

    def _build_layout(self) -> Layout:
        """Build the Rich Layout with all panels."""
        root = Layout()
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="log", size=self._max_messages + 2),
            Layout(name="footer", size=3),
        )

        # -- Header --
        root["header"].update(self._render_header())

        # -- Body: main (thought+action) | sidebar (hypothesis) --
        body = root["body"]
        body.split_row(
            Layout(name="center", ratio=3),
            Layout(name="sidebar", ratio=1, minimum_size=26),
        )

        # Center: split into thought panel on top, world+findings on bottom
        center = body["center"]
        center.split_column(
            Layout(name="thought", ratio=2),
            Layout(name="bottom", ratio=1, minimum_size=8),
        )
        center["thought"].update(self._render_thought_panel())

        # Bottom: world model | findings
        bottom = center["bottom"]
        bottom.split_row(
            Layout(name="world", ratio=1),
            Layout(name="findings", ratio=1),
        )
        bottom["world"].update(self._render_world_panel())
        bottom["findings"].update(self._render_findings_panel())

        # Sidebar: hypothesis queue
        body["sidebar"].update(self._render_hypothesis_panel())

        # -- Log area --
        root["log"].update(self._render_log_panel())

        # -- Footer --
        root["footer"].update(self._render_footer())

        return root

    # ------------------------------------------------------------------
    # Panel renderers
    # ------------------------------------------------------------------

    def _render_header(self) -> Panel:
        """Render the header bar with target, model, time, steps."""
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 0.0
            target = self._target
            model = self._model
            step = self._step_count
            total = self._total_steps

        header = Text()
        header.append("  TARGET ", style="bold white on blue")
        header.append(f" {target}  ", style="bold bright_white")
        header.append("  MODEL ", style="bold white on magenta")
        header.append(f" {model}  ", style="bold bright_white")
        header.append("  TIME ", style="bold white on green")
        header.append(f" {format_duration(elapsed)}  ", style="bold bright_white")
        header.append("  STEPS ", style="bold white on red")
        header.append(f" {step}/{total}", style="bold bright_white")

        return Panel(
            Align.center(header),
            box=box.SIMPLE,
            style="",
            padding=0,
        )

    def _render_thought_panel(self) -> Panel:
        """Render the main thought + action panel."""
        with self._lock:
            thought = self._current_thought
            action = self._current_action
            tool_running = self._tool_running
            tool_start = self._tool_start

        parts: list[Any] = []

        # Thought section
        if thought:
            thought_text = Text()
            thought_text.append("THINKING\n", style="bold bright_blue")
            # Show last ~15 lines if thought is very long
            lines = thought.split("\n")
            if len(lines) > 15:
                thought_text.append("[dim]...[/dim]\n")
                visible = "\n".join(lines[-15:])
            else:
                visible = thought
            thought_text.append(visible, style="white")
            parts.append(thought_text)
        else:
            parts.append(Text("Waiting for LLM response...", style="dim italic"))

        # Action section
        if action:
            action_text = Text()
            action_text.append("\n\nACTION ", style="bold bright_yellow")
            action_text.append(action, style="bright_yellow")
            parts.append(action_text)

        # Tool spinner
        if tool_running:
            tool_elapsed = time.time() - tool_start if tool_start else 0.0
            spinner_text = Text()
            spinner_text.append("\n")
            spinner_text.append("\u25cf ", style="bold bright_green")
            spinner_text.append(f"Executing {tool_running}", style="bold green")
            spinner_text.append(f" ({tool_elapsed:.1f}s)", style="dim")
            parts.append(spinner_text)

        content = Group(*parts)
        return Panel(
            content,
            title="[bold bright_blue]Agent[/bold bright_blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _render_hypothesis_panel(self) -> Panel:
        """Render the hypothesis queue panel."""
        with self._lock:
            active = self._active_hypothesis
            queue = list(self._hypothesis_queue)

        table = Table(
            box=None,
            show_header=False,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("marker", width=2, no_wrap=True)
        table.add_column("name", ratio=1)
        table.add_column("score", width=5, justify="right")

        if active:
            name = _truncate(active.get("name", active.get("technique", "?")), 18)
            score = active.get("score", active.get("total_score", 0))
            table.add_row(
                Text("\u25b6", style="bold bright_green"),
                Text(name, style="bold bright_white"),
                Text(f"{score:.1f}", style="bold bright_green"),
            )
        else:
            table.add_row(
                Text("-", style="dim"),
                Text("none active", style="dim italic"),
                Text("", style="dim"),
            )

        for h in queue:
            name = _truncate(h.get("name", h.get("technique", "?")), 18)
            score = h.get("score", h.get("total_score", 0))
            table.add_row(
                Text(" ", style="dim"),
                Text(name, style="bright_white"),
                Text(f"{score:.1f}", style="dim"),
            )

        # Fill empty slots so the panel keeps a consistent height
        for _ in range(max(0, 5 - len(queue))):
            table.add_row("", "", "")

        return Panel(
            table,
            title="[bold bright_green]Hypotheses[/bold bright_green]",
            border_style="bright_green",
            box=box.ROUNDED,
            padding=(0, 0),
        )

    def _render_world_panel(self) -> Panel:
        """Render the world model summary."""
        with self._lock:
            summary = self._world_summary

        return Panel(
            Text(summary, style="white"),
            title="[bold magenta]World Model[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _render_findings_panel(self) -> Panel:
        """Render the findings list."""
        with self._lock:
            findings = list(self._findings)

        table = Table(
            box=None,
            show_header=False,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("sev", width=6, no_wrap=True)
        table.add_column("title", ratio=1)

        if not findings:
            table.add_row(
                Text("", style="dim"),
                Text("No findings yet.", style="dim italic"),
            )
        else:
            # Show most recent findings (last 8)
            for f in findings[-8:]:
                sev = f.get("severity", "info").lower()
                tag = _SEVERITY_TAGS.get(sev, sev.upper())
                title = _truncate(f.get("title", ""), 40)
                style = _SEVERITY_STYLES.get(sev, Style())
                table.add_row(
                    Text.from_markup(f"[{tag}]"),
                    Text(title, style=style),
                )

        return Panel(
            table,
            title="[bold red]Findings[/bold red]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 0),
        )

    def _render_log_panel(self) -> Panel:
        """Render the scrolling log area."""
        with self._lock:
            messages = list(self._messages)

        if not messages:
            content = Text("Ready.", style="dim")
        else:
            content = Text.from_markup("\n".join(messages))

        return Panel(
            content,
            title="[bold]Log[/bold]",
            border_style="bright_black",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _render_footer(self) -> Panel:
        """Render the status bar."""
        with self._lock:
            tokens = self._tokens_used
            calls = self._llm_calls
            cost = self._cost
            phase = self._current_phase

        phase_color = _PHASE_COLORS.get(phase, "white")

        footer = Text()
        footer.append("  Tokens ", style="bold dim")
        footer.append(f"{tokens:,}  ", style="bright_white")
        footer.append("|", style="dim")
        footer.append("  Calls ", style="bold dim")
        footer.append(f"{calls}  ", style="bright_white")
        footer.append("|", style="dim")
        footer.append("  Cost ", style="bold dim")
        footer.append(f"{cost}  ", style="bright_white")
        footer.append("|", style="dim")
        footer.append("  Phase ", style="bold dim")
        footer.append(f"{phase.upper()}", style=f"bold {phase_color}")

        return Panel(
            Align.center(footer),
            box=box.SIMPLE,
            style="",
            padding=0,
        )


# ---------------------------------------------------------------------------
# Standalone helper functions
# ---------------------------------------------------------------------------


def print_banner(
    console: Console,
    target: str,
    model: str,
    fast_model: str,
    tools_count: int,
    hunt_number: int,
    budget: int,
) -> None:
    """Print a beautiful startup banner."""
    title = Text()
    title.append("\n")
    title.append("  PROJECT TRIAGE v4  ", style="bold white on bright_blue")
    title.append("  Autonomous Pentesting Agent  ", style="bold bright_blue")
    console.print(Align.center(title))
    console.print()

    grid = Table(
        box=box.SIMPLE_HEAVY,
        show_header=False,
        padding=(0, 2),
        expand=False,
    )
    grid.add_column("key", style="bold bright_blue", width=14)
    grid.add_column("value", style="bright_white")

    grid.add_row("Target", target)
    grid.add_row("Model", model)
    if fast_model and fast_model != model:
        grid.add_row("Fast Model", fast_model)
    grid.add_row("Tools", str(tools_count))
    grid.add_row("Hunt #", str(hunt_number))
    grid.add_row("Budget", f"{budget} steps")

    console.print(Align.center(grid))

    separator = Text()
    separator.append(
        "\u2500" * 60, style="bright_black"
    )
    console.print(Align.center(separator))
    console.print()


def print_finding_alert(
    console: Console,
    title: str,
    severity: str,
    confidence: int,
) -> None:
    """Print a highlighted finding alert outside of live mode."""
    sev = severity.lower()
    border = _SEVERITY_STYLES.get(sev, Style())
    tag = _SEVERITY_TAGS.get(sev, sev.upper())

    alert = Text()
    alert.append("\u26a0 FINDING ", style="bold")
    alert.append(f"[{tag}] ", style="")
    alert.append(title, style="bold bright_white")
    alert.append(f"  (confidence: {confidence}%)", style="dim")

    console.print(
        Panel(
            alert,
            border_style=border,
            box=box.DOUBLE,
            padding=(0, 1),
        )
    )


def print_hunt_complete(
    console: Console,
    findings_count: int,
    steps: int,
    elapsed: str,
    tokens: int,
) -> None:
    """Print hunt completion summary."""
    console.print()

    result = Table(
        box=box.SIMPLE_HEAVY,
        show_header=False,
        padding=(0, 2),
        expand=False,
    )
    result.add_column("key", style="bold bright_green", width=14)
    result.add_column("value", style="bright_white")

    result.add_row("Findings", str(findings_count))
    result.add_row("Steps", str(steps))
    result.add_row("Duration", elapsed)
    result.add_row("Tokens", f"{tokens:,}")

    title = Text()
    title.append("  HUNT COMPLETE  ", style="bold white on bright_green")
    console.print(Align.center(title))
    console.print(Align.center(result))

    separator = Text()
    separator.append(
        "\u2500" * 60, style="bright_black"
    )
    console.print(Align.center(separator))
    console.print()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if too long."""
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
