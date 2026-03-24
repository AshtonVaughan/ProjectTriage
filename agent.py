"""ReAct agent loop v3 - hypothesis-driven attack graph with persistent world model.

Replaces the linear phase pipeline with:
1. Hypothesis-driven graph traversal (attack_graph.py)
2. Persistent structured world model (world_model.py)
3. Vulnerability chain analysis (chain_analyzer.py)
4. Multi-role authorization testing (auth_context.py)
5. Race condition detection (tools/race.py)
6. Tech-stack fingerprinting (tech_fingerprint.py)
"""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console
from rich.panel import Panel

from attack_graph import AttackGraph
from auth_context import AuthContext
from chain_analyzer import ChainAnalyzer
from config import Config
from context import ContextManager, Step
from cost_tracker import CostTracker
from db import Database
from disclosures import DisclosureLookup
from evidence import EvidenceCapture
from hypothesis import Hypothesis, HypothesisEngine
from js_analyzer import analyze_target as js_analyze_target, integrate_with_target_model
from knowledge import format_knowledge_context, get_chain_suggestions, PIVOT_RULES, get_methodology
from memory import TargetMemory
from parallel import parallel_recon
from patterns import PatternsMemory
from prompts import SYSTEM_PROMPT, REACT_TEMPLATE
from provider import Provider, ReActResponse
from sanitizer import sanitize_action, sanitize_inputs
from scope import Scope
from session import SessionRecorder
from target_model import TargetModel
from tech_fingerprint import TechFingerprinter
from tool_registry import ToolRegistry
from validator import Validator
from world_model import WorldModel

# Maximum raw observation size before compression (bytes)
MAX_OBSERVATION_BYTES = 8000


class Agent:
    """Hypothesis-driven ReAct agent with persistent world model.

    Core loop: generate hypotheses -> test highest-ranked -> on finding: chain
    analysis + re-seed -> on dead end: pivot -> repeat until budget exhausted.
    """

    def __init__(
        self,
        config: Config,
        provider: Provider,
        registry: ToolRegistry,
        console: Console,
    ) -> None:
        self.config = config
        self.provider = provider
        self.registry = registry
        self.console = console
        self.context = ContextManager(max_tokens=config.max_context_tokens)
        self.db = Database(config.db_path)
        self.validator = Validator()
        self.patterns = PatternsMemory(config.data_dir)
        self.chain_analyzer = ChainAnalyzer()
        self.fingerprinter = TechFingerprinter()
        self.auth_context = AuthContext()
        self.disclosures = DisclosureLookup()

        # Initialized per-target in run()
        self.target_model: TargetModel | None = None
        self.world: WorldModel | None = None
        self.attack_graph: AttackGraph | None = None
        self.hypothesis_engine: HypothesisEngine | None = None
        self.memory: TargetMemory | None = None
        self.scope: Scope | None = None
        self.evidence: EvidenceCapture | None = None
        self.cost_tracker: CostTracker | None = None
        self.session_recorder: SessionRecorder | None = None

    def run(self, target: str) -> str:
        """Run the full agent loop against a target. Returns findings summary."""
        try:
            return self._run_inner(target)
        finally:
            self.db.close()

    def _run_inner(self, target: str) -> str:
        """Core run method - hypothesis-driven attack graph loop."""
        # Initialize per-target components
        self.target_model = TargetModel(target, self.config.findings_dir)
        self.world = WorldModel(target, self.config.findings_dir)
        self.hypothesis_engine = HypothesisEngine(self.db, target)
        self.memory = TargetMemory(self.target_model.target_dir)
        self.evidence = EvidenceCapture(self.target_model.target_dir)
        self.scope = Scope.from_target(target)

        # Total step budget = max_steps_per_phase * 5 (comparable to old 5-phase model)
        total_budget = self.config.max_steps_per_phase * 5

        # Try to resume from saved attack graph state
        resumed = AttackGraph.load_state(self.config.findings_dir, self.db, target)
        if resumed and resumed.total_steps > 0:
            self.attack_graph = resumed
            self.attack_graph.max_steps = total_budget
            self.console.print(
                f"[green]Resumed attack graph: {resumed.total_steps} steps done, "
                f"{len(resumed.hypothesis_queue)} hypotheses remaining, "
                f"{resumed.findings_count} findings[/green]"
            )
        else:
            self.attack_graph = AttackGraph(self.db, target, max_steps=total_budget)

        # Cost + session tracking
        self.cost_tracker = CostTracker(
            target=self.target_model.safe_name,
            model=self.provider.model,
        )
        self.session_recorder = SessionRecorder(
            target=self.target_model.safe_name,
            findings_dir=self.config.findings_dir,
        )
        self.session_recorder.set_metadata("model", self.provider.model)
        self.session_recorder.set_metadata("architecture", "v3_attack_graph")

        # Load existing scope
        existing_scope = Scope.load(self.target_model.target_dir)
        if existing_scope.rules:
            self.scope = existing_scope

        # Start hunt session
        session_id = self.db.start_hunt_session(
            target=target,
            provider=self.provider._detect_backend_name(),
            model=self.provider.model,
        )
        hunt_number = self.memory.get_hunt_count() + 1

        # Display hunt header
        stale_status = "STALE - full recon" if self.target_model.is_stale else "FRESH - reusing"
        prior_context = self.memory.load_context()
        defenses = self.memory.load_defenses()

        self.console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Architecture:[/bold] v3 Hypothesis-Driven Attack Graph\n"
            f"[bold]Provider:[/bold] {self.provider._detect_backend_name()} ({self.provider.model})\n"
            f"[bold]Tools:[/bold] {self.config.available_tools_summary()}\n"
            f"[bold]Target Model:[/bold] {stale_status}\n"
            f"[bold]Hunt #:[/bold] {hunt_number} | Budget: {total_budget} steps\n"
            + (f"[bold]Patterns:[/bold] {self.patterns.summary()}\n")
            + (f"[bold]Defenses:[/bold] {defenses[:200]}...\n" if defenses else "")
            + (f"[bold]Context:[/bold] {prior_context[:200]}...\n" if prior_context else ""),
            title="[bold red]NPUHacker v3[/bold red]",
            border_style="red",
        ))

        # Build tool embeddings for ToolRAG
        self.console.print("[dim]Building tool embeddings...[/dim]")
        self.registry.build_embeddings(self.provider.embed)

        # ============================================================
        # PHASE A: Parallel recon + fingerprinting + JS analysis
        # ============================================================

        # Run parallel recon if target model is stale
        if self.target_model.is_stale:
            self.console.print("\n[bold cyan]>>> Parallel Recon (subfinder + nmap + httpx)[/bold cyan]")
            self._run_parallel_recon(target)

        # Tech fingerprinting
        self.console.print("\n[bold cyan]>>> Tech Fingerprinting[/bold cyan]")
        self._run_fingerprinting(target)

        # JS bundle analysis
        self.console.print("\n[bold cyan]>>> JS Bundle Analysis[/bold cyan]")
        self._run_js_analysis(target)

        # Disclosure dedup check
        self._run_disclosure_check(target)

        # Crown jewels auto-detection (LLM-based)
        self.console.print("\n[bold cyan]>>> Crown Jewels Identification[/bold cyan]")
        self._detect_crown_jewels(target)

        # Generate initial hypotheses from recon + fingerprinting
        self._generate_initial_hypotheses(target)

        # If target model is fresh, skip basic recon hypotheses
        if not self.target_model.is_stale and self.target_model.has_recon:
            self.console.print(
                f"[green]Target model fresh ({self.target_model.summary()}). "
                f"Skipping recon hypotheses.[/green]"
            )

        # ============================================================
        # MAIN LOOP: Hypothesis-driven testing
        # ============================================================
        self.console.print(f"\n[bold cyan]>>> Starting hypothesis-driven testing ({total_budget} step budget)[/bold cyan]\n")

        consecutive_errors = 0
        recent_actions: list[str] = []

        while not self.attack_graph.is_complete:
            # Engagement meta-reasoning (100-hour rule equivalent)
            if self._should_disengage():
                self.console.print(
                    "[bold yellow]>>> Engagement meta-reasoning: diminishing returns detected. "
                    "Consider switching to a different target.[/bold yellow]"
                )
                break

            # Check abandonment (score-based)
            if self.attack_graph.should_abandon():
                self.console.print(
                    "[yellow]>>> Remaining hypotheses score below threshold.[/yellow]"
                )
                break

            # Check pivot with knowledge-based reasoning
            if self.attack_graph.should_pivot():
                pivot_advice = self._get_pivot_advice()
                self.console.print(f"[yellow]>>> Pivoting: {pivot_advice}[/yellow]")

            # Get next hypothesis
            hyp = self.attack_graph.next_hypothesis()
            if not hyp:
                # No more hypotheses - try generating more from current state
                new_count = self._generate_hypotheses_from_state(target)
                if new_count == 0:
                    self.console.print("[yellow]>>> No more hypotheses to test.[/yellow]")
                    break
                continue

            # Display current state
            phase_label = self.attack_graph.get_current_phase_label()
            self.console.print(
                f"[dim]{self.attack_graph.get_progress()} | "
                f"Phase: {phase_label} | "
                f"Testing: {hyp.technique} on {hyp.endpoint[:60]}[/dim]"
            )

            # Execute one ReAct step for this hypothesis
            step_start = time.monotonic()
            response = self._agent_step(target, hyp, phase_label)
            step_duration_ms = (time.monotonic() - step_start) * 1000

            # Sanitize
            available = list(self.registry.tools.keys())
            response.action = sanitize_action(response.action, available)
            if response.action not in ("ADVANCE", "DONE", ""):
                response.action_input = sanitize_inputs(
                    response.action, response.action_input
                )

            # Handle special actions
            if response.action == "DONE":
                self.console.print("[green]>>> Agent signaled testing complete.[/green]")
                break

            if response.action == "ADVANCE":
                # In graph mode, ADVANCE means "this hypothesis is done, move to next"
                reason = response.action_input.get("reason", "Hypothesis tested")
                self.attack_graph.record_result(hyp.id, success=False, finding=reason)
                self.attack_graph.record_step()
                continue

            # Dedup check
            action_key = f"{response.action}:{response.action_input.get('url', response.action_input.get('target', ''))}"
            if action_key in recent_actions:
                self.attack_graph.record_result(hyp.id, success=False, finding="Duplicate action")
                self.attack_graph.record_step()
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    break
                continue
            recent_actions.append(action_key)
            if len(recent_actions) > 30:
                recent_actions = recent_actions[-30:]

            # Empty action
            if not response.action:
                consecutive_errors += 1
                self.attack_graph.record_step()
                if consecutive_errors >= 5:
                    break
                continue

            # Scope check
            tool_target = response.action_input.get(
                "target", response.action_input.get("url", "")
            )
            if tool_target and self.scope and not self.scope.is_in_scope(tool_target):
                self.console.print(f"[red]BLOCKED: {tool_target} out of scope[/red]")
                self.attack_graph.record_result(hyp.id, success=False, finding="Out of scope")
                self.attack_graph.record_step()
                continue

            # Execute tool
            tool_start = time.monotonic()
            observation = self._execute_tool(response.action, response.action_input)
            tool_duration_ms = (time.monotonic() - tool_start) * 1000

            # Cap observation
            if len(observation) > MAX_OBSERVATION_BYTES:
                observation = observation[:MAX_OBSERVATION_BYTES] + "\n... [truncated]"

            # Record in session
            if self.session_recorder:
                self.session_recorder.record_tool(
                    tool_name=response.action,
                    tool_input=str(response.action_input)[:500],
                    tool_output=observation[:1000],
                    phase=phase_label,
                    step_number=self.attack_graph.total_steps + 1,
                    duration_ms=tool_duration_ms,
                )

            # Error tracking
            is_error = "error" in observation.lower()[:200] or "not found" in observation.lower()[:200]
            if is_error:
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    self.console.print("[red]>>> Too many errors. Moving on.[/red]")
                    self.attack_graph.record_result(hyp.id, success=False, finding="Repeated errors")
                    self.attack_graph.record_step()
                    break
            else:
                consecutive_errors = 0

            # Update world model
            self._update_world_model(response.action, response.action_input, observation)
            self._update_target_model(response.action, response.action_input, observation)

            # Compress observation
            compressed = self._compress_observation(response.action, observation)

            # Check if finding
            is_finding = self._is_finding(compressed)

            # Save evidence
            if self.evidence and len(observation) > 100:
                self.evidence.save_response(
                    tool_name=response.action,
                    output=observation,
                    hypothesis_id=hyp.id,
                    label="finding" if is_finding else "output",
                )

            # Record hypothesis result
            if is_finding:
                # Run 3-layer validation gate before recording
                validated = self._validate_finding(
                    title=compressed[:100],
                    target=target,
                    endpoint=hyp.endpoint,
                    technique=hyp.technique,
                    description=compressed,
                    observation=observation,
                )

                severity = validated.severity if validated else "unknown"
                status = validated.status if validated else "needs_proof"

                if validated and validated.status == "rejected":
                    self.console.print(
                        f"[yellow]Finding rejected by validator: "
                        f"{validated.validations[-1].notes if validated.validations else 'failed'}[/yellow]"
                    )
                    self.attack_graph.record_result(hyp.id, success=False, finding="Rejected by validator")
                else:
                    self.attack_graph.record_result(hyp.id, success=True, finding=compressed[:200])
                    self.world.add_finding(
                        id=hyp.id,
                        title=compressed[:100],
                        severity=severity,
                        description=compressed,
                        endpoint=hyp.endpoint,
                        technique=hyp.technique,
                        step_found=self.attack_graph.total_steps,
                        chain_potential=[hyp.technique],
                    )

                    if status == "needs_proof":
                        self.console.print(f"[yellow]Finding needs further proof ({severity})[/yellow]")
                    else:
                        self.console.print(f"[bold green]VALIDATED finding: {severity}[/bold green]")

                    # Chain analysis
                    self._run_chain_analysis()

                    # Record in session
                    if self.session_recorder:
                        self.session_recorder.record_finding(
                            finding_id=hyp.id,
                            title=compressed[:100],
                            severity=severity,
                            phase=phase_label,
                            step_number=self.attack_graph.total_steps + 1,
                        )

                    # Check if new recon suggested
                    if self.attack_graph.suggest_new_recon():
                        self.console.print("[cyan]>>> Finding suggests new recon needed[/cyan]")
                        self._generate_hypotheses_from_state(target)
            else:
                self.attack_graph.record_result(hyp.id, success=False, finding="")

            # Detect defenses
            if self._is_defense_signal(observation):
                defense = compressed[:150]
                if self.memory:
                    self.memory.add_defense(defense)
                self.console.print(f"[yellow]Defense: {defense}[/yellow]")

            # Add to context
            step = Step(
                phase=phase_label,
                thought=response.thought,
                action=response.action,
                action_input=str(response.action_input),
                observation_summary=compressed,
                step_number=0,
            )
            self.context.add_step(step)
            self.attack_graph.record_step()

            # Record in session
            if self.session_recorder:
                self.session_recorder.record_step(
                    phase=phase_label,
                    thought=response.thought,
                    action=response.action,
                    action_input=str(response.action_input)[:500],
                    observation=compressed[:500],
                    duration_ms=step_duration_ms,
                )

        # ============================================================
        # WRAP UP
        # ============================================================
        self.target_model.save()
        self.world.save()
        if self.scope:
            self.scope.save(self.target_model.target_dir)
        # Persist attack graph state for session resume
        if self.attack_graph:
            self.attack_graph.save_state(self.config.findings_dir)

        # Record hunt session
        findings_summary = self.attack_graph.get_findings_summary()
        self.memory.add_context_entry(
            hunt_number=hunt_number,
            findings_count=self.attack_graph.findings_count,
            phases_completed=f"{self.attack_graph.total_steps} steps",
            notes=findings_summary[:500],
        )
        self.db.end_hunt_session(
            session_id=session_id,
            hypotheses_tested=len(self.attack_graph.tested),
            findings_count=self.attack_graph.findings_count,
            notes=findings_summary[:500],
        )

        # Save session + cost
        if self.session_recorder:
            session_path = self.session_recorder.save()
            self.console.print(f"[dim]Session: {session_path}[/dim]")
        if self.cost_tracker:
            self.cost_tracker.save(self.config.findings_dir)
            self.cost_tracker.display(self.console)

        # Final summary
        self.console.print(Panel(
            findings_summary,
            title="[bold green]Findings Summary[/bold green]",
            border_style="green",
        ))

        # World model summary
        self.console.print(Panel(
            self.world.get_attack_context(),
            title="[bold blue]World Model State[/bold blue]",
            border_style="blue",
        ))

        return findings_summary

    # ==================================================================
    # Hypothesis generation
    # ==================================================================

    def _run_fingerprinting(self, target: str) -> None:
        """Tech-fingerprint the target and seed the world model."""
        try:
            profile = self.fingerprinter.fingerprint(target)
            self.console.print(
                f"[cyan]Tech: framework={profile.framework}, cdn={profile.cdn}, "
                f"auth={profile.auth_type}, api={profile.api_style}, "
                f"cloud={profile.cloud_provider}, waf={profile.waf}[/cyan]"
            )
            # Update world model
            if self.world:
                self.world.set_tech("framework", profile.framework)
                self.world.set_tech("cdn", profile.cdn)
                self.world.set_tech("auth_type", profile.auth_type)
                self.world.set_tech("api_style", profile.api_style)
                self.world.set_tech("cloud_provider", profile.cloud_provider)
                self.world.set_tech("server", profile.server)
                self.world.set_tech("waf", profile.waf)
            # Update target model
            if self.target_model:
                self.target_model.set_tech_stack("framework", profile.framework)
                self.target_model.set_tech_stack("cdn", profile.cdn)
                self.target_model.set_tech_stack("server", profile.server)

            # Generate tech-specific hypotheses
            tech_hyps = self.fingerprinter.generate_hypotheses_for_tech(profile, target)
            if tech_hyps and self.hypothesis_engine:
                created = []
                for h in tech_hyps:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", target),
                        technique=h.get("technique", ""),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 5),
                        exploitability=h.get("exploitability", 5),
                        impact=h.get("impact", 5),
                        effort=h.get("effort", 5),
                    )
                    if hyp:
                        created.append(hyp)
                if created and self.attack_graph:
                    self.attack_graph.add_hypotheses(created)
                    self.console.print(f"[cyan]Generated {len(created)} tech-specific hypotheses[/cyan]")
        except Exception as e:
            self.console.print(f"[yellow]Fingerprinting failed: {e}[/yellow]")

    def _run_parallel_recon(self, target: str) -> None:
        """Run subfinder + nmap + httpx in parallel for fast initial recon."""
        try:
            results = parallel_recon(target, self.config.tool_paths)
            for r in results:
                status = "[green]OK" if r.success else "[red]FAIL"
                self.console.print(f"  {status}[/] {r.tool_name} ({r.duration_seconds:.1f}s)")

                # Feed results into target model + world model
                if r.success and r.output:
                    if r.tool_name == "subfinder":
                        subs = [l.strip() for l in r.output.split("\n") if l.strip() and "." in l]
                        if self.target_model:
                            self.target_model.add_subdomains(subs)
                        if self.world:
                            for s in subs:
                                self.world.add_host(s)
                        self.console.print(f"  [cyan]{len(subs)} subdomains found[/cyan]")
                    elif r.tool_name == "nmap":
                        if self.target_model:
                            self.target_model.add_observation(f"nmap: {r.output[:200]}")
                    elif r.tool_name == "httpx":
                        if self.target_model:
                            self.target_model.add_observation(f"httpx: {r.output[:200]}")
        except Exception as e:
            self.console.print(f"[yellow]Parallel recon failed: {e}[/yellow]")

    def _run_js_analysis(self, target: str) -> None:
        """Analyze JavaScript bundles for endpoints, secrets, and internal URLs."""
        try:
            # Ensure target has protocol
            url = target if target.startswith("http") else f"https://{target}"
            analysis = js_analyze_target(url, max_files=15, timeout=15)

            files = analysis.get("files_analyzed", 0)
            endpoints = len(analysis.get("api_endpoints", []))
            secrets = len(analysis.get("secrets", []))
            internal = len(analysis.get("internal_urls", []))
            sourcemaps = len(analysis.get("source_map_urls", []))

            self.console.print(
                f"[cyan]JS analysis: {files} files, {endpoints} API endpoints, "
                f"{secrets} secrets, {internal} internal URLs, {sourcemaps} source maps[/cyan]"
            )

            # Feed into target model
            if self.target_model:
                integrate_with_target_model(analysis, self.target_model)

            # Feed endpoints into world model
            if self.world:
                for ep in analysis.get("api_endpoints", []):
                    full_url = url.rstrip("/") + ep if ep.startswith("/") else ep
                    self.world.add_host(
                        target.replace("https://", "").replace("http://", "").split("/")[0],
                    )
                for secret in analysis.get("secrets", []):
                    self.world.add_credential(
                        type=secret.get("type", "unknown"),
                        value=secret.get("value", "")[:50],
                        scope="js_bundle",
                        source_step=0,
                    )

            # Secrets are high-value findings
            if secrets > 0:
                self.console.print(f"[bold red]>>> {secrets} secrets found in JS bundles![/bold red]")
                for s in analysis.get("secrets", [])[:5]:
                    self.console.print(f"  [red]{s['type']}: {s['value'][:30]}...[/red]")

        except Exception as e:
            self.console.print(f"[yellow]JS analysis failed: {e}[/yellow]")

    def _run_disclosure_check(self, target: str) -> None:
        """Check HackerOne for prior disclosures to avoid duplicates."""
        try:
            # Extract program handle from target domain
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            parts = domain.split(".")
            handle = parts[-2] if len(parts) >= 2 else domain

            disclosures = self.disclosures.search_disclosed(handle, max_results=10)
            if disclosures:
                self.console.print(
                    f"[yellow]>>> {len(disclosures)} prior disclosures found for '{handle}'[/yellow]"
                )
                for d in disclosures[:5]:
                    self.console.print(
                        f"  [dim][{d.get('severity', '?')}] {d.get('title', '?')[:80]}[/dim]"
                    )
                # Store for hypothesis dedup
                if self.world:
                    for d in disclosures:
                        self.world.mark_surface_tested(
                            d.get("title", ""),
                            "prior_disclosure",
                            0,
                        )
            else:
                self.console.print(f"[dim]No prior disclosures found for '{handle}'[/dim]")
        except Exception as e:
            self.console.print(f"[dim]Disclosure check skipped: {e}[/dim]")

    def _generate_initial_hypotheses(self, target: str) -> None:
        """Generate initial hypotheses from recon data + patterns + defaults."""
        if not self.hypothesis_engine or not self.attack_graph:
            return

        # From target model recon data
        if self.target_model and self.target_model.has_recon:
            recon_hyps = self.hypothesis_engine.generate_from_recon(self.target_model.data)
            if recon_hyps:
                self.attack_graph.add_hypotheses(recon_hyps)

        # Always generate a comprehensive default set (dedup handles repeats)
        url = target if target.startswith("http") else f"https://{target}"
        defaults = [
            # Recon
            ("subdomain_enumeration", f"Enumerate subdomains of {target}", 3, 3, 3, 2),
            ("port_scan", f"Scan common ports on {target}", 3, 3, 3, 2),
            ("http_probe", f"Probe HTTP endpoints on {target}", 3, 3, 3, 2),
            ("header_analysis", f"Analyze security headers on {target}", 3, 4, 3, 2),
            ("js_analysis", f"Analyze JavaScript bundles for secrets and endpoints on {target}", 5, 5, 6, 3),
            # Discovery
            ("graphql_introspection", f"Check for GraphQL endpoint and introspection on {url}", 5, 6, 6, 2),
            ("subdomain_takeover", f"Check subdomains for dangling CNAME takeover", 4, 5, 5, 2),
            ("s3_bucket_exposure", f"Check for public S3/blob storage at {target}", 4, 5, 6, 2),
            # Auth testing
            ("jwt_attack", f"Analyze and test JWT tokens on {url}", 6, 7, 8, 3),
            ("idor", f"Test API endpoints for IDOR/BOLA on {url}", 6, 7, 8, 3),
            ("auth_bypass", f"Test authentication bypass techniques on {url}", 7, 6, 9, 4),
            # Vuln scan
            ("ssrf", f"Test for SSRF to cloud metadata on {url}", 7, 7, 9, 4),
            ("race_condition", f"Test payment/limit endpoints for race conditions on {url}", 7, 7, 8, 3),
            ("cache_poisoning", f"Test for web cache poisoning via unkeyed headers on {url}", 6, 6, 7, 4),
            ("desync", f"Test for HTTP request smuggling/desync on {url}", 5, 5, 8, 5),
            ("prompt_injection", f"Test AI/chatbot features for prompt injection on {url}", 7, 7, 7, 3),
            # Standard
            ("nuclei_scan", f"Run nuclei CVE templates against {url}", 3, 5, 5, 2),
        ]

        created = []
        for technique, desc, novelty, exploit, impact, effort in defaults:
            hyp = self.hypothesis_engine.create(
                endpoint=url if "://" in url else target,
                technique=technique,
                description=desc,
                novelty=novelty, exploitability=exploit,
                impact=impact, effort=effort,
            )
            if hyp:
                created.append(hyp)
        if created:
            self.attack_graph.add_hypotheses(created)

        self.console.print(
            f"[cyan]Hypothesis queue: {len(self.attack_graph.hypothesis_queue)} hypotheses loaded[/cyan]"
        )

    def _generate_hypotheses_from_state(self, target: str) -> int:
        """Generate new hypotheses based on current world model state. Returns count."""
        if not self.hypothesis_engine or not self.attack_graph or not self.world:
            return 0

        created = []

        # From world model findings - race condition candidates
        from tools.race import detect_race_candidates
        for finding in self.world.get_findings_for_chain_analysis():
            endpoint = finding.get("endpoint", "")
            if endpoint:
                candidates = detect_race_candidates(endpoint)
                for c in candidates:
                    hyp = self.hypothesis_engine.create(
                        endpoint=c["endpoint"],
                        technique="race_condition",
                        description=f"Race condition test: {c['reason']}",
                        novelty=7, exploitability=7, impact=7, effort=3,
                    )
                    if hyp:
                        created.append(hyp)

        # From auth context - IDOR/auth bypass tests
        auth_hyps = self.auth_context.get_all_test_hypotheses()
        for h in auth_hyps:
            hyp = self.hypothesis_engine.create(
                endpoint=h.get("endpoint", target),
                technique=h.get("technique", "auth_test"),
                description=h.get("description", ""),
                novelty=h.get("novelty", 6),
                exploitability=h.get("exploitability", 7),
                impact=h.get("impact", 8),
                effort=h.get("effort", 3),
            )
            if hyp:
                created.append(hyp)

        if created:
            self.attack_graph.add_hypotheses(created)
            self.console.print(f"[cyan]Generated {len(created)} new hypotheses from state[/cyan]")

        return len(created)

    def _run_chain_analysis(self) -> None:
        """Run chain analysis on current findings and inject chain hypotheses."""
        if not self.world or not self.attack_graph or not self.hypothesis_engine:
            return

        findings = self.world.get_findings_for_chain_analysis()
        if len(findings) < 2:
            return

        chains = self.chain_analyzer.analyze(findings)
        if not chains:
            return

        self.console.print(f"[bold magenta]>>> Chain analysis: {len(chains)} potential chains![/bold magenta]")
        for chain in chains:
            self.console.print(
                f"  [magenta]{chain['chain_name']} ({chain['chain_severity']}) "
                f"- confidence {chain['confidence']:.0%}[/magenta]"
            )

        # Convert chains to hypotheses
        chain_hyps_data = self.chain_analyzer.get_chain_hypotheses(chains)
        created = []
        for h in chain_hyps_data:
            hyp = self.hypothesis_engine.create(
                endpoint=h.get("endpoint", ""),
                technique=h.get("technique", ""),
                description=h.get("description", ""),
                novelty=8,
                exploitability=h.get("exploitability", 8),
                impact=h.get("impact", 9),
                effort=h.get("effort", 4),
            )
            if hyp:
                created.append(hyp)

        if created:
            self.attack_graph.add_hypotheses(created)
            self.console.print(f"[magenta]Injected {len(created)} chain hypotheses[/magenta]")

    # ==================================================================
    # Agent step execution
    # ==================================================================

    def _agent_step(self, target: str, hyp: Hypothesis, phase_label: str) -> ReActResponse:
        """Execute one ReAct step for a specific hypothesis."""
        # Build query for ToolRAG
        query = f"{hyp.technique} {hyp.endpoint} {phase_label}"
        tools = self.registry.retrieve(
            query=query,
            embed_fn=self.provider.embed,
            top_k=self.config.toolrag_top_k,
            phase=phase_label,
        )
        tool_descriptions = self.registry.get_descriptions(tools)

        # Build context with world model state + elite knowledge
        world_context = ""
        if self.world:
            world_context = self.world.get_attack_context(max_chars=1500)
        patterns_ctx = self.patterns.as_prompt_context()

        # Inject relevant attack methodology from knowledge base
        tech_stack = self.world.tech_stack if self.world else {}
        knowledge_ctx = format_knowledge_context(tech_stack, max_chars=2000)

        # Get chain suggestions if we have findings
        chain_hint = ""
        chain_suggestions = get_chain_suggestions(hyp.technique)
        if chain_suggestions:
            chain_hint = "\nPOSSIBLE CHAINS: " + "; ".join(
                f"{c['chain_with']} -> {c['result']} ({c['severity']})"
                for c in chain_suggestions[:3]
            )

        # Inject step-by-step methodology for this technique from knowledge base
        methodology = get_methodology(hyp.technique)
        methodology_hint = ""
        if methodology:
            methodology_hint = "\nMETHODOLOGY:\n" + "\n".join(methodology[:5])

        hypothesis_context = (
            f"\nCURRENT HYPOTHESIS: {hyp.technique} on {hyp.endpoint}\n"
            f"Description: {hyp.description}\n"
            f"Score: {hyp.total_score:.1f} (novelty={hyp.novelty}, "
            f"exploitability={hyp.exploitability}, impact={hyp.impact})\n"
            f"{chain_hint}"
            f"{methodology_hint}"
        )

        prompt = REACT_TEMPLATE.format(
            tool_descriptions=tool_descriptions,
            phase=f"{phase_label} - Testing hypothesis: {hyp.technique}",
            target=target,
            context=(
                self.context.build_context()
                + hypothesis_context
                + (f"\n{world_context}" if world_context else "")
                + (f"\n{knowledge_ctx}" if knowledge_ctx else "")
                + (f"\n{patterns_ctx}" if patterns_ctx else "")
            ),
        )

        step_start = time.monotonic()
        response = self.provider.react_step(SYSTEM_PROMPT, prompt)
        llm_duration_ms = (time.monotonic() - step_start) * 1000

        # Record in cost tracker
        if self.cost_tracker:
            self.cost_tracker.record_call(
                phase=phase_label,
                prompt=prompt,
                response=response.raw,
                duration_ms=llm_duration_ms,
                model=self.provider.model,
                label=f"hypothesis_{hyp.technique}",
            )

        if response.thought:
            self.console.print(f"\n[bold]Thought:[/bold] {response.thought}")
        if response.action and response.action not in ("ADVANCE", "DONE"):
            self.console.print(
                f"[bold blue]Action:[/bold blue] {response.action}"
                f"({_truncate(str(response.action_input), 100)})"
            )

        return response

    def _execute_tool(self, name: str, inputs: dict[str, Any]) -> str:
        """Execute a tool and return its output."""
        self.console.print(f"[dim]Executing {name}...[/dim]")
        result = self.registry.execute(name, inputs)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        returncode = result.get("returncode", -1)

        if returncode != 0 and stderr:
            output = f"Error (code {returncode}): {stderr}\n{stdout}"
        else:
            output = stdout

        display = _truncate(output, 300)
        if output:
            self.console.print(
                Panel(display, title=f"[dim]{name} output[/dim]", border_style="dim")
            )
        return output

    # ==================================================================
    # World model updates
    # ==================================================================

    def _update_world_model(self, action: str, inputs: dict[str, Any], output: str) -> None:
        """Update the structured world model from tool output."""
        if not self.world:
            return

        target_arg = inputs.get("target", inputs.get("url", inputs.get("targets", "")))

        if action == "subfinder" and output:
            for line in output.split("\n"):
                host = line.strip()
                if host and "." in host:
                    self.world.add_host(host)

        elif action == "nmap" and output:
            import re
            for match in re.finditer(r"(\d+)/(\w+)\s+(\w+)\s+(.*)", output):
                port_info = {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(4).strip(),
                    "state": match.group(3),
                }
                host = target_arg or "unknown"
                self.world.add_host(host, port_info=port_info)

        elif action == "curl" and output:
            # Look for auth-related info
            if "set-cookie:" in output.lower():
                import re
                for cookie_match in re.finditer(r"set-cookie:\s*([^;]+)", output, re.I):
                    cookie = cookie_match.group(1).strip()
                    if "=" in cookie:
                        name, _, val = cookie.partition("=")
                        # Detect auth cookies
                        auth_names = {"session", "token", "jwt", "auth", "sid"}
                        if any(a in name.lower() for a in auth_names):
                            self.world.add_credential(
                                type="cookie",
                                value=cookie,
                                scope=target_arg,
                                source_step=self.attack_graph.total_steps if self.attack_graph else 0,
                            )

        # Track tested surface
        if target_arg and action not in ("ADVANCE", "DONE", "SYSTEM", ""):
            self.world.mark_surface_tested(
                target_arg, action,
                self.attack_graph.total_steps if self.attack_graph else 0,
            )

    def _update_target_model(self, action: str, inputs: dict[str, Any], output: str) -> None:
        """Update legacy target model for backward compatibility."""
        if not self.target_model:
            return

        if action == "subfinder" and output:
            subdomains = [l.strip() for l in output.split("\n") if l.strip() and "." in l]
            self.target_model.add_subdomains(subdomains)
        elif action == "nmap" and output:
            self.target_model.add_observation(f"nmap: {output[:200]}")
        elif action == "httpx" and output:
            self.target_model.add_observation(f"httpx: {output[:200]}")
        elif action == "analyze_headers" and output:
            self.target_model.add_observation(f"headers: {output[:200]}")

    # ==================================================================
    # Helpers
    # ==================================================================

    # ==================================================================
    # Validation, crown jewels, engagement reasoning, pivot advice
    # ==================================================================

    def _validate_finding(
        self, title: str, target: str, endpoint: str, technique: str,
        description: str, observation: str,
    ):
        """Run 3-layer validation gate on a finding before recording it."""
        try:
            # Extract a curl command from the observation if present
            import re
            curl_match = re.search(r"(curl\s+[^\n]+)", observation)
            curl_cmd = curl_match.group(1) if curl_match else ""

            # Use a short evidence string to check
            evidence_words = ["vulnerable", "injection", "bypass", "leaked", "exposed"]
            expected = next((w for w in evidence_words if w in description.lower()), "")

            result = self.validator.validate(
                title=title,
                target=target,
                endpoint=endpoint,
                technique=technique,
                description=description,
                curl_command=curl_cmd,
                expected_evidence=expected,
                severity="medium",
            )
            return result
        except Exception as e:
            self.console.print(f"[dim]Validation error: {e}[/dim]")
            return None

    def _detect_crown_jewels(self, target: str) -> None:
        """Use LLM to auto-detect the target's crown jewels and boost attack graph scores."""
        try:
            from prompts import CROWN_JEWELS_PROMPT
            import json as _json

            # Build context from what we know
            tech = {}
            if self.world:
                tech = self.world.tech_stack if self.world else {}
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = self.target_model.data["endpoints"][:20]
            observations = []
            if self.target_model and self.target_model.data.get("recon_observations"):
                observations = self.target_model.data["recon_observations"][-10:]

            prompt = CROWN_JEWELS_PROMPT.format(
                target=target,
                tech_stack=str(tech),
                endpoints=str(endpoints)[:500],
                observations=str(observations)[:500],
            )

            # Use fast model if available for this analysis task
            response = self.provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.3,
                use_fast=True,
            )

            # Parse crown jewels from response
            jewels: list[str] = []
            for line in response.split("\n"):
                line = line.strip()
                if line.startswith("{"):
                    try:
                        data = _json.loads(line)
                        asset = data.get("asset", "")
                        if asset:
                            jewels.append(asset)
                            if self.world:
                                self.world.add_crown_jewel(
                                    asset=asset,
                                    value_type=data.get("value_type", "unknown"),
                                    priority=data.get("priority", 5),
                                    notes=data.get("attack_approach", ""),
                                )
                    except _json.JSONDecodeError:
                        continue

            if jewels and self.attack_graph:
                self.attack_graph.set_crown_jewels(jewels)
                self.console.print(f"[cyan]Crown jewels identified: {', '.join(jewels[:5])}[/cyan]")
                self.console.print("[cyan]Hypotheses targeting crown jewels boosted 1.5x[/cyan]")
            else:
                self.console.print("[dim]No crown jewels identified (will use default scoring)[/dim]")

        except Exception as e:
            self.console.print(f"[dim]Crown jewels detection skipped: {e}[/dim]")

    def _should_disengage(self) -> bool:
        """Engagement meta-reasoning: detect diminishing returns.

        Based on the 100-Hour Rule from elite bug bounty methodology.
        Signals: high step count + low finding rate + low remaining hypothesis scores.
        """
        if not self.attack_graph:
            return False

        steps = self.attack_graph.total_steps
        findings = self.attack_graph.findings_count
        remaining = len(self.attack_graph.hypothesis_queue)

        # Too early to judge
        if steps < 15:
            return False

        # Calculate finding rate (findings per 10 steps)
        rate = (findings / max(steps, 1)) * 10

        # If we've done 40+ steps with 0 findings, disengage
        if steps >= 40 and findings == 0:
            return True

        # If we've done 60+ steps with finding rate below 0.5 per 10 steps, disengage
        if steps >= 60 and rate < 0.5:
            return True

        # If remaining hypotheses are all low quality and we have some findings already
        if remaining > 0 and findings > 0:
            top_score = self.attack_graph.hypothesis_queue[0].total_score if self.attack_graph.hypothesis_queue else 0
            if top_score < 2.0 and steps > 30:
                return True

        return False

    def _get_pivot_advice(self) -> str:
        """Get knowledge-based pivot advice based on current situation."""
        if not self.attack_graph:
            return "Move to different attack surface"

        steps = self.attack_graph.total_steps
        findings = self.attack_graph.findings_count

        # Check pivot rules from knowledge base
        for rule in PIVOT_RULES:
            condition = rule["condition"].lower()
            if "3+ consecutive failures" in condition and self.attack_graph.should_pivot():
                return f"{rule['action']} - {rule['reasoning']}"
            if "all standard checks pass" in condition and steps > 20 and findings == 0:
                return f"{rule['action']} - {rule['reasoning']}"
            if "authentication seems solid" in condition and findings == 0:
                return f"{rule['action']} - {rule['reasoning']}"

        return "Move to a different attack surface with higher-scored hypotheses"

    def _compress_observation(self, tool_name: str, output: str) -> str:
        if len(output) < 200:
            return output
        try:
            return self.provider.compress(tool_name, output)
        except Exception:
            return output[:300] + "... [truncated]"

    def _is_finding(self, observation: str) -> bool:
        strong_signals = [
            "vulnerable", "vulnerability found", "injection confirmed",
            "xss confirmed", "sqli confirmed", "rce confirmed",
            "ssrf confirmed", "exploit successful", "bypass confirmed",
            "race condition detected",
        ]
        moderate_signals = [
            "injection", "xss", "sqli", "exposed", "leak",
            "bypass", "cve-", "misconfigur", "information disclosure",
            "race condition", "idor", "unauthorized access",
        ]
        lower = observation.lower()
        if any(signal in lower for signal in strong_signals):
            return True
        matches = sum(1 for signal in moderate_signals if signal in lower)
        return matches >= 2

    def _is_defense_signal(self, output: str) -> bool:
        defense_signals = [
            "403 forbidden", "rate limit", "blocked", "waf",
            "captcha", "cloudflare", "akamai", "incapsula",
            "access denied", "too many requests",
        ]
        lower = output.lower()
        return any(signal in lower for signal in defense_signals)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
