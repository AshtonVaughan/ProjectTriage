"""Project Triage v4 - Hypothesis-driven attack graph with elite reasoning.

Architecture:
1. Source intelligence (GitHub, Wayback, CNAME, API specs)
2. Tech fingerprinting -> framework-specific hypothesis generation
3. State machine extraction (XState/Redux/OpenAPI)
4. Domain knowledge (57 patterns across 6 industries, OWASP BLA)
5. Architectural anti-pattern detection (Orange Tsai methodology)
6. Assumption archaeology -> novel hypothesis generation
7. Intent modeling -> business logic violation tests
8. Hypothesis-driven attack graph (not linear phases)
9. MCTS-scored hypothesis selection with LLM Value Agent
10. AGoT reasoning (multi-path exploration with self-critique)
11. Persistent world model with MFR (trust boundaries, data flows, state machines)
12. Perceptor - structured observation compression (51% token reduction)
13. Chain analysis with connector bug reasoning
14. Edge analysis (inter-component boundary testing)
15. Coverage asymmetry (prioritize under-tested surfaces)
16. Multi-role auth testing (IDOR, auth bypass, JWT)
17. Workflow testing (skip-step, race, OAuth 7-point)
18. Self-reflection - CoVe + Reflexion 3-layer finding verification
19. Quality gate (4-layer validation, confidence scoring, anti-noise)
20. Cross-session strategy memory with experience merge
"""

from __future__ import annotations

import os
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel

from utils.utils import format_duration

from brain.agot_reasoner import AGoTReasoner
from brain.arch_analyzer import ArchAnalyzer
from brain.assumption_engine import AssumptionEngine
from models.attack_graph import AttackGraph
from models.auth_context import AuthContext
from intel.campaign_manager import CampaignManager
from brain.chain_analyzer import ChainAnalyzer
from brain.chain_engine import ChainEngine
from core.config import Config
from core.context import ContextManager, Step
from core.cost_tracker import CostTracker
from brain.coverage_asymmetry import CoverageAsymmetryDetector
from utils.db import Database
from intel.differential_engine import DifferentialEngine
from models.disclosures import DisclosureLookup
from brain.dom_analyzer import DOMAnalyzer
from brain.domain_knowledge import DomainKnowledge
from brain.edge_analyzer import EdgeAnalyzer
from utils.evidence_collector import EvidenceCollector as AdvancedEvidenceCollector
from intel.fuzzer import SmartFuzzer
from intel.h2_desync import H2DesyncTester
from intel.infra_scanner import InfraScanner
from intel.interactsh_client import InteractshClient
from intel.mcp_tester import MCPTester
from intel.monitor_mode import MonitorMode
from models.evidence import EvidenceCapture
from models.hypothesis import Hypothesis, HypothesisEngine
from brain.intent_model import IntentModel
from intel.js_analyzer import analyze_target as js_analyze_target, integrate_with_target_model
from models.knowledge import format_knowledge_context, get_chain_suggestions, PIVOT_RULES, get_methodology
from brain.mcts_explorer import MCTSExplorer
from intel.osint_engine import OSINTEngine
from models.memory import TargetMemory
from core.parallel import parallel_recon
from models.patterns import PatternsMemory
from brain.perceptor import Perceptor
from intel.program_intel import ProgramIntelligence
from core.prompts import SYSTEM_PROMPT, REACT_TEMPLATE
from core.provider import Provider, ReActResponse
from utils.quality_gate import QualityGate
from ui.report_generator import ReportGenerator
from utils.sanitizer import sanitize_action, sanitize_inputs
from core.scope import Scope
from brain.self_reflect import SelfReflector
from intel.source_analyzer import SourceAnalyzer
from core.session import SessionRecorder
from intel.source_intel import SourceIntel
from brain.state_machine import StateMachineExtractor
from intel.supply_chain import SupplyChainAnalyzer
from models.target_model import TargetModel
from brain.tech_fingerprint import TechFingerprinter
from core.tool_registry import ToolRegistry
from utils.validator import Validator
from brain.websocket_tester import WebSocketTester
from brain.workflow_tester import WorkflowTester
from brain.world_model import WorldModel
from ui.live_display import LiveDisplay, print_banner, print_finding_alert, print_hunt_complete
# New modules from gap analysis
from brain.confusion_engine import ConfusionEngine
from brain.client_analyzer import ClientAnalyzer
from brain.idor_engine import IDOREngine
from brain.procedural_memory import ProceduralMemory
from brain.lats_explorer import LATSExplorer
from brain.curriculum import CurriculumManager
from brain.escalation_router import EscalationRouter
from brain.data_manager import DataManager

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
        # v4 modules
        self.assumption_engine = AssumptionEngine()
        self.intent_model = IntentModel()
        self.edge_analyzer = EdgeAnalyzer()
        self.coverage_detector = CoverageAsymmetryDetector()
        self.workflow_tester = WorkflowTester()
        self.agot = AGoTReasoner()
        # Round 1 modules (state machine, domain knowledge, arch analysis)
        self.state_machine_extractor = StateMachineExtractor()
        self.domain_knowledge = DomainKnowledge()
        self.arch_analyzer = ArchAnalyzer()
        # Round 2 modules (perceptor, self-reflection, MCTS)
        self.perceptor = Perceptor(provider)
        self.self_reflect = SelfReflector(provider)
        self.mcts = MCTSExplorer(provider, config.data_dir)
        self.quality_gate = QualityGate()
        # Round 3 modules (infra scanning, OSINT, chain engine)
        self.infra_scanner = InfraScanner()
        self.osint_engine = OSINTEngine()
        self.chain_engine = ChainEngine()
        # Round 4 modules (DOM, WebSocket, client-side)
        self.dom_analyzer = DOMAnalyzer()
        self.ws_tester = WebSocketTester()
        # Round 5 modules (campaigns, reporting)
        self.campaign_mgr = CampaignManager(config.data_dir)
        self.report_gen = ReportGenerator()
        # Round 6 modules (fuzzing, supply chain)
        self.fuzzer = SmartFuzzer()
        self.supply_chain = SupplyChainAnalyzer()
        # Critical gap modules
        self.program_intel = ProgramIntelligence()
        self.oob = InteractshClient()
        self.differential = DifferentialEngine()
        self.evidence_adv = AdvancedEvidenceCollector(config.findings_dir)
        # High-priority gap modules
        self.h2_desync = H2DesyncTester()
        self.mcp_tester = MCPTester()
        self.monitor = MonitorMode(config.data_dir)
        self.source_analyzer = SourceAnalyzer()
        # New modules from deep research gap analysis
        self.confusion_engine = ConfusionEngine()
        self.client_deep = ClientAnalyzer()
        self.idor_engine = IDOREngine()
        self.procedural_memory = ProceduralMemory(config.data_dir)
        self.lats = LATSExplorer(provider, config.data_dir)
        self.curriculum = CurriculumManager(config.data_dir)
        self.escalation = EscalationRouter(provider, config)
        self.data_mgr = DataManager(config.data_dir)
        # Live TUI display
        self.display = LiveDisplay(console)

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
            # Ensure display is stopped even on crash
            self.display.stop()
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

        # Campaign management - resume or create
        campaign = self.campaign_mgr.find_campaign_for_target(target)
        if not campaign:
            campaign = self.campaign_mgr.create_campaign(target)
            self.console.print(f"[cyan]New campaign created: {campaign.campaign_id}[/cyan]")
        else:
            self.console.print(
                f"[cyan]Resuming campaign {campaign.campaign_id} "
                f"(session #{campaign.session_count + 1}, "
                f"{campaign.findings_count} prior findings)[/cyan]"
            )
        self.campaign_mgr.start_session(campaign)

        # Display hunt banner (beautiful startup screen)
        print_banner(
            self.console,
            target=target,
            model=self.provider.model,
            fast_model=self.provider.fast_model or "",
            tools_count=len(self.registry.tools),
            hunt_number=hunt_number,
            budget=total_budget,
        )

        # Build tool embeddings for ToolRAG
        self.console.print("[dim]Building tool embeddings...[/dim]")
        self.registry.build_embeddings(self.provider.embed)

        # ============================================================
        # PHASE A: Intelligence Gathering
        # ============================================================

        # Program intelligence - read scope, payouts, recent additions FIRST
        self.console.print("\n[bold cyan]>>> Program Intelligence[/bold cyan]")
        self._run_program_intel(target)

        # Start OOB callback session for blind vulnerability confirmation
        self.console.print("\n[bold cyan]>>> OOB Callback Session[/bold cyan]")
        oob_session = self.oob.start_session()
        if oob_session:
            self.console.print(f"[cyan]OOB domain: {oob_session.base_domain}[/cyan]")
        else:
            self.console.print("[yellow]OOB callbacks unavailable - blind vulns will lack proof[/yellow]")

        # Source intelligence (GitHub, Wayback, CNAME, API specs)
        self.console.print("\n[bold cyan]>>> Source Intelligence[/bold cyan]")
        self._run_source_intel(target)

        # OSINT deep scan (cloud assets, staging envs, source maps)
        self.console.print("\n[bold cyan]>>> OSINT Deep Scan[/bold cyan]")
        self._run_osint_deep(target)

        # Run parallel recon if target model is stale
        if self.target_model.is_stale:
            self.console.print("\n[bold cyan]>>> Parallel Recon (subfinder + nmap + httpx)[/bold cyan]")
            self._run_parallel_recon(target)

        # Tech fingerprinting
        self.console.print("\n[bold cyan]>>> Tech Fingerprinting[/bold cyan]")
        self._run_fingerprinting(target)

        # Monitor mode - detect attack surface changes since last session
        self.console.print("\n[bold cyan]>>> Surface Change Detection[/bold cyan]")
        self._run_monitor_check(target)

        # Infrastructure-class target identification
        self.console.print("\n[bold cyan]>>> Infrastructure Scanner ($100K methodology)[/bold cyan]")
        self._run_infra_scan(target)

        # HTTP/2 desync detection
        self.console.print("\n[bold cyan]>>> HTTP/2 Desync Detection[/bold cyan]")
        self._run_h2_desync(target)

        # JS bundle analysis
        self.console.print("\n[bold cyan]>>> JS Bundle Analysis[/bold cyan]")
        self._run_js_analysis(target)

        # State machine extraction from JS bundles
        self.console.print("\n[bold cyan]>>> State Machine Extraction[/bold cyan]")
        self._run_state_machine_analysis(target)

        # Disclosure dedup check
        self._run_disclosure_check(target)

        # Crown jewels auto-detection (LLM-based)
        self.console.print("\n[bold cyan]>>> Crown Jewels Identification[/bold cyan]")
        self._detect_crown_jewels(target)

        # ============================================================
        # PHASE B: Hypothesis Generation (all engines)
        # ============================================================

        # Generate initial hypotheses from recon + fingerprinting
        self._generate_initial_hypotheses(target)

        # Assumption archaeology - generate novel hypotheses
        self.console.print("[bold cyan]>>> Assumption Archaeology[/bold cyan]")
        self._run_assumption_engine(target)

        # Intent model - business logic violation tests
        self.console.print("[bold cyan]>>> Intent Modeling[/bold cyan]")
        self._run_intent_model(target)

        # Coverage asymmetry - boost under-tested surfaces
        self.console.print("[bold cyan]>>> Coverage Asymmetry Analysis[/bold cyan]")
        self._run_coverage_analysis()

        # Edge analysis hypotheses
        self.console.print("[bold cyan]>>> Inter-Component Edge Analysis[/bold cyan]")
        self._run_edge_analysis(target)

        # Domain-specific vulnerability patterns
        self.console.print("[bold cyan]>>> Domain Knowledge Analysis[/bold cyan]")
        self._run_domain_knowledge_hypotheses(target)

        # Architectural anti-pattern detection (Orange Tsai methodology)
        self.console.print("[bold cyan]>>> Architectural Anti-Pattern Analysis[/bold cyan]")
        self._run_arch_analysis_hypotheses(target)

        # DOM vulnerability hypotheses (DOM XSS, PP, postMessage, CSTI)
        self.console.print("[bold cyan]>>> DOM Vulnerability Analysis[/bold cyan]")
        self._run_dom_analysis(target)

        # WebSocket endpoint discovery and hypothesis generation
        self.console.print("[bold cyan]>>> WebSocket Discovery[/bold cyan]")
        self._run_websocket_discovery(target)

        # MCP/Agentic AI attack surface
        self.console.print("[bold cyan]>>> MCP/AI Attack Surface[/bold cyan]")
        self._run_mcp_analysis(target)

        # Source code analysis (source maps, exposed repos)
        self.console.print("[bold cyan]>>> Source Code Analysis[/bold cyan]")
        self._run_source_analysis(target)

        # Differential testing hypotheses (IDOR/BOLA/BFLA)
        self.console.print("[bold cyan]>>> Differential Testing (IDOR/BOLA)[/bold cyan]")
        self._run_differential_hypotheses(target)

        # Smart fuzzer hypotheses
        self.console.print("[bold cyan]>>> Smart Fuzzer[/bold cyan]")
        self._run_fuzzer_hypotheses(target)

        # Supply chain analysis
        self.console.print("[bold cyan]>>> Supply Chain Analysis[/bold cyan]")
        self._run_supply_chain_analysis(target)

        # Confusion attack analysis (Orange Tsai 2024 methodology)
        self.console.print("[bold cyan]>>> Confusion Attack Analysis[/bold cyan]")
        self._run_confusion_analysis(target)

        # Deep client-side analysis (postMessage, CSWSH, DOM clobbering, prototype pollution)
        self.console.print("[bold cyan]>>> Deep Client-Side Analysis[/bold cyan]")
        self._run_client_deep_analysis(target)

        # IDOR/BOLA systematic testing
        self.console.print("[bold cyan]>>> IDOR/BOLA Engine[/bold cyan]")
        self._run_idor_analysis(target)

        # Procedural memory - apply learned skills from previous sessions
        self.console.print("[bold cyan]>>> Procedural Memory (Learned Skills)[/bold cyan]")
        self._run_procedural_memory(target)

        # Curriculum-guided hypothesis ordering
        self.console.print("[bold cyan]>>> Curriculum Learning[/bold cyan]")
        self._run_curriculum_analysis(target)

        # If target model is fresh, skip basic recon hypotheses
        if not self.target_model.is_stale and self.target_model.has_recon:
            self.console.print(
                f"[green]Target model fresh ({self.target_model.summary()}). "
                f"Skipping recon hypotheses.[/green]"
            )

        # ============================================================
        # MAIN LOOP: Hypothesis-driven testing
        # ============================================================

        # Start the live TUI display
        self._hunt_start_time = time.monotonic()
        self.display.start(target, self.provider.model, total_budget)
        self.display.log(f"Starting hypothesis-driven testing ({total_budget} step budget)", "bold cyan")

        consecutive_errors = 0
        recent_actions: list[str] = []
        attack_path_log: list[str] = []  # For MCTS context

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

            # MCTS: Score top hypotheses and potentially reorder queue
            tech_stack = self.world.tech_stack if self.world else {}
            if (len(self.attack_graph.hypothesis_queue) >= 3
                    and self.attack_graph.total_steps % 5 == 0):
                try:
                    scored = self.mcts.score_top_n(
                        self.attack_graph.hypothesis_queue, attack_path_log, tech_stack, n=3,
                    )
                    if scored:
                        # Reorder queue head if MCTS disagrees with heuristic
                        best_hyp, best_score = scored[0]
                        if best_hyp.id != self.attack_graph.hypothesis_queue[0].id:
                            # Move MCTS-preferred hypothesis to front
                            queue = self.attack_graph.hypothesis_queue
                            queue.remove(best_hyp)
                            queue.insert(0, best_hyp)
                            self.console.print(
                                f"[dim]MCTS reorder: {best_hyp.technique} "
                                f"(score={best_score.numerical}/10: {best_score.explanation})[/dim]"
                            )
                except Exception as e:
                    self.console.print(f"[dim]MCTS scoring skipped: {e}[/dim]")

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

            # Update live display: hypothesis panel + stats
            self.display.update_hypothesis(
                active={"technique": hyp.technique, "total_score": hyp.total_score},
                queue=[
                    {"technique": h.technique, "total_score": h.total_score}
                    for h in self.attack_graph.hypothesis_queue[:5]
                ],
            )
            token_stats = self.provider.token_stats()
            self.display.update_stats(
                step=self.attack_graph.total_steps,
                tokens=token_stats.get("total_input", 0) + token_stats.get("total_output", 0),
                llm_calls=self.provider.total_calls,
                cost=f"A${0:.2f}",  # Local LLM = free
                phase=phase_label,
            )

            # Execute one ReAct step for this hypothesis
            step_start = time.monotonic()
            response = self._agent_step(target, hyp, phase_label)
            step_duration_ms = (time.monotonic() - step_start) * 1000

            # Update live display with thought + action
            if response.thought:
                self.display.update_thought(response.thought)
            if response.action and response.action not in ("ADVANCE", "DONE", ""):
                self.display.update_action(
                    response.action, str(response.action_input)[:120],
                )

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

            # Execute tool (with live display spinner)
            self.display.start_tool(response.action)
            tool_start = time.monotonic()
            observation = self._execute_tool(response.action, response.action_input)
            tool_duration_ms = (time.monotonic() - tool_start) * 1000
            is_tool_error = "error" in observation.lower()[:200]
            self.display.finish_tool(
                response.action, observation[:200], is_error=is_tool_error,
            )

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

            # Perceptor: structured extraction + compression (replaces raw compress)
            facts = self.perceptor.perceive(
                response.action, observation, hyp.endpoint, hyp.technique,
            )
            # Feed structured facts back into world model
            self.perceptor.feed_to_world_model(facts, self.world)
            compressed = facts.raw_summary

            # Log action to attack path for MCTS context
            attack_path_log.append(f"{response.action} on {hyp.endpoint}: {compressed[:80]}")
            if len(attack_path_log) > 20:
                attack_path_log = attack_path_log[-20:]

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
                # Quality gate: check for noise patterns first
                is_noise, noise_reason = self.quality_gate.is_noise(
                    hyp.technique, compressed,
                )
                if is_noise:
                    self.console.print(f"[dim]Noise filtered: {noise_reason}[/dim]")
                    self.attack_graph.record_result(hyp.id, success=False, finding="Noise filtered")
                    # Record MCTS experience
                    self.mcts.record_experience(
                        hyp.technique, hyp.endpoint, "nothing",
                        self.attack_graph.total_steps, tech_stack,
                    )
                else:
                    # Self-reflection: CoVe + Reflexion 3-layer verification
                    verification = self.self_reflect.verify_finding(
                        finding={
                            "title": compressed[:100],
                            "technique": hyp.technique,
                            "severity": "medium",
                            "endpoint": hyp.endpoint,
                        },
                        observation=observation,
                        context=compressed,
                    )

                    if not verification.passed or verification.grade in ("D", "F"):
                        self.console.print(
                            f"[yellow]Finding rejected by self-reflection "
                            f"(grade={verification.grade}, conf={verification.confidence:.0%}): "
                            f"{verification.rejection_reason or 'failed verification'}[/yellow]"
                        )
                        self.attack_graph.record_result(hyp.id, success=False, finding="Rejected by self-reflection")
                        self.mcts.record_experience(
                            hyp.technique, hyp.endpoint, "nothing",
                            self.attack_graph.total_steps, tech_stack,
                        )
                    else:
                        severity = "high" if verification.grade == "A" else "medium"
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

                        self.console.print(
                            f"[bold green]VERIFIED finding (grade={verification.grade}, "
                            f"conf={verification.confidence:.0%}): {verification.recommendation}[/bold green]"
                        )

                        # Update live display with finding
                        self.display.add_finding(
                            title=compressed[:100],
                            severity=severity,
                            confidence=int(verification.confidence * 100),
                            endpoint=hyp.endpoint,
                        )
                        print_finding_alert(
                            self.console,
                            title=compressed[:80],
                            severity=severity,
                            confidence=int(verification.confidence * 100),
                        )

                        # Build evidence package for the finding
                        try:
                            evidence_pkg = self.evidence_adv.build_evidence_package(
                                finding_id=hyp.id,
                                finding_title=compressed[:100],
                                tool_traces=[{
                                    "tool_name": response.action,
                                    "url": hyp.endpoint,
                                    "tool_input": str(response.action_input)[:200],
                                    "tool_output": observation[:500],
                                }],
                                observation=observation,
                            )
                            # Quantify impact
                            evidence_pkg.impact_metrics = self.evidence_adv.quantify_impact(
                                hyp.id, hyp.endpoint, hyp.technique,
                            )
                            if evidence_pkg.has_hard_evidence:
                                self.console.print(
                                    f"[green]Evidence: {evidence_pkg.evidence_summary}[/green]"
                                )
                        except Exception:
                            pass

                        # Record positive MCTS experience
                        outcome = "sqli_confirmed" if "sql" in hyp.technique.lower() else \
                                  "xss_confirmed" if "xss" in hyp.technique.lower() else \
                                  "ssrf_confirmed" if "ssrf" in hyp.technique.lower() else \
                                  "rce_confirmed" if "rce" in hyp.technique.lower() else \
                                  "idor_confirmed" if "idor" in hyp.technique.lower() else \
                                  "info_disclosure"
                        self.mcts.record_experience(
                            hyp.technique, hyp.endpoint, outcome,
                            self.attack_graph.total_steps, tech_stack,
                        )

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

            # Update live display: world model summary
            if self.world:
                self.display.update_world(
                    self.world.get_attack_context(max_chars=300)
                )

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
        # Stop the live display before printing final summaries
        self.display.stop()

        self.target_model.save()
        self.world.save()
        if self.scope:
            self.scope.save(self.target_model.target_dir)
        # Persist attack graph state for session resume
        if self.attack_graph:
            self.attack_graph.save_state(self.config.findings_dir)

        # Save MCTS cross-target memory
        try:
            self.mcts.merge_experiences()
            self.mcts._save_memory()
        except Exception:
            pass

        # Stop OOB callback session
        try:
            self.oob.stop_session()
        except Exception:
            pass

        # End campaign session
        try:
            self.campaign_mgr.end_session(
                campaign,
                steps=self.attack_graph.total_steps,
                findings_count=self.attack_graph.findings_count,
            )
        except Exception:
            pass

        # Auto-generate reports for verified findings
        try:
            findings_for_report = self.world.get_findings_for_chain_analysis() if self.world else []
            if findings_for_report:
                reports = self.report_gen.generate_batch(findings_for_report)
                report_dir = os.path.join(self.config.findings_dir, "reports")
                os.makedirs(report_dir, exist_ok=True)
                for i, report in enumerate(reports):
                    report_path = os.path.join(report_dir, f"report_{i+1}_{report.severity}.md")
                    with open(report_path, "w") as f:
                        f.write(report.markdown)
                if reports:
                    self.console.print(
                        f"[bold green]{len(reports)} reports auto-generated in {report_dir}[/bold green]"
                    )
        except Exception:
            pass

        # Display Round 2 module stats
        self.console.print(Panel(
            f"Perceptor: {self.perceptor.stats}\n"
            f"Self-Reflection: {self.self_reflect.stats}\n"
            f"MCTS Explorer: {self.mcts.stats}",
            title="[bold]Module Stats[/bold]",
            border_style="dim",
        ))

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

        # Hunt complete banner
        elapsed_seconds = time.monotonic() - (self._hunt_start_time or time.monotonic())
        token_stats = self.provider.token_stats()
        total_tokens = token_stats.get("total_input", 0) + token_stats.get("total_output", 0)
        print_hunt_complete(
            self.console,
            findings_count=self.attack_graph.findings_count,
            steps=self.attack_graph.total_steps,
            elapsed=format_duration(elapsed_seconds),
            tokens=total_tokens,
        )

        # Detailed findings summary
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

    def _run_source_intel(self, target: str) -> None:
        """Run source intelligence gathering - GitHub, Wayback, CNAME, API specs."""
        try:
            si = SourceIntel(target)
            report = si.full_recon()

            # Feed Wayback URLs into world model
            wayback_urls = report.get("wayback_urls", [])
            if wayback_urls:
                self.console.print(f"[cyan]Wayback: {len(wayback_urls)} archived URLs recovered[/cyan]")
                for url in wayback_urls[:50]:
                    if self.world:
                        self.world.mark_surface_tested(url, "wayback_discovery", 0)

            # Feed API specs
            specs = report.get("api_specs", [])
            if specs:
                self.console.print(f"[cyan]API specs: {len(specs)} discovered[/cyan]")

            # Feed GitHub repos
            repos = report.get("github_repos", [])
            if repos:
                self.console.print(f"[cyan]GitHub: {len(repos)} related repos found[/cyan]")

            # Feed JS endpoints (enhanced)
            js = report.get("js_endpoints", {})
            secrets = js.get("secrets", [])
            if secrets:
                self.console.print(f"[bold red]>>> {len(secrets)} secrets in source intelligence![/bold red]")
                if self.world:
                    for s in secrets:
                        self.world.add_credential(
                            type=s.get("type", "unknown"),
                            value=str(s.get("value", ""))[:50],
                            scope="source_intel",
                        )

            # Feed CNAME chains
            cname = report.get("cname_chains", {})
            if cname:
                for sub, chain in cname.items() if isinstance(cname, dict) else []:
                    if chain:
                        self.console.print(f"[cyan]CNAME: {sub} -> {' -> '.join(chain[:3])}[/cyan]")

            self.console.print(f"[dim]{report.get('summary', 'Source intel complete')}[/dim]")

        except Exception as e:
            self.console.print(f"[dim]Source intel skipped: {e}[/dim]")

    def _run_assumption_engine(self, target: str) -> None:
        """Generate novel hypotheses via assumption archaeology."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get all known endpoints from target model + world model
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = self.target_model.data["endpoints"]

            created = []
            for ep in endpoints[:30]:
                ep_url = ep.get("url", url)
                method = ep.get("method", "GET")
                # Extract parameter names from URL
                import re
                params = re.findall(r'[?&](\w+)=', ep_url)

                assumptions = self.assumption_engine.generate_assumptions(
                    ep_url, method, params, tech_stack
                )
                hyp_dicts = self.assumption_engine.assumptions_to_hypotheses(assumptions[:5])
                for h in hyp_dicts:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", ep_url),
                        technique=h.get("technique", "assumption_violation"),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 7),
                        exploitability=h.get("exploitability", 6),
                        impact=h.get("impact", 7),
                        effort=h.get("effort", 3),
                    )
                    if hyp:
                        created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} assumption-based hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Assumption engine skipped: {e}[/dim]")

    def _run_intent_model(self, target: str) -> None:
        """Generate business logic violation tests via intent modeling."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get endpoints
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = self.target_model.data["endpoints"]

            created = []
            for ep in endpoints[:20]:
                ep_url = ep.get("url", url)
                method = ep.get("method", "GET")
                import re
                params = re.findall(r'[?&](\w+)=', ep_url)

                violations = self.intent_model.generate_violation_tests(
                    ep_url, method, params, tech_stack
                )
                hyp_dicts = self.intent_model.violations_to_hypotheses(violations[:5])
                for h in hyp_dicts:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", ep_url),
                        technique=h.get("technique", "intent_violation"),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 7),
                        exploitability=h.get("exploitability", 7),
                        impact=h.get("impact", 8),
                        effort=h.get("effort", 3),
                    )
                    if hyp:
                        created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} intent-violation hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Intent model skipped: {e}[/dim]")

    def _run_coverage_analysis(self) -> None:
        """Boost hypothesis scores for under-tested surfaces."""
        if not self.attack_graph:
            return
        try:
            # Assess all endpoints in hypothesis queue
            assessments = []
            for hyp in self.attack_graph.hypothesis_queue:
                assessment = self.coverage_detector.assess_surface(hyp.endpoint)
                assessments.append(assessment)

            # Count coverage distribution
            low_count = sum(1 for a in assessments if a.estimated_coverage in ("low", "untested"))
            if low_count > 0:
                self.console.print(
                    f"[cyan]{low_count}/{len(assessments)} hypotheses target under-tested surfaces (boosted)[/cyan]"
                )

            # Apply boosts - modify hypothesis scores in-place
            for hyp, assessment in zip(self.attack_graph.hypothesis_queue, assessments):
                if assessment.priority_boost > 1.0:
                    hyp.total_score *= assessment.priority_boost
            self.attack_graph._sort_queue()

        except Exception as e:
            self.console.print(f"[dim]Coverage analysis skipped: {e}[/dim]")

    def _run_edge_analysis(self, target: str) -> None:
        """Generate hypotheses for inter-component boundary testing."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Identify component stack
            components = self.edge_analyzer.identify_components(url, {}, tech_stack)
            if len(components) < 2:
                self.console.print("[dim]Not enough components identified for edge analysis[/dim]")
                return

            self.console.print(f"[cyan]Components: {' -> '.join(components)}[/cyan]")

            # Build component graph in world model
            if self.world:
                for i, comp in enumerate(components):
                    connects = [components[i+1]] if i < len(components) - 1 else []
                    self.world.add_component(comp, "detected", connects)
                # Add trust boundaries between adjacent components
                for i in range(len(components) - 1):
                    self.world.add_trust_boundary(
                        components[i], components[i+1],
                        "component_boundary",
                    )

            # Generate edge tests
            edges = self.edge_analyzer.generate_edge_tests(components, url)
            created = []
            for edge in edges[:15]:
                hyp = self.hypothesis_engine.create(
                    endpoint=url,
                    technique=f"edge_{edge.data_type}",
                    description=f"Edge test: {edge.disagreement} between {edge.upstream} and {edge.downstream}",
                    novelty=8, exploitability=7,
                    impact=9 if edge.severity == "critical" else 7,
                    effort=4,
                )
                if hyp:
                    created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} edge-analysis hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Edge analysis skipped: {e}[/dim]")

    def _run_confusion_analysis(self, target: str) -> None:
        """Generate hypotheses for confusion attacks (Orange Tsai 2024 methodology)."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = self.target_model.data["endpoints"]

            hyp_dicts = self.confusion_engine.generate_confusion_hypotheses(
                url, tech_stack, endpoints
            )
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "confusion_attack"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 9),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 9),
                    effort=h.get("effort", 4),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} confusion-attack hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Confusion analysis skipped: {e}[/dim]")

    def _run_client_deep_analysis(self, target: str) -> None:
        """Generate hypotheses for deep client-side attacks (postMessage, CSWSH, DOM clobbering)."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get JS content from target model if available
            js_content = ""
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_data = self.target_model.data["js_analysis"]
                js_content = str(js_data.get("raw_content", ""))[:50000]

            hyp_dicts = self.client_deep.generate_client_hypotheses(url, js_content, tech_stack)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "client_side"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 8),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 4),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} client-side hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Client-side analysis skipped: {e}[/dim]")

    def _run_idor_analysis(self, target: str) -> None:
        """Generate systematic IDOR/BOLA test hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = self.target_model.data["endpoints"]

            auth_context = {}
            if self.auth_context:
                auth_context = {
                    "roles": self.auth_context.get_roles(),
                    "tokens": self.auth_context.get_token_summary(),
                }

            # Generate IDOR tests
            idor_tests = self.idor_engine.generate_idor_tests(endpoints, auth_context)
            bola_tests = self.idor_engine.generate_bola_tests(endpoints, tech_stack)
            all_tests = idor_tests + bola_tests

            hyp_dicts = self.idor_engine.idor_to_hypotheses(all_tests)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "idor"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 7),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 9),
                    effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} IDOR/BOLA hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]IDOR analysis skipped: {e}[/dim]")

    def _run_procedural_memory(self, target: str) -> None:
        """Apply learned skills from previous sessions to generate hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            tech_stack = self.world.tech_stack if self.world else {}
            url = target if target.startswith("http") else f"https://{target}"

            applicable_skills = self.procedural_memory.find_applicable_skills(tech_stack, url)
            if not applicable_skills:
                self.console.print("[dim]No applicable procedural skills for this tech stack[/dim]")
                return

            hyp_dicts = self.procedural_memory.get_skill_hypotheses(applicable_skills, target)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "procedural_skill"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 6),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 2),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(
                    f"[cyan]{len(created)} procedural skill hypotheses "
                    f"(from {len(applicable_skills)} learned skills)[/cyan]"
                )
        except Exception as e:
            self.console.print(f"[dim]Procedural memory skipped: {e}[/dim]")

    def _run_curriculum_analysis(self, target: str) -> None:
        """Apply curriculum learning to order hypotheses by difficulty progression."""
        if not self.attack_graph:
            return
        try:
            tech_stack = self.world.tech_stack if self.world else {}
            waf = tech_stack.get("waf", "unknown")
            auth_type = tech_stack.get("auth", "unknown")

            profile = self.curriculum.assess_target_difficulty(tech_stack, waf, auth_type)
            self.console.print(
                f"[cyan]Target difficulty: {profile.name} (level {profile.level}/10)[/cyan]"
            )

            # Get curriculum-ordered hypotheses
            hyp_dicts = self.curriculum.get_curriculum_hypotheses(
                profile.level, tech_stack
            )
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", target),
                    technique=h.get("technique", "curriculum"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 5),
                    exploitability=h.get("exploitability", 6),
                    impact=h.get("impact", 7),
                    effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(
                    f"[cyan]{len(created)} curriculum-guided hypotheses generated[/cyan]"
                )
        except Exception as e:
            self.console.print(f"[dim]Curriculum analysis skipped: {e}[/dim]")

    def _run_osint_deep(self, target: str) -> None:
        """Run deep OSINT: cloud assets, staging envs, source maps, JS secrets."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            company = domain.split(".")[-2] if "." in domain else domain

            # Cloud asset enumeration
            cloud_assets = self.osint_engine.run_cloud_enum(company, max_checks=15)
            if cloud_assets:
                self.console.print(
                    f"[cyan]Cloud: {len(cloud_assets)} assets found "
                    f"({sum(1 for a in cloud_assets if a.status == 'public_read')} public)[/cyan]"
                )

            # Staging environment discovery
            staging_envs = self.osint_engine.discover_staging(domain)
            if staging_envs:
                self.console.print(f"[cyan]Staging: {len(staging_envs)} dev/staging environments found[/cyan]")

            # Source map check on known JS URLs
            js_urls = []
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_data = self.target_model.data["js_analysis"]
                js_urls = js_data.get("js_urls", [])[:10]
            source_maps = self.osint_engine.run_source_map_check(js_urls)
            if source_maps:
                self.console.print(
                    f"[bold red]>>> {len(source_maps)} source maps found! "
                    f"({sum(len(sm.secrets_found) for sm in source_maps)} secrets)[/bold red]"
                )

            # JS secrets from any available JS content
            js_secrets: list[dict[str, str]] = []
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_content = str(self.target_model.data["js_analysis"].get("raw_content", ""))
                if js_content:
                    js_secrets = self.osint_engine.scan_js_secrets(js_content)
                    if js_secrets:
                        self.console.print(f"[bold red]>>> {len(js_secrets)} JS secrets found![/bold red]")

            # Generate hypotheses from OSINT findings
            hyp_dicts = self.osint_engine.generate_hypotheses(
                cloud_assets, source_maps, staging_envs, js_secrets, url,
            )
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "osint_finding"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 7),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 2),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} OSINT-based hypotheses generated[/cyan]")

        except Exception as e:
            self.console.print(f"[dim]OSINT deep scan skipped: {e}[/dim]")

    def _run_infra_scan(self, target: str) -> None:
        """Identify infrastructure-class targets and generate $100K-tier hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"

            # Gather all available recon data
            hosts = list(self.world.hosts.keys()) if self.world else [target]
            tech_stack = self.world.tech_stack if self.world else {}
            headers = {}
            if self.target_model and self.target_model.data.get("headers"):
                headers = self.target_model.data["headers"]
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = [
                    ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    for ep in self.target_model.data["endpoints"][:50]
                ]
            observations = []
            if self.target_model and self.target_model.data.get("recon_observations"):
                observations = self.target_model.data["recon_observations"][-20:]

            # Identify infrastructure targets
            infra_targets = self.infra_scanner.identify_infra_targets(
                hosts, tech_stack, headers, endpoints, observations,
            )
            if infra_targets:
                self.console.print(
                    f"[bold red]>>> {len(infra_targets)} infrastructure targets identified![/bold red]"
                )
                for it in infra_targets[:3]:
                    self.console.print(
                        f"  [red]P{it.priority} {it.category}: "
                        f"{it.payout_potential} tier[/red]"
                    )

            # Detect deserialization surfaces
            content_types = []
            if self.target_model and self.target_model.data.get("content_types"):
                content_types = self.target_model.data["content_types"]
            deser_surfaces = self.infra_scanner.detect_deserialization_surfaces(
                endpoints, content_types, headers,
            )
            if deser_surfaces:
                self.console.print(
                    f"[bold red]>>> {len(deser_surfaces)} deserialization surfaces detected![/bold red]"
                )

            # Generate hypotheses
            created = []
            infra_hyps = self.infra_scanner.generate_infra_hypotheses(infra_targets, url)
            deser_hyps = self.infra_scanner.generate_deser_hypotheses(deser_surfaces, url)

            for h in infra_hyps + deser_hyps:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "infra_scan"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 8),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 9),
                    effort=h.get("effort", 5),
                )
                if hyp:
                    # Apply payout tier boost
                    boost = h.get("priority_multiplier", 1.0)
                    if boost > 1.0:
                        hyp.total_score *= boost
                    created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} infrastructure hypotheses generated[/cyan]")

        except Exception as e:
            self.console.print(f"[dim]Infrastructure scan skipped: {e}[/dim]")

    def _run_state_machine_analysis(self, target: str) -> None:
        """Extract state machines from JS bundles and generate violation tests."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            # Get JS content from target model if available
            js_content = ""
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_data = self.target_model.data["js_analysis"]
                js_content = str(js_data.get("raw_content", ""))

            # Also try OpenAPI spec if available
            openapi_spec = None
            if self.target_model and self.target_model.data.get("api_specs"):
                specs = self.target_model.data["api_specs"]
                if specs:
                    openapi_spec = specs[0] if isinstance(specs[0], dict) else None

            machines = self.state_machine_extractor.extract_all(
                js_content=js_content,
                openapi_spec=openapi_spec,
            )

            total_violations = 0
            created = []
            for machine in machines[:5]:
                violations = self.state_machine_extractor.generate_violations(machine)
                hyp_dicts = self.state_machine_extractor.violations_to_hypotheses(violations[:5])
                for h in hyp_dicts:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", url),
                        technique=f"state_machine_{h.get('technique', 'violation')}",
                        description=h.get("description", ""),
                        novelty=8, exploitability=7, impact=8, effort=3,
                    )
                    if hyp:
                        created.append(hyp)
                total_violations += len(violations)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(
                    f"[cyan]{len(machines)} state machines found, "
                    f"{total_violations} violations, "
                    f"{len(created)} hypotheses generated[/cyan]"
                )
            else:
                self.console.print("[dim]No state machines extracted from JS bundles[/dim]")
        except Exception as e:
            self.console.print(f"[dim]State machine analysis skipped: {e}[/dim]")

    def _run_domain_knowledge_hypotheses(self, target: str) -> None:
        """Generate domain-specific vulnerability hypotheses (OWASP BLA)."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get endpoints for domain detection
            endpoints_raw = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints_raw = self.target_model.data["endpoints"]
            endpoint_strs = [
                ep.get("url", "") if isinstance(ep, dict) else str(ep)
                for ep in endpoints_raw[:50]
            ]

            domain = self.domain_knowledge.detect_domain(url, endpoint_strs, tech_stack)
            patterns = self.domain_knowledge.get_patterns(domain)

            if not patterns:
                self.console.print(f"[dim]No domain patterns for detected domain: {domain}[/dim]")
                return

            hyp_dicts = self.domain_knowledge.patterns_to_hypotheses(patterns[:12], url)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", f"domain_{domain}"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 8),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 4),
                )
                if hyp:
                    created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(
                    f"[cyan]Domain: {domain} - {len(created)} "
                    f"domain-specific hypotheses generated[/cyan]"
                )

            # Inject domain context into world model
            if self.world:
                domain_ctx = self.domain_knowledge.format_domain_context(domain, max_chars=500)
                if domain_ctx:
                    self.world.set_tech("detected_domain", domain)

        except Exception as e:
            self.console.print(f"[dim]Domain knowledge skipped: {e}[/dim]")

    def _run_arch_analysis_hypotheses(self, target: str) -> None:
        """Detect architectural anti-patterns and generate hypotheses (Orange Tsai)."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get response headers from target model
            headers = {}
            if self.target_model and self.target_model.data.get("headers"):
                headers = self.target_model.data["headers"]

            patterns = self.arch_analyzer.detect_patterns(url, tech_stack, headers)
            if not patterns:
                self.console.print("[dim]No architectural anti-patterns detected[/dim]")
                return

            created = []
            for pattern in patterns[:10]:
                hyp = self.hypothesis_engine.create(
                    endpoint=url,
                    technique=f"arch_{pattern.name}",
                    description=f"[Orange Tsai] {pattern.description}",
                    novelty=9, exploitability=7,
                    impact=9 if pattern.severity == "critical" else 8,
                    effort=5,
                )
                if hyp:
                    created.append(hyp)

            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(
                    f"[cyan]{len(created)} architectural anti-pattern hypotheses generated "
                    f"({', '.join(p.name for p in patterns[:3])})[/cyan]"
                )
        except Exception as e:
            self.console.print(f"[dim]Arch analysis skipped: {e}[/dim]")

    def _run_dom_analysis(self, target: str) -> None:
        """Generate DOM vulnerability hypotheses (XSS, PP, postMessage, CSTI)."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            hyp_dicts = self.dom_analyzer.generate_hypotheses(url, tech_stack)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "dom_vuln"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 7),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 7),
                    effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} DOM vulnerability hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]DOM analysis skipped: {e}[/dim]")

    def _run_websocket_discovery(self, target: str) -> None:
        """Discover WebSocket endpoints and generate security hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            # Get JS content for WS endpoint extraction
            js_content = ""
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_content = str(self.target_model.data["js_analysis"].get("raw_content", ""))

            # Get known endpoints
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = [
                    ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    for ep in self.target_model.data["endpoints"][:50]
                ]

            ws_endpoints = self.ws_tester.discover_ws_endpoints(url, js_content, endpoints)
            if not ws_endpoints:
                self.console.print("[dim]No WebSocket endpoints discovered[/dim]")
                return

            self.console.print(f"[cyan]Discovered {len(ws_endpoints)} WebSocket endpoints[/cyan]")
            for ep in ws_endpoints[:3]:
                self.console.print(f"  [dim]{ep.url} ({ep.protocol})[/dim]")

            hyp_dicts = self.ws_tester.generate_hypotheses(url, ws_endpoints, tech_stack)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "ws_vuln"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 7),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} WebSocket hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]WebSocket discovery skipped: {e}[/dim]")

    def _run_program_intel(self, target: str) -> None:
        """Fetch and operationalize bug bounty program policy."""
        try:
            scope = self.program_intel.get_scope_for_target(target)
            if scope.in_scope_assets:
                self.console.print(
                    f"[cyan]Program {scope.program_handle}: "
                    f"{len(scope.in_scope_assets)} in-scope assets[/cyan]"
                )

            # Fresh targets (zero-competition window)
            fresh = self.program_intel.get_fresh_targets(scope)
            if fresh:
                self.console.print(
                    f"[bold red]>>> {len(fresh)} FRESH scope additions detected! "
                    f"Zero-competition window.[/bold red]"
                )

            # Generate program-aware hypotheses
            if self.hypothesis_engine and self.attack_graph:
                hyp_dicts = self.program_intel.generate_hypotheses(
                    scope,
                    target if target.startswith("http") else f"https://{target}",
                )
                created = []
                for h in hyp_dicts:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", target),
                        technique=h.get("technique", "program_intel"),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 8),
                        exploitability=h.get("exploitability", 7),
                        impact=h.get("impact", 8),
                        effort=h.get("effort", 2),
                    )
                    if hyp:
                        created.append(hyp)
                if created:
                    self.attack_graph.add_hypotheses(created)
                    self.console.print(f"[cyan]{len(created)} program-aware hypotheses generated[/cyan]")

            # Inject scope context for LLM
            scope_ctx = self.program_intel.format_scope_context(scope)
            if scope_ctx and self.world:
                self.world.set_tech("program_scope", scope_ctx)

        except Exception as e:
            self.console.print(f"[dim]Program intel skipped: {e}[/dim]")

    def _run_monitor_check(self, target: str) -> None:
        """Run surface change detection against previous snapshot."""
        try:
            changes = self.monitor.run_monitor_cycle(target)
            if changes:
                self.console.print(f"[bold red]>>> {len(changes)} attack surface changes detected![/bold red]")
                for c in changes[:3]:
                    self.console.print(f"  [{c.priority}] {c.detail}")
                # Generate hypotheses from changes
                if self.hypothesis_engine and self.attack_graph:
                    hyps = self.monitor.generate_hypotheses_from_changes(changes)
                    created = []
                    for h in hyps:
                        hyp = self.hypothesis_engine.create(
                            endpoint=h.get("endpoint", target),
                            technique=h.get("technique", "monitor_change"),
                            description=h.get("description", ""),
                            novelty=h.get("novelty", 9), exploitability=h.get("exploitability", 7),
                            impact=h.get("impact", 8), effort=h.get("effort", 2),
                        )
                        if hyp:
                            created.append(hyp)
                    if created:
                        self.attack_graph.add_hypotheses(created)
                        self.console.print(f"[cyan]{len(created)} change-based hypotheses generated[/cyan]")
            else:
                self.console.print("[dim]No surface changes since last session[/dim]")
        except Exception as e:
            self.console.print(f"[dim]Monitor check skipped: {e}[/dim]")

    def _run_h2_desync(self, target: str) -> None:
        """Run HTTP/2 desync detection and generate hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            h2_support = self.h2_desync.detect_h2_support(url)
            if h2_support.get("h2_supported") or h2_support.get("h2c_supported"):
                self.console.print(f"[cyan]HTTP/2: supported={h2_support['h2_supported']}, h2c={h2_support['h2c_supported']}[/cyan]")
                endpoints = []
                if self.target_model and self.target_model.data.get("endpoints"):
                    endpoints = [ep.get("url", "") if isinstance(ep, dict) else str(ep) for ep in self.target_model.data["endpoints"][:30]]
                hyps = self.h2_desync.generate_hypotheses(url, h2_support, endpoints)
                created = []
                for h in hyps:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", url), technique=h.get("technique", "h2_desync"),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 9), exploitability=h.get("exploitability", 7),
                        impact=h.get("impact", 10), effort=h.get("effort", 5),
                    )
                    if hyp:
                        created.append(hyp)
                if created:
                    self.attack_graph.add_hypotheses(created)
                    self.console.print(f"[cyan]{len(created)} HTTP/2 desync hypotheses generated[/cyan]")
            else:
                self.console.print("[dim]Target does not support HTTP/2[/dim]")
        except Exception as e:
            self.console.print(f"[dim]H2 desync skipped: {e}[/dim]")

    def _run_mcp_analysis(self, target: str) -> None:
        """Discover and test MCP/AI endpoints."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}
            js_content = ""
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_content = str(self.target_model.data["js_analysis"].get("raw_content", ""))
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = [ep.get("url", "") if isinstance(ep, dict) else str(ep) for ep in self.target_model.data["endpoints"][:30]]
            ai_endpoints = self.mcp_tester.discover_ai_endpoints(url, js_content, endpoints)
            if ai_endpoints:
                self.console.print(f"[bold red]>>> {len(ai_endpoints)} AI/MCP endpoints discovered![/bold red]")
                for ep in ai_endpoints[:3]:
                    self.console.print(f"  [red]{ep.endpoint_type}: {ep.url}[/red]")
            hyps = self.mcp_tester.generate_hypotheses(url, ai_endpoints, tech_stack)
            created = []
            for h in hyps:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url), technique=h.get("technique", "ai_attack"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 9), exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 9), effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} AI/MCP hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]MCP analysis skipped: {e}[/dim]")

    def _run_source_analysis(self, target: str) -> None:
        """Analyze available source code for vulnerabilities."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}
            framework = str(tech_stack.get("framework", "")).lower()
            lang = "python" if any(f in framework for f in ["django", "flask", "fastapi"]) else \
                   "ruby" if "rails" in framework else "javascript"
            # Analyze source map content if available
            js_content = ""
            if self.target_model and self.target_model.data.get("js_analysis"):
                js_content = str(self.target_model.data["js_analysis"].get("raw_content", ""))
            if js_content and len(js_content) > 100:
                findings = self.source_analyzer.analyze_source(js_content, "js_bundle", lang)
                routes = self.source_analyzer.extract_routes(js_content, "express" if lang == "javascript" else "flask")
                unprotected = self.source_analyzer.find_unprotected_routes(routes)
                if findings:
                    self.console.print(f"[bold red]>>> {len(findings)} source code vulnerabilities found![/bold red]")
                if unprotected:
                    self.console.print(f"[bold red]>>> {len(unprotected)} unprotected routes found![/bold red]")
                hyps = self.source_analyzer.generate_hypotheses(findings, routes, url)
                created = []
                for h in hyps:
                    hyp = self.hypothesis_engine.create(
                        endpoint=h.get("endpoint", url), technique=h.get("technique", "source_vuln"),
                        description=h.get("description", ""),
                        novelty=h.get("novelty", 8), exploitability=h.get("exploitability", 8),
                        impact=h.get("impact", 9), effort=h.get("effort", 3),
                    )
                    if hyp:
                        created.append(hyp)
                if created:
                    self.attack_graph.add_hypotheses(created)
                    self.console.print(f"[cyan]{len(created)} source-analysis hypotheses generated[/cyan]")
            else:
                self.console.print("[dim]No source code available for analysis[/dim]")
        except Exception as e:
            self.console.print(f"[dim]Source analysis skipped: {e}[/dim]")

    def _run_differential_hypotheses(self, target: str) -> None:
        """Generate differential testing hypotheses for IDOR/BOLA detection."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = [
                    ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    for ep in self.target_model.data["endpoints"][:30]
                ]

            hyp_dicts = self.differential.generate_hypotheses(endpoints, url)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "differential"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 7),
                    exploitability=h.get("exploitability", 9),
                    impact=h.get("impact", 9),
                    effort=h.get("effort", 2),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} differential testing hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Differential testing skipped: {e}[/dim]")

    def _run_fuzzer_hypotheses(self, target: str) -> None:
        """Generate smart fuzzing hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            endpoints = []
            if self.target_model and self.target_model.data.get("endpoints"):
                endpoints = [
                    ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    for ep in self.target_model.data["endpoints"][:20]
                ]

            hyp_dicts = self.fuzzer.generate_hypotheses(url, endpoints)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "fuzz"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 6),
                    exploitability=h.get("exploitability", 7),
                    impact=h.get("impact", 7),
                    effort=h.get("effort", 3),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} fuzzing hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Fuzzer skipped: {e}[/dim]")

    def _run_supply_chain_analysis(self, target: str) -> None:
        """Generate supply chain vulnerability hypotheses."""
        if not self.hypothesis_engine or not self.attack_graph:
            return
        try:
            url = target if target.startswith("http") else f"https://{target}"
            tech_stack = self.world.tech_stack if self.world else {}

            hyp_dicts = self.supply_chain.generate_hypotheses(url, tech_stack)
            created = []
            for h in hyp_dicts:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "supply_chain"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 6),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 8),
                    effort=h.get("effort", 2),
                )
                if hyp:
                    created.append(hyp)
            if created:
                self.attack_graph.add_hypotheses(created)
                self.console.print(f"[cyan]{len(created)} supply chain hypotheses generated[/cyan]")
        except Exception as e:
            self.console.print(f"[dim]Supply chain analysis skipped: {e}[/dim]")

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
        """Run chain analysis on current findings and inject chain hypotheses.

        Uses both the original chain_analyzer (template-based) and the new
        chain_engine (capability-based graph reasoning with bidirectional search).
        """
        if not self.world or not self.attack_graph or not self.hypothesis_engine:
            return

        findings = self.world.get_findings_for_chain_analysis()
        if not findings:
            return

        created = []
        url = self.world._data.get("target", "") if self.world else ""

        # --- Original template-based chain analysis ---
        if len(findings) >= 2:
            chains = self.chain_analyzer.analyze(findings)
            if chains:
                self.console.print(f"[bold magenta]>>> Chain analysis: {len(chains)} potential chains![/bold magenta]")
                for chain in chains:
                    self.console.print(
                        f"  [magenta]{chain['chain_name']} ({chain['chain_severity']}) "
                        f"- confidence {chain['confidence']:.0%}[/magenta]"
                    )

                chain_hyps_data = self.chain_analyzer.get_chain_hypotheses(chains)
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

        # --- New capability-based chain engine (R3.3) ---
        try:
            chain_hyps = self.chain_engine.generate_chain_hypotheses(findings, url)
            for h in chain_hyps:
                hyp = self.hypothesis_engine.create(
                    endpoint=h.get("endpoint", url),
                    technique=h.get("technique", "chain_unknown"),
                    description=h.get("description", ""),
                    novelty=h.get("novelty", 9),
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 10),
                    effort=h.get("effort", 4),
                )
                if hyp:
                    created.append(hyp)
            if chain_hyps:
                self.console.print(
                    f"[magenta]Chain engine: {len(chain_hyps)} capability-based chain hypotheses[/magenta]"
                )
        except Exception as e:
            self.console.print(f"[dim]Chain engine skipped: {e}[/dim]")

        if created:
            self.attack_graph.add_hypotheses(created)
            self.console.print(f"[magenta]Injected {len(created)} total chain hypotheses[/magenta]")

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
        """Legacy compression - prefer perceptor.perceive() in the main loop."""
        if len(output) < 200:
            return output
        try:
            facts = self.perceptor.perceive(tool_name, output)
            return facts.raw_summary
        except Exception:
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
