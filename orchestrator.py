"""Orchestrator - Multi-agent specialist coordination for Project Triage v4.

Implements the R2.3 research findings:
- Specialist routing: hypotheses dispatched to domain-tuned agents
- Chain Analyst as OBSERVER: triggers on every world model finding write
- Parallel tool dispatch for independent hypothesis testing
- Communication via structured World Model (not free text)

Research basis:
- D-CIPHER, VulnBot, AWS, PentAGI, CheckMate consensus topology
- Parallel specialists beat sequential phases on coverage
- Chain assembly is most commonly MISSED in both human and AI teams
- Dedup is SHA-based on (endpoint, technique) - deterministic
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from chain_analyzer import ChainAnalyzer
    from hypothesis import Hypothesis, HypothesisEngine
    from attack_graph import AttackGraph
    from provider import Provider
    from world_model import WorldModel

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Specialist profiles - domain-tuned system prompt augmentations
# ---------------------------------------------------------------------------

@dataclass
class SpecialistProfile:
    """A specialist agent with domain-tuned prompting."""
    name: str
    techniques: list[str]  # technique prefixes this specialist handles
    system_augment: str  # appended to the base system prompt
    priority_boost: float = 1.0  # score multiplier when this specialist claims a hypothesis


SPECIALISTS: list[SpecialistProfile] = [
    SpecialistProfile(
        name="auth_specialist",
        techniques=[
            "jwt", "idor", "bola", "auth", "session", "oauth", "saml",
            "privilege", "role", "access_control", "token", "cookie",
        ],
        system_augment=(
            "You are an AUTHENTICATION AND AUTHORIZATION specialist. "
            "Your expertise: JWT attacks (alg:none, key confusion, claim tampering), "
            "IDOR/BOLA (numeric ID enumeration, UUID prediction, GraphQL node access), "
            "OAuth flows (redirect_uri manipulation, PKCE bypass, token theft), "
            "session management (fixation, prediction, insufficient expiry), "
            "privilege escalation (horizontal and vertical, role parameter tampering). "
            "Always test with multiple user roles. Always check both the API response "
            "AND the actual data returned - a 200 OK with empty data is not IDOR."
        ),
        priority_boost=1.2,
    ),
    SpecialistProfile(
        name="logic_specialist",
        techniques=[
            "logic", "business", "workflow", "race", "state_machine",
            "intent", "assumption", "domain_", "payment", "checkout",
            "registration", "transfer", "limit", "quota",
        ],
        system_augment=(
            "You are a BUSINESS LOGIC specialist. "
            "Your expertise: race conditions (TOCTOU, double-spend), "
            "workflow bypass (skip-step, out-of-order, concurrent), "
            "payment manipulation (negative amounts, currency confusion, rounding), "
            "state machine violations (forbidden transitions, replay attacks), "
            "multi-step flow abuse (parameter tampering between steps). "
            "Think about WHAT SHOULD HAPPEN vs WHAT ACTUALLY HAPPENS. "
            "The developer assumed users follow the happy path - violate that assumption."
        ),
        priority_boost=1.2,
    ),
    SpecialistProfile(
        name="vuln_specialist",
        techniques=[
            "sqli", "xss", "ssrf", "ssti", "xxe", "rce", "command",
            "injection", "desync", "smuggling", "cache", "poison",
            "prototype", "pollution", "prompt_inject",
        ],
        system_augment=(
            "You are a VULNERABILITY EXPLOITATION specialist. "
            "Your expertise: injection attacks (SQLi, XSS, SSTI, XXE, command injection), "
            "SSRF (cloud metadata, internal service access, protocol smuggling), "
            "HTTP desync/smuggling (CL.TE, TE.CL, H2.CL), "
            "cache poisoning (unkeyed headers, parameter cloaking), "
            "prototype pollution (server-side and client-side gadget chains). "
            "Always prove impact - a reflected input is not XSS without script execution. "
            "Always try WAF bypass variants if the first payload is blocked."
        ),
        priority_boost=1.1,
    ),
    SpecialistProfile(
        name="recon_specialist",
        techniques=[
            "recon", "subdomain", "port", "http_probe", "header",
            "js_analysis", "graphql_introspection", "nuclei", "takeover",
            "s3_bucket", "cloud", "edge_", "arch_",
        ],
        system_augment=(
            "You are a RECONNAISSANCE AND DISCOVERY specialist. "
            "Your expertise: subdomain enumeration, port scanning, "
            "JavaScript bundle analysis (secrets, API endpoints, source maps), "
            "GraphQL introspection and schema mining, "
            "cloud resource discovery (S3 buckets, Azure blobs, GCP storage), "
            "subdomain takeover (dangling CNAME, NS delegation), "
            "architectural analysis (component boundary detection). "
            "Focus on EXPANDING the attack surface. Every new endpoint, "
            "subdomain, or API version you find creates new testing opportunities."
        ),
        priority_boost=1.0,
    ),
]


def get_specialist_for_hypothesis(hyp: Hypothesis) -> SpecialistProfile | None:
    """Route a hypothesis to the right specialist based on technique name.

    Returns None if no specialist matches (falls through to generic agent).
    """
    technique_lower = hyp.technique.lower()
    for spec in SPECIALISTS:
        for prefix in spec.techniques:
            if prefix in technique_lower:
                return spec
    return None


# ---------------------------------------------------------------------------
# Chain Analyst Observer
# ---------------------------------------------------------------------------


class ChainAnalystObserver:
    """Observer that triggers chain analysis whenever a finding is added.

    Research finding: "Chain Analyst should be OBSERVER not scheduled."
    This means chain analysis runs automatically on every finding,
    not just when explicitly called.

    Also runs connector bug search and reverse chain search on each finding.
    """

    def __init__(
        self,
        chain_analyzer: ChainAnalyzer,
        hypothesis_engine: HypothesisEngine | None = None,
        attack_graph: AttackGraph | None = None,
    ) -> None:
        self._analyzer = chain_analyzer
        self._hypothesis_engine = hypothesis_engine
        self._attack_graph = attack_graph
        self._lock = threading.Lock()
        self._stats = {"triggers": 0, "chains_found": 0, "hypotheses_injected": 0}

    def on_finding_added(self, world: WorldModel) -> list[dict[str, Any]]:
        """Called whenever a finding is added to the world model.

        Runs chain analysis, connector bug search, and injects
        new hypotheses into the attack graph.

        Returns list of discovered chains (may be empty).
        """
        with self._lock:
            self._stats["triggers"] += 1

        findings = world.get_findings_for_chain_analysis()
        if len(findings) < 2:
            return []

        # Run chain analysis
        chains = self._analyzer.analyze(findings)

        # Run connector bug search
        connectors = self._analyzer.find_connector_bugs(findings)

        all_chains = chains + connectors
        if not all_chains:
            return []

        with self._lock:
            self._stats["chains_found"] += len(all_chains)

        # Inject chain hypotheses into attack graph
        if self._hypothesis_engine and self._attack_graph:
            chain_hyps = self._analyzer.get_chain_hypotheses(chains)
            created = []
            for h in chain_hyps:
                hyp = self._hypothesis_engine.create(
                    endpoint=h.get("endpoint", ""),
                    technique=h.get("technique", "chain_completion"),
                    description=h.get("description", ""),
                    novelty=8,
                    exploitability=h.get("exploitability", 8),
                    impact=h.get("impact", 9),
                    effort=h.get("effort", 4),
                )
                if hyp:
                    created.append(hyp)

            # Also create hypotheses from connector bugs
            for conn in connectors:
                for needed in conn.get("needed_bugs", []):
                    hyp = self._hypothesis_engine.create(
                        endpoint=needed.get("endpoint", ""),
                        technique=needed.get("technique", "connector_bug"),
                        description=f"Connector: {needed.get('description', '')}",
                        novelty=9,
                        exploitability=7,
                        impact=9,
                        effort=4,
                    )
                    if hyp:
                        created.append(hyp)

            if created:
                self._attack_graph.add_hypotheses(created)
                with self._lock:
                    self._stats["hypotheses_injected"] += len(created)

        return all_chains

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ---------------------------------------------------------------------------
# Parallel Tool Dispatch
# ---------------------------------------------------------------------------


def parallel_tool_dispatch(
    tasks: list[dict[str, Any]],
    execute_fn: Callable[[str, dict[str, Any]], str],
    max_workers: int = 3,
) -> list[dict[str, Any]]:
    """Execute multiple independent tool calls in parallel.

    Args:
        tasks: List of dicts with keys: tool_name, tool_input, hypothesis_id
        execute_fn: Function(tool_name, tool_input) -> output string
        max_workers: Max parallel executions

    Returns:
        List of result dicts: {hypothesis_id, tool_name, output, success, duration_ms}
    """
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        import time as _time
        futures = {}
        for task in tasks:
            start = _time.monotonic()
            future = executor.submit(
                execute_fn,
                task["tool_name"],
                task["tool_input"],
            )
            futures[future] = (task, start)

        for future in as_completed(futures):
            task, start = futures[future]
            duration_ms = (_time.monotonic() - start) * 1000
            try:
                output = future.result(timeout=60)
                results.append({
                    "hypothesis_id": task.get("hypothesis_id", ""),
                    "tool_name": task["tool_name"],
                    "output": output,
                    "success": True,
                    "duration_ms": duration_ms,
                })
            except Exception as e:
                results.append({
                    "hypothesis_id": task.get("hypothesis_id", ""),
                    "tool_name": task["tool_name"],
                    "output": f"Error: {e}",
                    "success": False,
                    "duration_ms": duration_ms,
                })

    return results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """Coordinates specialist agents, chain analyst observer, and parallel dispatch.

    This is the "team lead" from the research topology:
    - Routes hypotheses to domain-tuned specialists
    - Maintains the chain analyst observer
    - Can dispatch independent tool calls in parallel
    - Tracks specialist performance for adaptive routing
    """

    def __init__(
        self,
        chain_analyzer: ChainAnalyzer,
        hypothesis_engine: HypothesisEngine | None = None,
        attack_graph: AttackGraph | None = None,
    ) -> None:
        self.chain_observer = ChainAnalystObserver(
            chain_analyzer, hypothesis_engine, attack_graph,
        )
        self._specialist_stats: dict[str, dict[str, int]] = {
            spec.name: {"dispatched": 0, "findings": 0}
            for spec in SPECIALISTS
        }
        self._specialist_stats["generic"] = {"dispatched": 0, "findings": 0}

    def route_hypothesis(self, hyp: Hypothesis) -> tuple[SpecialistProfile | None, str]:
        """Route a hypothesis to the appropriate specialist.

        Returns (specialist_profile, augmented_system_prompt_suffix).
        Returns (None, "") if no specialist matches.
        """
        spec = get_specialist_for_hypothesis(hyp)
        if spec:
            self._specialist_stats[spec.name]["dispatched"] += 1
            return spec, spec.system_augment
        self._specialist_stats["generic"]["dispatched"] += 1
        return None, ""

    def notify_finding(self, world: WorldModel) -> list[dict[str, Any]]:
        """Notify the chain analyst observer that a finding was added.

        This is the key R2.3 change: chain analysis triggers as an OBSERVER
        on every finding, not on a schedule.

        Returns discovered chains.
        """
        return self.chain_observer.on_finding_added(world)

    def record_specialist_finding(self, hyp: Hypothesis) -> None:
        """Record that a specialist produced a finding (for adaptive routing)."""
        spec = get_specialist_for_hypothesis(hyp)
        name = spec.name if spec else "generic"
        self._specialist_stats[name]["findings"] += 1

    @property
    def stats(self) -> dict[str, Any]:
        """Return orchestrator statistics."""
        return {
            "specialists": dict(self._specialist_stats),
            "chain_observer": self.chain_observer.stats,
        }
