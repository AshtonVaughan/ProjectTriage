"""Chain Engine - Capability-based exploit chain construction for Project Triage v4.

Implements the "gadget model" from elite bug bounty methodology:
individual low-severity bugs are gadgets - harmless alone, devastating when chained.

Core data structures:
- Capability enum: what an attacker can do (SSRF, XSS, open redirect, etc.)
- ChainStep: a vulnerability that consumes preconditions and produces postconditions
- ExploitGraph: AND/OR graph for chain reasoning
- Bidirectional search: forward from findings, backward from goals

Research basis: R3.3 chain construction research, Bugcrowd gadget model,
MulVAL exploit dependency graphs, Orange Tsai chain methodology.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Capability taxonomy
# ---------------------------------------------------------------------------

class Capability(Enum):
    """What an attacker can do - capabilities gained/consumed in chains."""
    # Access primitives
    INITIAL_ACCESS = "initial_access"
    AUTHENTICATED_ACCESS = "authenticated_access"
    ADMIN_ACCESS = "admin_access"

    # URL/redirect control
    OPEN_REDIRECT = "open_redirect"
    CSPT = "client_side_path_traversal"

    # Server-side request
    SSRF_BLIND = "ssrf_blind"
    SSRF_READ = "ssrf_read"
    SSRF_FULL = "ssrf_full"

    # Cloud
    CLOUD_METADATA_READ = "cloud_metadata_read"
    CLOUD_IAM_CREDS = "cloud_iam_creds"

    # Script execution
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_SELF = "xss_self"

    # CSRF
    CSRF_STATE_CHANGE = "csrf_state_change"
    CSRF_LOGIN = "csrf_login"

    # Auth tokens
    OAUTH_REDIRECT_CONTROL = "oauth_redirect_control"
    SESSION_HIJACK = "session_hijack"
    JWT_FORGE = "jwt_forge"

    # Data access
    IDOR_READ = "idor_read"
    IDOR_WRITE = "idor_write"
    ENUMERATE_IDS = "enumerate_ids"
    READ_OTHER_USER_DATA = "read_other_user_data"

    # Code execution
    PATH_TRAVERSAL_READ = "path_traversal_read"
    PATH_TRAVERSAL_WRITE = "path_traversal_write"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"

    # Race condition
    CONCURRENT_STATE_MODIFY = "concurrent_state_modify"

    # Request manipulation
    HTTP_SMUGGLING = "http_smuggling"
    CACHE_POISONING = "cache_poisoning"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"

    # Impact goals (terminal capabilities)
    ACCOUNT_TAKEOVER = "account_takeover"
    RCE = "rce"
    MASS_DATA_BREACH = "mass_data_breach"
    FINANCIAL_IMPACT = "financial_impact"


# ---------------------------------------------------------------------------
# Chain step definitions
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    """A vulnerability type that transforms capabilities."""
    name: str
    consumes: list[Capability]  # What attacker needs before this step
    produces: list[Capability]  # What attacker gains after this step
    connector_weight: float  # 0.0=terminal, 1.0=universal connector
    severity_alone: str  # Severity in isolation
    severity_chained: str  # Severity when used in a chain
    description: str = ""


# The vulnerability transition table - the core of chain reasoning
VULN_TRANSITIONS: list[ChainStep] = [
    # --- URL/Redirect chains ---
    ChainStep(
        name="open_redirect",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.OPEN_REDIRECT],
        connector_weight=0.8,
        severity_alone="low",
        severity_chained="critical",
        description="Redirect user to attacker-controlled URL",
    ),
    ChainStep(
        name="open_redirect_to_oauth_theft",
        consumes=[Capability.OPEN_REDIRECT],
        produces=[Capability.OAUTH_REDIRECT_CONTROL, Capability.SESSION_HIJACK],
        connector_weight=0.0,
        severity_alone="low",
        severity_chained="critical",
        description="Use open redirect as OAuth redirect_uri to steal tokens",
    ),
    ChainStep(
        name="cspt",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.CSPT, Capability.CSRF_STATE_CHANGE],
        connector_weight=0.9,
        severity_alone="low",
        severity_chained="critical",
        description="Client-side path traversal manipulates API request paths",
    ),

    # --- SSRF chains ---
    ChainStep(
        name="ssrf_basic",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.SSRF_BLIND],
        connector_weight=0.7,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="ssrf_to_read",
        consumes=[Capability.SSRF_BLIND],
        produces=[Capability.SSRF_READ],
        connector_weight=0.6,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="ssrf_to_cloud_metadata",
        consumes=[Capability.SSRF_READ],
        produces=[Capability.CLOUD_METADATA_READ],
        connector_weight=0.3,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="cloud_metadata_to_iam",
        consumes=[Capability.CLOUD_METADATA_READ],
        produces=[Capability.CLOUD_IAM_CREDS],
        connector_weight=0.1,
        severity_alone="critical",
        severity_chained="critical",
    ),
    ChainStep(
        name="cloud_iam_to_rce",
        consumes=[Capability.CLOUD_IAM_CREDS],
        produces=[Capability.RCE],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),

    # --- XSS chains ---
    ChainStep(
        name="reflected_xss",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.XSS_REFLECTED],
        connector_weight=0.6,
        severity_alone="medium",
        severity_chained="high",
    ),
    ChainStep(
        name="stored_xss",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.XSS_STORED],
        connector_weight=0.5,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="self_xss",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.XSS_SELF],
        connector_weight=0.9,
        severity_alone="informational",
        severity_chained="critical",
        description="Self-XSS alone is N/A but chains with login CSRF",
    ),
    ChainStep(
        name="xss_to_session_hijack",
        consumes=[Capability.XSS_REFLECTED],
        produces=[Capability.SESSION_HIJACK],
        connector_weight=0.2,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="xss_to_account_takeover",
        consumes=[Capability.XSS_STORED],
        produces=[Capability.ACCOUNT_TAKEOVER],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),

    # --- CSRF chains ---
    ChainStep(
        name="login_csrf",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.CSRF_LOGIN],
        connector_weight=0.9,
        severity_alone="informational",
        severity_chained="critical",
        description="Force victim to log in as attacker - chains with self-XSS",
    ),
    ChainStep(
        name="self_xss_plus_login_csrf",
        consumes=[Capability.XSS_SELF, Capability.CSRF_LOGIN],
        produces=[Capability.XSS_STORED, Capability.ACCOUNT_TAKEOVER],
        connector_weight=0.0,
        severity_alone="informational",
        severity_chained="critical",
        description="Classic chain: self-XSS + login CSRF = stored XSS / ATO",
    ),

    # --- IDOR chains ---
    ChainStep(
        name="idor_read",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.IDOR_READ],
        connector_weight=0.5,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="id_enumeration",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.ENUMERATE_IDS],
        connector_weight=0.8,
        severity_alone="low",
        severity_chained="high",
    ),
    ChainStep(
        name="idor_plus_enum_to_mass_breach",
        consumes=[Capability.IDOR_READ, Capability.ENUMERATE_IDS],
        produces=[Capability.MASS_DATA_BREACH],
        connector_weight=0.0,
        severity_alone="medium",
        severity_chained="critical",
        description="IDOR + ID enumeration = mass data breach",
    ),

    # --- Auth chains ---
    ChainStep(
        name="jwt_algorithm_confusion",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.JWT_FORGE],
        connector_weight=0.3,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="jwt_to_admin",
        consumes=[Capability.JWT_FORGE],
        produces=[Capability.ADMIN_ACCESS, Capability.ACCOUNT_TAKEOVER],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),
    ChainStep(
        name="session_hijack_to_ato",
        consumes=[Capability.SESSION_HIJACK],
        produces=[Capability.ACCOUNT_TAKEOVER],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),

    # --- Path traversal chains ---
    ChainStep(
        name="path_traversal_read",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.PATH_TRAVERSAL_READ],
        connector_weight=0.6,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="path_traversal_write",
        consumes=[Capability.AUTHENTICATED_ACCESS],
        produces=[Capability.PATH_TRAVERSAL_WRITE],
        connector_weight=0.4,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="path_write_to_rce",
        consumes=[Capability.PATH_TRAVERSAL_WRITE],
        produces=[Capability.RCE],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
        description="Write to executable path = RCE (Meta $111,750 chain)",
    ),

    # --- Deserialization ---
    ChainStep(
        name="deserialization_to_rce",
        consumes=[Capability.DESERIALIZATION],
        produces=[Capability.RCE],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),

    # --- Race conditions ---
    ChainStep(
        name="race_condition",
        consumes=[Capability.AUTHENTICATED_ACCESS, Capability.CONCURRENT_STATE_MODIFY],
        produces=[Capability.FINANCIAL_IMPACT],
        connector_weight=0.0,
        severity_alone="high",
        severity_chained="critical",
    ),

    # --- HTTP smuggling as amplifier ---
    ChainStep(
        name="http_smuggling",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.HTTP_SMUGGLING],
        connector_weight=0.8,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="smuggling_to_cache_poison",
        consumes=[Capability.HTTP_SMUGGLING],
        produces=[Capability.CACHE_POISONING],
        connector_weight=0.5,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="cache_poison_xss",
        consumes=[Capability.CACHE_POISONING, Capability.XSS_REFLECTED],
        produces=[Capability.XSS_STORED, Capability.ACCOUNT_TAKEOVER],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
        description="Smuggling turns reflected XSS into wormable stored XSS",
    ),

    # --- Subdomain takeover chains ---
    ChainStep(
        name="subdomain_takeover",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.SUBDOMAIN_TAKEOVER],
        connector_weight=0.7,
        severity_alone="medium",
        severity_chained="critical",
    ),
    ChainStep(
        name="subdomain_to_cookie_injection",
        consumes=[Capability.SUBDOMAIN_TAKEOVER],
        produces=[Capability.SESSION_HIJACK],
        connector_weight=0.3,
        severity_alone="high",
        severity_chained="critical",
        description="Takeover trusted subdomain to set cookies for parent domain",
    ),

    # --- SQL injection chains ---
    ChainStep(
        name="sqli",
        consumes=[Capability.INITIAL_ACCESS],
        produces=[Capability.SQL_INJECTION],
        connector_weight=0.4,
        severity_alone="high",
        severity_chained="critical",
    ),
    ChainStep(
        name="sqli_to_mass_breach",
        consumes=[Capability.SQL_INJECTION],
        produces=[Capability.MASS_DATA_BREACH],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
    ),
    ChainStep(
        name="sqli_to_rce",
        consumes=[Capability.SQL_INJECTION],
        produces=[Capability.RCE],
        connector_weight=0.0,
        severity_alone="critical",
        severity_chained="critical",
        description="SQLi to RCE via INTO OUTFILE, xp_cmdshell, or UDF",
    ),
]


# ---------------------------------------------------------------------------
# Chain discovery result
# ---------------------------------------------------------------------------

@dataclass
class ExploitChain:
    """A discovered exploit chain."""
    steps: list[ChainStep]
    start_capability: Capability
    end_capability: Capability
    severity: str  # Overall chain severity
    confidence: float  # 0-1
    missing_links: list[Capability]  # Capabilities we still need
    description: str = ""

    @property
    def is_complete(self) -> bool:
        return len(self.missing_links) == 0

    @property
    def length(self) -> int:
        return len(self.steps)


# ---------------------------------------------------------------------------
# Chain Engine
# ---------------------------------------------------------------------------

class ChainEngine:
    """Capability-based exploit chain construction engine.

    Uses bidirectional search over the vulnerability transition table
    to discover chains from current findings to impact goals.
    """

    def __init__(self) -> None:
        self._transitions = VULN_TRANSITIONS
        # Build lookup indices
        self._by_consumes: dict[Capability, list[ChainStep]] = {}
        self._by_produces: dict[Capability, list[ChainStep]] = {}
        for step in self._transitions:
            for cap in step.consumes:
                self._by_consumes.setdefault(cap, []).append(step)
            for cap in step.produces:
                self._by_produces.setdefault(cap, []).append(step)

    def forward_search(
        self,
        current_capabilities: set[Capability],
        max_depth: int = 5,
    ) -> list[ExploitChain]:
        """Forward search: "I have these capabilities, what chains can I build?"

        BFS from current capabilities, following transitions whose
        preconditions are satisfied.
        """
        chains: list[ExploitChain] = []
        # BFS state: (current_caps, chain_so_far)
        queue: deque[tuple[set[Capability], list[ChainStep]]] = deque()
        queue.append((current_capabilities.copy(), []))
        visited: set[frozenset[Capability]] = set()

        while queue:
            caps, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            caps_key = frozenset(caps)
            if caps_key in visited:
                continue
            visited.add(caps_key)

            # Find applicable transitions
            for step in self._transitions:
                if step in path:
                    continue  # Don't reuse same step
                if all(c in caps for c in step.consumes):
                    new_caps = caps | set(step.produces)
                    new_path = path + [step]

                    # Check if we reached a terminal goal
                    terminal_goals = {
                        Capability.ACCOUNT_TAKEOVER,
                        Capability.RCE,
                        Capability.MASS_DATA_BREACH,
                        Capability.FINANCIAL_IMPACT,
                    }
                    reached_goals = terminal_goals & set(step.produces)
                    if reached_goals:
                        for goal in reached_goals:
                            chains.append(ExploitChain(
                                steps=new_path,
                                start_capability=list(current_capabilities)[0] if current_capabilities else Capability.INITIAL_ACCESS,
                                end_capability=goal,
                                severity="critical",
                                confidence=0.7,
                                missing_links=[],
                                description=f"Chain: {' -> '.join(s.name for s in new_path)} -> {goal.value}",
                            ))

                    queue.append((new_caps, new_path))

        return chains

    def backward_search(
        self,
        goal: Capability,
        current_capabilities: set[Capability],
        max_depth: int = 5,
    ) -> list[ExploitChain]:
        """Backward search: "I want to achieve Y, what do I need?"

        Works backward from the goal, finding what prerequisites
        are needed and what's missing from current capabilities.
        """
        chains: list[ExploitChain] = []
        # DFS backward: find steps that produce the goal
        self._backward_dfs(
            goal, current_capabilities, [], set(), max_depth, chains,
        )
        return chains

    def _backward_dfs(
        self,
        target: Capability,
        current_caps: set[Capability],
        path: list[ChainStep],
        visited: set[str],
        max_depth: int,
        results: list[ExploitChain],
    ) -> None:
        """DFS helper for backward search."""
        if len(path) >= max_depth:
            return

        # Find steps that produce the target capability
        producers = self._by_produces.get(target, [])
        for step in producers:
            if step.name in visited:
                continue

            new_visited = visited | {step.name}
            new_path = [step] + path  # Prepend (building backward)

            # Check what preconditions we're missing
            missing = [c for c in step.consumes if c not in current_caps]

            if not missing:
                # All preconditions met - complete chain
                results.append(ExploitChain(
                    steps=new_path,
                    start_capability=step.consumes[0] if step.consumes else Capability.INITIAL_ACCESS,
                    end_capability=target,
                    severity="critical",
                    confidence=0.8,
                    missing_links=[],
                    description=f"Chain: {' -> '.join(s.name for s in new_path)}",
                ))
            else:
                # Recurse to find producers of missing capabilities
                for missing_cap in missing:
                    self._backward_dfs(
                        missing_cap, current_caps, new_path,
                        new_visited, max_depth, results,
                    )

                # Also record partial chain with missing links
                if len(new_path) >= 2:
                    results.append(ExploitChain(
                        steps=new_path,
                        start_capability=step.consumes[0] if step.consumes else Capability.INITIAL_ACCESS,
                        end_capability=target,
                        severity="high",
                        confidence=0.4,
                        missing_links=missing,
                        description=(
                            f"Partial chain: {' -> '.join(s.name for s in new_path)} "
                            f"(missing: {', '.join(c.value for c in missing)})"
                        ),
                    ))

    def find_connector_bugs(
        self,
        current_capabilities: set[Capability],
        goal: Capability,
    ) -> list[dict[str, Any]]:
        """Identify specific connector bugs needed to complete chains.

        A connector bug bridges two capabilities that are otherwise
        disconnected. This is targeted hunting - we know exactly what
        we're looking for.
        """
        connectors: list[dict[str, Any]] = []

        # Find partial chains and extract missing links
        partial_chains = self.backward_search(goal, current_capabilities, max_depth=4)

        for chain in partial_chains:
            if chain.missing_links:
                for missing in chain.missing_links:
                    # Find what vulnerability types produce this capability
                    producers = self._by_produces.get(missing, [])
                    for producer in producers:
                        connectors.append({
                            "needed_capability": missing.value,
                            "connector_vuln": producer.name,
                            "connector_weight": producer.connector_weight,
                            "chain_context": chain.description,
                            "goal": goal.value,
                            "severity_if_found": chain.severity,
                        })

        # Deduplicate by connector vulnerability name
        seen = set()
        unique: list[dict[str, Any]] = []
        for c in connectors:
            key = c["connector_vuln"]
            if key not in seen:
                seen.add(key)
                unique.append(c)

        # Sort by connector weight descending (most useful connectors first)
        unique.sort(key=lambda x: x["connector_weight"], reverse=True)
        return unique

    def findings_to_capabilities(
        self,
        findings: list[dict[str, Any]],
    ) -> set[Capability]:
        """Convert a list of findings to a set of attacker capabilities.

        Maps finding techniques/types to the Capability enum.
        """
        caps = {Capability.INITIAL_ACCESS}  # Always start with this

        technique_map: dict[str, list[Capability]] = {
            "open_redirect": [Capability.OPEN_REDIRECT],
            "ssrf": [Capability.SSRF_BLIND, Capability.SSRF_READ],
            "xss": [Capability.XSS_REFLECTED],
            "stored_xss": [Capability.XSS_STORED],
            "self_xss": [Capability.XSS_SELF],
            "csrf": [Capability.CSRF_STATE_CHANGE],
            "login_csrf": [Capability.CSRF_LOGIN],
            "idor": [Capability.IDOR_READ],
            "sqli": [Capability.SQL_INJECTION],
            "path_traversal": [Capability.PATH_TRAVERSAL_READ],
            "file_upload": [Capability.PATH_TRAVERSAL_WRITE],
            "jwt": [Capability.JWT_FORGE],
            "deserialization": [Capability.DESERIALIZATION],
            "race_condition": [Capability.CONCURRENT_STATE_MODIFY],
            "smuggling": [Capability.HTTP_SMUGGLING],
            "subdomain_takeover": [Capability.SUBDOMAIN_TAKEOVER],
            "cache_poison": [Capability.CACHE_POISONING],
            "cloud_metadata": [Capability.CLOUD_METADATA_READ],
            "auth_bypass": [Capability.ADMIN_ACCESS],
            "cspt": [Capability.CSPT],
        }

        for finding in findings:
            technique = finding.get("technique", "").lower()
            for key, capabilities in technique_map.items():
                if key in technique:
                    caps.update(capabilities)

        return caps

    def generate_chain_hypotheses(
        self,
        findings: list[dict[str, Any]],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Generate hypotheses for chain completion from current findings.

        This is the main entry point: given current findings, what should
        we test next to build chains?
        """
        caps = self.findings_to_capabilities(findings)
        hypotheses: list[dict[str, Any]] = []

        # Terminal goals to search for
        goals = [
            Capability.ACCOUNT_TAKEOVER,
            Capability.RCE,
            Capability.MASS_DATA_BREACH,
            Capability.FINANCIAL_IMPACT,
        ]

        for goal in goals:
            # Forward search from current capabilities
            forward_chains = self.forward_search(caps, max_depth=4)
            for chain in forward_chains[:3]:
                if chain.is_complete:
                    hypotheses.append({
                        "endpoint": base_url,
                        "technique": f"chain_{chain.end_capability.value}",
                        "description": f"[CHAIN] {chain.description}",
                        "novelty": 9,
                        "exploitability": 8,
                        "impact": 10,
                        "effort": 4,
                    })

            # Find connector bugs needed
            connectors = self.find_connector_bugs(caps, goal)
            for conn in connectors[:3]:
                hypotheses.append({
                    "endpoint": base_url,
                    "technique": f"connector_{conn['connector_vuln']}",
                    "description": (
                        f"[CONNECTOR] Hunt for {conn['connector_vuln']} "
                        f"to complete chain to {conn['goal']}: {conn['chain_context']}"
                    ),
                    "novelty": 8,
                    "exploitability": 7,
                    "impact": 9,
                    "effort": 4,
                })

        # Deduplicate by technique
        seen = set()
        unique = []
        for h in hypotheses:
            if h["technique"] not in seen:
                seen.add(h["technique"])
                unique.append(h)

        return unique
