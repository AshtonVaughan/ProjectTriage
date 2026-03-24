"""State Machine Extractor for Project Triage v4.

Extracts the intended state machine from web applications by analyzing:
- XState configs in JS bundles
- Redux store shapes
- OpenAPI parameter dependencies
- Observed HTTP traffic patterns

Research basis: XState ships the complete state machine to the client in
bundled JS. Extract it, read the forbidden transitions, test them against
the backend.

References: OWASP BLA2:2025 (Concurrent Workflow Order Bypass),
BLA4 (Sequential State Bypass).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class StateTransition:
    from_state: str
    to_state: str
    action: str          # HTTP endpoint/method that triggers this transition
    guard: str = ""      # condition that must be true, empty if none
    is_forbidden: bool = False  # True if the machine says this should NOT happen


@dataclass
class StateMachine:
    name: str            # e.g. "checkout", "registration", "password_reset"
    states: list[str] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    initial_state: str = ""
    final_states: list[str] = field(default_factory=list)


@dataclass
class StateViolation:
    machine_name: str
    violation_type: str  # skip_step, forbidden_transition, out_of_order, concurrent_bypass
    description: str
    test_steps: list[dict] = field(default_factory=list)  # HTTP requests to execute
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_balanced_braces(text: str, start: int) -> str:
    """Return the substring from *start* to the matching closing brace.

    *start* must point at the opening '{'.
    """
    if start >= len(text) or text[start] != "{":
        return ""
    depth = 0
    i = start
    in_string = False
    escape_next = False
    quote_char = ""
    while i < len(text):
        ch = text[i]
        if escape_next:
            escape_next = False
            i += 1
            continue
        if ch == "\\":
            escape_next = True
            i += 1
            continue
        if in_string:
            if ch == quote_char:
                in_string = False
            i += 1
            continue
        if ch in ("'", '"', '`'):
            in_string = True
            quote_char = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return text[start:]


def _js_obj_to_json(raw: str) -> str:
    """Best-effort conversion of a JS object literal to valid JSON.

    Handles unquoted keys and trailing commas - the two most common
    differences between JS object syntax and JSON.
    """
    # Quote unquoted keys: word chars before a colon
    result = re.sub(
        r'(?<=[{,\n])\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:',
        r' "\1":',
        raw,
    )
    # Replace single quotes with double quotes (outside existing double quotes)
    result = result.replace("'", '"')
    # Remove trailing commas before } or ]
    result = re.sub(r',\s*([}\]])', r'\1', result)
    # Remove JS comments
    result = re.sub(r'//[^\n]*', '', result)
    result = re.sub(r'/\*.*?\*/', '', result, flags=re.DOTALL)
    # Strip function references - replace with null
    result = re.sub(r':\s*function\s*\([^)]*\)\s*\{[^}]*\}', ': null', result)
    result = re.sub(r':\s*\([^)]*\)\s*=>\s*\{[^}]*\}', ': null', result)
    result = re.sub(r':\s*[A-Za-z_$][A-Za-z0-9_$.]*(?=\s*[,}\]])', ': null', result)
    return result


def _safe_parse_js_object(raw: str) -> dict:
    """Try to parse a JS object literal into a Python dict."""
    converted = _js_obj_to_json(raw)
    try:
        return json.loads(converted)
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class StateMachineExtractor:
    """Extracts state machines from multiple sources and generates violations."""

    def __init__(self) -> None:
        self._machines: list[StateMachine] = []

    # -----------------------------------------------------------------------
    # 1. XState extraction
    # -----------------------------------------------------------------------

    def extract_from_xstate(self, js_content: str) -> list[StateMachine]:
        """Parse XState createMachine/Machine configs from JavaScript source.

        Looks for createMachine({...}) or Machine({...}) calls, extracts
        states, transitions, guards, and initial/final state info.
        """
        machines: list[StateMachine] = []

        # Find createMachine({...}) or Machine({...}) call sites
        pattern = re.compile(r'(?:createMachine|Machine)\s*\(')
        for m in pattern.finditer(js_content):
            # Locate the opening brace of the config object
            after_paren = m.end()
            brace_idx = js_content.find("{", after_paren - 1)
            if brace_idx == -1:
                continue
            raw_config = _extract_balanced_braces(js_content, brace_idx)
            if not raw_config:
                continue

            config = _safe_parse_js_object(raw_config)
            if not config:
                continue

            machine = self._parse_xstate_config(config)
            if machine.states:
                machines.append(machine)

        return machines

    def _parse_xstate_config(self, config: dict) -> StateMachine:
        """Turn an XState config dict into a StateMachine."""
        name = config.get("id", config.get("key", "unnamed"))
        initial = config.get("initial", "")
        states_cfg: dict = config.get("states", {})

        states: list[str] = list(states_cfg.keys())
        transitions: list[StateTransition] = []
        final_states: list[str] = []

        for state_name, state_def in states_cfg.items():
            if not isinstance(state_def, dict):
                continue

            # Detect final states
            if state_def.get("type") == "final":
                final_states.append(state_name)

            on_cfg = state_def.get("on", {})
            if not isinstance(on_cfg, dict):
                continue

            for event, target_cfg in on_cfg.items():
                targets = self._normalize_xstate_targets(target_cfg)
                for target_info in targets:
                    to_state = target_info.get("target", "")
                    guard = target_info.get("cond", target_info.get("guard", ""))
                    if isinstance(guard, dict):
                        guard = guard.get("type", str(guard))

                    # Strip leading # or . from XState target references
                    to_state = re.sub(r'^[#.]', '', str(to_state))

                    transitions.append(StateTransition(
                        from_state=state_name,
                        to_state=to_state,
                        action=event,
                        guard=str(guard) if guard else "",
                        is_forbidden=False,
                    ))

                    # If there is a guard, the unguarded version is forbidden
                    if guard:
                        transitions.append(StateTransition(
                            from_state=state_name,
                            to_state=to_state,
                            action=event,
                            guard="",
                            is_forbidden=True,
                        ))

        return StateMachine(
            name=str(name),
            states=states,
            transitions=transitions,
            initial_state=str(initial),
            final_states=final_states,
        )

    @staticmethod
    def _normalize_xstate_targets(cfg: Any) -> list[dict]:
        """Normalize XState event targets to a list of {target, cond} dicts."""
        if isinstance(cfg, str):
            return [{"target": cfg}]
        if isinstance(cfg, dict):
            return [cfg]
        if isinstance(cfg, list):
            results = []
            for item in cfg:
                if isinstance(item, str):
                    results.append({"target": item})
                elif isinstance(item, dict):
                    results.append(item)
            return results
        return []

    # -----------------------------------------------------------------------
    # 2. Redux extraction
    # -----------------------------------------------------------------------

    def extract_from_redux(self, js_content: str) -> list[StateMachine]:
        """Parse Redux reducer switch/case patterns.

        Looks for patterns like:
            case 'ACTION_TYPE': return {...state, step: 'next_step'}
        And createSlice patterns with reducers object.
        """
        machines: list[StateMachine] = []

        # Strategy A: classic switch/case reducers
        machines.extend(self._extract_redux_switch(js_content))

        # Strategy B: createSlice reducers
        machines.extend(self._extract_redux_slice(js_content))

        return machines

    def _extract_redux_switch(self, js_content: str) -> list[StateMachine]:
        """Extract from switch(action.type) { case ... } patterns."""
        machines: list[StateMachine] = []

        # Find reducer functions containing switch statements
        # Pattern: function someReducer ... switch(action.type)
        switch_pattern = re.compile(
            r'function\s+(\w*[Rr]educer\w*)\s*\([^)]*\)\s*\{',
        )

        for fn_match in switch_pattern.finditer(js_content):
            reducer_name = fn_match.group(1)
            fn_body_start = js_content.find("{", fn_match.start())
            fn_body = _extract_balanced_braces(js_content, fn_body_start)
            if not fn_body:
                continue

            machine = self._parse_switch_cases(reducer_name, fn_body)
            if machine.states:
                machines.append(machine)

        # Also look for anonymous reducers: (state, action) => { switch ...
        arrow_pattern = re.compile(
            r'(\w+)\s*(?::|=)\s*\([^)]*state[^)]*\)\s*=>\s*\{',
        )
        for arrow_match in arrow_pattern.finditer(js_content):
            name = arrow_match.group(1)
            body_start = js_content.find("{", arrow_match.start())
            body = _extract_balanced_braces(js_content, body_start)
            if not body or "switch" not in body:
                continue

            machine = self._parse_switch_cases(name, body)
            if machine.states:
                machines.append(machine)

        return machines

    def _parse_switch_cases(self, name: str, body: str) -> StateMachine:
        """Parse switch/case blocks to extract state transitions."""
        states: set[str] = set()
        transitions: list[StateTransition] = []

        # Match: case 'ACTION_TYPE' or case "ACTION_TYPE" or case ACTION_TYPE:
        case_pattern = re.compile(
            r"case\s+['\"]?([A-Z_][A-Z0-9_]*)['\"]?\s*:",
        )

        # Match state field assignments: step: 'value', status: 'value', etc.
        state_field_pattern = re.compile(
            r"""(?:step|status|stage|phase|state)\s*:\s*['"]([^'"]+)['"]""",
        )

        cases = list(case_pattern.finditer(body))
        for case_match in cases:
            action_type = case_match.group(1)
            # Get the body until the next case or default or end
            case_start = case_match.end()
            next_case = None
            for later in cases:
                if later.start() > case_start:
                    next_case = later.start()
                    break
            case_body = body[case_start:next_case] if next_case else body[case_start:]

            # Find state field value in the return
            field_match = state_field_pattern.search(case_body)
            if field_match:
                to_state = field_match.group(1)
                states.add(to_state)
                transitions.append(StateTransition(
                    from_state="*",
                    to_state=to_state,
                    action=action_type,
                ))

        state_list = sorted(states)
        # Infer ordering from transitions
        if transitions:
            initial = transitions[0].to_state if transitions else ""
            final = [transitions[-1].to_state] if transitions else []
        else:
            initial = ""
            final = []

        return StateMachine(
            name=name,
            states=state_list,
            transitions=transitions,
            initial_state=initial,
            final_states=final,
        )

    def _extract_redux_slice(self, js_content: str) -> list[StateMachine]:
        """Extract from createSlice({ name, reducers: {...} }) patterns."""
        machines: list[StateMachine] = []

        slice_pattern = re.compile(r'createSlice\s*\(')
        for m in slice_pattern.finditer(js_content):
            brace_idx = js_content.find("{", m.end() - 1)
            if brace_idx == -1:
                continue
            raw = _extract_balanced_braces(js_content, brace_idx)
            if not raw:
                continue

            config = _safe_parse_js_object(raw)
            if not config:
                continue

            slice_name = config.get("name", "unnamed_slice")
            initial_state_cfg = config.get("initialState", {})
            reducers = config.get("reducers", {})

            states: set[str] = set()
            transitions: list[StateTransition] = []

            # Extract state field from initialState
            step_field = ""
            if isinstance(initial_state_cfg, dict):
                for key in ("step", "status", "stage", "phase", "state"):
                    if key in initial_state_cfg:
                        step_field = key
                        val = initial_state_cfg[key]
                        if isinstance(val, str):
                            states.add(val)
                        break

            # Each reducer key is an action
            for action_name in reducers:
                states.add(action_name)
                transitions.append(StateTransition(
                    from_state="*",
                    to_state=action_name,
                    action=f"{slice_name}/{action_name}",
                ))

            state_list = sorted(states)
            machines.append(StateMachine(
                name=str(slice_name),
                states=state_list,
                transitions=transitions,
                initial_state=str(initial_state_cfg.get(step_field, ""))
                    if isinstance(initial_state_cfg, dict) and step_field else "",
                final_states=[],
            ))

        return machines

    # -----------------------------------------------------------------------
    # 3. OpenAPI extraction
    # -----------------------------------------------------------------------

    def extract_from_openapi(self, spec: dict) -> list[StateMachine]:
        """Build dependency graph from OpenAPI spec.

        Checks if operation parameters reference response fields from other
        operations, building directed edges: operation A must precede B.
        Groups into workflows.
        """
        if not spec or not isinstance(spec, dict):
            return []

        paths: dict = spec.get("paths", {})
        operations: list[dict] = []

        # Collect all operations
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op_def in methods.items():
                if method.startswith("x-") or not isinstance(op_def, dict):
                    continue
                operations.append({
                    "path": path,
                    "method": method.upper(),
                    "id": op_def.get("operationId", f"{method}_{path}"),
                    "parameters": op_def.get("parameters", []),
                    "request_body": op_def.get("requestBody", {}),
                    "responses": op_def.get("responses", {}),
                    "tags": op_def.get("tags", []),
                    "summary": op_def.get("summary", ""),
                })

        # Build response field index: field_name -> operation that produces it
        response_fields: dict[str, str] = {}
        for op in operations:
            for _code, resp in op["responses"].items():
                if not isinstance(resp, dict):
                    continue
                content = resp.get("content", {})
                for _ctype, media in content.items():
                    if not isinstance(media, dict):
                        continue
                    schema = media.get("schema", {})
                    props = schema.get("properties", {})
                    for field_name in props:
                        response_fields[field_name] = op["id"]

        # Build edges: if operation B needs a parameter whose name matches
        # a response field from operation A, then A -> B
        edges: list[tuple[str, str]] = []
        for op in operations:
            params = op.get("parameters", [])
            if not isinstance(params, list):
                continue
            for param in params:
                if not isinstance(param, dict):
                    continue
                param_name = param.get("name", "")
                if param_name in response_fields:
                    source_op = response_fields[param_name]
                    if source_op != op["id"]:
                        edges.append((source_op, op["id"]))

            # Also check requestBody fields
            rb = op.get("request_body", {})
            if isinstance(rb, dict):
                rb_content = rb.get("content", {})
                for _ctype, media in rb_content.items():
                    if not isinstance(media, dict):
                        continue
                    rb_schema = media.get("schema", {})
                    rb_props = rb_schema.get("properties", {})
                    for field_name in rb_props:
                        if field_name in response_fields:
                            source_op = response_fields[field_name]
                            if source_op != op["id"]:
                                edges.append((source_op, op["id"]))

        if not edges:
            return []

        # Group edges by tag into separate state machines
        op_by_id = {op["id"]: op for op in operations}
        tag_groups: dict[str, list[tuple[str, str]]] = {}
        for src, dst in edges:
            src_tags = op_by_id.get(src, {}).get("tags", ["default"])
            dst_tags = op_by_id.get(dst, {}).get("tags", ["default"])
            combined_tags = set(src_tags) | set(dst_tags)
            tag = next(iter(combined_tags)) if combined_tags else "default"
            tag_groups.setdefault(tag, []).append((src, dst))

        machines: list[StateMachine] = []
        for tag, group_edges in tag_groups.items():
            all_states: set[str] = set()
            transitions: list[StateTransition] = []
            targets: set[str] = set()
            sources: set[str] = set()

            for src, dst in group_edges:
                all_states.add(src)
                all_states.add(dst)
                sources.add(src)
                targets.add(dst)

                dst_op = op_by_id.get(dst, {})
                transitions.append(StateTransition(
                    from_state=src,
                    to_state=dst,
                    action=f"{dst_op.get('method', 'GET')} {dst_op.get('path', '')}",
                ))

            # Initial states have no incoming edges
            initial_candidates = sources - targets
            initial = next(iter(sorted(initial_candidates))) if initial_candidates else ""

            # Final states have no outgoing edges
            final_candidates = targets - sources
            final = sorted(final_candidates)

            machines.append(StateMachine(
                name=f"openapi_{tag}",
                states=sorted(all_states),
                transitions=transitions,
                initial_state=initial,
                final_states=final,
            ))

        return machines

    # -----------------------------------------------------------------------
    # 4. Traffic-based extraction
    # -----------------------------------------------------------------------

    def extract_from_traffic(self, requests: list[dict]) -> list[StateMachine]:
        """Infer state machine from observed HTTP request sequences.

        Each request dict: {url, method, status, timestamp}
        Clusters requests by URL path pattern, builds a transition graph
        from temporal ordering, identifies loops, branches, terminal states.
        """
        if not requests:
            return []

        # Sort by timestamp
        sorted_reqs = sorted(requests, key=lambda r: r.get("timestamp", 0))

        # Normalize URLs to path patterns (strip query params, collapse IDs)
        def normalize_path(url: str) -> str:
            # Remove scheme + host
            path = re.sub(r'^https?://[^/]+', '', url)
            # Remove query string
            path = path.split("?")[0]
            # Collapse numeric/uuid path segments to placeholders
            path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{id}', path)
            path = re.sub(r'/\d+', '/{id}', path)
            return path

        # Build sequence of normalized states
        state_sequence: list[str] = []
        for req in sorted_reqs:
            method = req.get("method", "GET").upper()
            path = normalize_path(req.get("url", ""))
            status = req.get("status", 200)
            if 200 <= status < 400:
                state_label = f"{method} {path}"
                state_sequence.append(state_label)

        if len(state_sequence) < 2:
            return []

        # Build transition counts
        transition_counts: dict[tuple[str, str], int] = {}
        for i in range(len(state_sequence) - 1):
            pair = (state_sequence[i], state_sequence[i + 1])
            transition_counts[pair] = transition_counts.get(pair, 0) + 1

        # Filter to transitions seen more than once (noise reduction)
        # If total transitions are small, keep all
        min_count = 2 if len(transition_counts) > 10 else 1
        transitions: list[StateTransition] = []
        all_states: set[str] = set()

        for (src, dst), count in transition_counts.items():
            if count >= min_count:
                all_states.add(src)
                all_states.add(dst)
                transitions.append(StateTransition(
                    from_state=src,
                    to_state=dst,
                    action=dst,  # The destination endpoint IS the action
                ))

        if not transitions:
            # Fall back to all transitions
            for (src, dst), _count in transition_counts.items():
                all_states.add(src)
                all_states.add(dst)
                transitions.append(StateTransition(
                    from_state=src,
                    to_state=dst,
                    action=dst,
                ))

        # Identify initial and final states
        sources = {t.from_state for t in transitions}
        targets = {t.to_state for t in transitions}
        initial_candidates = sources - targets
        final_candidates = targets - sources

        initial = state_sequence[0] if state_sequence else ""
        if initial_candidates:
            initial = next(iter(sorted(initial_candidates)))

        return [StateMachine(
            name="traffic_inferred",
            states=sorted(all_states),
            transitions=transitions,
            initial_state=initial,
            final_states=sorted(final_candidates),
        )]

    # -----------------------------------------------------------------------
    # 5. Violation generation
    # -----------------------------------------------------------------------

    def generate_violations(self, machine: StateMachine) -> list[StateViolation]:
        """Generate test cases that violate the intended state machine flow.

        Covers: skip-step, reverse order, forbidden transitions, final state
        without prerequisites, and concurrent bypass (race condition).
        """
        violations: list[StateViolation] = []

        # Build ordered state list from transitions if possible
        ordered_states = self._topological_order(machine)
        if not ordered_states:
            ordered_states = machine.states

        # Map states to their entry actions
        state_actions: dict[str, str] = {}
        for t in machine.transitions:
            if not t.is_forbidden:
                state_actions[t.to_state] = t.action

        # 1. Skip each intermediate step
        for i in range(len(ordered_states)):
            for j in range(i + 2, len(ordered_states)):
                skipped = ordered_states[i + 1:j]
                violations.append(StateViolation(
                    machine_name=machine.name,
                    violation_type="skip_step",
                    description=(
                        f"Skip from '{ordered_states[i]}' directly to "
                        f"'{ordered_states[j]}', bypassing: {skipped}"
                    ),
                    test_steps=[
                        {"action": state_actions.get(ordered_states[i], ""),
                         "note": f"Enter state '{ordered_states[i]}'"},
                        {"action": state_actions.get(ordered_states[j], ""),
                         "note": f"Skip to state '{ordered_states[j]}' directly"},
                    ],
                    severity="high",
                ))

        # 2. Execute transitions in reverse order
        if len(ordered_states) >= 2:
            reverse_steps = []
            for state in reversed(ordered_states):
                action = state_actions.get(state, "")
                if action:
                    reverse_steps.append({
                        "action": action,
                        "note": f"Execute '{state}' out of order (reversed)",
                    })
            if reverse_steps:
                violations.append(StateViolation(
                    machine_name=machine.name,
                    violation_type="out_of_order",
                    description=(
                        f"Execute all states of '{machine.name}' in reverse "
                        f"order: {list(reversed(ordered_states))}"
                    ),
                    test_steps=reverse_steps,
                    severity="high",
                ))

        # 3. Execute forbidden transitions directly
        for t in machine.transitions:
            if t.is_forbidden:
                violations.append(StateViolation(
                    machine_name=machine.name,
                    violation_type="forbidden_transition",
                    description=(
                        f"Execute forbidden transition from '{t.from_state}' "
                        f"to '{t.to_state}' via '{t.action}' without guard "
                        f"'{t.guard}'"
                    ),
                    test_steps=[
                        {"action": t.action,
                         "from_state": t.from_state,
                         "to_state": t.to_state,
                         "note": "Execute without satisfying guard condition"},
                    ],
                    severity="high",
                ))

        # 4. Execute final state action without completing prerequisites
        for final in machine.final_states:
            action = state_actions.get(final, "")
            if action:
                violations.append(StateViolation(
                    machine_name=machine.name,
                    violation_type="skip_step",
                    description=(
                        f"Jump directly to final state '{final}' from "
                        f"initial state '{machine.initial_state}' without "
                        f"completing any prerequisites"
                    ),
                    test_steps=[
                        {"action": action,
                         "note": (
                             f"Execute final state action directly from "
                             f"'{machine.initial_state}'"
                         )},
                    ],
                    severity="critical",
                ))

        # 5. Concurrent execution of the same transition (race condition)
        for t in machine.transitions:
            if t.is_forbidden:
                continue
            violations.append(StateViolation(
                machine_name=machine.name,
                violation_type="concurrent_bypass",
                description=(
                    f"Send concurrent requests for transition "
                    f"'{t.from_state}' -> '{t.to_state}' via '{t.action}' "
                    f"to exploit race conditions"
                ),
                test_steps=[
                    {"action": t.action,
                     "note": "Request 1 (concurrent)",
                     "concurrent": True},
                    {"action": t.action,
                     "note": "Request 2 (concurrent)",
                     "concurrent": True},
                    {"action": t.action,
                     "note": "Request 3 (concurrent)",
                     "concurrent": True},
                ],
                severity="critical",
            ))

        return violations

    def _topological_order(self, machine: StateMachine) -> list[str]:
        """Attempt topological sort of states based on transitions.

        Returns ordered list, or empty list if the graph has cycles.
        """
        # Build adjacency list (non-forbidden transitions only)
        graph: dict[str, list[str]] = {s: [] for s in machine.states}
        in_degree: dict[str, int] = {s: 0 for s in machine.states}

        for t in machine.transitions:
            if t.is_forbidden:
                continue
            if t.from_state in graph and t.to_state in in_degree:
                if t.to_state not in graph[t.from_state]:
                    graph[t.from_state].append(t.to_state)
                    in_degree[t.to_state] = in_degree.get(t.to_state, 0) + 1

        # Kahn's algorithm
        queue = [s for s in machine.states if in_degree.get(s, 0) == 0]
        # Prefer starting with the initial state
        if machine.initial_state and machine.initial_state in queue:
            queue.remove(machine.initial_state)
            queue.insert(0, machine.initial_state)

        ordered: list[str] = []
        while queue:
            node = queue.pop(0)
            ordered.append(node)
            for neighbor in graph.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(ordered) != len(machine.states):
            return []  # Cycle detected
        return ordered

    # -----------------------------------------------------------------------
    # 6. Convert violations to hypothesis format
    # -----------------------------------------------------------------------

    def violations_to_hypotheses(
        self, violations: list[StateViolation]
    ) -> list[dict]:
        """Convert violations to attack graph hypothesis format.

        Skip-step = high impact (BLA4).
        Concurrent bypass = critical (BLA2).
        """
        severity_map = {
            "skip_step": "high",
            "forbidden_transition": "high",
            "out_of_order": "medium",
            "concurrent_bypass": "critical",
        }

        owasp_map = {
            "skip_step": "OWASP BLA4:2025 - Sequential State Bypass",
            "forbidden_transition": "OWASP BLA4:2025 - Sequential State Bypass",
            "out_of_order": "OWASP BLA4:2025 - Sequential State Bypass",
            "concurrent_bypass": "OWASP BLA2:2025 - Concurrent Workflow Order Bypass",
        }

        hypotheses: list[dict] = []
        for v in violations:
            hypotheses.append({
                "id": f"sm_{v.machine_name}_{v.violation_type}_{len(hypotheses)}",
                "type": "state_machine_violation",
                "name": f"State machine violation: {v.violation_type} in {v.machine_name}",
                "description": v.description,
                "severity": severity_map.get(v.violation_type, v.severity),
                "reference": owasp_map.get(v.violation_type, ""),
                "test_steps": v.test_steps,
                "machine_name": v.machine_name,
                "violation_type": v.violation_type,
                "confidence": 0.7 if v.violation_type == "concurrent_bypass" else 0.6,
            })

        return hypotheses

    # -----------------------------------------------------------------------
    # 7. Run all extractors
    # -----------------------------------------------------------------------

    def extract_all(
        self,
        js_content: str = "",
        openapi_spec: dict | None = None,
        traffic: list[dict] | None = None,
    ) -> list[StateMachine]:
        """Run all extractors and merge results.

        Deduplicates state machines by name/similarity.
        """
        all_machines: list[StateMachine] = []

        if js_content:
            all_machines.extend(self.extract_from_xstate(js_content))
            all_machines.extend(self.extract_from_redux(js_content))

        if openapi_spec:
            all_machines.extend(self.extract_from_openapi(openapi_spec))

        if traffic:
            all_machines.extend(self.extract_from_traffic(traffic))

        # Deduplicate by name - prefer machines with more states
        seen: dict[str, StateMachine] = {}
        for m in all_machines:
            key = m.name.lower()
            if key not in seen or len(m.states) > len(seen[key].states):
                seen[key] = m

        self._machines = list(seen.values())
        return self._machines
