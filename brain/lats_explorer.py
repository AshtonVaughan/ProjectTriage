"""LATS Explorer - Language Agent Tree Search for Project Triage.

Unifies ReAct + Reflexion + Tree-of-Thought into a single exploration framework.
Proven to outperform each component individually (ICML 2024).

Key differences from MCTSExplorer (mcts_explorer.py):
- LLM as value function: semantic state quality estimation, not random rollouts
- Reflexion integration: failed paths generate verbal feedback stored as memory
- Environment grounding: actual tool execution results verify hypotheses
- UCT selection informed by accumulated reflections (explicit failure memory)

Architecture:
- LATSNode captures state, action, observation, self-critique, and LLM value
- Reflections accumulate as a growing list of "what didn't work and why"
- UCT formula: value + C * sqrt(ln(parent_visits) / node_visits)
- Backpropagation updates both value estimates and visit counts up the tree

Research basis:
- LATS (Zhou et al., ICML 2024): Language Agent Tree Search
- Reflexion (Shinn et al., NeurIPS 2023): verbal reinforcement learning
- Tree-of-Thought (Yao et al., NeurIPS 2023): deliberate reasoning trees
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.provider import Provider

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

VALUE_ESTIMATION_PROMPT = """You are a value estimator for an autonomous penetration testing agent.

Current world state:
{state_summary}

Action that led to this state:
{action}

Observation / tool output:
{observation}

Full path reflections (lessons learned so far):
{reflections}

Target context:
{target_context}

Estimate the value of this node for finding high-severity vulnerabilities (0.0 to 1.0):
- 0.9-1.0: Strong evidence of exploitability; confirmed or near-confirmed finding
- 0.7-0.8: Promising signal; technique is applicable, partial confirmation
- 0.5-0.6: Worth exploring further; reasonable attack surface identified
- 0.3-0.4: Weak signal; possible but unlikely to yield findings
- 0.0-0.2: Dead end; already ruled out, blocked, or irrelevant to target

Return ONLY a JSON object: {{"value": <float 0.0-1.0>, "rationale": "<one sentence>"}}"""


REFLECTION_PROMPT = """You are generating a self-critique for a failed or dead-end attack path.

Attack trajectory (ordered steps):
{trajectory}

Final observation (why the path ended):
{final_observation}

Target tech stack:
{tech_stack}

Generate a concise reflection that explains:
1. Why this path failed or was a dead end
2. What the observations reveal about the target's defenses or architecture
3. What future paths should avoid or prioritize instead

Write as a single paragraph of natural language. Be specific - mention the endpoint,
technique, and the concrete reason for failure. Future exploration will use this
to avoid repeating the same mistakes.

Return ONLY a JSON object: {{"reflection": "<paragraph>"}}"""


HYPOTHESIS_VALUE_PROMPT = """You are prioritizing unexplored attack hypotheses.

Current accumulated reflections (failures to avoid):
{reflections}

Unexplored hypothesis:
- Technique: {technique}
- Endpoint: {endpoint}
- Description: {description}

Given what has already failed, estimate the value of trying this hypothesis (0.0 to 1.0).
Penalize hypotheses that resemble patterns in the reflections.
Reward hypotheses that target different attack surfaces or techniques.

Return ONLY a JSON object: {{"value": <float 0.0-1.0>, "rationale": "<one sentence>"}}"""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LATSNode:
    """Node in the LATS search tree."""

    state: dict[str, Any]          # Current world state summary
    action: str                    # Hypothesis/action that led here
    observation: str               # Tool output / result
    reflection: str                # Self-critique of this path
    value: float                   # LLM-estimated value (0-1)
    visits: int                    # Number of times this node was visited
    children: list[LATSNode] = field(default_factory=list)
    parent: LATSNode | None = field(default=None, repr=False)
    depth: int = 0
    is_terminal: bool = False      # Finding confirmed or dead end
    created_at: float = field(default_factory=time.time)
    node_id: str = ""              # Unique identifier for serialization

    def uct_score(self, exploration_constant: float) -> float:
        """Upper Confidence Bound for Trees score.

        UCT = value + C * sqrt(ln(parent_visits) / visits)

        The exploration term encourages visiting less-explored nodes.
        Nodes with zero visits get infinite score (must be explored first).
        """
        if self.visits == 0:
            return float("inf")
        if self.parent is None or self.parent.visits == 0:
            return self.value
        exploitation = self.value
        exploration = exploration_constant * math.sqrt(
            math.log(self.parent.visits) / self.visits
        )
        return exploitation + exploration

    def to_dict(self) -> dict[str, Any]:
        """Serialize node to dict (excludes parent ref to avoid cycles)."""
        return {
            "node_id": self.node_id,
            "state": self.state,
            "action": self.action,
            "observation": self.observation,
            "reflection": self.reflection,
            "value": self.value,
            "visits": self.visits,
            "depth": self.depth,
            "is_terminal": self.is_terminal,
            "created_at": self.created_at,
            "children": [c.to_dict() for c in self.children],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], parent: LATSNode | None = None) -> LATSNode:
        """Deserialize node from dict, rebuilding parent refs."""
        node = cls(
            state=data["state"],
            action=data["action"],
            observation=data["observation"],
            reflection=data["reflection"],
            value=data["value"],
            visits=data["visits"],
            depth=data["depth"],
            is_terminal=data["is_terminal"],
            created_at=data.get("created_at", time.time()),
            node_id=data.get("node_id", ""),
            parent=parent,
        )
        for child_data in data.get("children", []):
            child = cls.from_dict(child_data, parent=node)
            node.children.append(child)
        return node


# ---------------------------------------------------------------------------
# Main explorer class
# ---------------------------------------------------------------------------

class LATSExplorer:
    """Language Agent Tree Search explorer for autonomous pentesting.

    Provides hypothesis scoring and exploration strategy using:
    - LLM-based value estimation (semantic understanding of state quality)
    - Reflexion-style verbal memory of failed paths
    - UCT selection with configurable exploration constant

    Designed as a drop-in enhancement alongside or replacing MCTSExplorer.
    Accepts the same provider interface.
    """

    def __init__(
        self,
        provider: Provider,
        data_dir: Path,
        exploration_constant: float = 1.414,  # sqrt(2) is theoretically optimal
        max_depth: int = 15,
        max_reflections: int = 50,
    ) -> None:
        self.provider = provider
        self.data_dir = Path(data_dir)
        self.exploration_constant = exploration_constant
        self.max_depth = max_depth
        self.max_reflections = max_reflections

        self.root: LATSNode | None = None
        self.reflections: list[str] = []        # Accumulated verbal failure memory
        self.best_trajectory: list[LATSNode] = []
        self._node_counter: int = 0
        self._stats: dict[str, int] = {
            "nodes_created": 0,
            "nodes_evaluated": 0,
            "reflections_generated": 0,
            "backpropagations": 0,
            "prune_operations": 0,
        }

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self, target: str, initial_state: dict[str, Any]) -> None:
        """Create root node from initial reconnaissance state.

        Args:
            target: Target URL or identifier.
            initial_state: World state summary from initial recon
                           (e.g. tech stack, endpoints, auth surface).
        """
        state = {**initial_state, "target": target, "phase": "initial_recon"}
        self.root = LATSNode(
            state=state,
            action="initialize",
            observation=f"Initial reconnaissance of {target}",
            reflection="",
            value=0.5,  # Neutral starting value - unknown territory
            visits=1,
            depth=0,
            node_id=self._next_id(),
        )
        self._stats["nodes_created"] += 1
        log.info("LATS tree initialized for target: %s", target)

    # ------------------------------------------------------------------
    # Core LATS operations
    # ------------------------------------------------------------------

    def select_next_action(
        self,
        current_state: dict[str, Any],
        available_hypotheses: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """UCT-based selection combining exploitation and exploration.

        Walks the tree from root using UCT scores to find the most
        promising leaf, then scores available hypotheses considering
        accumulated reflections to avoid previously failed patterns.

        Args:
            current_state: Current world state summary.
            available_hypotheses: List of candidate hypothesis dicts, each
                with at least 'technique', 'endpoint', 'description'.

        Returns:
            The highest-value hypothesis dict with an added 'lats_value' key.
        """
        if not available_hypotheses:
            return {}

        # Walk tree to find best leaf via UCT
        best_leaf = self._uct_select(self.root) if self.root else None

        # Score hypotheses using LLM, informed by reflections
        scored: list[tuple[dict[str, Any], float]] = []
        reflections_ctx = self._format_reflections(limit=10)

        for hyp in available_hypotheses[:8]:  # Cap at 8 to limit LLM calls
            value = self._estimate_hypothesis_value(hyp, reflections_ctx)
            scored.append((hyp, value))

        # Sort descending by value
        scored.sort(key=lambda x: x[1], reverse=True)

        if scored:
            best_hyp, best_val = scored[0]
            best_hyp = dict(best_hyp)  # Don't mutate caller's dict
            best_hyp["lats_value"] = best_val
            best_hyp["selected_from_leaf_depth"] = best_leaf.depth if best_leaf else 0
            return best_hyp

        return available_hypotheses[0]

    def expand(
        self,
        node: LATSNode,
        hypotheses: list[dict[str, Any]],
    ) -> list[LATSNode]:
        """Expand a node with multiple candidate actions.

        Each hypothesis becomes a child node with an initial value estimate.
        The LLM evaluates each child's promise before any tool execution.

        Args:
            node: Parent node to expand from.
            hypotheses: List of hypothesis dicts to try as child actions.

        Returns:
            List of newly created child nodes.
        """
        if node.depth >= self.max_depth:
            log.debug("Max depth %d reached, skipping expansion", self.max_depth)
            return []

        new_children: list[LATSNode] = []
        reflections_ctx = self._format_reflections(limit=8)

        for hyp in hypotheses:
            action_str = f"{hyp.get('technique', 'unknown')} on {hyp.get('endpoint', 'unknown')}"
            child = LATSNode(
                state=dict(node.state),
                action=action_str,
                observation="",          # Populated after tool execution
                reflection="",           # Populated after path terminates
                value=self._estimate_hypothesis_value(hyp, reflections_ctx),
                visits=0,
                depth=node.depth + 1,
                parent=node,
                node_id=self._next_id(),
            )
            node.children.append(child)
            new_children.append(child)
            self._stats["nodes_created"] += 1

        log.debug("Expanded node %s with %d children", node.node_id, len(new_children))
        return new_children

    def evaluate(self, node: LATSNode, llm_value_prompt: str = "") -> float:
        """LLM-based value estimation for a node.

        Asks: 'Given this state and path, how promising is this direction
        for finding high-severity vulnerabilities?'

        Args:
            node: Node to evaluate.
            llm_value_prompt: Optional override prompt (for testing/customization).

        Returns:
            Estimated value in range [0.0, 1.0].
        """
        reflections_ctx = self._format_reflections(limit=8)
        target_ctx = json.dumps(node.state.get("tech_stack", {}), default=str)[:400]

        prompt = llm_value_prompt or VALUE_ESTIMATION_PROMPT.format(
            state_summary=json.dumps(node.state, default=str)[:600],
            action=node.action[:300],
            observation=node.observation[:500],
            reflections=reflections_ctx[:800],
            target_context=target_ctx,
        )

        try:
            response = self.provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.2,
                use_fast=True,
            )
            parsed = _parse_json(response)
            value = float(parsed.get("value", 0.5))
            value = max(0.0, min(1.0, value))
            node.value = value
            self._stats["nodes_evaluated"] += 1
            return value
        except Exception as e:
            log.warning("LATS value estimation failed for node %s: %s", node.node_id, e)
            return 0.5

    def reflect(self, trajectory: list[LATSNode]) -> str:
        """Generate verbal reflection on a failed or dead-end trajectory.

        The reflection is stored in the explorer's memory and used in future
        UCT selections to steer away from similar patterns.

        Args:
            trajectory: Ordered list of nodes from root to terminal leaf.

        Returns:
            Natural language reflection paragraph.
        """
        if not trajectory:
            return ""

        terminal = trajectory[-1]

        # Format trajectory as ordered action-observation pairs
        traj_lines: list[str] = []
        for i, node in enumerate(trajectory):
            traj_lines.append(f"  Step {i}: {node.action}")
            if node.observation:
                traj_lines.append(f"    Observation: {node.observation[:200]}")

        tech_stack = trajectory[0].state.get("tech_stack", {}) if trajectory else {}
        prompt = REFLECTION_PROMPT.format(
            trajectory="\n".join(traj_lines),
            final_observation=terminal.observation[:600],
            tech_stack=json.dumps(tech_stack, default=str)[:400],
        )

        try:
            response = self.provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.3,
                use_fast=True,
            )
            parsed = _parse_json(response)
            reflection = parsed.get("reflection", "")
            if not reflection:
                reflection = str(parsed)[:400]
        except Exception as e:
            log.warning("LATS reflection generation failed: %s", e)
            reflection = (
                f"Path via '{terminal.action}' terminated at depth {terminal.depth}. "
                f"Observation: {terminal.observation[:150]}"
            )

        # Store reflection, cap list to avoid unbounded growth
        self.reflections.append(reflection)
        if len(self.reflections) > self.max_reflections:
            self.reflections = self.reflections[-self.max_reflections:]

        # Attach to terminal node
        terminal.reflection = reflection
        terminal.is_terminal = True
        self._stats["reflections_generated"] += 1

        log.info("Generated reflection for depth-%d trajectory", len(trajectory))
        return reflection

    def backpropagate(self, node: LATSNode, value: float) -> None:
        """Backpropagate value up the tree, updating visit counts.

        Uses incremental mean update: new_value = old_value + (value - old_value) / visits
        This is equivalent to computing the running average without storing all values.

        Args:
            node: Leaf node where evaluation originated.
            value: Value to propagate (0.0-1.0).
        """
        current: LATSNode | None = node
        while current is not None:
            current.visits += 1
            # Incremental mean: avoids storing sum separately
            current.value += (value - current.value) / current.visits
            current = current.parent
            self._stats["backpropagations"] += 1

        # Update best trajectory whenever we backpropagate
        self._update_best_trajectory()

    # ------------------------------------------------------------------
    # Tree navigation helpers
    # ------------------------------------------------------------------

    def _uct_select(self, node: LATSNode | None) -> LATSNode | None:
        """Recursively select the most promising leaf via UCT."""
        if node is None:
            return None

        # If leaf (no children) or unexpanded terminal, return node
        if not node.children or node.is_terminal:
            return node

        # Filter out fully explored terminals
        candidates = [c for c in node.children if not c.is_terminal or c.visits == 0]
        if not candidates:
            return node

        best = max(candidates, key=lambda c: c.uct_score(self.exploration_constant))
        return self._uct_select(best)

    def _estimate_hypothesis_value(
        self,
        hyp: dict[str, Any],
        reflections_ctx: str,
    ) -> float:
        """Ask LLM to score an unexplored hypothesis given reflections."""
        prompt = HYPOTHESIS_VALUE_PROMPT.format(
            reflections=reflections_ctx[:800],
            technique=hyp.get("technique", "unknown"),
            endpoint=hyp.get("endpoint", "unknown"),
            description=str(hyp.get("description", ""))[:300],
        )
        try:
            response = self.provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.2,
                use_fast=True,
            )
            parsed = _parse_json(response)
            value = float(parsed.get("value", 0.5))
            return max(0.0, min(1.0, value))
        except Exception as e:
            log.warning("Hypothesis value estimation failed: %s", e)
            return 0.5

    def _format_reflections(self, limit: int = 10) -> str:
        """Format recent reflections as a numbered list for prompts."""
        recent = self.reflections[-limit:]
        if not recent:
            return "No reflections yet - this is the first exploration pass."
        lines = [f"  {i + 1}. {r}" for i, r in enumerate(recent)]
        return "\n".join(lines)

    def _update_best_trajectory(self) -> None:
        """Walk the highest-value path from root to leaf and cache it."""
        if self.root is None:
            return

        path: list[LATSNode] = []
        current: LATSNode = self.root

        while True:
            path.append(current)
            if not current.children:
                break
            # Follow highest-value child
            best_child = max(current.children, key=lambda c: c.value)
            if best_child.value <= 0.0:
                break
            current = best_child

        self.best_trajectory = path

    def _next_id(self) -> str:
        """Generate a sequential node identifier."""
        self._node_counter += 1
        return f"lats_{self._node_counter:04d}"

    # ------------------------------------------------------------------
    # Public output methods
    # ------------------------------------------------------------------

    def get_best_trajectory(self) -> list[dict[str, Any]]:
        """Return the highest-value path through the tree as serializable dicts.

        Returns:
            List of node dicts from root to the highest-value leaf.
        """
        self._update_best_trajectory()
        return [
            {
                "depth": n.depth,
                "action": n.action,
                "observation": n.observation,
                "value": round(n.value, 4),
                "visits": n.visits,
                "reflection": n.reflection,
                "is_terminal": n.is_terminal,
            }
            for n in self.best_trajectory
        ]

    def get_exploration_stats(self) -> dict[str, Any]:
        """Return tree statistics: depth, breadth, value distribution.

        Returns:
            Dict with tree metrics and exploration progress.
        """
        if self.root is None:
            return {"error": "Tree not initialized"}

        all_nodes = _collect_all_nodes(self.root)
        values = [n.value for n in all_nodes]
        depths = [n.depth for n in all_nodes]
        terminals = [n for n in all_nodes if n.is_terminal]

        return {
            "total_nodes": len(all_nodes),
            "max_depth": max(depths) if depths else 0,
            "max_breadth": max(
                len(n.children) for n in all_nodes
            ) if all_nodes else 0,
            "terminal_nodes": len(terminals),
            "total_reflections": len(self.reflections),
            "best_trajectory_length": len(self.best_trajectory),
            "best_trajectory_value": round(self.best_trajectory[-1].value, 4)
            if self.best_trajectory else 0.0,
            "value_distribution": {
                "min": round(min(values), 4) if values else 0.0,
                "max": round(max(values), 4) if values else 0.0,
                "mean": round(sum(values) / len(values), 4) if values else 0.0,
                "high_value_nodes": sum(1 for v in values if v >= 0.7),
                "low_value_nodes": sum(1 for v in values if v <= 0.2),
            },
            "internal_stats": self._stats,
        }

    def prune_low_value(self, threshold: float = 0.1) -> int:
        """Prune subtrees below value threshold to save memory.

        Nodes on the best trajectory are never pruned regardless of value.

        Args:
            threshold: Nodes with value <= threshold are pruned.

        Returns:
            Number of nodes removed.
        """
        if self.root is None:
            return 0

        protected_ids = {n.node_id for n in self.best_trajectory}
        removed = _prune_recursive(self.root, threshold, protected_ids)
        self._stats["prune_operations"] += 1
        log.info("Pruned %d low-value nodes (threshold=%.2f)", removed, threshold)
        return removed

    def integrate_with_attack_graph(
        self,
        attack_graph: Any,
    ) -> list[dict[str, Any]]:
        """Convert LATS insights into hypothesis dicts for the attack graph.

        Hypotheses from high-value unexplored nodes get a priority boost.
        Hypotheses resembling reflection patterns get a penalty.

        Args:
            attack_graph: Attack graph object with a .hypotheses or similar
                          attribute (duck-typed, reads .get_pending_hypotheses()
                          if available).

        Returns:
            List of hypothesis dicts sorted by lats_adjusted_priority.
        """
        if self.root is None:
            return []

        # Collect high-value unvisited leaves
        all_nodes = _collect_all_nodes(self.root)
        high_value_leaves = [
            n for n in all_nodes
            if n.visits == 0 and n.value >= 0.6 and not n.is_terminal
        ]

        # Extract pending hypotheses from attack graph if possible
        pending: list[dict[str, Any]] = []
        if hasattr(attack_graph, "get_pending_hypotheses"):
            pending = list(attack_graph.get_pending_hypotheses())
        elif hasattr(attack_graph, "hypotheses"):
            pending = [
                h.__dict__ if hasattr(h, "__dict__") else h
                for h in attack_graph.hypotheses
            ]

        reflections_ctx = self._format_reflections(limit=10)

        # Re-score pending hypotheses with LATS insight
        boosted: list[dict[str, Any]] = []
        for hyp in pending:
            hyp_dict = dict(hyp) if not isinstance(hyp, dict) else hyp
            lats_val = self._estimate_hypothesis_value(hyp_dict, reflections_ctx)

            # Boost if the hypothesis matches a high-value leaf's action
            for leaf in high_value_leaves:
                if hyp_dict.get("technique", "") in leaf.action:
                    lats_val = min(1.0, lats_val + 0.15)
                    break

            hyp_dict["lats_adjusted_priority"] = lats_val
            boosted.append(hyp_dict)

        boosted.sort(key=lambda h: h["lats_adjusted_priority"], reverse=True)
        return boosted

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_state(self, filepath: Path) -> None:
        """Serialize tree state for session resumption.

        Args:
            filepath: Path to write JSON state file.
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        state = {
            "version": 1,
            "saved_at": time.time(),
            "exploration_constant": self.exploration_constant,
            "max_depth": self.max_depth,
            "max_reflections": self.max_reflections,
            "node_counter": self._node_counter,
            "reflections": self.reflections,
            "stats": self._stats,
            "tree": self.root.to_dict() if self.root else None,
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            log.info("LATS state saved to %s", filepath)
        except Exception as e:
            log.error("Failed to save LATS state: %s", e)

    @classmethod
    def load_state(
        cls,
        filepath: Path,
        provider: Provider,
    ) -> LATSExplorer | None:
        """Resume from saved tree state.

        Args:
            filepath: Path to a JSON state file previously written by save_state().
            provider: LLM provider instance.

        Returns:
            Restored LATSExplorer, or None if loading failed.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            log.warning("LATS state file not found: %s", filepath)
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception as e:
            log.error("Failed to read LATS state file: %s", e)
            return None

        explorer = cls(
            provider=provider,
            data_dir=filepath.parent,
            exploration_constant=state.get("exploration_constant", 1.414),
            max_depth=state.get("max_depth", 15),
            max_reflections=state.get("max_reflections", 50),
        )
        explorer._node_counter = state.get("node_counter", 0)
        explorer.reflections = state.get("reflections", [])
        explorer._stats = state.get("stats", explorer._stats)

        tree_data = state.get("tree")
        if tree_data:
            explorer.root = LATSNode.from_dict(tree_data, parent=None)
            explorer._update_best_trajectory()

        log.info(
            "LATS state loaded from %s (%d reflections, tree root: %s)",
            filepath,
            len(explorer.reflections),
            explorer.root.node_id if explorer.root else "none",
        )
        return explorer


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _parse_json(text: str) -> Any:
    """Parse JSON from LLM response, handling markdown code fences."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        end = text.rfind(end_char) + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

    return {"value": 0.5, "rationale": text[:200], "reflection": text[:400]}


def _collect_all_nodes(root: LATSNode) -> list[LATSNode]:
    """BFS traversal to collect all nodes in the tree."""
    result: list[LATSNode] = []
    queue: list[LATSNode] = [root]
    while queue:
        node = queue.pop(0)
        result.append(node)
        queue.extend(node.children)
    return result


def _prune_recursive(
    node: LATSNode,
    threshold: float,
    protected_ids: set[str],
) -> int:
    """Recursively prune children below threshold, return count removed."""
    removed = 0
    survivors: list[LATSNode] = []

    for child in node.children:
        if child.node_id in protected_ids or child.value > threshold:
            # Keep - recurse into survivors
            removed += _prune_recursive(child, threshold, protected_ids)
            survivors.append(child)
        else:
            # Prune this subtree entirely - count all its nodes
            removed += 1 + len(_collect_all_nodes(child)) - 1

    node.children = survivors
    return removed
