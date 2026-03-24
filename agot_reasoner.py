"""Adaptive Graph of Thoughts (AGoT) Reasoner for Project Triage v4.

Replaces flat ReAct (one thought per step) with adaptive graph decomposition
that explores multiple attack paths, self-critiques, and backtracks.

Research basis: AGoT achieves +277% on explorative problem solving vs direct
inference. LATS achieves 94.4% on HumanEval. Both dramatically outperform
ReAct on multi-step reasoning tasks.

Key insight from MFR paper: "Hallucinations are representational failures,
not reasoning failures." The LLM isn't bad at reasoning - it just needs an
explicit model of what it's reasoning about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThoughtNode:
    """A single node in the thought graph."""
    id: int
    thought: str
    action: str
    action_input: dict[str, Any]
    observation: str = ""
    score: float = 0.0  # Self-evaluated promise score (0-1)
    parent_id: int | None = None
    children: list[int] = field(default_factory=list)
    status: str = "pending"  # pending, executed, succeeded, failed, abandoned
    critique: str = ""  # Self-critique after observation
    learning: str = ""  # What was learned from this node


@dataclass
class ReasoningPath:
    """A complete path through the thought graph."""
    nodes: list[ThoughtNode]
    total_score: float = 0.0
    outcome: str = ""  # finding, dead_end, needs_more_info


class AGoTReasoner:
    """Adaptive Graph of Thoughts reasoner.

    Instead of flat ReAct (think -> act -> observe -> repeat),
    this explores multiple paths, evaluates their promise, and
    backtracks when a path fails.

    The key architectural decision: decompose complex hypotheses into
    sub-problems, explore the most promising sub-problem first, and
    carry failure reasons as learning when backtracking.
    """

    def __init__(self, max_branches: int = 3, max_depth: int = 5) -> None:
        self.max_branches = max_branches  # Max parallel paths to consider
        self.max_depth = max_depth  # Max depth before forcing evaluation
        self.nodes: dict[int, ThoughtNode] = {}
        self._next_id = 0
        self.root: ThoughtNode | None = None
        self.best_path: ReasoningPath | None = None
        self._learnings: list[str] = []  # Accumulated learnings from failures

    def create_root(self, hypothesis_technique: str, hypothesis_description: str, endpoint: str) -> ThoughtNode:
        """Create the root node for a new hypothesis exploration."""
        self._next_id = 0
        self.nodes.clear()
        self._learnings.clear()

        root = ThoughtNode(
            id=self._next_id,
            thought=f"Testing hypothesis: {hypothesis_technique} on {endpoint}. {hypothesis_description}",
            action="",
            action_input={},
            score=0.5,
            status="pending",
        )
        self._next_id += 1
        self.nodes[root.id] = root
        self.root = root
        return root

    def generate_branches(
        self,
        parent: ThoughtNode,
        possible_actions: list[dict[str, Any]],
    ) -> list[ThoughtNode]:
        """Generate branch nodes from possible next actions.

        Each action dict: {thought, action, action_input, score}
        Only the top max_branches are kept.
        """
        # Sort by score and take top branches
        sorted_actions = sorted(possible_actions, key=lambda a: a.get("score", 0), reverse=True)
        branches = []

        for action_data in sorted_actions[:self.max_branches]:
            node = ThoughtNode(
                id=self._next_id,
                thought=action_data.get("thought", ""),
                action=action_data.get("action", ""),
                action_input=action_data.get("action_input", {}),
                score=action_data.get("score", 0.5),
                parent_id=parent.id,
                status="pending",
            )
            self._next_id += 1
            self.nodes[node.id] = node
            parent.children.append(node.id)
            branches.append(node)

        return branches

    def select_best_branch(self) -> ThoughtNode | None:
        """Select the most promising unexplored branch (highest score, pending status)."""
        pending = [
            n for n in self.nodes.values()
            if n.status == "pending" and n.action  # Has an action to execute
        ]
        if not pending:
            return None
        return max(pending, key=lambda n: n.score)

    def record_observation(
        self,
        node: ThoughtNode,
        observation: str,
        success: bool,
        critique: str = "",
    ) -> None:
        """Record the result of executing a node's action."""
        node.observation = observation
        node.critique = critique
        node.status = "succeeded" if success else "failed"

        if not success and critique:
            learning = f"On {node.action}: {critique}"
            node.learning = learning
            self._learnings.append(learning)

    def get_self_critique_prompt(self, node: ThoughtNode) -> str:
        """Generate a prompt for the LLM to self-critique a result."""
        parent_context = ""
        if node.parent_id is not None and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            parent_context = f"Previous step: {parent.thought}\nPrevious result: {parent.observation}\n"

        learnings_ctx = ""
        if self._learnings:
            learnings_ctx = "Learnings from failed attempts:\n" + "\n".join(
                f"  - {l}" for l in self._learnings[-5:]
            ) + "\n"

        return f"""Self-critique this result:

{parent_context}Current action: {node.action}({node.action_input})
Result: {node.observation[:500]}

{learnings_ctx}
Answer these questions in 2-3 sentences:
1. Did this result match what I expected? If not, why?
2. What does this tell me about the application's architecture or security?
3. Does this finding enable a chain I haven't considered?
4. What should I try next based on this result?"""

    def get_branch_generation_prompt(
        self,
        node: ThoughtNode,
        available_tools: list[str],
        world_context: str = "",
    ) -> str:
        """Generate a prompt for the LLM to propose multiple next actions."""
        path_so_far = self._get_path_to_node(node)
        path_summary = "\n".join(
            f"  Step {i+1}: {n.action}({str(n.action_input)[:80]}) -> {n.observation[:100]}"
            for i, n in enumerate(path_so_far) if n.observation
        )

        learnings_ctx = ""
        if self._learnings:
            learnings_ctx = "\nLearnings from failed attempts:\n" + "\n".join(
                f"  - {l}" for l in self._learnings[-5:]
            )

        return f"""Given the current state, propose {self.max_branches} different next actions.
For each, estimate how promising it is (score 0-1).

Path so far:
{path_summary}

Current observation: {node.observation[:300]}
{node.critique}
{learnings_ctx}

{world_context}

Available tools: {', '.join(available_tools)}

For each proposed action, output one JSON per line:
{{"thought": "why this action", "action": "tool_name", "action_input": {{}}, "score": 0.7}}

Propose {self.max_branches} different approaches (not variations of the same thing).
Consider: (a) go deeper on current path, (b) try a different angle, (c) verify/chain with other findings."""

    def should_backtrack(self, node: ThoughtNode) -> bool:
        """Determine if we should backtrack from this node."""
        # Backtrack if: failed, or depth exceeded, or score dropped below threshold
        if node.status == "failed":
            return True

        depth = self._get_depth(node)
        if depth >= self.max_depth:
            return True

        # If score is very low after observation, backtrack
        if node.observation and node.score < 0.2:
            return True

        return False

    def get_best_path(self) -> ReasoningPath:
        """Get the most promising complete path through the graph."""
        # Find all leaf nodes (succeeded or with observations)
        leaves = [
            n for n in self.nodes.values()
            if n.status in ("succeeded", "failed") and not n.children
        ]

        if not leaves:
            return ReasoningPath(nodes=[], total_score=0, outcome="no_results")

        # Score each path from root to leaf
        best_score = -1.0
        best_path_nodes: list[ThoughtNode] = []
        best_outcome = "dead_end"

        for leaf in leaves:
            path = self._get_path_to_node(leaf)
            path_score = sum(n.score for n in path) / max(len(path), 1)

            if leaf.status == "succeeded":
                path_score *= 1.5  # Boost successful paths

            if path_score > best_score:
                best_score = path_score
                best_path_nodes = path
                best_outcome = "finding" if leaf.status == "succeeded" else "dead_end"

        self.best_path = ReasoningPath(
            nodes=best_path_nodes,
            total_score=best_score,
            outcome=best_outcome,
        )
        return self.best_path

    def get_accumulated_learnings(self) -> str:
        """Get all learnings from this hypothesis exploration."""
        if not self._learnings:
            return ""
        return "Learnings:\n" + "\n".join(f"  - {l}" for l in self._learnings)

    def get_graph_summary(self) -> str:
        """Human-readable summary of the thought graph."""
        total = len(self.nodes)
        succeeded = sum(1 for n in self.nodes.values() if n.status == "succeeded")
        failed = sum(1 for n in self.nodes.values() if n.status == "failed")
        pending = sum(1 for n in self.nodes.values() if n.status == "pending")

        return (
            f"Thought graph: {total} nodes ({succeeded} succeeded, "
            f"{failed} failed, {pending} pending), "
            f"{len(self._learnings)} learnings accumulated"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_path_to_node(self, node: ThoughtNode) -> list[ThoughtNode]:
        """Get the path from root to this node."""
        path = [node]
        current = node
        while current.parent_id is not None and current.parent_id in self.nodes:
            current = self.nodes[current.parent_id]
            path.append(current)
        path.reverse()
        return path

    def _get_depth(self, node: ThoughtNode) -> int:
        """Get the depth of a node in the graph."""
        depth = 0
        current = node
        while current.parent_id is not None and current.parent_id in self.nodes:
            current = self.nodes[current.parent_id]
            depth += 1
        return depth
