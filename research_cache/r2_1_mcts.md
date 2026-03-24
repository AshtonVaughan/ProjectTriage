# R2.1 MCTS for Security Testing - COMPLETED

## Key Findings

### Empirical-MCTS (Feb 2026):
- PE-EMP evolves the meta-prompt MID-SEARCH (not between problems)
- Memory Optimization Agent with 4 ops: Add, Modify, Merge, Delete
- Merge = synthesize fragmented experiences into general principles
- Cross-problem transfer: 110 to 311 experiences across 8 rollouts
- Tech stack fingerprint = taxonomy key for cross-target learning

### SWE-Search (ICLR 2025):
- Value Agent produces (numerical score, natural language explanation)
- Explanation travels UP the tree as context for re-expansion
- Discriminator Agent: 3 rounds of 5-agent debate to select best solution
- Depth penalty is asymmetric (prefers shallow solutions - WRONG for security chains)

### Reward Signal for Pentesting:
- Form params found = 20 pts, SQLi confirmed = 60-100 pts, brute force = 150, terminal = 1000
- LLM Value Agent approach (SWE-Search) sidesteps need for compositional reward formula
- PentestThinkingMCP already implements MCTS + attack step scoring on GitHub

## Implementation Plan:
1. Use PE-EMP to evolve attack prompts mid-search (inference-time adaptation)
2. LLM Value Agent scores "how promising is this partial attack path?"
3. Memory Merge operation for cross-target pattern learning
4. Override depth penalty to NOT penalize deep chains (security needs depth)
5. Tech stack fingerprint as taxonomy key for experience retrieval
