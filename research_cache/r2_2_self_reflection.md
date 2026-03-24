# R2.2 Self-Reflection Research - COMPLETED

## Key Findings (use these for implementation)

### Reflexion Architecture (3 roles):
- Actor: executes tasks
- Evaluator: scores output (binary or heuristic)
- Self-Reflection Model: generates verbal post-mortem on failures
- Store reflections in episodic memory, prepend to next trial (sliding window of last 3-5)

### Chain-of-Verification (CoVe) - 4 steps:
1. Draft the finding
2. Generate falsification questions INDEPENDENTLY
3. Execute verifications WITHOUT seeing draft (prevents rationalization)
4. Synthesize verified conclusion

### Three-Layer Verification Stack for pentesting:
- Layer 1: Process-level doubt (PRM) - score each step's evidence quality
- Layer 2: CoVe gate before any finding is surfaced
- Layer 3: Adversarial reflection (debate between two agents for High/Critical findings)

### Key implementation rules:
- Independence is mandatory in verification (don't show draft during verification)
- Evaluator must prefer hard evidence (OOB callback, data extracted) over soft signals
- Reflections must be SPECIFIC not generic
- Memory truncation to last 3-5 reflections is a feature
- Use debate structure for High/Critical findings
- Frame debate as truth-seeking not adversarial winning
