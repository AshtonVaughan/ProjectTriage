"""Self-Reflection - CoVe + Reflexion 3-layer verification for Project Triage v4.

Implements a rigorous finding verification pipeline:
- Layer 1: PRM (Process Reward Model) - scores per-step evidence quality
- Layer 2: CoVe gate - Chain-of-Verification with independent falsification
- Layer 3: Adversarial debate for High/Critical findings

Research basis:
- Reflexion (Shinn et al.): Actor/Evaluator/Self-Reflection 3 roles
- CoVe (Dhuliawala et al.): 4-step verification with independence constraint
- Independence is MANDATORY: don't show draft during verification steps
- Evaluator must prefer hard evidence (OOB callback, data extracted) over soft signals
- Reflections must be SPECIFIC not generic
- Memory truncation to last 3-5 reflections is a feature, not a bug
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from provider import Provider

log = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of the 3-layer verification pipeline."""
    passed: bool
    confidence: float  # 0.0 - 1.0
    grade: str  # A/B/C/D/F
    recommendation: str  # report / review / investigate / suppress
    prm_score: float = 0.0
    cove_passed: bool = False
    cove_questions: list[str] = field(default_factory=list)
    cove_answers: list[str] = field(default_factory=list)
    debate_verdict: str | None = None  # only for High/Critical
    reflections_used: list[str] = field(default_factory=list)
    rejection_reason: str | None = None


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

PRM_PROMPT = """You are evaluating the evidence quality of a security finding.

Finding: {title}
Technique: {technique}
Observation: {observation}

Score the evidence quality from 0.0 to 1.0:
- 1.0 = Hard proof: data extracted, OOB callback received, code execution confirmed
- 0.7 = Strong indicator: error messages revealing internals, timing differences confirmed
- 0.4 = Soft signal: unusual behavior, different response codes, but could be by design
- 0.1 = Speculation: no concrete evidence, just theoretical possibility

Return ONLY a JSON object: {{"score": <float>, "reasoning": "<one sentence>"}}"""

COVE_QUESTIONS_PROMPT = """You are a skeptical security reviewer. Generate 3-5 falsification questions that would DISPROVE this finding is a real vulnerability.

Technique: {technique}
Endpoint: {endpoint}
Context: {context}

Think about:
- Could this behavior be intentional/by design?
- Is there a non-security explanation?
- Could the evidence be misinterpreted?
- Would this actually be exploitable in practice?

Return ONLY a JSON array of question strings. No explanation."""

COVE_VERIFY_PROMPT = """You are independently verifying a security claim. Answer this question based ONLY on the evidence provided.

Question: {question}

Evidence from tool output:
{observation}

Is the answer to this question "yes this IS a real vulnerability" or "no, this could be a false positive"?

Return ONLY a JSON object: {{"verdict": "real" or "false_positive", "reasoning": "<one sentence>"}}"""

DEBATE_ADVOCATE_PROMPT = """You are arguing that this IS a real, exploitable security vulnerability worth reporting.

Finding: {title}
Technique: {technique}
Evidence: {observation}

Make your strongest case in 3-4 sentences. Focus on:
- What specific data/behavior proves exploitation?
- What is the concrete security impact?
- Why this is NOT a false positive or by-design behavior."""

DEBATE_SKEPTIC_PROMPT = """You are arguing that this is NOT a real vulnerability and should NOT be reported.

Finding: {title}
Technique: {technique}
Evidence: {observation}

Make your strongest case in 3-4 sentences. Focus on:
- Why the evidence is insufficient or misinterpreted
- How this could be intentional/by-design behavior
- Why this would be rejected by a triager."""

DEBATE_JUDGE_PROMPT = """You are a senior security triager judging a debate about whether a finding is a real vulnerability.

ADVOCATE says: {advocate_argument}

SKEPTIC says: {skeptic_argument}

Original evidence: {observation}

Who makes the stronger case? Return ONLY a JSON object:
{{"verdict": "real" or "false_positive", "confidence": <0.0-1.0>, "reasoning": "<one sentence>"}}"""

REFLECTION_PROMPT = """A security finding was {outcome} during verification.

Finding: {title}
Technique: {technique}
PRM Score: {prm_score}
CoVe Result: {cove_result}
Rejection Reason: {rejection_reason}

Generate a SPECIFIC lesson learned for future verification. Do NOT be generic.
Bad: "Be more careful with evidence"
Good: "SSRF findings against AWS metadata need actual data extraction, not just 200 response codes"

Return one sentence - the specific lesson."""


class SelfReflector:
    """3-layer verification pipeline with episodic memory.

    Layer 1: PRM - evidence quality scoring (fast model)
    Layer 2: CoVe - independent falsification (fast model)
    Layer 3: Adversarial debate for High/Critical (slow model)

    Episodic memory stores last N reflections from prior verifications,
    prepended to future verification prompts for learning.
    """

    def __init__(self, provider: Provider, max_reflections: int = 5) -> None:
        self._provider = provider
        self._max_reflections = max_reflections
        self._reflections: list[dict[str, Any]] = []
        self._stats = {"verified": 0, "rejected": 0, "debated": 0}

    def verify_finding(
        self,
        finding: dict[str, Any],
        observation: str,
        context: str = "",
    ) -> VerificationResult:
        """Run the full 3-layer verification pipeline.

        Args:
            finding: Dict with keys: title, technique, severity (optional).
            observation: Raw tool output as evidence.
            context: Additional context about the finding.

        Returns:
            VerificationResult with grade, confidence, and recommendation.
        """
        title = finding.get("title", "Unknown finding")
        technique = finding.get("technique", "unknown")
        severity = finding.get("severity", "medium")
        endpoint = finding.get("endpoint", "")

        # Gather reflections from episodic memory
        reflections_used = [r["lesson"] for r in self._reflections[-self._max_reflections:]]

        # ----- Layer 1: PRM - Evidence Quality Score -----
        prm_score = self._prm_score(title, technique, observation)

        if prm_score < 0.3:
            self._stats["rejected"] += 1
            result = VerificationResult(
                passed=False,
                confidence=prm_score,
                grade="D",
                recommendation="suppress",
                prm_score=prm_score,
                reflections_used=reflections_used,
                rejection_reason=f"Evidence quality too low (PRM={prm_score:.2f})",
            )
            self._add_reflection(title, technique, prm_score, "failed_prm",
                                 f"PRM={prm_score:.2f}, evidence insufficient")
            return result

        # ----- Layer 2: CoVe - Chain-of-Verification -----
        cove_passed, cove_questions, cove_answers = self._cove_gate(
            title, technique, endpoint, observation, context,
        )

        if not cove_passed:
            self._stats["rejected"] += 1
            result = VerificationResult(
                passed=False,
                confidence=prm_score * 0.5,
                grade="C",
                recommendation="investigate",
                prm_score=prm_score,
                cove_passed=False,
                cove_questions=cove_questions,
                cove_answers=cove_answers,
                reflections_used=reflections_used,
                rejection_reason="Failed CoVe falsification gate",
            )
            self._add_reflection(title, technique, prm_score, "failed_cove",
                                 "CoVe falsification questions raised doubt")
            return result

        # ----- Layer 3: Adversarial Debate (High/Critical only) -----
        debate_verdict = None
        if severity in ("high", "critical"):
            self._stats["debated"] += 1
            debate_verdict, debate_confidence = self._adversarial_debate(
                title, technique, observation,
            )
            if debate_verdict == "false_positive":
                self._stats["rejected"] += 1
                result = VerificationResult(
                    passed=False,
                    confidence=debate_confidence,
                    grade="C",
                    recommendation="investigate",
                    prm_score=prm_score,
                    cove_passed=True,
                    cove_questions=cove_questions,
                    cove_answers=cove_answers,
                    debate_verdict=debate_verdict,
                    reflections_used=reflections_used,
                    rejection_reason="Adversarial debate: skeptic prevailed",
                )
                self._add_reflection(title, technique, prm_score, "failed_debate",
                                     "Debate skeptic won - evidence not convincing enough")
                return result

        # ----- All layers passed -----
        self._stats["verified"] += 1
        confidence = self._compute_confidence(prm_score, cove_passed, debate_verdict)
        grade = self._grade_from_confidence(confidence)
        recommendation = self._recommendation_from_grade(grade)

        result = VerificationResult(
            passed=True,
            confidence=confidence,
            grade=grade,
            recommendation=recommendation,
            prm_score=prm_score,
            cove_passed=True,
            cove_questions=cove_questions,
            cove_answers=cove_answers,
            debate_verdict=debate_verdict,
            reflections_used=reflections_used,
        )
        self._add_reflection(title, technique, prm_score, "passed",
                             f"Verified with confidence={confidence:.2f}")
        return result

    # ------------------------------------------------------------------
    # Layer 1: PRM
    # ------------------------------------------------------------------

    def _prm_score(self, title: str, technique: str, observation: str) -> float:
        """Score evidence quality using the fast model."""
        prompt = PRM_PROMPT.format(
            title=title,
            technique=technique,
            observation=observation[:2000],
        )
        try:
            response = self._provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.1,
                use_fast=True,
            )
            parsed = self._parse_json(response)
            score = float(parsed.get("score", 0.5))
            return max(0.0, min(1.0, score))
        except Exception as e:
            log.warning("PRM scoring failed: %s", e)
            return 0.5  # Neutral on failure

    # ------------------------------------------------------------------
    # Layer 2: CoVe
    # ------------------------------------------------------------------

    def _cove_gate(
        self,
        title: str,
        technique: str,
        endpoint: str,
        observation: str,
        context: str,
    ) -> tuple[bool, list[str], list[str]]:
        """Chain-of-Verification with independence constraint.

        Step 1: Generate falsification questions (WITHOUT seeing the finding draft)
        Step 2: Answer each question INDEPENDENTLY against raw evidence
        Step 3: Synthesize - pass only if majority say "real"

        Returns: (passed, questions, answers)
        """
        # Step 1: Generate falsification questions
        q_prompt = COVE_QUESTIONS_PROMPT.format(
            technique=technique,
            endpoint=endpoint,
            context=context[:500],
        )
        try:
            q_response = self._provider.chat(
                [{"role": "user", "content": q_prompt}],
                temperature=0.3,
                use_fast=True,
            )
            questions = self._parse_json(q_response)
            if not isinstance(questions, list):
                questions = questions.get("questions", []) if isinstance(questions, dict) else []
            questions = questions[:5]  # Cap at 5
        except Exception:
            questions = [
                "Could this behavior be intentional or by design?",
                "Is the evidence strong enough to confirm exploitation?",
                "Would a triager accept this without additional proof?",
            ]

        if not questions:
            return True, [], []  # No questions = pass by default

        # Step 2: Answer each question independently (WITHOUT seeing draft)
        answers: list[str] = []
        real_count = 0
        for question in questions:
            v_prompt = COVE_VERIFY_PROMPT.format(
                question=question,
                observation=observation[:1500],
            )
            try:
                v_response = self._provider.chat(
                    [{"role": "user", "content": v_prompt}],
                    temperature=0.1,
                    use_fast=True,
                )
                parsed = self._parse_json(v_response)
                verdict = parsed.get("verdict", "false_positive")
                reasoning = parsed.get("reasoning", "")
                answers.append(f"{verdict}: {reasoning}")
                if verdict == "real":
                    real_count += 1
            except Exception:
                answers.append("error: verification failed")

        # Step 3: Majority vote
        passed = real_count > len(questions) / 2
        return passed, questions, answers

    # ------------------------------------------------------------------
    # Layer 3: Adversarial Debate
    # ------------------------------------------------------------------

    def _adversarial_debate(
        self,
        title: str,
        technique: str,
        observation: str,
    ) -> tuple[str, float]:
        """Run advocate vs skeptic debate, judged by a third call.

        Uses the SLOW model for deeper reasoning on High/Critical findings.

        Returns: (verdict, confidence)
        """
        obs_truncated = observation[:2000]

        # Advocate argues it IS real
        try:
            advocate = self._provider.chat(
                [{"role": "user", "content": DEBATE_ADVOCATE_PROMPT.format(
                    title=title, technique=technique, observation=obs_truncated,
                )}],
                temperature=0.3,
                use_fast=False,  # Slow model for depth
            )
        except Exception:
            advocate = "Unable to argue - defaulting to cautious acceptance."

        # Skeptic argues it is NOT real
        try:
            skeptic = self._provider.chat(
                [{"role": "user", "content": DEBATE_SKEPTIC_PROMPT.format(
                    title=title, technique=technique, observation=obs_truncated,
                )}],
                temperature=0.3,
                use_fast=False,
            )
        except Exception:
            skeptic = "Unable to argue - defaulting to cautious rejection."

        # Judge decides
        try:
            judge_response = self._provider.chat(
                [{"role": "user", "content": DEBATE_JUDGE_PROMPT.format(
                    advocate_argument=advocate,
                    skeptic_argument=skeptic,
                    observation=obs_truncated,
                )}],
                temperature=0.1,
                use_fast=False,
            )
            parsed = self._parse_json(judge_response)
            verdict = parsed.get("verdict", "false_positive")
            confidence = float(parsed.get("confidence", 0.5))
            return verdict, max(0.0, min(1.0, confidence))
        except Exception:
            return "real", 0.5  # Default to cautious acceptance on error

    # ------------------------------------------------------------------
    # Episodic Memory (Reflexion)
    # ------------------------------------------------------------------

    def _add_reflection(
        self,
        title: str,
        technique: str,
        prm_score: float,
        outcome: str,
        details: str,
    ) -> None:
        """Generate and store a specific reflection for future use."""
        try:
            response = self._provider.chat(
                [{"role": "user", "content": REFLECTION_PROMPT.format(
                    outcome=outcome,
                    title=title,
                    technique=technique,
                    prm_score=f"{prm_score:.2f}",
                    cove_result=outcome,
                    rejection_reason=details,
                )}],
                temperature=0.3,
                use_fast=True,
            )
            lesson = response.strip()
        except Exception:
            lesson = f"{technique}: {outcome} - {details}"

        self._reflections.append({
            "finding": title,
            "technique": technique,
            "outcome": outcome,
            "lesson": lesson,
            "timestamp": time.time(),
        })

        # Truncate to max
        if len(self._reflections) > self._max_reflections:
            self._reflections = self._reflections[-self._max_reflections:]

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_confidence(prm_score: float, cove_passed: bool, debate_verdict: str | None) -> float:
        """Compute overall confidence from all three layers."""
        base = prm_score * 0.4  # 40% from evidence quality

        if cove_passed:
            base += 0.35  # 35% from CoVe

        if debate_verdict == "real":
            base += 0.25  # 25% from debate
        elif debate_verdict is None:
            base += 0.15  # Medium/Low don't go through debate, partial credit

        return max(0.0, min(1.0, base))

    @staticmethod
    def _grade_from_confidence(confidence: float) -> str:
        """Map confidence to letter grade."""
        score = int(confidence * 100)
        if score >= 90:
            return "A"
        if score >= 70:
            return "B"
        if score >= 50:
            return "C"
        if score >= 30:
            return "D"
        return "F"

    @staticmethod
    def _recommendation_from_grade(grade: str) -> str:
        """Map grade to action recommendation."""
        return {
            "A": "report",
            "B": "review",
            "C": "investigate",
            "D": "suppress",
            "F": "suppress",
        }.get(grade, "suppress")

    @staticmethod
    def _parse_json(text: str) -> Any:
        """Parse JSON from LLM response, handling formatting issues."""
        text = text.strip()
        # Strip markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Find JSON in text
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end = text.rfind(end_char) + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

        return {"raw": text[:200]}

    @property
    def stats(self) -> dict[str, Any]:
        """Return verification statistics."""
        return {
            **self._stats,
            "reflections": len(self._reflections),
            "recent_lessons": [r["lesson"] for r in self._reflections[-3:]],
        }
