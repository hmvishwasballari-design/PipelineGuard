"""Deterministic risk scoring for GitHub Actions workflows.

Pure functional calculation of workflow risk scores (0-100) and letter grades (A-F).
Combines severity weights, detector confidence, and trigger exposure multipliers
without randomness or state.

Scoring Formula:
----------------
1. Each finding has a base weight determined by its severity and confidence:
   - CRITICAL: 40.0
   - HIGH:     25.0
   - MEDIUM:   15.0
   - LOW:       6.0
   - INFO:      2.0

   Confidence multipliers:
   - HIGH:   1.0
   - MEDIUM: 0.8
   - LOW:    0.5

   finding_weight = severity_weight * confidence_multiplier

2. Aggregate finding weights:
   - max_weight = max(finding_weights) if findings else 0.0
   - sum_weight = sum(finding_weights)
   - max_component = min(max_weight, 40.0)
   - sum_component = min(0.6 * sum_weight, 40.0)
   - base_score = max_component + sum_component  (range 0.0 - 80.0)

3. Trigger exposure multiplier (applied only when findings exist):
   - pull_request_target: 1.4 (privileged execution on untrusted PR context)
   - issue_comment:       1.3 (untrusted contributor comments triggering workflow)
   - workflow_run:        1.3 (runs after untrusted workflow completed)
   - pull_request:        1.1 (standard pull request trigger)
   - push / others:       1.0 (push or default triggers)

   trigger_multiplier = max(trigger_multipliers for active triggers, default 1.0)
   raw_score = base_score * trigger_multiplier

4. Final clamping and grading:
   - score = min(100, max(0, int(round(raw_score))))
   - Grade mapping:
     - 0 - 15:  A (minimal or no risk)
     - 16 - 35: B (low risk)
     - 36 - 55: C (moderate risk)
     - 56 - 75: D (elevated risk)
     - 76 - 100: F (critical / severe risk)
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from security.workflow.constants import (
    CONFIDENCE_MULTIPLIERS,
    GRADE_A_MAX_SCORE,
    GRADE_B_MAX_SCORE,
    GRADE_C_MAX_SCORE,
    GRADE_D_MAX_SCORE,
    MAX_RISK_SCORE,
    SEVERITY_WEIGHTS,
    TRIGGER_MULTIPLIERS,
)
from security.workflow.finding import Finding
from security.workflow.models import Workflow
from security.workflow.rules import lookup

MAX_SINGLE_FINDING_COMPONENT: Final[float] = 40.0
MAX_SUM_FINDING_COMPONENT: Final[float] = 40.0
SUM_WEIGHT_FACTOR: Final[float] = 0.6
DEFAULT_FINDING_WEIGHT: Final[float] = 2.0
DEFAULT_TRIGGER_MULTIPLIER: Final[float] = 1.0
DEFAULT_CONFIDENCE_MULTIPLIER: Final[float] = 1.0


@dataclass(frozen=True)
class RiskScore:
    """Outcome of risk scoring for a workflow.

    Attributes:
        score: Integer risk score in [0, 100].
        grade: Letter grade from "A" (lowest risk) to "F" (highest risk).
    """

    score: int
    grade: str


def _extract_triggers(triggers_or_workflow: Workflow | Iterable[str] | None) -> set[str]:
    """Extract a set of trigger names from a Workflow or string iterable."""
    if triggers_or_workflow is None:
        return set()
    if isinstance(triggers_or_workflow, Workflow):
        on = triggers_or_workflow.on
        if on is None:
            return set()
        if isinstance(on, str):
            return {on}
        if isinstance(on, (list, tuple)):
            return {str(x) for x in on}
        if isinstance(on, dict):
            return {str(k) for k in on}
        return set()
    return {str(t) for t in triggers_or_workflow}


def score_to_grade(score: int) -> str:
    """Map a numerical risk score (0-100) to a letter grade (A-F)."""
    if score <= GRADE_A_MAX_SCORE:
        return "A"
    if score <= GRADE_B_MAX_SCORE:
        return "B"
    if score <= GRADE_C_MAX_SCORE:
        return "C"
    if score <= GRADE_D_MAX_SCORE:
        return "D"
    return "F"


def calculate_risk(
    findings: Sequence[Finding],
    triggers: Workflow | Iterable[str] | None = None,
) -> RiskScore:
    """Calculate a deterministic risk score (0-100) and grade for a workflow.

    Args:
        findings: The security findings associated with the workflow.
        triggers: The triggers configured for the workflow (or Workflow instance).

    Returns:
        A :class:`RiskScore` containing the integer score (0-100) and grade (A-F).
    """
    if not findings:
        return RiskScore(score=0, grade="A")

    active_triggers = _extract_triggers(triggers)

    # 1. Compute finding weights
    finding_weights: list[float] = []
    for f in findings:
        sev = lookup(f.rule_id).severity
        base_w = SEVERITY_WEIGHTS.get(sev, DEFAULT_FINDING_WEIGHT)
        conf_mult = CONFIDENCE_MULTIPLIERS.get(f.confidence, DEFAULT_CONFIDENCE_MULTIPLIER)
        finding_weights.append(base_w * conf_mult)

    max_w = max(finding_weights)
    sum_w = sum(finding_weights)

    max_component = min(max_w, MAX_SINGLE_FINDING_COMPONENT)
    sum_component = min(SUM_WEIGHT_FACTOR * sum_w, MAX_SUM_FINDING_COMPONENT)
    base_score = max_component + sum_component

    # 2. Trigger exposure multiplier
    trigger_mult = DEFAULT_TRIGGER_MULTIPLIER
    if active_triggers:
        trigger_mult = max(
            (TRIGGER_MULTIPLIERS.get(t, DEFAULT_TRIGGER_MULTIPLIER) for t in active_triggers),
            default=DEFAULT_TRIGGER_MULTIPLIER,
        )

    raw_score = base_score * trigger_mult
    score = min(MAX_RISK_SCORE, max(0, round(raw_score)))
    grade = score_to_grade(score)

    return RiskScore(score=score, grade=grade)


__all__ = [
    "RiskScore",
    "calculate_risk",
    "score_to_grade",
]
