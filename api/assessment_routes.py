from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from models.context_enriched_event import ContextEnrichedEvent
from models.security_alert import SecurityAlert
from models.security_assessment import SecurityAssessment
from risk.risk_engine import RiskEngine
from rules.rule_engine import RuleEngine


router = APIRouter(
    prefix="/api/l2",
    tags=["L2 Assessment"],
)

rule_engine = RuleEngine()
risk_engine = RiskEngine()

NEXT_STAGE = "llm_reasoning"


class BatchAssessmentRequest(BaseModel):
    events: list[ContextEnrichedEvent] = Field(
        default_factory=list
    )


def _to_assessments(
    alerts: list[SecurityAlert],
) -> list[SecurityAssessment]:
    """
    SecurityAlert -> RiskEngine.assess() -> SecurityAssessment.
    """

    assessments: list[SecurityAssessment] = []

    for alert in alerts:
        assessments.append(
            SecurityAssessment(
                alert=alert,
                risk=risk_engine.assess(alert),
                evidence=alert.evidence,
                mitre_attack=alert.mitre_attack,
                recommended_next_stage=NEXT_STAGE,
            )
        )

    return assessments


def assess_event(
    event: ContextEnrichedEvent,
) -> list[SecurityAssessment]:
    """
    Single-event assessment. Threshold rules are skipped here
    because they require the complete event collection.
    """

    return _to_assessments(
        rule_engine.evaluate_event(event)
    )


def assess_events(
    events: list[ContextEnrichedEvent],
) -> list[SecurityAssessment]:
    """
    Batch assessment over the complete enriched-event collection so
    threshold, time-window and group-by rules can trigger.
    """

    return _to_assessments(
        rule_engine.evaluate_events(events)
    )


@router.post(
    "/assess",
    response_model=list[SecurityAssessment],
)
def assess_single_event(
    event: ContextEnrichedEvent,
) -> list[SecurityAssessment]:
    try:
        return assess_event(event)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Assessment failed: {exc}",
        ) from exc


@router.post(
    "/assess/batch",
    response_model=list[SecurityAssessment],
)
def assess_batch(
    request: BatchAssessmentRequest | list[ContextEnrichedEvent],
) -> list[SecurityAssessment]:
    events = (
        request
        if isinstance(request, list)
        else request.events
    )

    try:
        return assess_events(events)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Batch assessment failed: {exc}",
        ) from exc
