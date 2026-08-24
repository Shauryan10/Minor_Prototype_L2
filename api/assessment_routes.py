from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from models.context_enriched_event import ContextEnrichedEvent
from models.security_assessment import SecurityAssessment
from rules.rule_engine import RuleEngine
from risk.risk_engine import RiskEngine


router = APIRouter(
    prefix="/api/l2",
    tags=["L2 Assessment"],
)

rule_engine = RuleEngine()
risk_engine = RiskEngine()


class BatchAssessmentRequest(BaseModel):
    events: list[ContextEnrichedEvent]


def _assess_event(
    event: ContextEnrichedEvent,
) -> list[SecurityAssessment]:
    alerts = rule_engine.evaluate_event(event)

    assessments: list[SecurityAssessment] = []

    for alert in alerts:
        risk = risk_engine.assess(alert)

        assessments.append(
            SecurityAssessment(
                alert=alert,
                risk=risk,
                evidence=alert.evidence,
                mitre_attack=alert.mitre_attack,
                recommended_next_stage="llm_reasoning",
                schema_version="1.0",
            )
        )

    return assessments


@router.post(
    "/assess",
    response_model=list[SecurityAssessment],
)
def assess_single_event(
    event: ContextEnrichedEvent,
) -> list[SecurityAssessment]:
    try:
        return _assess_event(event)

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
    request: BatchAssessmentRequest,
) -> list[SecurityAssessment]:
    try:
        return _assess_batch(request.events)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Batch assessment failed: {exc}",
        ) from exc


def _assess_batch(
    events: list[ContextEnrichedEvent],
) -> list[SecurityAssessment]:
    """
    Run rules across the complete event set.

    This is important because threshold/time-window rules
    require multiple events at once.
    """
    alerts = rule_engine.evaluate_events(events)

    assessments: list[SecurityAssessment] = []

    for alert in alerts:
        risk = risk_engine.assess(alert)

        assessments.append(
            SecurityAssessment(
                alert=alert,
                risk=risk,
                evidence=alert.evidence,
                mitre_attack=alert.mitre_attack,
                recommended_next_stage="llm_reasoning",
                schema_version="1.0",
            )
        )

    return assessments