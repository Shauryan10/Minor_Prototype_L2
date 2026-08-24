from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .security_alert import SecurityAlert


class RiskAssessment(BaseModel):
    score: float
    level: str
    factors: list[dict[str, Any]] = Field(default_factory=list)
    method: str = "deterministic"


class SecurityAssessment(BaseModel):
    alert: SecurityAlert

    risk: RiskAssessment

    evidence: list[dict[str, Any]] = Field(default_factory=list)

    mitre_attack: dict[str, Any] = Field(default_factory=dict)

    recommended_next_stage: str = "llm_reasoning"

    schema_version: str = "1.0"