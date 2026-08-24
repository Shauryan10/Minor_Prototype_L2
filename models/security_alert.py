from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SecurityAlert(BaseModel):
    alert_id: str
    event_ids: list[str] = Field(default_factory=list)

    rule_id: str
    rule_name: str

    severity: str
    confidence: float

    mitre_attack: dict[str, Any] = Field(default_factory=dict)
    entities: dict[str, Any] = Field(default_factory=dict)

    asset_context: dict[str, Any] = Field(default_factory=dict)
    user_context: dict[str, Any] = Field(default_factory=dict)
    threat_context: dict[str, Any] = Field(default_factory=dict)

    evidence: list[dict[str, Any]] = Field(default_factory=list)
    triggered_conditions: list[dict[str, Any]] = Field(default_factory=list)

    timestamp: str
    status: str = "new"