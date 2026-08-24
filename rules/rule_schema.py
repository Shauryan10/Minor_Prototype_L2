from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class RuleCondition(BaseModel):
    field: str
    operator: Literal[
        "equals",
        "contains",
        "greater_than",
        "less_than",
        "in",
    ]
    value: Any


class RuleDefinition(BaseModel):
    rule_id: str
    rule_name: str
    description: str = ""

    conditions: list[RuleCondition] = Field(default_factory=list)

    severity: str = "medium"
    confidence: float = 0.5

    threshold: int | None = None
    window_minutes: int | None = None
    group_by: str | None = None

    mitre_attack: dict[str, Any] = Field(default_factory=dict)

    enabled: bool = True

    action: str = "generate_alert"