from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ContextEnrichedEvent(BaseModel):
    """
    Contract consumed by L2.

    L2 does not parse raw logs and does not perform source-specific
    normalization. The upstream module is responsible for creating this
    object.
    """

    event_id: str
    timestamp: str
    normalized_event: dict[str, Any] = Field(default_factory=dict)

    entities: dict[str, Any] = Field(default_factory=dict)
    asset_context: dict[str, Any] = Field(default_factory=dict)
    user_context: dict[str, Any] = Field(default_factory=dict)
    threat_context: dict[str, Any] = Field(default_factory=dict)

    mitre_attack: dict[str, Any] = Field(default_factory=dict)
    retrieved_context: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_metadata: dict[str, Any] = Field(default_factory=dict)