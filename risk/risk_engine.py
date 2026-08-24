from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models.security_alert import SecurityAlert
from models.security_assessment import RiskAssessment

from .scoring import calculate_risk_score
from .weights import (
    DEFAULT_WEIGHTS,
    MAX_RISK_LEVEL,
    RISK_LEVEL_THRESHOLDS,
)


DEFAULT_WEIGHTS_PATH = (
    Path(__file__).resolve().parent.parent
    / "rules_config"
    / "risk_weights.json"
)

RISK_METHOD = "deterministic_weighted"

# Field names used by the L2 enrichment for asset criticality
# and user privilege.
ASSET_CRITICALITY_KEYS = (
    "criticality",
    "asset_criticality",
    "criticality_level",
)

USER_PRIVILEGE_KEYS = (
    "privilege",
    "privilege_level",
    "privileges",
    "role",
)


def risk_level(score: float) -> str:
    """
    Transparent threshold mapping:

        0     <= score < 25   -> low
        25    <= score < 50   -> medium
        50    <= score < 75   -> high
        75    <= score <= 100 -> critical
    """

    for upper_bound, level in RISK_LEVEL_THRESHOLDS:
        if score < upper_bound:
            return level

    return MAX_RISK_LEVEL


def _load_weights(path: str | Path | None = None) -> dict[str, float]:
    """
    Load the configurable weights from rules_config/risk_weights.json.

    Falls back to DEFAULT_WEIGHTS when the file is missing, empty or
    malformed.
    """

    weights_path = Path(path or DEFAULT_WEIGHTS_PATH)

    if not weights_path.exists():
        return dict(DEFAULT_WEIGHTS)

    try:
        content = weights_path.read_text(
            encoding="utf-8"
        ).strip()

        if not content:
            return dict(DEFAULT_WEIGHTS)

        data = json.loads(content)

        if not isinstance(data, dict) or not data:
            return dict(DEFAULT_WEIGHTS)

        return {
            str(key): float(value)
            for key, value in data.items()
        }

    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return dict(DEFAULT_WEIGHTS)


def _first_present(
    context: dict[str, Any] | None,
    keys: tuple[str, ...],
) -> Any:
    """
    Return the first non-empty value found under the given keys.
    """

    if not isinstance(context, dict):
        return None

    for key in keys:
        value = context.get(key)

        if value not in (None, "", [], {}):
            return value

    return None


class RiskEngine:
    """
    Deterministic risk assessment for SecurityAlert objects.

    The engine never parses raw events: it consumes only the fields
    the Rule Engine already placed on the alert.
    """

    def __init__(
        self,
        weights_path: str | Path | None = None,
    ) -> None:
        self.weights_path = Path(
            weights_path or DEFAULT_WEIGHTS_PATH
        )
        self.weights = _load_weights(self.weights_path)

    def reload_weights(self) -> None:
        self.weights = _load_weights(self.weights_path)

    def assess(
        self,
        alert: SecurityAlert,
    ) -> RiskAssessment:
        score, factors = calculate_risk_score(
            severity=alert.severity,
            confidence=alert.confidence,
            asset_criticality=_first_present(
                alert.asset_context,
                ASSET_CRITICALITY_KEYS,
            ),
            user_privilege=_first_present(
                alert.user_context,
                USER_PRIVILEGE_KEYS,
            ),
            threat_context=alert.threat_context,
            mitre_attack=alert.mitre_attack,
            weights=self.weights,
        )

        return RiskAssessment(
            score=score,
            level=risk_level(score),
            factors=factors,
            method=RISK_METHOD,
        )
