from __future__ import annotations

import json
from pathlib import Path

from models.security_alert import SecurityAlert
from models.security_assessment import RiskAssessment

from .scoring import calculate_risk_score
from .weights import DEFAULT_WEIGHTS


DEFAULT_WEIGHTS_PATH = (
    Path(__file__).resolve().parent.parent
    / "rules_config"
    / "risk_weights.json"
)


def _risk_level(score: float) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _load_weights(path: str | Path | None = None) -> dict[str, float]:
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

        if not isinstance(data, dict):
            return dict(DEFAULT_WEIGHTS)

        return {
            str(key): float(value)
            for key, value in data.items()
        }

    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return dict(DEFAULT_WEIGHTS)


class RiskEngine:
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
        score, factor_details = calculate_risk_score(
            severity=alert.severity,
            confidence=alert.confidence,
            asset_criticality=alert.asset_context.get(
                "criticality"
            ),
            user_privilege=alert.user_context.get(
                "privilege_level"
            ),
            threat_context=alert.threat_context,
            mitre_attack=alert.mitre_attack,
            weights=self.weights,
        )

        return RiskAssessment(
            score=score,
            level=_risk_level(score),
            factors=factor_details,
            method="deterministic_weighted",
        )