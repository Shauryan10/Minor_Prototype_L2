#risk_score =
#   severity × severity_weight
#  + confidence × confidence_weight
#  + asset_criticality × asset_weight
#  + user_privilege × privilege_weight
#  + threat_context × threat_weight
#  + mitre_context × mitre_weight

from __future__ import annotations

from typing import Any

from .weights import DEFAULT_WEIGHTS, SEVERITY_WEIGHTS


CRITICALITY_SCORES = {
    "unknown": 0.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

PRIVILEGE_SCORES = {
    "unknown": 0.0,
    "none": 0.0,
    "standard": 40.0,
    "user": 40.0,
    "high": 75.0,
    "privileged": 90.0,
    "root": 100.0,
    "administrator": 90.0,
}

THREAT_CONFIDENCE_SCORES = {
    "unknown": 0.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 85.0,
}


def normalize_severity(value: str | None) -> float:
    """
    Convert rule severity into 0-100.
    """
    if not value:
        return 0.0

    raw = SEVERITY_WEIGHTS.get(value.lower(), 0)
    return (raw / 50.0) * 100.0


def normalize_confidence(value: float | None) -> float:
    """
    Convert confidence in [0,1] to [0,100].
    """
    if value is None:
        return 0.0

    return max(0.0, min(float(value), 1.0)) * 100.0


def normalize_asset_criticality(value: Any) -> float:
    if value is None:
        return 0.0

    key = str(value).strip().lower()
    return CRITICALITY_SCORES.get(key, 0.0)


def normalize_user_privilege(value: Any) -> float:
    if value is None:
        return 0.0

    key = str(value).strip().lower()
    return PRIVILEGE_SCORES.get(key, 0.0)


def normalize_threat_context(
    threat_context: dict[str, Any] | None,
) -> float:
    if not threat_context:
        return 0.0

    ioc_matches = threat_context.get("ioc_matches") or []

    if ioc_matches:
        confidence = str(
            threat_context.get("confidence", "medium")
        ).lower()

        if confidence in THREAT_CONFIDENCE_SCORES:
            return THREAT_CONFIDENCE_SCORES[confidence]

        numeric_confidence = threat_context.get("confidence")

        if isinstance(numeric_confidence, (int, float)):
            return normalize_confidence(float(numeric_confidence))

        return 50.0

    return 0.0


def normalize_mitre_context(
    mitre_attack: dict[str, Any] | None,
) -> float:
    if not mitre_attack:
        return 0.0

    techniques = mitre_attack.get("techniques") or []
    tactics = mitre_attack.get("tactics") or []

    if not techniques and not tactics:
        return 0.0

    confidence = mitre_attack.get("confidence")

    if isinstance(confidence, (int, float)):
        return normalize_confidence(float(confidence))

    return 50.0


def calculate_risk_score(
    *,
    severity: str,
    confidence: float,
    asset_criticality: Any,
    user_privilege: Any,
    threat_context: dict[str, Any] | None,
    mitre_attack: dict[str, Any] | None,
    weights: dict[str, float] | None = None,
) -> tuple[float, list[dict[str, Any]]]:
    """
    Deterministic weighted risk calculation.

    All factor values are normalized to [0,100].
    """

    active_weights = dict(weights or DEFAULT_WEIGHTS)

    factor_values = {
        "severity": normalize_severity(severity),
        "confidence": normalize_confidence(confidence),
        "asset_criticality": normalize_asset_criticality(
            asset_criticality
        ),
        "user_privilege": normalize_user_privilege(
            user_privilege
        ),
        "threat_context": normalize_threat_context(
            threat_context
        ),
        "mitre_context": normalize_mitre_context(
            mitre_attack
        ),
    }

    # Keep only configured factors.
    total_weight = sum(
        float(active_weights.get(key, 0.0))
        for key in factor_values
    )

    if total_weight <= 0:
        raise ValueError("Risk weights must contain a positive total weight.")

    # Normalize weights in case the configuration does not sum exactly to 1.
    normalized_weights = {
        key: float(active_weights.get(key, 0.0)) / total_weight
        for key in factor_values
    }

    contributions: list[dict[str, Any]] = []

    score = 0.0

    for factor_name, factor_value in factor_values.items():
        weight = normalized_weights[factor_name]
        contribution = factor_value * weight

        score += contribution

        contributions.append(
            {
                "factor": factor_name,
                "value": round(factor_value, 2),
                "weight": round(weight, 4),
                "contribution": round(contribution, 2),
            }
        )

    score = round(max(0.0, min(score, 100.0)), 2)

    return score, contributions