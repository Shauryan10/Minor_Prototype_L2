# Deterministic weighted risk score.
#
# risk_score =
#     severity           x severity_weight
#   + confidence         x confidence_weight
#   + asset_criticality  x asset_criticality_weight
#   + user_privilege     x user_privilege_weight
#   + threat_context     x threat_context_weight
#   + mitre_context      x mitre_context_weight
#
# Every factor is normalized to [0,100] and the configured weights
# are re-normalized to sum to 1.0, so the final score stays in
# [0,100].

from __future__ import annotations

from typing import Any

from .weights import (
    CRITICALITY_SCORES,
    DEFAULT_WEIGHTS,
    NEUTRAL_EVIDENCE_SCORE,
    PRIVILEGE_SCORES,
    RISK_FACTORS,
    SEVERITY_SCORES,
    THREAT_CONFIDENCE_SCORES,
)


# Keys that may carry actual threat/IOC evidence on threat_context.
THREAT_EVIDENCE_KEYS = (
    "ioc_matches",
    "iocs",
    "matches",
    "indicators",
    "threat_matches",
)

# Keys that may carry a MITRE technique or tactic mapping.
MITRE_TECHNIQUE_KEYS = (
    "techniques",
    "technique_id",
    "technique_name",
    "technique",
)

MITRE_TACTIC_KEYS = (
    "tactics",
    "tactic_id",
    "tactic_name",
    "tactic",
)


def _clamp(value: float) -> float:
    return max(0.0, min(float(value), 100.0))


def _confidence_to_scale(value: Any) -> float | None:
    """
    Interpret a confidence-like value on the 0-100 scale.

    Values in [0,1] are treated as fractions, values above 1 are
    treated as already being on the 0-100 scale.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    numeric = float(value)

    if numeric <= 1.0:
        return _clamp(numeric * 100.0)

    return _clamp(numeric)


def normalize_severity(value: Any) -> float:
    """
    Map the project severity vocabulary (low/medium/high/critical)
    to 0-100. Numeric severities are clamped into range.
    """

    if value is None:
        return 0.0

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _clamp(float(value))

    return SEVERITY_SCORES.get(str(value).strip().lower(), 0.0)


def normalize_confidence(value: Any) -> float:
    """
    Convert a detection confidence in [0,1] to [0,100].
    """

    scaled = _confidence_to_scale(value)

    return 0.0 if scaled is None else scaled


def normalize_asset_criticality(value: Any) -> float:
    if value is None:
        return 0.0

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _clamp(float(value))

    return CRITICALITY_SCORES.get(str(value).strip().lower(), 0.0)


def normalize_user_privilege(value: Any) -> float:
    if value is None:
        return 0.0

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _clamp(float(value))

    return PRIVILEGE_SCORES.get(str(value).strip().lower(), 0.0)


def _has_threat_evidence(threat_context: dict[str, Any]) -> bool:
    """
    Presence of threat_context alone is not evidence of a threat.
    """

    for key in THREAT_EVIDENCE_KEYS:
        if threat_context.get(key):
            return True

    for key in ("is_malicious", "known_malicious", "threat_detected"):
        if threat_context.get(key) is True:
            return True

    reputation = threat_context.get("reputation")

    if isinstance(reputation, str) and reputation.strip().lower() in (
        "malicious",
        "suspicious",
    ):
        return True

    return False


def normalize_threat_context(
    threat_context: dict[str, Any] | None,
) -> float:
    """
    Score threat intelligence only when there is real evidence
    (IOC matches, malicious reputation, ...). Missing or empty
    threat context contributes 0 instead of a fabricated score.
    """

    if not isinstance(threat_context, dict) or not threat_context:
        return 0.0

    if not _has_threat_evidence(threat_context):
        return 0.0

    confidence = threat_context.get("confidence")

    if isinstance(confidence, str):
        key = confidence.strip().lower()

        if key in THREAT_CONFIDENCE_SCORES:
            return THREAT_CONFIDENCE_SCORES[key]

    scaled = _confidence_to_scale(confidence)

    if scaled is not None:
        return scaled

    return NEUTRAL_EVIDENCE_SCORE


def _has_mitre_mapping(mitre_attack: dict[str, Any]) -> bool:
    for key in MITRE_TECHNIQUE_KEYS + MITRE_TACTIC_KEYS:
        if mitre_attack.get(key):
            return True

    return False


def normalize_mitre_context(
    mitre_attack: dict[str, Any] | None,
) -> float:
    """
    A mapped technique/tactic produces a non-zero factor. The
    existing MITRE mapping confidence is used when available.
    """

    if not isinstance(mitre_attack, dict) or not mitre_attack:
        return 0.0

    if not _has_mitre_mapping(mitre_attack):
        return 0.0

    scaled = _confidence_to_scale(
        mitre_attack.get("confidence")
    )

    if scaled is not None:
        return scaled

    return NEUTRAL_EVIDENCE_SCORE


def normalize_weights(
    weights: dict[str, float] | None = None,
) -> dict[str, float]:
    """
    Restrict weights to the known risk factors and re-normalize
    them so that they sum to 1.0.
    """

    active_weights = dict(weights or DEFAULT_WEIGHTS)

    resolved: dict[str, float] = {}

    for factor in RISK_FACTORS:
        try:
            resolved[factor] = max(
                0.0,
                float(active_weights.get(factor, 0.0)),
            )
        except (TypeError, ValueError):
            resolved[factor] = 0.0

    total_weight = sum(resolved.values())

    if total_weight <= 0:
        resolved = dict(DEFAULT_WEIGHTS)
        total_weight = sum(resolved.values())

    return {
        factor: value / total_weight
        for factor, value in resolved.items()
    }


def calculate_risk_score(
    *,
    severity: Any,
    confidence: Any,
    asset_criticality: Any,
    user_privilege: Any,
    threat_context: dict[str, Any] | None,
    mitre_attack: dict[str, Any] | None,
    weights: dict[str, float] | None = None,
) -> tuple[float, list[dict[str, Any]]]:
    """
    Deterministic weighted risk calculation.

    Returns the final score in [0,100] and the individual factor
    contributions used to produce it.
    """

    normalized_weights = normalize_weights(weights)

    factor_values: dict[str, float] = {
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

    contributions: list[dict[str, Any]] = []

    score = 0.0

    for factor in RISK_FACTORS:
        factor_value = factor_values[factor]
        weight = normalized_weights[factor]
        contribution = factor_value * weight

        score += contribution

        contributions.append(
            {
                "factor": factor,
                "value": round(factor_value, 2),
                "weight": round(weight, 4),
                "contribution": round(contribution, 2),
            }
        )

    score = round(_clamp(score), 2)

    return score, contributions
