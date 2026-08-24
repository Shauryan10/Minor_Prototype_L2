# Single source of truth for the deterministic risk model.
#
# The configurable weights live in rules_config/risk_weights.json.
# DEFAULT_WEIGHTS is only the fallback used when that file is
# missing, empty or malformed.

from __future__ import annotations


SEVERITY_WEIGHT = 0.35
CONFIDENCE_WEIGHT = 0.20
ASSET_CRITICALITY_WEIGHT = 0.20
USER_PRIVILEGE_WEIGHT = 0.10
THREAT_CONTEXT_WEIGHT = 0.10
MITRE_CONTEXT_WEIGHT = 0.05

DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": SEVERITY_WEIGHT,
    "confidence": CONFIDENCE_WEIGHT,
    "asset_criticality": ASSET_CRITICALITY_WEIGHT,
    "user_privilege": USER_PRIVILEGE_WEIGHT,
    "threat_context": THREAT_CONTEXT_WEIGHT,
    "mitre_context": MITRE_CONTEXT_WEIGHT,
}

RISK_FACTORS: tuple[str, ...] = (
    "severity",
    "confidence",
    "asset_criticality",
    "user_privilege",
    "threat_context",
    "mitre_context",
)

# ---------------------------------------------------------------
# Factor normalization tables (all values are on the 0-100 scale)
# ---------------------------------------------------------------

SEVERITY_SCORES: dict[str, float] = {
    "info": 0.0,
    "informational": 0.0,
    "unknown": 0.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

CRITICALITY_SCORES: dict[str, float] = {
    "unknown": 0.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

PRIVILEGE_SCORES: dict[str, float] = {
    "unknown": 0.0,
    "none": 0.0,
    "standard": 40.0,
    "user": 40.0,
    "service": 60.0,
    "high": 75.0,
    "privileged": 90.0,
    "administrator": 90.0,
    "admin": 90.0,
    "domain_admin": 100.0,
    "root": 100.0,
}

# Qualitative threat-intelligence confidence, used only when
# actual IOC/threat evidence is present on the alert.
THREAT_CONFIDENCE_SCORES: dict[str, float] = {
    "unknown": 0.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 85.0,
    "confirmed": 100.0,
}

# Score used when threat/MITRE evidence exists but carries no
# usable confidence value.
NEUTRAL_EVIDENCE_SCORE = 50.0

# ---------------------------------------------------------------
# Risk level thresholds
#
#   0     <= score < 25   -> low
#   25    <= score < 50   -> medium
#   50    <= score < 75   -> high
#   75    <= score <= 100 -> critical
# ---------------------------------------------------------------

RISK_LEVEL_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (25.0, "low"),
    (50.0, "medium"),
    (75.0, "high"),
)

MAX_RISK_LEVEL = "critical"
