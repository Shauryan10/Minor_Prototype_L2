#risk_score =
#   severity × severity_weight
#  + confidence × confidence_weight
#  + asset_criticality × asset_weight
#  + user_privilege × privilege_weight
#  + threat_context × threat_weight
#  + mitre_context × mitre_weight

def calculate_risk_score(
    severity: float,
    confidence: float,
    asset_criticality: float,
    user_privilege: float,
    threat_context: float,
    mitre_context: float,
) -> float:
    score = (
        severity * 0.35
        + confidence * 0.20
        + asset_criticality * 0.20
        + user_privilege * 0.10
        + threat_context * 0.10
        + mitre_context * 0.05
    )

    return round(max(0.0, min(100.0, score)), 2)

def get_risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"