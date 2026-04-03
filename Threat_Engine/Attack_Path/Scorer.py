"""
ArchGuard - Attack Path: Scorer
---------------------------------
Scores and ranks attack paths based on severity, tactic coverage,
asset sensitivity, and path length.

Scoring factors:
    1. Maximum severity of threats along the path (0-40 points)
    2. Number of Critical/High threats along the path (0-30 points)
    3. Sensitivity of assets at the target component (0-20 points)
    4. Tactic coverage — high value tactics present (0-10 points)
"""

from Threat_Engine.model import Severity
from Threat_Engine.Attack_Path.Tactic_order import HIGH_VALUE_TACTICS

SEVERITY_SCORES = {
    Severity.CRITICAL: 40,
    Severity.HIGH:     30,
    Severity.MEDIUM:   20,
    Severity.LOW:      10,
}

SENSITIVITY_SCORES = {
    "critical": 20,
    "high":     15,
    "medium":   10,
    "low":       5,
}


def score_path(path: dict) -> int:
    """
    Score an attack path on a 0-100 scale.

    path dict expected keys:
        steps           : list of step dicts
        target_assets   : list of asset sensitivity strings
        threat_ids      : list of threat IDs along the path
        threats_by_id   : dict of threat_id -> Threat object
    """
    score = 0

    threats_by_id = path.get("threats_by_id", {})
    steps         = path.get("steps", [])
    target_assets = path.get("target_assets", [])

    # 1. Maximum severity score (0-40)
    severities = [
        threats_by_id[s["threat_id"]].severity
        for s in steps
        if s.get("threat_id") and s["threat_id"] in threats_by_id
    ]
    if severities:
        max_sev = max(severities, key=lambda s: list(SEVERITY_SCORES.keys()).index(s)
                      if s in SEVERITY_SCORES else 0)
        score += SEVERITY_SCORES.get(max_sev, 0)

    # 2. Critical/High threat count (0-30, capped)
    critical_high = sum(
        1 for s in steps
        if s.get("threat_id") and s["threat_id"] in threats_by_id
        and threats_by_id[s["threat_id"]].severity in (Severity.CRITICAL, Severity.HIGH)
    )
    score += min(critical_high * 10, 30)

    # 3. Target asset sensitivity (0-20)
    if target_assets:
        max_sensitivity = max(
            SENSITIVITY_SCORES.get(s, 0) for s in target_assets
        )
        score += max_sensitivity

    # 4. High value tactic coverage (0-10)
    tactics_in_path = {s.get("tactic", "") for s in steps}
    high_value_covered = len(tactics_in_path & HIGH_VALUE_TACTICS)
    score += min(high_value_covered * 3, 10)

    return min(score, 100)


def rank_paths(paths: list[dict]) -> list[dict]:
    """
    Sort paths by score descending, return top 5.
    Adds 'rank' field to each path.
    """
    scored = sorted(paths, key=lambda p: p.get("score", 0), reverse=True)
    top5   = scored[:5]

    for i, path in enumerate(top5, start=1):
        path["rank"] = i

    return top5