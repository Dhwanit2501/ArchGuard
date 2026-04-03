"""
ArchGuard - Attack Path: Finder
---------------------------------
Finds realistic multi-step attack paths through the architecture graph
using identified threats and their ATT&CK/ATLAS technique mappings.

Algorithm:
    1. Find entry points  — internet-facing or untrusted-reachable components
                            with threats
    2. Find target nodes  — components with high-sensitivity assets,
                            Exfiltration/Impact techniques, or credential stores
    3. DFS traversal      — find all paths from entry to target,
                            bounded by max depth and threat-annotated edges
    4. Build attack steps — map each component along the path to its
                            most relevant threat and technique, advancing
                            the kill chain and preferring ATLAS on AI components
    5. Score and rank     — return top 5 paths by severity score

Key design decisions:
    - Kill chain advances: each step uses a tactic LATER than the previous step
    - Framework preference: ATLAS techniques preferred on AI components (agentic)
    - Entry point requires at least one identified threat
    - Targets include credential/PII stores and Exfiltration/Impact components
"""

from Threat_Engine.model import Threat, Severity
from graph.base import GraphInterface
from Threat_Engine.Attack_Path.Tactic_order import (
    get_primary_tactic, get_tactic_rank,
    is_entry_tactic, is_terminal_tactic,
)
from Threat_Engine.Attack_Path.Scorer import score_path, rank_paths


MAX_PATH_DEPTH = 6
MAX_PATHS      = 20

# Component types considered AI-native — prefer ATLAS techniques on these
AI_COMPONENT_TYPES = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}


def find_attack_paths(
    graph: GraphInterface,
    arch:  dict,
    threats: list[Threat],
) -> list[dict]:
    """Main entry point. Returns top 5 ranked attack paths."""
    is_agentic   = arch.get("project", {}).get("architecture_type") == "agentic-ai"
    node_lookup  = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup  = {tz["id"]: tz for tz in arch.get("trust_zones", [])}
    asset_lookup = {a["id"]: a for a in arch.get("assets", [])}

    threats_by_component: dict[str, list[Threat]] = {}
    for t in threats:
        threats_by_component.setdefault(t.component, []).append(t)

    threats_by_id = {t.id: t for t in threats}

    adjacency: dict[str, list[str]] = {}
    for edge in graph.get_edges():
        adjacency.setdefault(edge["src"], []).append(edge["dst"])

    entry_points = _find_entry_points(node_lookup, zone_lookup, threats_by_component)
    targets      = _find_targets(node_lookup, threats_by_component, asset_lookup, is_agentic)

    if not entry_points or not targets:
        return []

    all_paths = []
    for entry in entry_points:
        if len(all_paths) >= MAX_PATHS:
            break
        _dfs(entry, [entry], {entry}, targets, adjacency,
             threats_by_component, all_paths, MAX_PATH_DEPTH)

    if not all_paths:
        return []

    built_paths = []
    for i, component_path in enumerate(all_paths):
        built = _build_path(
            component_path, threats_by_component, threats_by_id,
            asset_lookup, node_lookup, is_agentic, i + 1,
        )
        if built:
            built_paths.append(built)

    return rank_paths(built_paths)


# Entry points and targets

def _find_entry_points(node_lookup, zone_lookup, threats_by_component):
    entries = []
    for node_id, node in node_lookup.items():
        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        is_exposed = (
            node.get("internet_facing", False)
            or trust_level == "untrusted"
        )

        if not is_exposed:
            continue

        # Must have at least one identified threat
        if not threats_by_component.get(node_id):
            continue

        entries.append(node_id)

    return entries


def _find_targets(node_lookup, threats_by_component, asset_lookup, is_agentic):
    targets = set()

    for node_id, node in node_lookup.items():
        if node.get("stores_credentials") or node.get("stores_pii"):
            targets.add(node_id)
            continue

        for threat in threats_by_component.get(node_id, []):
            for mapping in threat.attack_mapping:
                tactics = mapping.get("tactics", [mapping.get("tactic", "")])
                if isinstance(tactics, str):
                    tactics = [tactics]
                if any(is_terminal_tactic(t) for t in tactics):
                    targets.add(node_id)
                    break

    return targets


# DFS traversal

def _dfs(current, path, visited, targets, adjacency,
         threats_by_component, all_paths, max_depth):
    if len(all_paths) >= MAX_PATHS:
        return

    if current in targets and len(path) > 1:
        all_paths.append(list(path))
        return

    if len(path) >= max_depth:
        return

    for neighbour in adjacency.get(current, []):
        if neighbour in visited:
            continue
        if neighbour not in targets and not threats_by_component.get(neighbour):
            continue
        visited.add(neighbour)
        path.append(neighbour)
        _dfs(neighbour, path, visited, targets, adjacency,
             threats_by_component, all_paths, max_depth)
        path.pop()
        visited.remove(neighbour)


# Path building with kill chain advancement and framework preference

def _build_path(component_path, threats_by_component, threats_by_id,
                asset_lookup, node_lookup, is_agentic, path_index):
    steps      = []
    threat_ids = []

    # Track last tactic rank to advance kill chain
    last_tactic_rank = -1

    is_first = True
    for component in component_path:
        component_threats = threats_by_component.get(component, [])
        node             = node_lookup.get(component, {})
        node_type        = node.get("type", "")
        is_ai_component  = node_type in AI_COMPONENT_TYPES

        # Target with no threats — mark as reached
        if not component_threats:
            if component == component_path[-1]:
                steps.append({
                    "step"              : len(steps) + 1,
                    "component"         : component,
                    "component_type"    : node_type,
                    "tactic"            : "Impact",
                    "technique_id"      : "",
                    "technique_name"    : "Target Reached",
                    "framework"         : "",
                    "threat_id"         : "",
                    "threat_subcategory": "High-value target accessed",
                    "threat_severity"   : "High",
                })
            continue

        # Pick best threat and technique
        best_threat, best_mapping = _pick_advancing_step(
            component_threats = component_threats,
            last_tactic_rank  = last_tactic_rank,
            is_first          = is_first,
            is_ai_component   = is_ai_component,
            is_agentic        = is_agentic,
        )

        if not best_mapping:
            is_first = False
            continue

        tactics = best_mapping.get("tactics", [best_mapping.get("tactic", "Unknown")])
        if isinstance(tactics, str):
            tactics = [tactics]

        primary_tactic   = get_primary_tactic(tactics, is_agentic)
        last_tactic_rank = get_tactic_rank(primary_tactic, is_agentic)
        is_first         = False

        steps.append({
            "step"              : len(steps) + 1,
            "component"         : component,
            "component_type"    : node_type,
            "tactic"            : primary_tactic,
            "technique_id"      : best_mapping.get("technique_id", ""),
            "technique_name"    : best_mapping.get("technique_name", ""),
            "framework"         : best_mapping.get("framework", ""),
            "threat_id"         : best_threat.id,
            "threat_subcategory": best_threat.subcategory,
            "threat_severity"   : best_threat.severity.value,
        })
        threat_ids.append(best_threat.id)

    if len(steps) < 2:
        return None

    target_assets = [
        asset.get("sensitivity", "low")
        for asset in asset_lookup.values()
        if asset.get("sensitivity") in ("high", "critical")
    ]

    path = {
        "id"                   : f"AP-{path_index:03d}",
        "entry_point"          : component_path[0],
        "target"               : component_path[-1],
        "components_traversed" : component_path,
        "steps"                : steps,
        "threat_ids"           : threat_ids,
        "threats_by_id"        : threats_by_id,
        "target_assets"        : target_assets,
        "step_count"           : len(steps),
    }

    path["score"]    = score_path(path)
    path["severity"] = _path_severity(steps)
    path["name"]     = _path_name(component_path, steps)

    del path["threats_by_id"]
    return path


def _pick_advancing_step(component_threats, last_tactic_rank,
                          is_first, is_ai_component, is_agentic):
    """
    Pick the best threat and technique for a path step.

    Rules:
    1. First step — prefer Initial Access / AI Model Access techniques
    2. Subsequent steps — prefer techniques whose tactic is LATER in
       the kill chain than the previous step (advancing)
    3. On AI components in agentic architectures — prefer ATLAS techniques
       over ATT&CK since they better describe AI-specific exploitation
    4. Fallback — if no advancing technique exists, pick the best
       available technique rather than leaving the step empty
    """

    def score_mapping(mapping, threat, prefer_atlas):
        tactics = mapping.get("tactics", [mapping.get("tactic", "Unknown")])
        if isinstance(tactics, str):
            tactics = [tactics]

        primary_tactic = get_primary_tactic(tactics, is_agentic)
        tactic_rank    = get_tactic_rank(primary_tactic, is_agentic)
        framework      = mapping.get("framework", "").upper()
        severity_score = _severity_rank(threat.severity)

        # Bonus for advancing the kill chain
        advances = tactic_rank > last_tactic_rank
        advance_bonus = 100 if advances else 0

        # Bonus for ATLAS on AI components in agentic architectures
        atlas_bonus = 50 if (prefer_atlas and framework == "ATLAS") else 0

        # Penalty for going backwards in kill chain
        backward_penalty = -200 if (not is_first and tactic_rank < last_tactic_rank) else 0

        return advance_bonus + atlas_bonus + severity_score + backward_penalty - tactic_rank

    prefer_atlas = is_ai_component and is_agentic

    # Collect all (threat, mapping) pairs
    candidates = []
    for threat in component_threats:
        for mapping in threat.attack_mapping:
            candidates.append((threat, mapping))

    if not candidates:
        return None, None

    # First step — filter to Initial Access / AI Model Access
    if is_first:
        entry_candidates = [
            (t, m) for t, m in candidates
            if any(tac in ("Initial Access", "AI Model Access")
                   for tac in (m.get("tactics", []) if isinstance(m.get("tactics"), list)
                                else [m.get("tactic", "")]))
        ]
        if entry_candidates:
            candidates = entry_candidates

    # Score and pick best
    best_threat, best_mapping = max(
        candidates,
        key=lambda pair: score_mapping(pair[1], pair[0], prefer_atlas)
    )

    return best_threat, best_mapping



def _severity_rank(severity: Severity) -> int:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        return order.index(severity)
    except ValueError:
        return 0


def _path_severity(steps: list) -> str:
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    if not steps:
        return "Low"
    return max(
        (s.get("threat_severity", "Low") for s in steps),
        key=lambda s: severity_rank.get(s, 0)
    )


def _path_name(component_path: list, steps: list) -> str:
    if not steps:
        return f"{component_path[0]} -> {component_path[-1]}"
    first_tactic = steps[0].get("tactic", "Initial Access")
    last_tactic  = steps[-1].get("tactic", "Impact")
    return f"{first_tactic} via {component_path[0]} -> {last_tactic} on {component_path[-1]}"