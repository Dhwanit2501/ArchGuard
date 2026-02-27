"""
ArchGuard - STRIDE Rule: Repudiation
--------------------------------------
Repudiation threats arise when actions performed in the system
cannot be traced, audited, or attributed to a specific actor.

Rules:
    R-01: Logging disabled on a component
    R-02: Internet-facing component with no logging
    R-03: Component handling sensitive assets has no logging
    R-04: Boundary-crossing flow has no logging on either endpoint
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.REPUDIATION
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    # R-01: Logging disabled on any component
    for node in graph.get_nodes():
        if node.get("logging") is not False:
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.MEDIUM,
            node_zone.get("trust_level", "medium"),
        )

        threats.append(Threat(
            id          = next(_id),
            component   = node["id"],
            category    = CATEGORY,
            subcategory = "Logging Disabled",
            severity    = severity,
            description = (
                f"Logging is disabled on '{node['id']}' "
                f"(type: {node.get('type', 'unknown')}). "
                f"Actions performed by or against this component cannot be "
                f"audited or attributed. Security incidents may go undetected "
                f"and forensic investigation becomes impossible."
            ),
            sources     = [SOURCE],
            root_cause  = f"logging=False|component={node['id']}",
            mitigations = [
                "Enable structured logging on all components",
                "Forward logs to a centralized log management system (e.g. CloudWatch, ELK)",
                "Define log retention policies aligned with compliance requirements",
            ],
        ))

    # R-02: Internet-facing component with no logging
    for node in graph.get_nodes():
        if not node.get("internet_facing"):
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        threats.append(Threat(
            id          = next(_id),
            component   = node["id"],
            category    = CATEGORY,
            subcategory = "Internet-Facing Component Without Logging",
            severity    = Severity.HIGH,
            description = (
                f"'{node['id']}' is internet-facing and has logging disabled. "
                f"All external interactions with this component are unaudited. "
                f"Attackers can probe, enumerate, and exploit this component "
                f"without leaving any trace in the system."
            ),
            sources     = [SOURCE],
            root_cause  = f"internet_facing=True|logging=False|component={node['id']}",
            mitigations = [
                "Enable access logging on all internet-facing components",
                "Log all requests including source IP, method, and response codes",
                "Set up real-time alerting on anomalous access patterns",
            ],
        ))

    # R-03: Component handling sensitive assets has no logging
    sensitive_asset_ids = {
        a["id"] for a in arch.get("assets", [])
        if a.get("sensitivity") in ("high", "critical")
    }

    for edge in graph.get_edges():
        assets = edge.get("assets", [])
        if not any(a in sensitive_asset_ids for a in assets):
            continue

        # Check destination component logging
        dst_node = node_lookup.get(edge["dst"], {})
        if dst_node.get("logging") is not False:
            continue

        node_zone = zone_lookup.get(dst_node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.HIGH,
            node_zone.get("trust_level", "medium"),
            _asset_sensitivities(assets, arch),
        )

        threats.append(Threat(
            id          = next(_id),
            component   = edge["dst"],
            category    = CATEGORY,
            subcategory = "Sensitive Asset Handler Without Logging",
            severity    = severity,
            description = (
                f"'{edge['dst']}' handles sensitive assets "
                f"({', '.join(assets)}) via flow '{edge.get('flow_id', '?')}' "
                f"but has logging disabled. Access to and operations on sensitive "
                f"data cannot be audited or attributed."
            ),
            sources     = [SOURCE],
            root_cause  = f"logging=False|sensitive_assets|component={edge['dst']}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Enable audit logging on all components that handle sensitive data",
                "Log all read and write operations on sensitive assets",
                "Implement tamper-evident logging (e.g. write-once log storage)",
            ],
        ))

    # R-04: Both endpoints of a boundary-crossing flow lack logging
    for edge in graph.get_edges():
        if not edge.get("crosses_boundary"):
            continue

        src_node = node_lookup.get(edge["src"], {})
        dst_node = node_lookup.get(edge["dst"], {})

        src_no_log = src_node.get("logging") is False
        dst_no_log = dst_node.get("logging") is False

        if src_no_log and dst_no_log:
            threats.append(Threat(
                id          = next(_id),
                component   = edge["dst"],
                category    = CATEGORY,
                subcategory = "Boundary-Crossing Flow With No Logging on Either Endpoint",
                severity    = Severity.HIGH,
                description = (
                    f"Flow '{edge.get('flow_id', '?')}' crosses a trust boundary "
                    f"from '{edge['src']}' to '{edge['dst']}' but neither endpoint "
                    f"has logging enabled. Cross-boundary interactions are completely "
                    f"unaudited, making it impossible to detect or investigate "
                    f"unauthorized access."
                ),
                sources     = [SOURCE],
                root_cause  = f"boundary_no_logging|flow={edge.get('flow_id')}",
                data_flow   = edge.get("flow_id"),
                mitigations = [
                    "Enable logging on all components involved in boundary-crossing flows",
                    "Log the full request and response metadata at both endpoints",
                    "Correlate logs across boundaries using a shared request ID",
                ],
            ))

    return threats


# Helpers

def _id_counter():
    i = 1
    while True:
        yield f"R-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]