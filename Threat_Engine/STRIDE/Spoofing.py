"""
ArchGuard - STRIDE Rule: Spoofing
----------------------------------
Spoofing threats arise when a component or data flow fails to properly
verify the identity of the sender or caller.

Rules:
    S-01: Unauthenticated flow crossing a trust boundary
    S-02: Internet-facing component with no authentication mechanism
    S-03: Internal service reachable directly from untrusted zone
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity, bump_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.SPOOFING
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    # S-01: Unauthenticated boundary-crossing flow
    for edge in graph.get_edges():
        if edge.get("crosses_boundary") and not edge.get("authenticated"):
            src      = edge["src"]
            dst      = edge["dst"]
            src_node = node_lookup.get(src, {})
            dst_node = node_lookup.get(dst, {})
            src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})
            assets   = edge.get("assets", [])

            severity = calculate_severity(
                Severity.HIGH,
                src_zone.get("trust_level", "medium"),
                _asset_sensitivities(assets, arch),
            )

            threats.append(Threat(
                id          = next(_id),
                component   = dst,
                category    = CATEGORY,
                subcategory = "Unauthenticated Boundary Crossing",
                severity    = severity,
                description = (
                    f"Flow '{edge.get('flow_id', '?')}' crosses a trust boundary "
                    f"from '{src}' to '{dst}' without authentication. "
                    f"An attacker can impersonate any client and send arbitrary "
                    f"requests without proving identity."
                ),
                sources     = [SOURCE],
                root_cause  = f"authenticated=False|crosses_boundary=True|flow={edge.get('flow_id')}",
                data_flow   = edge.get("flow_id"),
                assets      = assets,
                mitigations = [
                    "Implement token-based authentication (JWT / OAuth2)",
                    "Validate identity at every trust boundary crossing",
                    "Reject unauthenticated requests at the entry point",
                ],
            ))

    # S-02: Internet-facing component with no auth
    for node in graph.get_nodes():
        if not node.get("internet_facing"):
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        # Check if any incoming flow to this node is unauthenticated
        incoming = [
            e for e in graph.get_edges()
            if e["dst"] == node["id"] and not e.get("authenticated")
        ]

        if incoming:
            severity = calculate_severity(
                Severity.HIGH,
                node_zone.get("trust_level", "medium"),
            )

            threats.append(Threat(
                id          = next(_id),
                component   = node["id"],
                category    = CATEGORY,
                subcategory = "Unauthenticated Internet-Facing Component",
                severity    = severity,
                description = (
                    f"'{node['id']}' is internet-facing and accepts unauthenticated "
                    f"requests. Any external actor can interact with this component "
                    f"without proving their identity, enabling spoofing and impersonation."
                ),
                sources     = [SOURCE],
                root_cause  = f"internet_facing=True|unauthenticated_incoming|component={node['id']}",
                mitigations = [
                    "Require authentication on all internet-facing endpoints",
                    "Implement API key validation or OAuth2 at the entry point",
                    "Deploy a WAF to filter unauthenticated traffic",
                ],
            ))

    # S-03: Internal service directly reachable from untrusted zone
    for edge in graph.get_edges():
        src      = edge["src"]
        dst      = edge["dst"]
        src_node = node_lookup.get(src, {})
        dst_node = node_lookup.get(dst, {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})
        dst_zone = zone_lookup.get(dst_node.get("trust_zone", ""), {})

        src_level = src_zone.get("trust_level", "medium")
        dst_level = dst_zone.get("trust_level", "medium")

        # Untrusted → internal (non-gateway) component directly
        if (src_level == "untrusted"
                and dst_node.get("type") not in ("api-gateway", "load-balancer", "network-gateway")
                and not dst_node.get("internet_facing")):

            threats.append(Threat(
                id          = next(_id),
                component   = dst,
                category    = CATEGORY,
                subcategory = "Direct Access to Internal Component from Untrusted Zone",
                severity    = Severity.CRITICAL,
                description = (
                    f"Internal component '{dst}' (type: {dst_node.get('type')}) "
                    f"is directly reachable from the untrusted zone via flow "
                    f"'{edge.get('flow_id', '?')}'. Internal services should never "
                    f"be directly accessible from untrusted sources without passing "
                    f"through a gateway or load balancer."
                ),
                sources     = [SOURCE],
                root_cause  = f"untrusted_direct_access|component={dst}",
                data_flow   = edge.get("flow_id"),
                mitigations = [
                    "Route all external traffic through an API gateway or load balancer",
                    "Remove direct network paths from untrusted zones to internal services",
                    "Enforce network segmentation and firewall rules",
                ],
            ))

    return threats


# Helpers

def _id_counter():
    """Simple counter for threat IDs within this module."""
    i = 1
    prefix = "S"
    while True:
        yield f"{prefix}-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    """Look up sensitivity levels for a list of asset IDs."""
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]