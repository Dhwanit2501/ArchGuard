"""
ArchGuard - STRIDE Rule: Tampering
------------------------------------
Tampering threats arise when data in transit or at rest can be
modified without detection.

Rules:
    T-01: Unencrypted flow crossing a trust boundary
    T-02: Unencrypted flow carrying sensitive assets
    T-03: Database not encrypted at rest
    T-04: Unencrypted internal flow (lower severity)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.TAMPERING
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    # T-01: Unencrypted boundary-crossing flow
    for edge in graph.get_edges():
        if not edge.get("crosses_boundary"):
            continue
        if edge.get("encrypted_in_transit"):
            continue

        src      = edge["src"]
        dst      = edge["dst"]
        src_node = node_lookup.get(src, {})
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
            subcategory = "Unencrypted Boundary-Crossing Flow",
            severity    = severity,
            description = (
                f"Flow '{edge.get('flow_id', '?')}' crosses a trust boundary "
                f"from '{src}' to '{dst}' without encryption. "
                f"An attacker with network access can intercept and modify "
                f"data in transit without detection."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_in_transit=False|crosses_boundary=True|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Enforce TLS/HTTPS on all boundary-crossing flows",
                "Implement certificate pinning for sensitive communications",
                "Use mutual TLS (mTLS) for service-to-service communication",
            ],
        ))

    # T-02: Unencrypted flow carrying sensitive assets
    for edge in graph.get_edges():
        if edge.get("encrypted_in_transit"):
            continue

        assets       = edge.get("assets", [])
        sensitivities= _asset_sensitivities(assets, arch)

        # Only flag if carrying medium/high/critical assets
        if not any(s in ("medium", "high", "critical") for s in sensitivities):
            continue

        # Skip if already caught by T-01 (boundary crossing)
        if edge.get("crosses_boundary"):
            continue

        src      = edge["src"]
        dst      = edge["dst"]
        src_node = node_lookup.get(src, {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.MEDIUM,
            src_zone.get("trust_level", "medium"),
            sensitivities,
        )

        threats.append(Threat(
            id          = next(_id),
            component   = dst,
            category    = CATEGORY,
            subcategory = "Unencrypted Flow Carrying Sensitive Assets",
            severity    = severity,
            description = (
                f"Flow '{edge.get('flow_id', '?')}' from '{src}' to '{dst}' "
                f"carries sensitive assets ({', '.join(assets)}) without encryption. "
                f"Data integrity cannot be guaranteed and assets are exposed to "
                f"interception and modification."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_in_transit=False|sensitive_assets|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Encrypt all flows carrying sensitive data",
                "Implement data integrity checks (HMAC or digital signatures)",
                "Classify and track sensitive assets through all flows",
            ],
        ))

    # T-03: Database not encrypted at rest
    for node in graph.get_nodes():
        if node.get("type") not in ("database", "object-storage", "vector-store", "memory-store"):
            continue
        if node.get("encrypted_at_rest") is False:
            node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

            severity = calculate_severity(
                Severity.HIGH,
                node_zone.get("trust_level", "medium"),
            )

            # Check if it stores sensitive data
            stores_sensitive = node.get("stores_pii") or node.get("stores_credentials")
            if stores_sensitive:
                from Threat_Engine.model import bump_severity
                severity = bump_severity(severity, 1)

            threats.append(Threat(
                id          = next(_id),
                component   = node["id"],
                category    = CATEGORY,
                subcategory = "Storage Not Encrypted at Rest",
                severity    = severity,
                description = (
                    f"'{node['id']}' (type: {node.get('type')}) is not encrypted "
                    f"at rest. If the underlying storage is compromised, all stored "
                    f"data is directly accessible and can be tampered with."
                    + (" Stores PII and/or credentials." if stores_sensitive else "")
                ),
                sources     = [SOURCE],
                root_cause  = f"encrypted_at_rest=False|component={node['id']}",
                mitigations = [
                    "Enable encryption at rest using AES-256 or equivalent",
                    "Use cloud provider managed encryption keys (e.g. AWS KMS)",
                    "Rotate encryption keys regularly",
                ],
            ))

    # T-04: Unencrypted internal flow
    for edge in graph.get_edges():
        if edge.get("encrypted_in_transit"):
            continue
        if edge.get("crosses_boundary"):
            continue  # already handled by T-01

        assets        = edge.get("assets", [])
        sensitivities = _asset_sensitivities(assets, arch)

        # Skip if already caught by T-02
        if any(s in ("medium", "high", "critical") for s in sensitivities):
            continue

        src = edge["src"]
        dst = edge["dst"]

        threats.append(Threat(
            id          = next(_id),
            component   = dst,
            category    = CATEGORY,
            subcategory = "Unencrypted Internal Flow",
            severity    = Severity.LOW,
            description = (
                f"Internal flow '{edge.get('flow_id', '?')}' from '{src}' to '{dst}' "
                f"is not encrypted. While internal, an attacker with network access "
                f"(e.g. via lateral movement) can intercept and modify data."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_in_transit=False|internal|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            mitigations = [
                "Encrypt internal flows with TLS even within trust zones",
                "Implement a service mesh with mTLS (e.g. Istio, Linkerd)",
            ],
        ))

    return threats


# Helpers

def _id_counter():
    i = 1
    while True:
        yield f"T-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]