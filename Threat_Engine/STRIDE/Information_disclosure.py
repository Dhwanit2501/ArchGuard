"""
ArchGuard - STRIDE Rule: Information Disclosure
-------------------------------------------------
Information Disclosure threats arise when sensitive data is exposed
to unauthorized parties through flows, storage, or component behavior.

Rules:
    I-01: Unencrypted flow carrying sensitive assets crossing a boundary
    I-02: Database storing PII or credentials not encrypted at rest
    I-03: Sensitive assets flow to a component in a lower trust zone
    I-04: Unencrypted flow carrying any sensitive assets (internal)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity, bump_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.INFORMATION_DISCLOSURE
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    TRUST_ORDER = ["untrusted", "low", "medium", "high", "trusted", "critical"]

    def trust_rank(level: str) -> int:
        return TRUST_ORDER.index(level) if level in TRUST_ORDER else 2

    # I-01: Unencrypted boundary-crossing flow with sensitive assets
    for edge in graph.get_edges():
        if not edge.get("crosses_boundary"):
            continue
        if edge.get("encrypted_in_transit"):
            continue

        assets        = edge.get("assets", [])
        sensitivities = _asset_sensitivities(assets, arch)

        if not sensitivities:
            continue

        src_node = node_lookup.get(edge["src"], {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.HIGH,
            src_zone.get("trust_level", "medium"),
            sensitivities,
        )

        threats.append(Threat(
            id          = next(_id),
            component   = edge["dst"],
            category    = CATEGORY,
            subcategory = "Sensitive Data Exposed in Unencrypted Boundary-Crossing Flow",
            severity    = severity,
            description = (
                f"Flow '{edge.get('flow_id', '?')}' carries sensitive assets "
                f"({', '.join(assets)}) across a trust boundary from '{edge['src']}' "
                f"to '{edge['dst']}' without encryption. An attacker with network "
                f"access can intercept and read the sensitive data in transit."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_in_transit=False|crosses_boundary=True|sensitive_assets|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Enforce TLS/HTTPS on all boundary-crossing flows",
                "Encrypt sensitive fields individually (field-level encryption)",
                "Avoid transmitting credentials or PII unless absolutely necessary",
            ],
        ))

    # I-02: Storage of PII or credentials not encrypted at rest 
    for node in graph.get_nodes():
        if node.get("type") not in (
            "database", "object-storage", "vector-store",
            "memory-store", "storage"
        ):
            continue

        stores_pii   = node.get("stores_pii", False)
        stores_creds = node.get("stores_credentials", False)

        if not (stores_pii or stores_creds):
            continue

        if node.get("encrypted_at_rest") is not False:
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})
        severity  = calculate_severity(
            Severity.HIGH,
            node_zone.get("trust_level", "medium"),
        )
        severity = bump_severity(severity, 1)  # PII/creds always bump up

        what = []
        if stores_pii:   what.append("PII")
        if stores_creds: what.append("credentials")

        threats.append(Threat(
            id          = next(_id),
            component   = node["id"],
            category    = CATEGORY,
            subcategory = "Sensitive Data Stored Without Encryption at Rest",
            severity    = severity,
            description = (
                f"'{node['id']}' stores {' and '.join(what)} but is not encrypted "
                f"at rest. If the underlying storage is compromised or accessed "
                f"directly, all sensitive data is exposed in plaintext."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_at_rest=False|stores_sensitive|component={node['id']}",
            mitigations = [
                "Enable encryption at rest (AES-256 minimum)",
                "Use cloud provider managed keys with strict access controls (e.g. AWS KMS)",
                "Hash credentials using bcrypt/Argon2 rather than storing plaintext",
                "Apply data masking for PII fields where full values are not required",
            ],
        ))

    # I-03: Sensitive assets flow to a lower trust zone
    for edge in graph.get_edges():
        assets        = edge.get("assets", [])
        sensitivities = _asset_sensitivities(assets, arch)

        if not any(s in ("high", "critical") for s in sensitivities):
            continue

        src_node = node_lookup.get(edge["src"], {})
        dst_node = node_lookup.get(edge["dst"], {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})
        dst_zone = zone_lookup.get(dst_node.get("trust_zone", ""), {})

        src_rank = trust_rank(src_zone.get("trust_level", "medium"))
        dst_rank = trust_rank(dst_zone.get("trust_level", "medium"))

        # Sensitive data flowing to a lower trust zone
        if dst_rank < src_rank:
            severity = calculate_severity(
                Severity.HIGH,
                dst_zone.get("trust_level", "medium"),
                sensitivities,
            )

            threats.append(Threat(
                id          = next(_id),
                component   = edge["dst"],
                category    = CATEGORY,
                subcategory = "Sensitive Assets Flowing to Lower Trust Zone",
                severity    = severity,
                description = (
                    f"Flow '{edge.get('flow_id', '?')}' carries sensitive assets "
                    f"({', '.join(assets)}) from '{edge['src']}' "
                    f"[{src_zone.get('trust_level')}] to '{edge['dst']}' "
                    f"[{dst_zone.get('trust_level')}] — a zone with lower trust. "
                    f"Sensitive data should never flow to less trusted environments."
                ),
                sources     = [SOURCE],
                root_cause  = f"sensitive_assets_to_lower_trust|flow={edge.get('flow_id')}",
                data_flow   = edge.get("flow_id"),
                assets      = assets,
                mitigations = [
                    "Avoid passing sensitive data to lower trust zones",
                    "Sanitize or redact sensitive fields before sending to lower trust components",
                    "Re-evaluate the architecture to prevent downward data flows",
                ],
            ))

    # I-04: Unencrypted internal flow carrying sensitive assets
    for edge in graph.get_edges():
        if edge.get("encrypted_in_transit"):
            continue
        if edge.get("crosses_boundary"):
            continue  # already covered by I-01

        assets        = edge.get("assets", [])
        sensitivities = _asset_sensitivities(assets, arch)

        if not any(s in ("high", "critical") for s in sensitivities):
            continue

        src_node = node_lookup.get(edge["src"], {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.MEDIUM,
            src_zone.get("trust_level", "medium"),
            sensitivities,
        )

        threats.append(Threat(
            id          = next(_id),
            component   = edge["dst"],
            category    = CATEGORY,
            subcategory = "Sensitive Data in Unencrypted Internal Flow",
            severity    = severity,
            description = (
                f"Internal flow '{edge.get('flow_id', '?')}' carries sensitive "
                f"assets ({', '.join(assets)}) from '{edge['src']}' to '{edge['dst']}' "
                f"without encryption. An attacker who achieves lateral movement "
                f"within the zone can intercept this data."
            ),
            sources     = [SOURCE],
            root_cause  = f"encrypted_in_transit=False|internal|sensitive_assets|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Encrypt all internal flows carrying sensitive data",
                "Implement a service mesh with automatic mTLS",
                "Apply least-privilege data access — only pass what each service needs",
            ],
        ))

    return threats


# Helpers

def _id_counter():
    i = 1
    while True:
        yield f"I-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]