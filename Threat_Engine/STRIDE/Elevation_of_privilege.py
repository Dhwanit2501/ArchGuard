"""
ArchGuard - STRIDE Rule: Elevation of Privilege
-------------------------------------------------
Elevation of Privilege threats arise when a component or actor can
gain access or capabilities beyond what is intended.

Rules:
    E-01: Authenticated flow with no authorization check defined
    E-02: Component storing credentials accessible from low trust zone
    E-03: Over-permissioned service (accesses resources beyond its role)
    E-04: Internal service skips authorization on inter-service calls
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity, bump_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.ELEVATION_OF_PRIVILEGE
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    TRUST_ORDER = ["untrusted", "low", "medium", "high", "trusted", "critical"]

    def trust_rank(level: str) -> int:
        return TRUST_ORDER.index(level) if level in TRUST_ORDER else 2

    # E-01: Authenticated flow with no authorization defined
    for edge in graph.get_edges():
        if not edge.get("authenticated"):
            continue
        if edge.get("authorized", True):
            continue  # authorized is fine

        src_node = node_lookup.get(edge["src"], {})
        dst_node = node_lookup.get(edge["dst"], {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})
        assets   = edge.get("assets", [])

        severity = calculate_severity(
            Severity.HIGH,
            src_zone.get("trust_level", "medium"),
            _asset_sensitivities(assets, arch),
        )

        threats.append(Threat(
            id          = next(_id),
            component   = edge["dst"],
            category    = CATEGORY,
            subcategory = "Authentication Without Authorization",
            severity    = severity,
            description = (
                f"Flow '{edge.get('flow_id', '?')}' from '{edge['src']}' to "
                f"'{edge['dst']}' is authenticated but has no authorization check "
                f"defined. Any authenticated user can access any resource or "
                f"operation without role or permission validation."
            ),
            sources     = [SOURCE],
            root_cause  = f"authenticated=True|authorized=False|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            assets      = assets,
            mitigations = [
                "Implement role-based access control (RBAC) or attribute-based access control (ABAC)",
                "Validate permissions at each service boundary, not just the entry point",
                "Apply principle of least privilege — grant only what is needed",
            ],
        ))

    # E-02: Component storing credentials accessible from low trust zone
    for node in graph.get_nodes():
        if not node.get("stores_credentials"):
            continue

        node_zone  = zone_lookup.get(node.get("trust_zone", ""), {})
        node_level = node_zone.get("trust_level", "medium")

        # Check if any incoming flow comes from a low trust zone
        for edge in graph.get_edges():
            if edge["dst"] != node["id"]:
                continue

            src_node  = node_lookup.get(edge["src"], {})
            src_zone  = zone_lookup.get(src_node.get("trust_zone", ""), {})
            src_level = src_zone.get("trust_level", "medium")

            if trust_rank(src_level) <= trust_rank("low"):
                severity = calculate_severity(
                    Severity.CRITICAL,
                    src_level,
                )

                threats.append(Threat(
                    id          = next(_id),
                    component   = node["id"],
                    category    = CATEGORY,
                    subcategory = "Credential Store Accessible from Low Trust Zone",
                    severity    = severity,
                    description = (
                        f"'{node['id']}' stores credentials and is accessible "
                        f"from '{edge['src']}' in the {src_level} trust zone "
                        f"via flow '{edge.get('flow_id', '?')}'. "
                        f"An attacker who compromises the low-trust component "
                        f"can directly access and exfiltrate stored credentials, "
                        f"enabling privilege escalation across the system."
                    ),
                    sources     = [SOURCE],
                    root_cause  = f"stores_credentials=True|low_trust_access|component={node['id']}",
                    data_flow   = edge.get("flow_id"),
                    mitigations = [
                        "Restrict credential store access to high-trust components only",
                        "Use a dedicated secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)",
                        "Never store credentials in components accessible from untrusted zones",
                        "Rotate credentials regularly and detect unauthorized access attempts",
                    ],
                ))

    # E-03: Service accesses resources beyond its scope
    for node in graph.get_nodes():
        if not node.get("over_privileged"):
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.HIGH,
            node_zone.get("trust_level", "medium"),
        )

        threats.append(Threat(
            id          = next(_id),
            component   = node["id"],
            category    = CATEGORY,
            subcategory = "Over-Privileged Service",
            severity    = severity,
            description = (
                f"'{node['id']}' is marked as over-privileged, meaning it has "
                f"access to resources or operations beyond what its role requires. "
                f"If this component is compromised, an attacker inherits all of "
                f"its excessive permissions, enabling lateral movement and "
                f"privilege escalation."
            ),
            sources     = [SOURCE],
            root_cause  = f"over_privileged=True|component={node['id']}",
            mitigations = [
                "Apply principle of least privilege — remove all unnecessary permissions",
                "Scope IAM roles and service accounts to the minimum required actions",
                "Regularly audit and review service permissions",
                "Use separate service accounts for each service",
            ],
        ))

    # E-04: Inter-service flow with no authentication and no authorization
    for edge in graph.get_edges():
        if edge.get("crosses_boundary"):
            continue  # boundary flows handled by Spoofing

        src_node = node_lookup.get(edge["src"], {})
        dst_node = node_lookup.get(edge["dst"], {})

        # Only internal service-to-service flows
        src_type = src_node.get("type", "")
        dst_type = dst_node.get("type", "")

        service_types = (
            "microservice", "api-gateway", "function",
            "serverless", "compute", "tool-executor"
        )

        if src_type not in service_types or dst_type not in service_types:
            continue

        if edge.get("authenticated") or edge.get("authorized", True):
            continue

        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})

        severity = calculate_severity(
            Severity.MEDIUM,
            src_zone.get("trust_level", "medium"),
        )

        threats.append(Threat(
            id          = next(_id),
            component   = edge["dst"],
            category    = CATEGORY,
            subcategory = "Unauthenticated Inter-Service Call",
            severity    = severity,
            description = (
                f"Internal flow '{edge.get('flow_id', '?')}' from service "
                f"'{edge['src']}' to service '{edge['dst']}' has no authentication "
                f"or authorization. Any service within the zone can call "
                f"'{edge['dst']}' and perform any operation without restriction. "
                f"A compromised service can abuse this to escalate its privileges."
            ),
            sources     = [SOURCE],
            root_cause  = f"internal_no_auth|service_to_service|flow={edge.get('flow_id')}",
            data_flow   = edge.get("flow_id"),
            mitigations = [
                "Implement mutual TLS (mTLS) for all inter-service communication",
                "Use service-to-service authentication tokens (e.g. SPIFFE/SPIRE)",
                "Apply zero-trust networking within the service mesh",
            ],
        ))

    return threats


# Helper

def _id_counter():
    i = 1
    while True:
        yield f"E-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]