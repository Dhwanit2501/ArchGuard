"""
ArchGuard - STRIDE Rule: Denial of Service
--------------------------------------------
Denial of Service threats arise when components can be overwhelmed,
exhausted, or made unavailable due to missing protective controls.

Rules:
    D-01: Internet-facing entry point with no rate limiting
    D-02: Public-facing component with no DDoS protection
    D-03: Internal service directly reachable with no resource limits
    D-04: Queue or event broker with no message validation / limits
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    calculate_severity
)
from graph.base import GraphInterface


CATEGORY = StrideCategory.DENIAL_OF_SERVICE
SOURCE   = "STRIDE"


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    # D-01: Internet-facing entry point with no rate limiting
    for node in graph.get_nodes():
        if not node.get("internet_facing"):
            continue

        has_rate_limiting = node.get("rate_limiting", False)
        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        if not has_rate_limiting:
            severity = calculate_severity(
                Severity.HIGH,
                node_zone.get("trust_level", "medium"),
            )

            threats.append(Threat(
                id          = next(_id),
                component   = node["id"],
                category    = CATEGORY,
                subcategory = "Internet-Facing Component Without Rate Limiting",
                severity    = severity,
                description = (
                    f"'{node['id']}' is internet-facing but has no rate limiting "
                    f"configured. An attacker can flood this component with requests, "
                    f"exhausting resources and causing service degradation or outage "
                    f"for legitimate users."
                ),
                sources     = [SOURCE],
                root_cause  = f"rate_limiting=False|internet_facing=True|component={node['id']}",
                mitigations = [
                    "Implement rate limiting at the API gateway or load balancer",
                    "Configure per-client and per-endpoint request quotas",
                    "Use token bucket or sliding window rate limiting algorithms",
                ],
            ))

    # D-02: Public-facing component with no DDoS protection
    for node in graph.get_nodes():
        if not node.get("internet_facing"):
            continue

        has_ddos = node.get("ddos_protection", False)
        has_waf  = node.get("waf_enabled", False)
        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        if not has_ddos and not has_waf:
            severity = calculate_severity(
                Severity.MEDIUM,
                node_zone.get("trust_level", "medium"),
            )

            threats.append(Threat(
                id          = next(_id),
                component   = node["id"],
                category    = CATEGORY,
                subcategory = "No DDoS Protection on Public-Facing Component",
                severity    = severity,
                description = (
                    f"'{node['id']}' is publicly accessible but has no DDoS "
                    f"protection or WAF configured. Volumetric or application-layer "
                    f"DDoS attacks can render this component unavailable."
                ),
                sources     = [SOURCE],
                root_cause  = f"ddos_protection=False|waf_enabled=False|component={node['id']}",
                mitigations = [
                    "Enable cloud provider DDoS protection (e.g. AWS Shield, Azure DDoS Protection)",
                    "Deploy a Web Application Firewall (WAF) for application-layer protection",
                    "Configure traffic scrubbing and anomaly detection",
                ],
            ))

    # D-03: Internal service reachable from untrusted zone
    for edge in graph.get_edges():
        src_node = node_lookup.get(edge["src"], {})
        dst_node = node_lookup.get(edge["dst"], {})
        src_zone = zone_lookup.get(src_node.get("trust_zone", ""), {})

        if src_zone.get("trust_level") != "untrusted":
            continue

        if dst_node.get("type") in ("api-gateway", "load-balancer", "network-gateway"):
            continue

        has_resource_limits = dst_node.get("resource_limits", False)

        if not has_resource_limits:
            threats.append(Threat(
                id          = next(_id),
                component   = edge["dst"],
                category    = CATEGORY,
                subcategory = "Internal Service Reachable from Untrusted Zone Without Resource Limits",
                severity    = Severity.HIGH,
                description = (
                    f"Internal service '{edge['dst']}' is reachable from the "
                    f"untrusted zone via flow '{edge.get('flow_id', '?')}' and has "
                    f"no resource limits configured. An attacker can exhaust "
                    f"compute, memory, or connection resources of this service."
                ),
                sources     = [SOURCE],
                root_cause  = f"untrusted_reachable|no_resource_limits|component={edge['dst']}",
                data_flow   = edge.get("flow_id"),
                mitigations = [
                    "Configure CPU, memory, and connection limits on internal services",
                    "Implement circuit breakers to prevent cascade failures",
                    "Block direct access from untrusted zones to internal services",
                ],
            ))

    # D-04: Queue or event broker with no message limits
    for node in graph.get_nodes():
        if node.get("type") not in ("queue",):
            continue

        has_msg_limits = node.get("message_size_limit", False)
        has_rate_limit = node.get("rate_limiting", False)
        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        if not has_msg_limits or not has_rate_limit:
            severity = calculate_severity(
                Severity.MEDIUM,
                node_zone.get("trust_level", "medium"),
            )

            missing = []
            if not has_msg_limits: missing.append("message size limits")
            if not has_rate_limit:  missing.append("rate limiting")

            threats.append(Threat(
                id          = next(_id),
                component   = node["id"],
                category    = CATEGORY,
                subcategory = "Queue Without Message Size or Rate Limits",
                severity    = severity,
                description = (
                    f"'{node['id']}' (queue/event broker) is missing "
                    f"{' and '.join(missing)}. An attacker or misbehaving producer "
                    f"can flood the queue with oversized or excessive messages, "
                    f"causing consumers to be overwhelmed or the broker to run out "
                    f"of storage."
                ),
                sources     = [SOURCE],
                root_cause  = f"no_message_limits|component={node['id']}",
                mitigations = [
                    "Configure maximum message size limits on the queue",
                    "Set producer rate limits to prevent message flooding",
                    "Implement dead-letter queues for unprocessable messages",
                    "Monitor queue depth and alert on abnormal growth",
                ],
            ))

    return threats

# Helper Counter
def _id_counter():
    i = 1
    while True:
        yield f"D-{i:03d}"
        i += 1