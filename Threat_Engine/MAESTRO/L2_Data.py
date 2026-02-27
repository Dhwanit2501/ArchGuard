"""
ArchGuard - MAESTRO Layer 2: Data Operations
----------------------------------------------
Threats arising from how data is processed, prepared, and stored
for AI agents, including databases, vector stores, and RAG pipelines.

Source: MAESTRO Layer 2 Threat Landscape
    - Data Poisoning
    - Data Exfiltration
    - Denial of Service on Data Infrastructure
    - Data Tampering
    - Compromised RAG Pipelines

Design-Time Detectable Rules:
    M2-01: Data store accepts input from untrusted source without validation (Data Poisoning)
    M2-02: Data store unencrypted or accessible from low trust zone (Data Exfiltration)
    M2-03: Data store has no rate limiting or resource limits (DoS on Data Infrastructure)
    M2-04: Unencrypted flows to/from data stores (Data Tampering)
    M2-05: RAG pipeline accepts unvalidated data from untrusted sources (Compromised RAG Pipelines)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity, bump_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L2_DATA
SOURCE = "MAESTRO-L2"

STORAGE_TYPES = {"vector-store", "memory-store", "database", "object-storage", "storage"}
RAG_TYPES     = {"vector-store", "memory-store"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    for node in graph.get_nodes():
        if node.get("type") not in STORAGE_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # ── M2-01: Data store accepts input from untrusted source (Data Poisoning) ──
        #
        # MAESTRO L2: Data Poisoning — manipulating training data or stored data
        # to compromise AI agent behavior, leading to biased results or unintended
        # consequences in AI decision making.
        #
        # Design-time signal: incoming flow from untrusted/low trust zone to the
        # data store without input validation. Poisoned data enters the store and
        # corrupts what the agent retrieves and reasons over.

        for edge in graph.get_edges():
            if edge["dst"] != node["id"]:
                continue

            src_node  = node_lookup.get(edge["src"], {})
            src_zone  = zone_lookup.get(src_node.get("trust_zone", ""), {})
            src_level = src_zone.get("trust_level", "medium")

            if src_level not in ("untrusted", "low"):
                continue

            has_validation = edge.get("input_validation", False)

            if not has_validation:
                assets   = edge.get("assets", [])
                severity = calculate_severity(
                    Severity.HIGH,
                    src_level,
                    _asset_sensitivities(assets, arch),
                )

                threats.append(Threat(
                    id           = next(_id),
                    component    = node["id"],
                    category     = StrideCategory.TAMPERING,
                    maestro_layer= LAYER,
                    subcategory  = "Unvalidated Input to Data Store — Data Poisoning Risk",
                    severity     = severity,
                    description  = (
                        f"'{node['id']}' ({node.get('type')}) accepts data from "
                        f"'{edge['src']}' ({src_level} trust) via flow "
                        f"'{edge.get('flow_id', '?')}' without input validation. "
                        f"An attacker can manipulate this data to compromise AI "
                        f"agent behavior, leading to biased results or unintended "
                        f"consequences in AI decision making — a data poisoning attack."
                    ),
                    sources      = [SOURCE],
                    root_cause   = f"input_validation=False|untrusted_input|data_store|component={node['id']}",
                    data_flow    = edge.get("flow_id"),
                    assets       = assets,
                    mitigations  = [
                        "Validate and sanitize all data before writing to AI data stores",
                        "Implement provenance tracking — record the source of all stored data",
                        "Restrict write access to data stores to trusted components only",
                        "Regularly audit and scan data store contents for anomalous entries",
                    ],
                ))

        # ── M2-02: Data store unencrypted or accessible from low trust zone (Data Exfiltration) ──
        #
        # MAESTRO L2: Data Exfiltration — stealing sensitive AI data stored in
        # databases or data stores, exposing private and confidential information
        # related to AI systems.
        #
        # Design-time signal: storage component not encrypted at rest OR accessible
        # via flow from a low trust zone. Either condition enables an attacker to
        # steal sensitive data from the store.

        not_encrypted = node.get("encrypted_at_rest") is False
        no_access_controls = node.get("access_controls") is False

        if not_encrypted or no_access_controls:
            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
            )

            if not_encrypted and no_access_controls:
                severity = bump_severity(severity, 1)

            missing = []
            if not_encrypted:       missing.append("encryption at rest")
            if no_access_controls:  missing.append("access controls")

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.INFORMATION_DISCLOSURE,
                maestro_layer= LAYER,
                subcategory  = "Data Store Without Encryption or Access Controls — Exfiltration Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) is missing "
                    f"{' and '.join(missing)}. Sensitive AI data — including "
                    f"embeddings, knowledge base contents, and agent memory — "
                    f"can be stolen by an attacker who gains access to the "
                    f"underlying storage, exposing private and confidential "
                    f"information related to the AI system."
                ),
                sources      = [SOURCE],
                root_cause   = f"encrypted_at_rest=False|access_controls=False|component={node['id']}",
                mitigations  = [
                    "Enable encryption at rest on all AI data stores",
                    "Implement strict access controls — only authorized components can read",
                    "Use provider-managed encryption keys with access auditing",
                    "Monitor and alert on unusual read patterns from data stores",
                ],
            ))

        # ── M2-03: Data store has no rate limiting or resource limits (DoS on Data Infrastructure) ──
        #
        # MAESTRO L2: Denial of Service on Data Infrastructure — disrupting access
        # to data needed by AI agents, preventing agent functionality and interrupting
        # normal operation of the AI system.
        #
        # Design-time signal: no rate_limiting AND no resource_limits on the data store.
        # An attacker can flood the store with requests or consume all resources,
        # making the data unavailable to the agent.

        has_rate_limiting   = node.get("rate_limiting", False)
        has_resource_limits = node.get("resource_limits", False)

        if not has_rate_limiting and not has_resource_limits:
            severity = calculate_severity(
                Severity.MEDIUM,
                trust_level,
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.DENIAL_OF_SERVICE,
                maestro_layer= LAYER,
                subcategory  = "Data Store Without Rate Limiting or Resource Limits — DoS Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no rate limiting "
                    f"or resource limits defined. An attacker can disrupt access "
                    f"to data needed by the AI agent by flooding the store with "
                    f"requests or exhausting its resources, preventing agent "
                    f"functionality and interrupting normal AI system operation."
                ),
                sources      = [SOURCE],
                root_cause   = f"rate_limiting=False|resource_limits=False|data_store|component={node['id']}",
                mitigations  = [
                    "Implement rate limiting on all data store access endpoints",
                    "Configure resource limits (storage, memory, connections) on data stores",
                    "Implement circuit breakers to protect downstream agents from store failures",
                    "Use read replicas to distribute load and improve availability",
                ],
            ))

        # ── M2-04: Unencrypted flows to/from data stores (Data Tampering) ──
        #
        # MAESTRO L2: Data Tampering — modifying AI data in transit or at rest,
        # leading to incorrect agent behavior or inaccurate results within AI systems.
        #
        # Design-time signal: any flow to or from the data store that is not
        # encrypted in transit. An attacker with network access can intercept
        # and modify data as it moves to/from the store.

        store_flows = [
            e for e in graph.get_edges()
            if e["src"] == node["id"] or e["dst"] == node["id"]
        ]

        for edge in store_flows:
            if edge.get("encrypted_in_transit"):
                continue

            direction = "to" if edge["dst"] == node["id"] else "from"
            other     = edge["src"] if direction == "to" else edge["dst"]
            assets    = edge.get("assets", [])

            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
                _asset_sensitivities(assets, arch),
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.TAMPERING,
                maestro_layer= LAYER,
                subcategory  = f"Unencrypted Flow {direction.capitalize()} Data Store — Data Tampering Risk",
                severity     = severity,
                description  = (
                    f"Flow '{edge.get('flow_id', '?')}' {direction} '{node['id']}' "
                    f"{'from' if direction == 'to' else 'to'} '{other}' is not "
                    f"encrypted in transit. An attacker with network access can "
                    f"intercept and modify AI data as it moves {direction} the store, "
                    f"leading to incorrect agent behavior or inaccurate results."
                ),
                sources      = [SOURCE],
                root_cause   = f"encrypted_in_transit=False|data_store_flow|flow={edge.get('flow_id')}",
                data_flow    = edge.get("flow_id"),
                assets       = assets,
                mitigations  = [
                    "Enforce TLS encryption on all flows to and from data stores",
                    "Implement data integrity checks (HMAC) on stored and retrieved data",
                    "Use mutual TLS (mTLS) for service-to-datastore communication",
                ],
            ))

    # ── M2-05: RAG pipeline accepts unvalidated data from untrusted sources (Compromised RAG) ──
    #
    # MAESTRO L2: Compromised RAG Pipelines — injecting malicious code or data
    # into AI data processing workflows, causing erroneous results or malicious
    # AI agent behavior.
    #
    # Design-time signal: a RAG-type storage component (vector-store, memory-store)
    # receives data from an untrusted/low trust source without input validation.
    # This is more specific than M2-01 — it focuses on the RAG retrieval pipeline
    # specifically and the downstream impact on agent reasoning.

    for node in graph.get_nodes():
        if node.get("type") not in RAG_TYPES:
            continue

        node_zone = zone_lookup.get(node.get("trust_zone", ""), {})

        for edge in graph.get_edges():
            if edge["dst"] != node["id"]:
                continue

            src_node  = node_lookup.get(edge["src"], {})
            src_zone  = zone_lookup.get(src_node.get("trust_zone", ""), {})
            src_level = src_zone.get("trust_level", "medium")

            if src_level not in ("untrusted", "low"):
                continue

            has_validation = edge.get("input_validation", False)

            if not has_validation:
                threats.append(Threat(
                    id           = next(_id),
                    component    = node["id"],
                    category     = StrideCategory.TAMPERING,
                    maestro_layer= LAYER,
                    subcategory  = "RAG Pipeline Accepts Unvalidated Untrusted Data — Compromised RAG Risk",
                    severity     = Severity.CRITICAL,
                    description  = (
                        f"'{node['id']}' ({node.get('type')}) is part of a RAG "
                        f"pipeline and accepts data from '{edge['src']}' "
                        f"({src_level} trust) via flow '{edge.get('flow_id', '?')}' "
                        f"without validation. An attacker can inject malicious content "
                        f"into the RAG pipeline, causing erroneous or malicious agent "
                        f"behavior when the poisoned data is retrieved and used in "
                        f"the agent's reasoning context — a RAG poisoning attack."
                    ),
                    sources      = [SOURCE],
                    root_cause   = f"rag_unvalidated_untrusted_input|component={node['id']}",
                    data_flow    = edge.get("flow_id"),
                    mitigations  = [
                        "Validate and sanitize all documents before indexing into RAG pipeline",
                        "Implement content filtering on all data entering the vector store",
                        "Restrict write access to the RAG pipeline to trusted components only",
                        "Monitor retrieved content for anomalous or adversarial patterns",
                        "Implement document provenance tracking in the RAG pipeline",
                    ],
                ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M2-{i:03d}"
        i += 1


def _asset_sensitivities(asset_ids: list[str], arch: dict) -> list[str]:
    asset_map = {a["id"]: a.get("sensitivity", "low") for a in arch.get("assets", [])}
    return [asset_map[a] for a in asset_ids if a in asset_map]