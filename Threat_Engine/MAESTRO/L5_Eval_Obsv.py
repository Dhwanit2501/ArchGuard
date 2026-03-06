"""
ArchGuard - MAESTRO Layer 5: Evaluation and Observability
----------------------------------------------------------
Threats arising from how AI agents are evaluated and monitored,
including tools and processes for tracking performance and
detecting anomalies.

Source: MAESTRO Layer 5 Threat Landscape
    - Manipulation of Evaluation Metrics
    - Compromised Observability Tools
    - Denial of Service on Evaluation Infrastructure
    - Evasion of Detection              [NOT detectable at design time - excluded]
    - Data Leakage through Observability
    - Poisoning Observability Data

Design-Time Detectable Rules:
    M5-01: No evaluation integrity controls (Manipulation of Evaluation Metrics)
    M5-02: No monitoring defined on AI component (Compromised Observability Tools)
    M5-03: No resource limits on agent reasoning chain (DoS on Evaluation Infrastructure)
    M5-04: No log sanitization on sensitive data handlers (Data Leakage through Observability)
    M5-05: No audit log integrity controls (Poisoning Observability Data)

Excluded Threats (not detectable from architecture schema):
    - Evasion of Detection: requires runtime behavioral analysis — the agent must
      be executing for evasion patterns to be observable. Cannot be detected from
      architecture schema alone.
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L5_OBSERVABILITY
SOURCE = "MAESTRO-L5"

# Components that participate in evaluation and observability
OBSERVABLE_TYPES = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    zone_lookup  = {tz["id"]: tz for tz in arch.get("trust_zones", [])}
    node_lookup  = {n["id"]: n for n in graph.get_nodes()}
    assets       = {a["id"]: a for a in arch.get("assets", [])}

    for node in graph.get_nodes():
        if node.get("type") not in OBSERVABLE_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # M5-01: No evaluation integrity controls─
        # (Manipulation of Evaluation Metrics)
        #
        # MAESTRO L5: Adversaries influencing benchmarks to favor their AI agents
        # through poisoned datasets or biased test cases, resulting in inaccurate
        # performance data.
        #
        # Design-time signal: no evaluation_integrity defined on the component.
        # Without evaluation integrity controls, adversaries can manipulate
        # benchmarks and test cases to produce misleading performance data,
        # masking actual model weaknesses or malicious behavior.

        if not node.get("evaluation_integrity", False):
            severity = calculate_severity(Severity.MEDIUM, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.TAMPERING,
                maestro_layer = LAYER,
                subcategory   = "No Evaluation Integrity Controls — Evaluation Metric Manipulation Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no evaluation integrity "
                    f"controls defined. Adversaries can influence benchmarks through "
                    f"poisoned datasets or biased test cases, resulting in inaccurate "
                    f"performance data that masks actual model weaknesses or malicious "
                    f"behavior."
                ),
                sources       = [SOURCE],
                root_cause    = f"evaluation_integrity=False|observability|component={node['id']}",
                mitigations   = [
                    "Implement integrity verification on all evaluation datasets and test cases",
                    "Use cryptographically signed evaluation datasets to detect tampering",
                    "Separate evaluation environments from training and production pipelines",
                    "Maintain a held-out, independently verified benchmark dataset",
                    "Audit evaluation pipelines for unauthorized modifications to test cases",
                ],
            ))

        # M5-02: No monitoring defined (Compromised Observability Tools)
        #
        # MAESTRO L5: Attackers injecting malicious code into monitoring systems
        # that exfiltrate system data or hide malicious behaviour, compromising
        # the integrity and security of the AI monitoring process.
        #
        # Design-time signal: no logging defined on the component. Without
        # monitoring, attackers can inject malicious code into the observability
        # layer and operate undetected — there is no monitoring process to
        # compromise or rely on.

        if not node.get("logging", False):
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.REPUDIATION,
                maestro_layer = LAYER,
                subcategory   = "No Monitoring on AI Component — Compromised Observability Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no monitoring or logging "
                    f"defined. Without an observability layer, attackers can inject "
                    f"malicious code that exfiltrates system data or hides malicious "
                    f"behaviour, with no monitoring process in place to detect or "
                    f"respond to the compromise."
                ),
                sources       = [SOURCE],
                root_cause    = f"logging=False|observability|component={node['id']}",
                mitigations   = [
                    "Implement comprehensive logging on all AI agent components",
                    "Use tamper-resistant, append-only logging infrastructure",
                    "Deploy monitoring systems independently from the AI components they observe",
                    "Implement integrity verification on monitoring tool binaries and configs",
                    "Alert on gaps or anomalies in monitoring data streams",
                ],
            ))

        # M5-03: No resource limits on reasoning chain
        # (Denial of Service on Evaluation Infrastructure)
        #
        # MAESTRO L5: Disrupting the AI evaluation process to prevent proper
        # testing and detection of compromised behavior, leading to a lack of
        # visibility of AI agent performance.
        #
        # Design-time signal: no resource_limits AND no rate_limiting defined.
        # Without resource controls, an attacker can overwhelm the evaluation
        # infrastructure, preventing the detection of compromised AI behavior.

        has_resource_limits = node.get("resource_limits", False)
        has_rate_limiting   = node.get("rate_limiting", False)

        if not has_resource_limits and not has_rate_limiting:
            severity = calculate_severity(Severity.MEDIUM, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.DENIAL_OF_SERVICE,
                maestro_layer = LAYER,
                subcategory   = "No Resource Limits on Agent Component — DoS on Evaluation Infrastructure Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no resource limits or "
                    f"rate limiting defined. An attacker can disrupt the AI evaluation "
                    f"process by overwhelming this component, preventing proper testing "
                    f"and detection of compromised behavior and eliminating visibility "
                    f"into AI agent performance."
                ),
                sources       = [SOURCE],
                root_cause    = f"resource_limits=False|rate_limiting=False|observability|component={node['id']}",
                mitigations   = [
                    "Define resource limits for all AI components participating in evaluation",
                    "Isolate evaluation infrastructure from production workloads",
                    "Implement rate limiting to prevent evaluation pipeline flooding",
                    "Use dedicated evaluation environments with independent resource pools",
                    "Monitor evaluation infrastructure for signs of resource exhaustion",
                ],
            ))

        # M5-04: No log sanitization (Data Leakage through Observability)
        #
        # MAESTRO L5: Sensitive AI information inadvertently exposed through logs
        # or monitoring dashboards due to misconfiguration, creating privacy and
        # confidentiality risks.
        #
        # Design-time signal: no log_sanitization defined on a component that
        # handles sensitive assets. Without log sanitization, sensitive data
        # processed by AI components leaks into logs and monitoring dashboards.

        has_log_sanitization = node.get("log_sanitization", False)

        # Determine if this component handles sensitive assets
        outgoing_assets = []
        for edge in graph.get_edges():
            if edge["src"] == node["id"] or edge["dst"] == node["id"]:
                outgoing_assets.extend(edge.get("assets", []))

        handles_sensitive = any(
            assets.get(a, {}).get("sensitivity") in ("high", "critical")
            for a in outgoing_assets
        )

        if not has_log_sanitization and handles_sensitive:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.INFORMATION_DISCLOSURE,
                maestro_layer = LAYER,
                subcategory   = "No Log Sanitization on Sensitive Data Handler — Observability Data Leakage Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) handles sensitive assets "
                    f"but has no log sanitization defined. Sensitive AI information "
                    f"can be inadvertently exposed through logs or monitoring dashboards "
                    f"due to misconfiguration, creating privacy and confidentiality risks."
                ),
                sources       = [SOURCE],
                root_cause    = f"log_sanitization=False|sensitive_assets=True|observability|component={node['id']}",
                mitigations   = [
                    "Implement log sanitization to scrub sensitive data before writing to logs",
                    "Apply PII and credential redaction in all logging pipelines",
                    "Restrict access to monitoring dashboards containing AI operational data",
                    "Define explicit data retention and masking policies for observability data",
                    "Audit log outputs regularly for inadvertent sensitive data exposure",
                ],
            ))

        # M5-05: No audit log integrity controls (Poisoning Observability Data)
        #
        # MAESTRO L5: Manipulating the data fed into the observability system for
        # AI systems, hiding incidents from security teams and masking malicious
        # activity.
        #
        # Design-time signal: no audit_log_integrity defined on the component.
        # Without tamper-proof audit logging, attackers can manipulate observability
        # data to hide malicious activity from security teams.

        if not node.get("audit_log_integrity", False):
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.REPUDIATION,
                maestro_layer = LAYER,
                subcategory   = "No Audit Log Integrity Controls — Observability Data Poisoning Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no audit log integrity "
                    f"controls defined. An attacker can manipulate the observability "
                    f"data fed into monitoring systems for this AI component, hiding "
                    f"incidents from security teams and masking malicious activity."
                ),
                sources       = [SOURCE],
                root_cause    = f"audit_log_integrity=False|observability|component={node['id']}",
                mitigations   = [
                    "Use append-only, cryptographically signed audit logs for all AI components",
                    "Store audit logs in an immutable, independently secured log store",
                    "Implement log integrity verification to detect tampering",
                    "Separate log write access from log read access using strict IAM controls",
                    "Alert on any detected modification or deletion of audit log entries",
                ],
            ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M5-{i:03d}"
        i += 1