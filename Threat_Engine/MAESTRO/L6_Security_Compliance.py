"""
ArchGuard - MAESTRO Layer 6: Security and Compliance (Vertical Layer)
----------------------------------------------------------------------
This vertical layer cuts across all other layers, ensuring that security
and compliance controls are integrated into all AI agent operations.
This layer assumes that AI agents are also used as a security tool.

Source: MAESTRO Layer 6 Threat Landscape
    - Security Agent Data Poisoning
    - Evasion of Security AI Agents     [NOT detectable at design time - excluded]
    - Compromised Security AI Agents
    - Regulatory Non-Compliance by AI Security Agents
    - Bias in Security AI Agents        [NOT detectable at design time - excluded]
    - Lack of Explainability in Security AI Agents
    - Model Extraction of AI Security Agents

Design-Time Detectable Rules:
    M6-01: No input validation on AI component (Security Agent Data Poisoning)
    M6-02: No output filtering + no content policy (Compromised Security AI Agents)
    M6-03: No compliance controls defined (Regulatory Non-Compliance)
    M6-04: No explainability controls defined (Lack of Explainability)
    M6-05: No auth or rate limiting on LLM (Model Extraction)

Excluded Threats (not detectable from architecture schema):
    - Evasion of Security AI Agents: requires runtime — adversarial evasion
      patterns only observable when the agent is executing.
    - Bias in Security AI Agents: requires runtime evaluation of model outputs
      across population samples — not visible from architecture schema alone.

New Properties Required:
    - compliance_controls: bool  (no existing property captures this)
    - explainability: bool       (no existing property captures this)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L6_SECURITY
SOURCE = "MAESTRO-L6"

LLM_TYPES      = {"llm", "agent"}
ALL_AI_TYPES   = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}
    assets      = {a["id"]: a for a in arch.get("assets", [])}

    for node in graph.get_nodes():
        if node.get("type") not in ALL_AI_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # M6-01: No input validation (Security Agent Data Poisoning)
        #
        # MAESTRO L6: Attackers manipulating the training or operational data
        # used by AI security agents, causing them to misidentify threats or
        # generate false positives, impacting the AI security process.
        #
        # Design-time signal: input_validation already exists on components.
        # Without input validation, operational data fed to AI security agents
        # can be manipulated to poison their security decision-making.

        incoming_flows = [
            e for e in graph.get_edges()
            if e["dst"] == node["id"]
        ]

        if incoming_flows and not node.get("input_validation", False):
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.TAMPERING,
                maestro_layer = LAYER,
                subcategory   = "No Input Filtering on AI Component — Security Agent Data Poisoning Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no input validation "
                    f"defined and receives operational data. Attackers can manipulate "
                    f"the data used by this AI security agent, causing it to "
                    f"misidentify threats or generate false positives and impacting "
                    f"the AI security process."
                ),
                sources       = [SOURCE],
                root_cause    = f"input_validation=False|security|component={node['id']}",
                mitigations   = [
                    "Implement strict input validation on all data fed into AI security agents",
                    "Use integrity verification on operational data sources",
                    "Separate security-critical data pipelines from general data flows",
                    "Monitor data inputs for statistical anomalies indicating poisoning",
                    "Apply allowlist-based validation — reject inputs outside expected distribution",
                ],
            ))

        # M6-02: No output filtering + no content policy
        # (Compromised Security AI Agents)
        #
        # MAESTRO L6: Attackers gaining control over AI security agents, using
        # them to perform malicious tasks or to disable security systems,
        # directly impacting the AI security process.
        #
        # Design-time signal: output_filtering + content_policy both absent.
        # Without these controls, a compromised AI agent can produce outputs
        # that disable security systems or perform malicious actions undetected.

        has_output_filtering = node.get("output_filtering", False)
        has_content_policy   = node.get("content_policy", False)

        if not has_output_filtering and not has_content_policy:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.ELEVATION_OF_PRIVILEGE,
                maestro_layer = LAYER,
                subcategory   = "No Output Filtering or Content Policy — Compromised Security Agent Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no output filtering "
                    f"or content policy defined. An attacker who gains control over "
                    f"this AI security agent can use it to perform malicious tasks "
                    f"or disable security systems, directly impacting the AI security "
                    f"process without any output-level controls to prevent it."
                ),
                sources       = [SOURCE],
                root_cause    = f"output_filtering=False|content_policy=False|security|component={node['id']}",
                mitigations   = [
                    "Implement output filtering on all AI security agent outputs",
                    "Define and enforce a content policy that prevents security-disabling outputs",
                    "Apply a secondary validation layer on agent outputs before they take effect",
                    "Implement human-in-the-loop checkpoints for high-impact security decisions",
                    "Monitor agent outputs for patterns indicative of compromise or misuse",
                ],
            ))

        # M6-03: No compliance controls (Regulatory Non-Compliance)
        #
        # MAESTRO L6: AI security agents operating in violation of privacy
        # regulations or other compliance standards due to misconfiguration
        # or improper training, creating legal risks.
        #
        # Design-time signal: compliance_controls (new property) absent.
        # Without defined compliance controls, the AI agent may process data
        # in ways that violate GDPR, HIPAA, or other applicable regulations.

        if not node.get("compliance_controls", False):
            severity = calculate_severity(Severity.MEDIUM, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.INFORMATION_DISCLOSURE,
                maestro_layer = LAYER,
                subcategory   = "No Compliance Controls Defined — Regulatory Non-Compliance Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no compliance controls "
                    f"defined. This AI security agent may operate in violation of "
                    f"privacy regulations such as GDPR or HIPAA, or other compliance "
                    f"standards, due to misconfiguration or improper training, "
                    f"creating legal and regulatory risk."
                ),
                sources       = [SOURCE],
                root_cause    = f"compliance_controls=False|security|component={node['id']}",
                mitigations   = [
                    "Define and enforce compliance controls aligned with applicable regulations",
                    "Implement data residency and sovereignty controls on AI agent data handling",
                    "Conduct regular compliance audits of AI agent behavior and data usage",
                    "Apply data minimization principles to limit regulatory exposure",
                    "Document compliance posture for each AI component in the architecture",
                ],
            ))

        # M6-04: No explainability controls (Lack of Explainability)
        #
        # MAESTRO L6: The lack of transparency in security AI agent decision-making,
        # causing difficulty in auditing actions or identifying the root cause of
        # security failures.
        #
        # Design-time signal: explainability (new property) absent on LLM/agent
        # components. Without explainability controls, security decisions made
        # by AI agents cannot be audited or traced to a root cause.

        if node.get("type") in LLM_TYPES and not node.get("explainability", False):
            severity = calculate_severity(Severity.MEDIUM, trust_level)

            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.REPUDIATION,
                maestro_layer = LAYER,
                subcategory   = "No Explainability Controls — Security Decision Auditability Risk",
                severity      = severity,
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no explainability "
                    f"controls defined. The lack of transparency in this AI security "
                    f"agent's decision-making causes difficulty in auditing actions "
                    f"or identifying the root cause of security failures, undermining "
                    f"accountability and incident response."
                ),
                sources       = [SOURCE],
                root_cause    = f"explainability=False|security|component={node['id']}",
                mitigations   = [
                    "Implement explainability mechanisms to log reasoning behind security decisions",
                    "Use interpretable model outputs with confidence scores and decision rationale",
                    "Maintain an audit trail of all security decisions made by AI agents",
                    "Apply chain-of-thought logging to capture intermediate reasoning steps",
                    "Conduct periodic explainability audits to validate decision transparency",
                ],
            ))

        # M6-05: No auth or rate limiting on LLM (Model Extraction)
        #
        # MAESTRO L6: Attackers extracting the underlying model of an AI security
        # agent, creating ways to bypass security systems by understanding how
        # the system works.
        #
        # Design-time signal: rate_limiting absent on LLM components receiving
        # external input. Without rate limiting, attackers can repeatedly query
        # the model to extract its behavior and build bypass strategies.
        # Uses existing rate_limiting property — no new property needed.

        if node.get("type") in LLM_TYPES:
            incoming_unauth = [
                e for e in graph.get_edges()
                if e["dst"] == node["id"]
                and not e.get("authenticated", False)
            ]

            has_rate_limiting = node.get("rate_limiting", False)

            if incoming_unauth and not has_rate_limiting:
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.INFORMATION_DISCLOSURE,
                    maestro_layer = LAYER,
                    subcategory   = "No Auth or Rate Limiting on LLM — Model Extraction Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) receives unauthenticated "
                        f"input and has no rate limiting defined. An attacker can "
                        f"repeatedly query this AI security agent to extract the "
                        f"underlying model behavior, creating ways to bypass security "
                        f"systems by understanding how the system works."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"rate_limiting=False|unauthenticated_input=True|security|component={node['id']}",
                    mitigations   = [
                        "Implement rate limiting on all LLM inference endpoints",
                        "Require authentication for all access to AI security agent APIs",
                        "Monitor query patterns for signs of systematic model extraction",
                        "Limit response detail to reduce information available for extraction",
                        "Implement query diversity detection to flag extraction attempts",
                    ],
                ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M6-{i:03d}"
        i += 1