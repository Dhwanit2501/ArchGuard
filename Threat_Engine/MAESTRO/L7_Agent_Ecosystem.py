"""
ArchGuard - MAESTRO Layer 7: Agent Ecosystem
---------------------------------------------
The ecosystem layer represents the marketplace where AI agents interface
with real-world applications and users, from intelligent customer service
platforms to sophisticated enterprise automation solutions.

Source: MAESTRO Layer 7 Threat Landscape
    - Compromised Agents
    - Agent Impersonation
    - Agent Identity Attack
    - Agent Tool Misuse
    - Agent Goal Manipulation
    - Marketplace Manipulation          [NOT detectable at design time - excluded]
    - Integration Risks
    - Horizontal/Vertical Vulnerabilities [NOT detectable at design time - excluded]
    - Repudiation
    - Compromised Agent Registry        [NOT detectable at design time - excluded]
    - Malicious Agent Discovery         [NOT detectable at design time - excluded]
    - Agent Pricing Model Manipulation  [NOT detectable at design time - excluded]
    - Inaccurate Agent Capability Description [NOT detectable at design time - excluded]

Design-Time Detectable Rules:
    M7-01: No identity verification between agents (Compromised Agents + Agent Impersonation + Agent Identity Attack)
    M7-02: No tool scope restrictions or allowlist (Agent Tool Misuse)
    M7-03: No human oversight on agent chain (Agent Goal Manipulation)
    M7-04: Unauthenticated or unvalidated external integrations (Integration Risks)
    M7-05: No logging or audit trail on agent actions (Repudiation)

Excluded Threats (not detectable from architecture schema):
    - Marketplace Manipulation: external marketplace — not in architecture scope
    - Horizontal/Vertical Solution Vulnerabilities: requires industry-specific
      runtime knowledge not visible from schema
    - Compromised Agent Registry: external infrastructure — outside architecture scope
    - Malicious Agent Discovery: discovery mechanism is external — not schema detectable
    - Agent Pricing Model Manipulation: financial/billing system — outside scope
    - Inaccurate Agent Capability Description: documentation quality — not detectable

New Properties Required:
    - agent_identity_verification: bool  (no existing property captures inter-agent identity)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L7_ECOSYSTEM
SOURCE = "MAESTRO-L7"

AGENT_TYPES    = {"llm", "agent"}
ALL_AI_TYPES   = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}
TOOL_TYPES     = {"tool-executor"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}
    node_lookup = {n["id"]: n for n in graph.get_nodes()}

    for node in graph.get_nodes():
        if node.get("type") not in ALL_AI_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # M7-01: No identity verification between agents
        # (Compromised Agents + Agent Impersonation + Agent Identity Attack)
        #
        # MAESTRO L7:
        # - Compromised Agents: malicious AI agents posing as legitimate services
        # - Agent Impersonation: deceiving users or other agents by impersonating
        #   legitimate AI agents within the ecosystem
        # - Agent Identity Attack: compromising identity and authorization mechanisms
        #   of AI agents, resulting in unauthorized access and control
        #
        # Design-time signal: no agent_identity_verification defined on agent
        # components that receive input from other agents. Without identity
        # verification, any component can impersonate a legitimate agent.

        if node.get("type") in AGENT_TYPES:
            incoming_agent_flows = [
                e for e in graph.get_edges()
                if e["dst"] == node["id"]
                and node_lookup.get(e["src"], {}).get("type") in ALL_AI_TYPES
            ]

            if incoming_agent_flows and not node.get("agent_identity_verification", False):
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.SPOOFING,
                    maestro_layer = LAYER,
                    subcategory   = "No Agent Identity Verification — Compromised Agent / Impersonation Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) receives input from "
                        f"other agents but has no agent identity verification defined. "
                        f"Malicious agents can pose as legitimate services, deceive "
                        f"other agents through impersonation, or compromise identity "
                        f"and authorization mechanisms to gain unauthorized access "
                        f"and control over this agent."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"agent_identity_verification=False|inter_agent_flow=True|ecosystem|component={node['id']}",
                    mitigations   = [
                        "Implement mutual authentication between all communicating agents",
                        "Use cryptographic identity tokens for agent-to-agent communication",
                        "Maintain a verified agent registry with signed capability declarations",
                        "Reject messages from agents that cannot present valid identity proofs",
                        "Audit all inter-agent communications for identity anomalies",
                    ],
                ))

        # M7-02: No tool scope restrictions or allowlist (Agent Tool Misuse)
        #
        # MAESTRO L7: AI agents being manipulated to utilize their tools in ways
        # not intended, leading to unforeseen and potentially harmful actions
        # within the system.
        #
        # Design-time signal: no tool_scope_restrictions AND no tool_allowlist
        # on tool-executor components. Without scope restrictions, agents can
        # invoke tools in unintended and potentially harmful ways.

        if node.get("type") in TOOL_TYPES:
            has_scope       = node.get("tool_scope_restrictions", False)
            has_allowlist   = node.get("tool_allowlist", False)

            if not has_scope and not has_allowlist:
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.ELEVATION_OF_PRIVILEGE,
                    maestro_layer = LAYER,
                    subcategory   = "No Tool Scope Restrictions or Allowlist — Agent Tool Misuse Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) has no tool scope "
                        f"restrictions or allowlist defined. AI agents can be "
                        f"manipulated to utilize this tool executor in ways not "
                        f"intended, leading to unforeseen and potentially harmful "
                        f"actions within the system."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"tool_scope_restrictions=False|tool_allowlist=False|ecosystem|component={node['id']}",
                    mitigations   = [
                        "Define explicit tool scope restrictions limiting what each tool can do",
                        "Implement a tool allowlist — agents may only invoke pre-approved tools",
                        "Apply least-privilege principles to tool execution permissions",
                        "Validate all tool invocation parameters against expected schemas",
                        "Log and monitor all tool invocations for out-of-scope usage patterns",
                    ],
                ))

        # M7-03: No human oversight (Agent Goal Manipulation)
        #
        # MAESTRO L7: Attackers manipulating the intended goals of AI agents,
        # causing them to pursue objectives different from their original purpose
        # or be detrimental to the environment.
        #
        # Design-time signal: human_oversight already exists on project level.
        # Without human oversight checkpoints in the agent chain, goal
        # manipulation can go undetected and unchecked.

        if node.get("type") in AGENT_TYPES:
            project          = arch.get("project", {})
            has_oversight    = project.get("human_oversight", False)

            if not has_oversight:
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.ELEVATION_OF_PRIVILEGE,
                    maestro_layer = LAYER,
                    subcategory   = "No Human Oversight in Agent Chain — Agent Goal Manipulation Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) operates in an agent "
                        f"chain with no human oversight defined. Attackers can "
                        f"manipulate the intended goals of this AI agent, causing it "
                        f"to pursue objectives different from its original purpose or "
                        f"behave in ways detrimental to the environment, without any "
                        f"human checkpoint to detect or stop the deviation."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"human_oversight=False|ecosystem|component={node['id']}",
                    mitigations   = [
                        "Implement human-in-the-loop checkpoints for high-impact agent decisions",
                        "Define explicit goal constraints that agents cannot override",
                        "Monitor agent goal states and alert on deviations from intended objectives",
                        "Require human approval for agent actions above a defined risk threshold",
                        "Implement goal integrity verification to detect manipulation attempts",
                    ],
                ))

        # M7-04: Unauthenticated or unvalidated external integrations
        # (Integration Risks)
        #
        # MAESTRO L7: Vulnerabilities or weaknesses in APIs or SDKs used to
        # integrate AI agents with other systems, resulting in compromised
        # interactions and wider security issues.
        #
        # Design-time signal: internet_facing component with no authentication
        # on incoming flows AND no input_validation. Uses existing properties.

        if node.get("internet_facing") and not node.get("input_validation", False):
            incoming_unauth = [
                e for e in graph.get_edges()
                if e["dst"] == node["id"]
                and not e.get("authenticated", False)
            ]

            if incoming_unauth:
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.TAMPERING,
                    maestro_layer = LAYER,
                    subcategory   = "Unauthenticated External Integration Without Validation — Integration Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) is internet-facing, "
                        f"receives unauthenticated input, and has no input validation "
                        f"defined. Vulnerabilities in APIs or SDKs used to integrate "
                        f"this AI agent with external systems can result in compromised "
                        f"interactions and wider security issues across the ecosystem."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"internet_facing=True|authenticated=False|input_validation=False|ecosystem|component={node['id']}",
                    mitigations   = [
                        "Require authentication on all external integration endpoints",
                        "Implement strict input validation on all data received from external systems",
                        "Use API gateways with security controls for all external integrations",
                        "Apply SDK version pinning and integrity verification",
                        "Conduct regular security assessments of external integration points",
                    ],
                ))

        # M7-05: No logging or audit trail on agent actions (Repudiation)
        #
        # MAESTRO L7: AI agents denying actions they performed, creating
        # accountability issues in the system due to the difficulty in tracing
        # actions back to an AI agent.
        #
        # Design-time signal: no logging AND no audit_log_integrity on agent
        # components. Uses existing properties — no new property needed.

        if node.get("type") in AGENT_TYPES:
            has_logging          = node.get("logging", False)
            has_audit_integrity  = node.get("audit_log_integrity", False)

            if not has_logging and not has_audit_integrity:
                severity = calculate_severity(Severity.HIGH, trust_level)

                threats.append(Threat(
                    id            = next(_id),
                    component     = node["id"],
                    category      = StrideCategory.REPUDIATION,
                    maestro_layer = LAYER,
                    subcategory   = "No Logging or Audit Trail on Agent — Ecosystem Repudiation Risk",
                    severity      = severity,
                    description   = (
                        f"'{node['id']}' ({node.get('type')}) has no logging or "
                        f"audit log integrity defined. This AI agent can deny actions "
                        f"it performed, creating accountability issues in the ecosystem "
                        f"due to the difficulty in tracing actions back to this agent."
                    ),
                    sources       = [SOURCE],
                    root_cause    = f"logging=False|audit_log_integrity=False|ecosystem|component={node['id']}",
                    mitigations   = [
                        "Implement comprehensive, tamper-proof logging on all agent actions",
                        "Maintain a cryptographically signed audit trail for all agent decisions",
                        "Use append-only log storage to prevent after-the-fact modification",
                        "Correlate agent action logs with external system logs for traceability",
                        "Define clear accountability policies mapping actions to agent identities",
                    ],
                ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M7-{i:03d}"
        i += 1