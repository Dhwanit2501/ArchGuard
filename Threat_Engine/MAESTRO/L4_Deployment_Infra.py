"""
ArchGuard - MAESTRO Layer 4: Deployment and Infrastructure
-----------------------------------------------------------
Threats arising from the infrastructure on which AI agents run,
including cloud, on-premise, containers, and orchestration systems.

Source: MAESTRO Layer 4 Threat Landscape
    - Compromised Container Images
    - Orchestration Attacks
    - Infrastructure-as-Code (IaC) Manipulation
    - Denial of Service (DoS) Attacks
    - Resource Hijacking
    - Lateral Movement                  [NOT detectable at design time - excluded]

Design-Time Detectable Rules:
    M4-01: No container image verification (Compromised Container Images)
    M4-02: No access controls on infrastructure component (Orchestration Attacks)
    M4-03: No integrity verification on infrastructure component (IaC Manipulation)
    M4-04: No resource limits or rate limiting (DoS Attacks)
    M4-05: No logging on infrastructure component (Resource Hijacking)

Excluded Threats (not detectable from architecture schema):
    - Lateral Movement: network topology isolation cannot be determined from
      component-level schema properties alone — requires runtime network
      configuration data.

Property Reuse (no new properties added except container_image_verification):
    - M4-02 reuses  access_controls       (already on storage components)
    - M4-03 reuses  integrity_verification (added in L3)
    - M4-04 reuses  resource_limits + rate_limiting (already exist)
    - M4-05 reuses  logging               (already exists)

New Properties Required:
    - container_image_verification: bool  (no existing property covers image signing)
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L4_INFRA
SOURCE = "MAESTRO-L4"

INFRA_TYPES = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    for node in graph.get_nodes():
        if node.get("type") not in INFRA_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # M4-01: No container image verification (Compromised Container Images)
        #
        # MAESTRO L4: Malicious code injected into AI agent containers infecting
        # production systems and compromising the AI deployment environment.
        #
        # Design-time signal: container_image_verification absent (new property —
        # no existing property captures image signing/digest verification).

        if not node.get("container_image_verification", False):
            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.TAMPERING,
                maestro_layer = LAYER,
                subcategory   = "No Container Image Verification — Compromised Container Image Risk",
                severity      = calculate_severity(Severity.HIGH, trust_level),
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no container image "
                    f"verification defined. Malicious code can be injected into AI "
                    f"agent containers, infecting production systems and compromising "
                    f"the entire AI deployment environment."
                ),
                sources       = [SOURCE],
                root_cause    = f"container_image_verification=False|infra|component={node['id']}",
                mitigations   = [
                    "Implement cryptographic verification of all container images before deployment",
                    "Use signed container images from trusted registries only",
                    "Scan container images for vulnerabilities and malicious code pre-deployment",
                    "Pin container image digests rather than mutable tags",
                    "Use a private container registry with strict push access controls",
                ],
            ))

        # M4-02: No access controls (Orchestration Attacks)
        #
        # MAESTRO L4: Exploiting vulnerabilities in orchestration systems like
        # Kubernetes to gain unauthorized access and control over AI deployment
        # systems, disrupting AI agent functionality.
        #
        # Design-time signal: reuses access_controls (already exists on components).
        # Without access controls, the orchestration layer managing AI agent
        # deployments can be exploited for unauthorized access.

        if not node.get("access_controls", False):
            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.ELEVATION_OF_PRIVILEGE,
                maestro_layer = LAYER,
                subcategory   = "No Access Controls on Infrastructure — Orchestration Attack Risk",
                severity      = calculate_severity(Severity.HIGH, trust_level),
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no access controls "
                    f"defined. An attacker can exploit vulnerabilities in the "
                    f"orchestration system managing this component to gain unauthorized "
                    f"access and control over AI deployment systems, disrupting "
                    f"AI agent functionality."
                ),
                sources       = [SOURCE],
                root_cause    = f"access_controls=False|infra|component={node['id']}",
                mitigations   = [
                    "Implement RBAC on all orchestration systems managing AI components",
                    "Apply least-privilege principles to orchestration service accounts",
                    "Restrict access to orchestration APIs and management interfaces",
                    "Enable audit logging on all orchestration control plane actions",
                    "Network-isolate the orchestration control plane from the data plane",
                ],
            ))

        # M4-03: No integrity verification (IaC Manipulation)
        #
        # MAESTRO L4: Tampering with Terraform or CloudFormation scripts to
        # provision compromised AI resources, leading to insecure deployment
        # infrastructure for AI agents.
        #
        # Design-time signal: reuses integrity_verification (added in L3).
        # Without integrity verification, tampered IaC scripts can silently
        # provision insecure infrastructure for AI agents.

        if not node.get("integrity_verification", False):
            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.TAMPERING,
                maestro_layer = LAYER,
                subcategory   = "No Integrity Verification on Infrastructure — IaC Manipulation Risk",
                severity      = calculate_severity(Severity.HIGH, trust_level),
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no integrity "
                    f"verification defined. An attacker can tamper with Terraform or "
                    f"CloudFormation scripts provisioning this AI component, leading "
                    f"to the creation of insecure deployment infrastructure."
                ),
                sources       = [SOURCE],
                root_cause    = f"integrity_verification=False|infra|component={node['id']}",
                mitigations   = [
                    "Implement integrity verification and signing for all IaC scripts",
                    "Use policy-as-code tools (e.g. OPA, Checkov) to validate IaC before apply",
                    "Enforce code review and approval workflows for all IaC changes",
                    "Store IaC in version-controlled repositories with branch protection",
                    "Audit IaC pipelines for unauthorized modifications",
                ],
            ))

        # M4-04: No resource limits or rate limiting (DoS Attacks)
        #
        # MAESTRO L4: Overwhelming infrastructure resources supporting AI agents,
        # causing AI systems to become unavailable to legitimate users.
        #
        # Design-time signal: reuses resource_limits + rate_limiting (both exist).

        if not node.get("resource_limits", False) and not node.get("rate_limiting", False):
            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.DENIAL_OF_SERVICE,
                maestro_layer = LAYER,
                subcategory   = "No Resource Limits on Infrastructure — DoS Attack Risk",
                severity      = calculate_severity(Severity.MEDIUM, trust_level),
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no resource limits "
                    f"or rate limiting defined at the infrastructure level. An attacker "
                    f"can overwhelm the infrastructure resources supporting this AI "
                    f"agent component, causing unavailability to legitimate users."
                ),
                sources       = [SOURCE],
                root_cause    = f"resource_limits=False|rate_limiting=False|infra|component={node['id']}",
                mitigations   = [
                    "Define CPU, memory, and network resource limits for all AI infrastructure components",
                    "Implement auto-scaling with hard upper bounds to prevent resource exhaustion",
                    "Use rate limiting at the infrastructure layer to prevent request flooding",
                    "Implement circuit breakers to isolate overloaded components",
                    "Monitor infrastructure resource usage and alert on anomalous consumption",
                ],
            ))

        # M4-05: No logging (Resource Hijacking)
        #
        # MAESTRO L4: Attackers using compromised AI infrastructure for
        # cryptomining or other illicit purposes, leading to performance
        # degradation of AI agents.
        #
        # Design-time signal: reuses logging (already exists). Without logging,
        # unauthorized resource consumption for illicit purposes goes undetected.

        if not node.get("logging", False):
            threats.append(Threat(
                id            = next(_id),
                component     = node["id"],
                category      = StrideCategory.DENIAL_OF_SERVICE,
                maestro_layer = LAYER,
                subcategory   = "No Logging on Infrastructure Component — Resource Hijacking Risk",
                severity      = calculate_severity(Severity.MEDIUM, trust_level),
                description   = (
                    f"'{node['id']}' ({node.get('type')}) has no logging defined. "
                    f"An attacker who compromises this AI infrastructure component "
                    f"can use it for cryptomining or other illicit purposes, causing "
                    f"performance degradation of AI agents without detection."
                ),
                sources       = [SOURCE],
                root_cause    = f"logging=False|infra|component={node['id']}",
                mitigations   = [
                    "Implement continuous logging on all AI infrastructure components",
                    "Alert on unexpected spikes in CPU, GPU, memory, or network usage",
                    "Use anomaly detection to identify unauthorized workloads",
                    "Apply strict workload identity controls to prevent unauthorized process execution",
                    "Regularly audit running processes and containers for unauthorized workloads",
                ],
            ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M4-{i:03d}"
        i += 1