"""
ArchGuard - MAESTRO Layer 3: Agent Frameworks
-----------------------------------------------
Threats arising from the frameworks used to build AI agents,
including toolkits for conversational AI and frameworks that
integrate data.

Source: MAESTRO Layer 3 Threat Landscape
    - Compromised Framework Components
    - Backdoor Attacks              [NOT detectable at design time - excluded]
    - Input Validation Attacks
    - Supply Chain Attacks
    - Denial of Service on Framework APIs
    - Framework Evasion

Design-Time Detectable Rules:
    M3-01: No input validation on agent framework component (Input Validation Attacks)
    M3-02: No rate limiting or resource limits on framework (DoS on Framework APIs)
    M3-03: No integrity verification on framework components (Compromised Framework Components)
    M3-04: No dependency verification defined (Supply Chain Attacks)
    M3-05: No output filtering or security controls on framework (Framework Evasion)

Excluded Threats (not detectable from architecture schema):
    - Backdoor Attacks: requires runtime inspection of framework internals,
      not visible from architecture schema
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L3_FRAMEWORK
SOURCE = "MAESTRO-L3"

FRAMEWORK_TYPES = {"llm", "agent", "tool-executor"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    for node in graph.get_nodes():
        if node.get("type") not in FRAMEWORK_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # ── M3-01: No input validation (Input Validation Attacks) ──────
        #
        # MAESTRO L3: Input Validation Attacks — exploiting weaknesses in
        # how the AI framework handles user inputs, allowing for code
        # injection and potential system compromise of AI agent systems.
        #
        # Design-time signal: no input_validation defined on the framework
        # component AND it receives input from untrusted or low trust zones.
        # Without validation, malicious inputs reach the framework directly
        # enabling code injection and system compromise.

        has_input_validation = node.get("input_validation", False)

        incoming_untrusted = [
            e for e in graph.get_edges()
            if e["dst"] == node["id"]
            and zone_lookup.get(
                node_lookup.get(e["src"], {}).get("trust_zone", ""), {}
            ).get("trust_level") in ("untrusted", "low")
        ]

        if incoming_untrusted and not has_input_validation:
            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.TAMPERING,
                maestro_layer= LAYER,
                subcategory  = "No Input Validation on Framework — Input Validation Attack Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no input validation "
                    f"defined and receives input from untrusted sources. An attacker "
                    f"can exploit weaknesses in how the AI framework handles user "
                    f"inputs, allowing for code injection and potential system "
                    f"compromise of the AI agent system."
                ),
                sources      = [SOURCE],
                root_cause   = f"input_validation=False|untrusted_input|framework|component={node['id']}",
                mitigations  = [
                    "Implement strict input validation on all framework entry points",
                    "Sanitize and normalize all user inputs before passing to framework",
                    "Apply allowlist-based input validation — reject anything not explicitly permitted",
                    "Use a dedicated input validation layer before the framework processes requests",
                ],
            ))

        # ── M3-02: No rate limiting or resource limits (DoS on Framework APIs) ──
        #
        # MAESTRO L3: Denial of Service on Framework APIs — disrupting the AI
        # framework's ability to function, overloading services and preventing
        # normal operation for the AI agents.
        #
        # Design-time signal: no rate_limiting AND no resource_limits defined
        # on the framework component. Without these controls, an attacker can
        # overload the framework API and prevent normal agent operation.

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
                subcategory  = "No Rate Limiting or Resource Limits on Framework — DoS Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no rate limiting "
                    f"or resource limits defined. An attacker can disrupt the AI "
                    f"framework's ability to function by overloading its services, "
                    f"preventing normal operation of the AI agents that depend on "
                    f"this framework component."
                ),
                sources      = [SOURCE],
                root_cause   = f"rate_limiting=False|resource_limits=False|framework|component={node['id']}",
                mitigations  = [
                    "Implement rate limiting on all framework API endpoints",
                    "Define resource consumption limits per request and per session",
                    "Implement circuit breakers to prevent cascading failures",
                    "Monitor framework API usage and alert on abnormal load patterns",
                ],
            ))

        # ── M3-03: No integrity verification (Compromised Framework Components) ──
        #
        # MAESTRO L3: Compromised Framework Components — malicious code in
        # libraries or modules used by AI frameworks, compromising the
        # functionality of the framework and leading to unexpected results.
        #
        # Design-time signal: no integrity_verification defined on the framework
        # component. Without integrity checks, malicious or tampered framework
        # components can be loaded without detection.

        has_integrity_verification = node.get("integrity_verification", False)

        if not has_integrity_verification:
            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.TAMPERING,
                maestro_layer= LAYER,
                subcategory  = "No Integrity Verification on Framework — Compromised Component Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no integrity "
                    f"verification defined. Malicious code in libraries or modules "
                    f"used by this AI framework component can compromise its "
                    f"functionality, leading to unexpected results and potentially "
                    f"malicious behavior from the AI agent."
                ),
                sources      = [SOURCE],
                root_cause   = f"integrity_verification=False|framework|component={node['id']}",
                mitigations  = [
                    "Implement cryptographic integrity verification on all framework components",
                    "Use signed package verification for all framework dependencies",
                    "Pin framework component versions to verified, known-good releases",
                    "Monitor framework component checksums and alert on changes",
                ],
            ))

        # ── M3-04: No dependency verification (Supply Chain Attacks) ────
        #
        # MAESTRO L3: Supply Chain Attacks — targeting the AI framework's
        # dependencies, compromising software before delivery and distribution,
        # resulting in compromised AI agent software.
        #
        # Design-time signal: no dependency_verification defined on the
        # framework component. Without dependency verification, compromised
        # upstream packages can be silently incorporated into the framework.

        has_dependency_verification = node.get("dependency_verification", False)

        if not has_dependency_verification:
            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.TAMPERING,
                maestro_layer= LAYER,
                subcategory  = "No Dependency Verification on Framework — Supply Chain Attack Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no dependency "
                    f"verification defined. An attacker can target the AI "
                    f"framework's upstream dependencies, compromising software "
                    f"before delivery and distribution and resulting in compromised "
                    f"AI agent software without the operator's knowledge."
                ),
                sources      = [SOURCE],
                root_cause   = f"dependency_verification=False|framework|component={node['id']}",
                mitigations  = [
                    "Implement software bill of materials (SBOM) for all framework dependencies",
                    "Use dependency scanning tools to detect known vulnerabilities",
                    "Lock dependency versions and verify checksums on every build",
                    "Use a private package registry to control approved dependencies",
                    "Monitor upstream packages for unexpected changes or new versions",
                ],
            ))

        # ── M3-05: No output filtering or security controls (Framework Evasion) ──
        #
        # MAESTRO L3: Framework Evasion — AI agents specifically designed to
        # bypass security controls within the framework, using advanced techniques
        # to perform unauthorized actions.
        #
        # Design-time signal: no output_filtering defined on the framework
        # component. Without output filtering, agents can produce outputs that
        # bypass framework security controls and perform unauthorized actions.

        has_output_filtering = node.get("output_filtering", False)

        if not has_output_filtering:
            severity = calculate_severity(
                Severity.HIGH,
                trust_level,
            )

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.ELEVATION_OF_PRIVILEGE,
                maestro_layer= LAYER,
                subcategory  = "No Output Filtering on Framework — Framework Evasion Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' ({node.get('type')}) has no output filtering "
                    f"defined. AI agents can use advanced techniques to bypass "
                    f"security controls within the framework, producing outputs "
                    f"that perform unauthorized actions outside the agent's "
                    f"intended scope."
                ),
                sources      = [SOURCE],
                root_cause   = f"output_filtering=False|framework|component={node['id']}",
                mitigations  = [
                    "Implement output filtering on all framework component outputs",
                    "Define explicit security controls that cannot be bypassed by agent outputs",
                    "Use a separate security enforcement layer independent of the framework",
                    "Regularly test framework security controls with adversarial agent prompts",
                    "Monitor agent outputs for patterns indicative of evasion attempts",
                ],
            ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M3-{i:03d}"
        i += 1