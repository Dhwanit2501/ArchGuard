"""
ArchGuard - MAESTRO Layer 1: Foundation Models
------------------------------------------------
Threats arising from the core AI model on which an agent is built.

Source: MAESTRO Layer 1 Threat Landscape
    - Adversarial Examples
    - Model Stealing
    - Backdoor Attacks          [NOT detectable at design time - excluded]
    - Membership Inference      [NOT detectable at design time - excluded]
    - Data Poisoning (Training) [NOT detectable at design time - excluded]
    - Reprogramming Attacks
    - Denial of Service Attacks

Design-Time Detectable Rules:
    M1-01: No input validation on LLM (Adversarial Examples)
    M1-02: LLM exposed without authentication or rate limiting (Model Stealing)
    M1-03: No content policy on LLM (Reprogramming Attacks)
    M1-04: No rate limiting or resource controls on LLM (Denial of Service)

Excluded Threats (not detectable from architecture schema):
    - Backdoor Attacks: requires model inspection, not visible in architecture
    - Membership Inference: requires runtime analysis of model outputs
    - Data Poisoning (Training Phase): training pipeline outside architecture scope
"""

from Threat_Engine.model import (
    Threat, Severity, StrideCategory,
    MaestroLayer, calculate_severity
)
from graph.base import GraphInterface


LAYER  = MaestroLayer.L1_FOUNDATION
SOURCE = "MAESTRO-L1"

LLM_TYPES = {"llm", "agent"}


def run(graph: GraphInterface, arch: dict) -> list[Threat]:
    threats = []
    _id     = _id_counter()

    node_lookup = {n["id"]: n for n in graph.get_nodes()}
    zone_lookup = {tz["id"]: tz for tz in arch.get("trust_zones", [])}

    for node in graph.get_nodes():
        if node.get("type") not in LLM_TYPES:
            continue

        node_zone   = zone_lookup.get(node.get("trust_zone", ""), {})
        trust_level = node_zone.get("trust_level", "medium")

        # ── M1-01: No input validation (Adversarial Examples) ──
        # MAESTRO L1: Adversarial Examples — inputs specifically crafted
        # to fool the AI model into making incorrect predictions or behave
        # in unexpected ways, causing instability or incorrect responses.
        has_input_validation = node.get("input_validation", False)

        incoming_untrusted = [
            e for e in graph.get_edges()
            if e["dst"] == node["id"]
            and zone_lookup.get(
                node_lookup.get(e["src"], {}).get("trust_zone", ""), {}
            ).get("trust_level") in ("untrusted", "low")
        ]

        if incoming_untrusted and not has_input_validation:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.TAMPERING,
                maestro_layer= LAYER,
                subcategory  = "No Input Validation — Adversarial Example Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' receives input from untrusted sources but "
                    f"has no input validation defined. Adversarial inputs — "
                    f"specifically crafted to fool the model — have a direct "
                    f"path to the foundation model, causing incorrect predictions, "
                    f"instability, or unexpected behavior from the AI."
                ),
                sources      = [SOURCE],
                root_cause   = f"input_validation=False|untrusted_input|component={node['id']}",
                mitigations  = [
                    "Implement input validation and sanitization before model invocation",
                    "Use adversarial input detection classifiers at the model boundary",
                    "Apply input length and format constraints to limit attack surface",
                    "Monitor model confidence scores to detect adversarial inputs at runtime",
                ],
            ))

        # ── M1-02: LLM exposed without auth or rate limiting (Model Stealing) ──
        # MAESTRO L1: Model Stealing — attackers extracting a copy of the AI
        # model through repeated API queries, resulting in IP theft or
        # competitive disadvantage.
        has_rate_limiting = node.get("rate_limiting", False)

        incoming_unauth = [
            e for e in graph.get_edges()
            if e["dst"] == node["id"] and not e.get("authenticated")
        ]

        if incoming_unauth and not has_rate_limiting:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.INFORMATION_DISCLOSURE,
                maestro_layer= LAYER,
                subcategory  = "LLM Accessible Without Auth or Rate Limiting — Model Stealing Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' accepts unauthenticated requests and has "
                    f"no rate limiting defined. An attacker can issue unlimited "
                    f"systematic queries to extract a functional copy of the model "
                    f"through API interactions — a model stealing attack resulting "
                    f"in intellectual property theft or competitive disadvantage."
                ),
                sources      = [SOURCE],
                root_cause   = f"unauthenticated=True|rate_limiting=False|component={node['id']}",
                mitigations  = [
                    "Require authentication on all LLM inference endpoints",
                    "Implement strict rate limiting per client to prevent bulk querying",
                    "Monitor query patterns for systematic model extraction behaviour",
                    "Watermark model outputs to detect stolen model derivatives",
                ],
            ))

        # ── M1-03: No content policy (Reprogramming Attacks) ──
        # MAESTRO L1: Reprogramming Attacks — repurposing the AI model for
        # a malicious task different from its original intent, manipulating
        # the model for unexpected and harmful uses.
        has_content_policy = node.get("content_policy", False)

        if not has_content_policy:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.ELEVATION_OF_PRIVILEGE,
                maestro_layer= LAYER,
                subcategory  = "No Content Policy — Reprogramming Attack Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' has no content policy defined. Without "
                    f"explicit boundaries on permitted tasks and outputs, the "
                    f"model can be repurposed for malicious tasks different from "
                    f"its original intent — a reprogramming attack that manipulates "
                    f"the model for unexpected and harmful uses."
                ),
                sources      = [SOURCE],
                root_cause   = f"content_policy=False|component={node['id']}",
                mitigations  = [
                    "Define an explicit content policy constraining permitted model tasks",
                    "Enforce policy at the system prompt level",
                    "Regularly red-team the model to detect reprogramming attempts",
                    "Implement output classifiers to detect out-of-scope model behaviour",
                ],
            ))

        # ── M1-04: No rate limiting or resource controls (Denial of Service) ──
        # MAESTRO L1: Denial of Service — overwhelming foundation models with
        # computationally expensive queries or adversarially crafted inputs
        # (sponge attacks) to exhaust resources, degrade inference performance,
        # or cause service unavailability. Results in operational downtime,
        # cascade failures across dependent agents, and increased costs.
        has_resource_limits = node.get("resource_limits", False)

        if not has_rate_limiting and not has_resource_limits:
            severity = calculate_severity(Severity.HIGH, trust_level)

            threats.append(Threat(
                id           = next(_id),
                component    = node["id"],
                category     = StrideCategory.DENIAL_OF_SERVICE,
                maestro_layer= LAYER,
                subcategory  = "No Rate Limiting or Resource Controls — DoS Risk",
                severity     = severity,
                description  = (
                    f"'{node['id']}' has no rate limiting or resource controls "
                    f"defined. An attacker can overwhelm the foundation model "
                    f"with computationally expensive or adversarially crafted "
                    f"queries (sponge attacks), exhausting computational resources, "
                    f"degrading inference performance, and causing service "
                    f"unavailability. This can result in cascade failures across "
                    f"all dependent AI agents and increased computational costs."
                ),
                sources      = [SOURCE],
                root_cause   = f"rate_limiting=False|resource_limits=False|component={node['id']}",
                mitigations  = [
                    "Implement per-client rate limiting on model inference endpoints",
                    "Set maximum token limits per request to prevent expensive queries",
                    "Configure compute resource limits (CPU/GPU quotas) per model instance",
                    "Monitor inference latency and alert on abnormal resource consumption",
                    "Implement query complexity scoring to reject expensive inputs",
                ],
            ))

    return threats


def _id_counter():
    i = 1
    while True:
        yield f"M1-{i:03d}"
        i += 1