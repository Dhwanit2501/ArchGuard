"""
ArchGuard - LLM Prompt Templates
----------------------------------
Defines the three prompt templates used for AI-assisted enrichment:

    1. Attack path narrative   — explains a full attack path
    2. Threat explanation      — explains an individual threat in context
    3. Additional risks        — suggests context-aware risks not caught by rules

Design principles:
    - System prompts constrain the LLM strictly to provided data
    - All responses are structured JSON for reliable parsing
    - Architecture type is always passed for context-aware reasoning
    - Output length is bounded to prevent essay-style responses
"""


# Prompt 1: Attack Path Narrative

ATTACK_PATH_SYSTEM = """You are a security analyst with 20+ years of experience explaining attack paths to a mixed audience of technical architects and business stakeholders. Keep the explanation technical by default by using the metadata about the attack path provided like MITRE tactics and techniques. Simplify the technical risk when explaining to business stakeholders and lean towards reputational damage and compliance, also include some compliance names/regulations to support the case. Your explanations must be grounded strictly in the provided path data. Do not invent threats, techniques, or components that are not in the input. Keep explanations clear, concise, and free of jargon where possible."""


def attack_path_user(attack_path: dict, architecture_type: str) -> str:
    import json

    # Build a clean summary of the path for the prompt
    steps_summary = []
    for s in attack_path.get("steps", []):
        steps_summary.append({
            "step"       : s["step"],
            "component"  : s["component"],
            "tactic"     : s["tactic"],
            "technique"  : s["technique_name"],
            "weakness"   : s["threat_subcategory"],
            "severity"   : s["threat_severity"],
        })

    path_summary = {
        "route"      : " -> ".join(attack_path.get("components_traversed", [])),
        "severity"   : attack_path.get("severity"),
        "entry_point": attack_path.get("entry_point"),
        "target"     : attack_path.get("target"),
        "steps"      : steps_summary,
    }

    return f"""Given the following attack path identified in a {architecture_type} architecture, explain it. Describe what the attacker does at each step, why each step is possible given the identified weakness, and try to create a relationship between the steps. For the final step, describe specifically what the attacker can steal, access, or damage once they reach the target - not just that they reached it. End with one sentence summarizing the business risk.
    The path severity is {attack_path.get('severity')}. If Critical, use urgent and direct language. If High, use firm and clear language. If Medium, use measured language.

Attack Path:
{json.dumps(path_summary, indent=2)}

Respond in this exact JSON format with no additional text, no markdown, no code blocks:
{{
  "attack_story": "full story of the attack in 3-5 sentences",
  "step_walkthrough": [
    {{"step": 1, "threat_explanation": "what happens at this step"}},
    {{"step": 2, "threat_explanation": "what happens at this step"}}
  ],
  "business_impact": "one sentence on business impact - vary the angle based on the path: focus on financial loss for credential theft paths, operational disruption for DoS or availability paths, regulatory exposure for data exfiltration paths, and reputational damage for paths that compromise outputs visible to end users"
}}"""


# Prompt 2: Threat Explanation

THREAT_EXPLANATION_SYSTEM = """You are a security engineer with 20+ years of experience explaining design-time threats to developers and architects in pure technical terms. Be specific, grounded, and practical. Do not speculate beyond what the threat data provides."""


def threat_explanation_user(threat: dict, architecture_type: str) -> str:
    return f"""Explain the following security threat identified in a {architecture_type} architecture. Describe what the weakness is, how an attacker could exploit it, and why it matters for this specific component. Keep it under 3 sentences.

Threat:
Component  : {threat.get('component')}
Category   : {threat.get('category')}
Subcategory: {threat.get('subcategory')}
Condition  : {threat.get('root_cause')}
Severity   : {threat.get('severity')}
Framework  : {', '.join(threat.get('sources', []))}

Respond in this exact JSON format with no additional text, no markdown, no code blocks:
{{
  "threat_context": "Explanation in 2-3 sentences"
}}"""


# Prompt 3: Additional Context-Aware Risks

ADDITIONAL_RISKS_SYSTEM = """You are a senior security architect with 20+ years of experience reviewing threat models. You must only suggest risks that are plausible given the architecture description provided. Do not suggest risks that are already covered in the identified threats list. Keep suggestions grounded and specific to the architecture type and components described."""


def additional_risks_user(arch: dict, threats: list, architecture_type: str) -> str:
    import json

    # Summarize components
    component_list = [
        f"{c['id']} ({c.get('type', 'unknown')})"
        for c in arch.get("components", [])
    ]

    # Summarize existing threats (just subcategories to avoid token overload)
    threat_summary = list({t.get("subcategory", "") for t in threats})[:20]

    return f"""Given the following architecture description and the threats already identified, suggest up to 3 additional security risks that may not have been captured by the automated analysis. Focus on design-level risks that arise from how components interact, not implementation details.

Architecture Type: {architecture_type}
Components: {', '.join(component_list)}
Already Identified Threats (sample): {', '.join(threat_summary)}

Respond in this exact JSON format with no additional text, no markdown, no code blocks:
{{
  "additional_risks": [
    {{
      "component": "component name",
      "risk": "description of the risk in 2 sentences",
      "suggested_mitigation": "one practical fix, keep it technical"
    }}
  ]
}}"""