"""
ArchGuard - ATT&CK / ATLAS Mapping Module
------------------------------------------
Maps each identified STRIDE/MAESTRO threat to relevant ATT&CK or ATLAS
techniques.

Priority:
    1. If threat.suggested_techniques is set (rule-level declaration) → use those
    2. Otherwise fall back to category-level + MAESTRO layer buckets

All technique IDs verified against MITRE ATLAS and ATT&CK registries.
"""

from Threat_Engine.model import Threat, StrideCategory, MaestroLayer
from Threat_Engine.Mapping.techniques import ATTACK, ATLAS, ALL_TECHNIQUES, Technique


# Fallback technique buckets (category-level)
# Used only when a rule has not declared suggested_techniques

# Software / Service-based — ATT&CK
SOFTWARE_TECHNIQUES = {
    StrideCategory.SPOOFING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1133"],  # External Remote Services
        ATTACK["T1078"],  # Valid Accounts
    ],
    StrideCategory.TAMPERING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1059"],  # Command and Scripting Interpreter
        ATTACK["T1212"],  # Exploitation for Credential Access
    ],
    StrideCategory.REPUDIATION: [
        ATTACK["T1078"],  # Valid Accounts
        ATTACK["T1552"],  # Unsecured Credentials
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        ATTACK["T1552"],  # Unsecured Credentials
        ATTACK["T1555"],  # Credentials from Password Stores
        ATTACK["T1539"],  # Steal Web Session Cookie
        ATTACK["T1528"],  # Steal Application Access Token
        ATTACK["T1041"],  # Exfiltration Over C2 Channel
        ATTACK["T1567"],  # Exfiltration Over Web Service
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1059"],  # Command and Scripting Interpreter
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        ATTACK["T1068"],  # Exploitation for Privilege Escalation
        ATTACK["T1134"],  # Access Token Manipulation
        ATTACK["T1098"],  # Account Manipulation
        ATTACK["T1210"],  # Exploitation of Remote Services
        ATTACK["T1110"],  # Brute Force
        ATTACK["T1212"],  # Exploitation for Credential Access
    ],
}

# Cloud-native — ATT&CK
CLOUD_TECHNIQUES = {
    StrideCategory.SPOOFING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1078"],  # Valid Accounts
    ],
    StrideCategory.TAMPERING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1651"],  # Cloud Administration Command
        ATTACK["T1648"],  # Serverless Execution
    ],
    StrideCategory.REPUDIATION: [
        ATTACK["T1078"],  # Valid Accounts
        ATTACK["T1552"],  # Unsecured Credentials
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        ATTACK["T1552"],  # Unsecured Credentials
        ATTACK["T1528"],  # Steal Application Access Token
        ATTACK["T1537"],  # Transfer Data to Cloud Account
        ATTACK["T1567"],  # Exfiltration Over Web Service
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1648"],  # Serverless Execution
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        ATTACK["T1068"],  # Exploitation for Privilege Escalation
        ATTACK["T1134"],  # Access Token Manipulation
        ATTACK["T1098"],  # Account Manipulation
        ATTACK["T1210"],  # Exploitation of Remote Services
        ATTACK["T1021"],  # Remote Services
    ],
}

# Event-driven — ATT&CK
EVENT_TECHNIQUES = {
    StrideCategory.SPOOFING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1078"],  # Valid Accounts
    ],
    StrideCategory.TAMPERING: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1648"],  # Serverless Execution
    ],
    StrideCategory.REPUDIATION: [
        ATTACK["T1078"],  # Valid Accounts
        ATTACK["T1552"],  # Unsecured Credentials
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        ATTACK["T1552"],  # Unsecured Credentials
        ATTACK["T1567"],  # Exfiltration Over Web Service
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        ATTACK["T1190"],  # Exploit Public-Facing Application
        ATTACK["T1648"],  # Serverless Execution
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        ATTACK["T1068"],  # Exploitation for Privilege Escalation
        ATTACK["T1021"],  # Remote Services
    ],
}

# Agentic AI — Single Agent ReAct (ATLAS)
SINGLE_AGENT_TECHNIQUES = {
    StrideCategory.SPOOFING: [
        ATLAS["AML.T0093"],  # Prompt Infiltration via Public-Facing Application
        ATLAS["AML.T0040"],  # AI Model Inference API Access
        ATLAS["AML.T0098"],  # AI Agent Tool Credential Harvesting
    ],
    StrideCategory.TAMPERING: [
        ATLAS["AML.T0080"],  # AI Agent Context Poisoning
        ATLAS["AML.T0099"],  # AI Agent Tool Data Poisoning
        ATLAS["AML.T0043"],  # Craft Adversarial Data
        ATLAS["AML.T0071"],  # False RAG Entry Injection
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
    ],
    StrideCategory.REPUDIATION: [
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
        ATLAS["AML.T0035"],  # AI Artifact Collection
        ATLAS["AML.T0102"],  # Generate Malicious Commands
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        ATLAS["AML.T0040"],  # AI Model Inference API Access
        ATLAS["AML.T0057"],  # LLM Data Leakage
        ATLAS["AML.T0086"],  # Exfiltration via AI Agent Tool Invocation
        ATLAS["AML.T0024"],  # Exfiltration via AI Inference API
        ATLAS["AML.T0056"],  # Extract LLM System Prompt
        ATLAS["AML.T0083"],  # Credentials from AI Agent Configuration
        ATLAS["AML.T0055"],  # Unsecured Credentials
        ATLAS["AML.T0085"],  # Data from AI Services
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        ATLAS["AML.T0029"],  # Denial of AI Service
        ATLAS["AML.T0034"],  # Cost Harvesting
        ATLAS["AML.T0046"],  # Spamming AI System with Chaff Data
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        ATLAS["AML.T0054"],  # LLM Jailbreak
        ATLAS["AML.T0015"],  # Evade AI Model
        ATLAS["AML.T0068"],  # LLM Prompt Obfuscation
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
        ATLAS["AML.T0048"],  # External Harms
        ATLAS["AML.T0102"],  # Generate Malicious Commands
    ],
}

# Agentic AI — Multi-Agent Hierarchical (ATLAS)
MULTI_AGENT_TECHNIQUES = {
    StrideCategory.SPOOFING: SINGLE_AGENT_TECHNIQUES[StrideCategory.SPOOFING] + [
        ATLAS["AML.T0052"],  # Phishing
        ATLAS["AML.T0047"],  # AI-Enabled Product or Service
    ],
    StrideCategory.TAMPERING: SINGLE_AGENT_TECHNIQUES[StrideCategory.TAMPERING] + [
        ATLAS["AML.T0018"],  # Manipulate AI Model
        ATLAS["AML.T0070"],  # RAG Poisoning
        ATLAS["AML.T0094"],  # Delay Execution of LLM Instructions
        ATLAS["AML.T0092"],  # Manipulate User LLM Chat History
        ATLAS["AML.T0103"],  # Deploy AI Agent
    ],
    StrideCategory.REPUDIATION: SINGLE_AGENT_TECHNIQUES[StrideCategory.REPUDIATION] + [
        ATLAS["AML.T0096"],  # AI Service API
        ATLAS["AML.T0072"],  # Reverse Shell
        ATLAS["AML.T0036"],  # Data from Information Repositories
    ],
    StrideCategory.INFORMATION_DISCLOSURE: SINGLE_AGENT_TECHNIQUES[StrideCategory.INFORMATION_DISCLOSURE] + [
        ATLAS["AML.T0082"],  # RAG Credential Harvesting
        ATLAS["AML.T0036"],  # Data from Information Repositories
        ATLAS["AML.T0069"],  # Discover LLM System Information
        ATLAS["AML.T0063"],  # Discover AI Model Outputs
    ],
    StrideCategory.DENIAL_OF_SERVICE: SINGLE_AGENT_TECHNIQUES[StrideCategory.DENIAL_OF_SERVICE] + [
        ATLAS["AML.T0050"],  # Command and Scripting Interpreter
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: SINGLE_AGENT_TECHNIQUES[StrideCategory.ELEVATION_OF_PRIVILEGE] + [
        ATLAS["AML.T0012"],  # Valid Accounts
        ATLAS["AML.T0091"],  # Use Alternate Authentication Material
        ATLAS["AML.T0005"],  # Create Proxy AI Model
        ATLAS["AML.T0061"],  # LLM Prompt Self-Replication
        ATLAS["AML.T0084"],  # Discover AI Agent Configuration
        ATLAS["AML.T0007"],  # Discover AI Artifacts
        ATLAS["AML.T0013"],  # Discover AI Model Ontology
        ATLAS["AML.T0062"],  # Discover LLM Hallucinations
    ],
}

# MAESTRO layer fallback techniques
MAESTRO_TECHNIQUES = {
    MaestroLayer.L1_FOUNDATION: [
        ATLAS["AML.T0043"],  # Craft Adversarial Data
        ATLAS["AML.T0040"],  # AI Model Inference API Access
        ATLAS["AML.T0015"],  # Evade AI Model
        ATLAS["AML.T0029"],  # Denial of AI Service
    ],
    MaestroLayer.L2_DATA: [
        ATLAS["AML.T0070"],  # RAG Poisoning
        ATLAS["AML.T0082"],  # RAG Credential Harvesting
        ATLAS["AML.T0057"],  # LLM Data Leakage
        ATLAS["AML.T0036"],  # Data from Information Repositories
    ],
    MaestroLayer.L3_FRAMEWORK: [
        ATLAS["AML.T0080"],  # AI Agent Context Poisoning
        ATLAS["AML.T0099"],  # AI Agent Tool Data Poisoning
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
        ATLAS["AML.T0015"],  # Evade AI Model
    ],
    MaestroLayer.L4_INFRA: [
        ATLAS["AML.T0103"],  # Deploy AI Agent
        ATLAS["AML.T0029"],  # Denial of AI Service
        ATLAS["AML.T0034"],  # Cost Harvesting
    ],
    MaestroLayer.L5_OBSERVABILITY: [
        ATLAS["AML.T0063"],  # Discover AI Model Outputs
        ATLAS["AML.T0057"],  # LLM Data Leakage
        ATLAS["AML.T0043"],  # Craft Adversarial Data
    ],
    MaestroLayer.L6_SECURITY: [
        ATLAS["AML.T0015"],  # Evade AI Model
        ATLAS["AML.T0040"],  # AI Model Inference API Access
        ATLAS["AML.T0083"],  # Credentials from AI Agent Configuration
    ],
    MaestroLayer.L7_ECOSYSTEM: [
        ATLAS["AML.T0052"],  # Phishing
        ATLAS["AML.T0091"],  # Use Alternate Authentication Material
        ATLAS["AML.T0053"],  # AI Agent Tool Invocation
        ATLAS["AML.T0048"],  # External Harms
    ],
}


# Mapper

def _select_technique_map(arch: dict) -> dict:
    arch_type = arch.get("project", {}).get("architecture_type", "software")
    pattern   = arch.get("project", {}).get("pattern", "")

    if arch_type == "agentic-ai":
        if pattern == "hierarchical":
            return MULTI_AGENT_TECHNIQUES
        return SINGLE_AGENT_TECHNIQUES
    elif arch_type == "cloud":
        return CLOUD_TECHNIQUES
    elif arch_type == "event-driven":
        return EVENT_TECHNIQUES
    else:
        return SOFTWARE_TECHNIQUES


def map_threats(threats: list[Threat], arch: dict) -> list[Threat]:
    """
    Annotate each threat with ATT&CK / ATLAS techniques.

    Priority:
        1. threat.suggested_techniques declared at rule level → use those only
        2. Fallback → category-level bucket + MAESTRO layer bucket
    """
    technique_map = _select_technique_map(arch)

    for threat in threats:
        seen: dict[str, Technique] = {}

        if threat.suggested_techniques:
            arch_type = arch.get("project", {}).get("architecture_type", "software")

            if arch_type == "agentic-ai":
                # Return as-is — MAESTRO handles ATLAS techniques separately
                filtered = threat.suggested_techniques
            else:
                # Filter against confirmed technique set for this architecture
                valid_ids = {t.id for techniques in technique_map.values() for t in techniques}
                filtered  = [tid for tid in threat.suggested_techniques if tid in valid_ids]

            for tid in filtered:
                if tid in ALL_TECHNIQUES:
                    seen[tid] = ALL_TECHNIQUES[tid]
        else:
            # Fallback — category-level bucket
            for t in technique_map.get(threat.category, []):
                seen[t.id] = t

            # Add MAESTRO layer techniques
            if threat.maestro_layer and threat.maestro_layer in MAESTRO_TECHNIQUES:
                for t in MAESTRO_TECHNIQUES[threat.maestro_layer]:
                    seen[t.id] = t

        # Build attack_techniques (sorted IDs)
        threat.attack_techniques = sorted(seen.keys())

        # Build attack_mapping (sorted by first tactic then technique_id)
        threat.attack_mapping = sorted(
            [
                {
                    "tactics"        : t.tactic if isinstance(t.tactic, list) else [t.tactic],
                    "technique_id"   : t.id,
                    "technique_name" : t.name,
                    "framework"      : t.framework,
                    "url"            : t.url,
                }
                for t in seen.values()
            ],
            key=lambda x: (x["tactics"][0], x["technique_id"])
        )

    return threats