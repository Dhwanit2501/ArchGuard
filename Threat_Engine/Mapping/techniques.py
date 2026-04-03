"""
ArchGuard - ATT&CK / ATLAS Technique Definitions
--------------------------------------------------
Single source of truth for all technique metadata used in mappings.
Each technique has an ID, name, tactic, and framework (ATTACK or atlas).

Architectures covered:
    - software  : Software / Service-based (ATT&CK Enterprise)
    - cloud     : Cloud-native (ATT&CK Enterprise)
    - event     : Event-driven (ATT&CK Enterprise)
    - single    : Agentic AI Single Agent ReAct (MITRE ATLAS)
    - multi     : Agentic AI Multi-Agent Hierarchical (MITRE ATLAS)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id        : str   # e.g. T1190, AML.T0051
    name      : str
    tactic    : list[str]
    framework : str   # "ATTACK" or "atlas"
    url       : str


# ATT&CK Techniques


ATTACK = {

    # Initial Access
    "T1190": Technique(
        id="T1190", name="Exploit Public-Facing Application",
        tactic=["Initial Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1190/"
    ),
    "T1133": Technique(
        id="T1133", name="External Remote Services",
        tactic=["Initial Access", " Persistence"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1133/"
    ),
    "T1078": Technique(
        id="T1078", name="Valid Accounts",
        tactic=["Initial Access",  "Defense Evasion", "Persistence", "Privilege Escalation"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1078/"
    ),

    # Execution
    "T1059": Technique(
        id="T1059", name="Command and Scripting Interpreter",
        tactic=["Execution"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1059/"
    ),
    "T1648": Technique(
        id="T1648", name="Serverless Execution",
        tactic=["Execution"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1648/"
    ),
    "T1651": Technique(
        id="T1651", name="Cloud Administration Command",
        tactic=["Execution"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1651/"
    ),

    # Privilege Escalation
    "T1068": Technique(
        id="T1068", name="Exploitation for Privilege Escalation",
        tactic=["Privilege Escalation"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1068/"
    ),
    "T1134": Technique(
        id="T1134", name="Access Token Manipulation",
        tactic=["Privilege Escalation",  "Defense Evasion"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1134/"
    ),
    "T1098": Technique(
        id="T1098", name="Account Manipulation",
        tactic=["Privilege Escalation"," Persistence"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1098/"
    ),

    # Credential Access
    "T1110": Technique(
        id="T1110", name="Brute Force",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1110/"
    ),
    "T1555": Technique(
        id="T1555", name="Credentials from Password Stores",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1555/"
    ),
    "T1212": Technique(
        id="T1212", name="Exploitation for Credential Access",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1212/"
    ),
    "T1528": Technique(
        id="T1528", name="Steal Application Access Token",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1528/"
    ),
    "T1539": Technique(
        id="T1539", name="Steal Web Session Cookie",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1539/"
    ),
    "T1552": Technique(
        id="T1552", name="Unsecured Credentials",
        tactic=["Credential Access"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1552/"
    ),

    # Lateral Movement
    "T1210": Technique(
        id="T1210", name="Exploitation of Remote Services",
        tactic=["Lateral Movement"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1210/"
    ),
    "T1021": Technique(
        id="T1021", name="Remote Services",
        tactic=["Lateral Movement"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1021/"
    ),

    # Exfiltration
    "T1041": Technique(
        id="T1041", name="Exfiltration Over C2 Channel",
        tactic=["Exfiltration"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1041/"
    ),
    "T1567": Technique(
        id="T1567", name="Exfiltration Over Web Service",
        tactic=["Exfiltration"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1567/"
    ),
    "T1537": Technique(
        id="T1537", name="Transfer Data to Cloud Account",
        tactic=["Exfiltration"], framework="ATTACK",
        url="https://attack.mitre.org/techniques/T1537/"
    ),
}


# MITRE ATLAS Techniques

ATLAS = {

    #Initial Access
    "AML.T0093": Technique(
        id="AML.T0093", name="Prompt Infiltration via Public-Facing Application",
        tactic=["Initial Access", "Persistence"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0093/"
    ),
    "AML.T0012": Technique(
        id="AML.T0012", name="Valid Accounts",
        tactic=["Initial Access","Privilege Escalation"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0012/"
    ),
    "AML.T0052": Technique(
        id="AML.T0052", name="Phishing",
        tactic=["Initial Access", "Lateral Movement"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0052/"
    ),

    # AI Model Access
    "AML.T0040": Technique(
        id="AML.T0040", name="AI Model Inference API Access",
        tactic=["AI Model Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0040/"
    ),
    "AML.T0047": Technique(
        id="AML.T0047", name="AI-Enabled Product or Service",
        tactic=["AI Model Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0047/"
    ),

    # Execution
    "AML.T0103": Technique(
        id="AML.T0103", name="Deploy AI Agent",
        tactic=["Execution"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0103/"
    ),
    "AML.T0050": Technique(
        id="AML.T0050", name="Command and Scripting Interpreter",
        tactic=["Execution"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0050/"
    ),
    "AML.T0053": Technique(
        id="AML.T0053", name="AI Agent Tool Invocation",
        tactic=["Execution","Privilege Escalation"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0053/"
    ),

    # Persistence
    "AML.T0080": Technique(
        id="AML.T0080", name="AI Agent Context Poisoning",
        tactic=["Persistence"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0080/"
    ),
    "AML.T0099": Technique(
        id="AML.T0099", name="AI Agent Tool Data Poisoning",
        tactic=["Persistence"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0099/"
    ),
    "AML.T0061": Technique(
        id="AML.T0061", name="LLM Prompt Self-Replication",
        tactic=["Persistence"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0061/"
    ),
    "AML.T0018": Technique(
        id="AML.T0018", name="Manipulate AI Model",
        tactic=["Persistence", "AI Attack Staging"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0018/"
    ),
    "AML.T0070": Technique(
        id="AML.T0070", name="RAG Poisoning",
        tactic=["Persistence"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0070/"
    ),

    # Privilege Escalation
    "AML.T0054": Technique(
        id="AML.T0054", name="LLM Jailbreak",
        tactic= ["Privilege Escalation", "Defense Evasion"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0054/"
    ),

    # Defense Evasion
    "AML.T0015": Technique(
        id="AML.T0015", name="Evade AI Model",
        tactic= ["Initial Access", "Defense Evasion", "Impact"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0015/"
    ),
    "AML.T0068": Technique(
        id="AML.T0068", name="LLM Prompt Obfuscation",
        tactic=["Defense Evasion"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0068/"
    ),
    "AML.T0094": Technique(
        id="AML.T0094", name="Delay Execution of LLM Instructions",
        tactic=["Defense Evasion"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0094/"
    ),
    "AML.T0071": Technique(
        id="AML.T0071", name="False RAG Entry Injection",
        tactic=["Defense Evasion"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0071/"
    ),
    "AML.T0092": Technique(
        id="AML.T0092", name="Manipulate User LLM Chat History",
        tactic=["Defense Evasion"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0092/"
    ),

    # Credential Access
    "AML.T0098": Technique(
        id="AML.T0098", name="AI Agent Tool Credential Harvesting",
        tactic=["Credential Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0098/"
    ),
    "AML.T0083": Technique(
        id="AML.T0083", name="Credentials from AI Agent Configuration",
        tactic=["Credential Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0083/"
    ),
    "AML.T0082": Technique(
        id="AML.T0082", name="RAG Credential Harvesting",
        tactic=["Credential Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0082/"
    ),
    "AML.T0055": Technique(
        id="AML.T0055", name="Unsecured Credentials",
        tactic=["Credential Access"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0055/"
    ),

    # Discovery
    "AML.T0084": Technique(
        id="AML.T0084", name="Discover AI Agent Configuration",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0084/"
    ),
    "AML.T0007": Technique(
        id="AML.T0007", name="Discover AI Artifacts",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0007/"
    ),
    "AML.T0013": Technique(
        id="AML.T0013", name="Discover AI Model Ontology",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0013/"
    ),
    "AML.T0063": Technique(
        id="AML.T0063", name="Discover AI Model Outputs",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0063/"
    ),
    "AML.T0062": Technique(
        id="AML.T0062", name="Discover LLM Hallucinations",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0062/"
    ),
    "AML.T0069": Technique(
        id="AML.T0069", name="Discover LLM System Information",
        tactic=["Discovery"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0069/"
    ),

    # Lateral Movement
    "AML.T0091": Technique(
        id="AML.T0091", name="Use Alternate Authentication Material",
        tactic=["Lateral Movement"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0091/"
    ),

    # Collection
    "AML.T0035": Technique(
        id="AML.T0035", name="AI Artifact Collection",
        tactic=["Collection"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0035/"
    ),
    "AML.T0085": Technique(
        id="AML.T0085", name="Data from AI Services",
        tactic=["Collection"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0085/"
    ),
    "AML.T0036": Technique(
        id="AML.T0036", name="Data from Information Repositories",
        tactic=["Collection"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0036/"
    ),

    # AI Attack Staging
    "AML.T0043": Technique(
        id="AML.T0043", name="Craft Adversarial Data",
        tactic=["AI Attack Staging"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0043/"
    ),
    "AML.T0102": Technique(
        id="AML.T0102", name="Generate Malicious Commands",
        tactic=["AI Attack Staging"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0102/"
    ),
    "AML.T0005": Technique(
        id="AML.T0005", name="Create Proxy AI Model",
        tactic=["AI Attack Staging"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0005/"
    ),

    # Command and Control
    "AML.T0096": Technique(
        id="AML.T0096", name="AI Service API",
        tactic=["Command and Control"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0096/"
    ),
    "AML.T0072": Technique(
        id="AML.T0072", name="Reverse Shell",
        tactic=["Command and Control"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0072/"
    ),
    "AML.T0108": Technique(
        id="AML.T0108", name="AI Agent",
        tactic=["Command and Control"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0108/"
    ),

    # Exfiltration
    "AML.T0086": Technique(
        id="AML.T0086", name="Exfiltration via AI Agent Tool Invocation",
        tactic=["Exfiltration"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0086/"
    ),
    "AML.T0024": Technique(
        id="AML.T0024", name="Exfiltration via AI Inference API",
        tactic=["Exfiltration"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0024/"
    ),
    "AML.T0056": Technique(
        id="AML.T0056", name="Extract LLM System Prompt",
        tactic=["Exfiltration"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0056/"
    ),
    "AML.T0057": Technique(
        id="AML.T0057", name="LLM Data Leakage",
        tactic=["Exfiltration"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0057/"
    ),

    # Impact
    "AML.T0034": Technique(
        id="AML.T0034", name="Cost Harvesting",
        tactic=["Impact"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0034/"
    ),
    "AML.T0029": Technique(
        id="AML.T0029", name="Denial of AI Service",
        tactic=["Impact"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0029/"
    ),
    "AML.T0048": Technique(
        id="AML.T0048", name="External Harms",
        tactic=["Impact"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0048/"
    ),
    "AML.T0046": Technique(
        id="AML.T0046", name="Spamming AI System with Chaff Data",
        tactic=["Impact"], framework="ATLAS",
        url="https://atlas.mitre.org/techniques/AML.T0046/"
    ),
}


# Combined lookup
ALL_TECHNIQUES = {**ATTACK, **ATLAS}