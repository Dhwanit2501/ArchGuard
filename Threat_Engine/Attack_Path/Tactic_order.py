"""
ArchGuard - Attack Path: Tactic Ordering
-----------------------------------------
Defines the kill chain tactic ordering for ATT&CK and ATLAS.
Used to sequence attack steps in a realistic attacker progression.

ATT&CK Enterprise kill chain order:
    Initial Access → Execution → Persistence → Privilege Escalation →
    Defense Evasion → Credential Access → Discovery →
    Lateral Movement → Collection → Exfiltration → Impact

ATLAS kill chain order:
    Initial Access → AI Model Access → Execution → Persistence →
    Privilege Escalation → Defense Evasion → Credential Access →
    Discovery → Lateral Movement → Collection → AI Attack Staging →
    Command and Control → Exfiltration → Impact
"""

# ATT&CK Enterprise tactic order
ATTCK_TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# MITRE ATLAS tactic order
ATLAS_TACTIC_ORDER = [
    "Initial Access",
    "AI Model Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "AI Attack Staging",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Entry tactics — paths must start with one of these
ENTRY_TACTICS = {"Initial Access", "AI Model Access"}

# Terminal tactics — paths end when reaching one of these
TERMINAL_TACTICS = {"Exfiltration", "Impact"}

# High value tactics — used for scoring
HIGH_VALUE_TACTICS = {"Exfiltration", "Impact", "Credential Access", "Lateral Movement"}


def get_tactic_rank(tactic: str, is_agentic: bool = False) -> int:
    """Return kill chain rank. Lower = earlier. Unknown = 999."""
    order = ATLAS_TACTIC_ORDER if is_agentic else ATTCK_TACTIC_ORDER
    try:
        return order.index(tactic)
    except ValueError:
        return 999


def get_primary_tactic(tactics: list, is_agentic: bool = False) -> str:
    """Return the earliest kill chain tactic from a list."""
    if not tactics:
        return "Unknown"
    return min(tactics, key=lambda t: get_tactic_rank(t, is_agentic))


def is_entry_tactic(tactic: str) -> bool:
    return tactic in ENTRY_TACTICS


def is_terminal_tactic(tactic: str) -> bool:
    return tactic in TERMINAL_TACTICS