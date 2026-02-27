"""
ArchGuard - Threat Models
--------------------------
Defines the Threat dataclass — the common language spoken by every
rule file, MAESTRO layer, deduplicator, and engine in the system.

Every rule returns a list[Threat]. The engine collects them all,
deduplicates, and outputs the final threat list.
"""

from dataclasses import dataclass, field
from enum import Enum


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"

    def __gt__(self, other):
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other):
        return self == other or self > other


class StrideCategory(str, Enum):
    SPOOFING                = "Spoofing"
    TAMPERING               = "Tampering"
    REPUDIATION             = "Repudiation"
    INFORMATION_DISCLOSURE  = "Information Disclosure"
    DENIAL_OF_SERVICE       = "Denial of Service"
    ELEVATION_OF_PRIVILEGE  = "Elevation of Privilege"


class MaestroLayer(str, Enum):
    L1_FOUNDATION       = "MAESTRO-L1: Foundation Models"
    L2_DATA             = "MAESTRO-L2: Data Operations"
    L3_FRAMEWORK        = "MAESTRO-L3: Agent Frameworks"
    L4_INFRA            = "MAESTRO-L4: Deployment & Infrastructure"
    L5_OBSERVABILITY    = "MAESTRO-L5: Evaluation & Observability"
    L6_SECURITY         = "MAESTRO-L6: Security & Compliance"
    L7_ECOSYSTEM        = "MAESTRO-L7: Agent Ecosystem"


# ─────────────────────────────────────────────
# Threat dataclass
# ─────────────────────────────────────────────

@dataclass
class Threat:
    """
    Represents a single identified threat.

    Fields:
        id              : unique threat ID e.g. "T-001"
        component       : component id this threat applies to
        category        : STRIDE category (always set)
        maestro_layer   : MAESTRO layer if AI-specific (None for pure STRIDE)
        subcategory     : specific threat name e.g. "Prompt Injection"
        severity        : Critical / High / Medium / Low
        description     : human-readable explanation of the threat
        sources         : which frameworks identified this e.g. ["STRIDE", "MAESTRO-L3"]
        root_cause      : short key used for deduplication e.g. "encrypted_in_transit=False"
        mitigations     : list of recommended fixes
        data_flow       : flow id if this is a flow-level threat (None for node-level)
        assets          : sensitive assets involved in this threat
        attck_techniques: ATT&CK technique IDs (populated later by mapping module)
    """

    id               : str
    component        : str
    category         : StrideCategory
    subcategory      : str
    severity         : Severity
    description      : str
    sources          : list[str]
    root_cause       : str
    mitigations      : list[str]          = field(default_factory=list)
    maestro_layer    : MaestroLayer | None = None
    data_flow        : str | None          = None
    assets           : list[str]           = field(default_factory=list)
    attck_techniques : list[str]           = field(default_factory=list)


# ─────────────────────────────────────────────
# Severity utilities
# ─────────────────────────────────────────────

# Asset sensitivity → severity bump
SENSITIVITY_SEVERITY = {
    "critical" : Severity.CRITICAL,
    "high"     : Severity.HIGH,
    "medium"   : Severity.MEDIUM,
    "low"      : Severity.LOW,
}

# Trust level → base severity modifier
TRUST_SEVERITY = {
    "untrusted" : 2,   # bump severity by 2 levels
    "low"       : 1,   # bump by 1
    "medium"    : 0,   # no change
    "high"      : 0,
    "trusted"   : 0,
}

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def bump_severity(base: Severity, levels: int) -> Severity:
    """
    Bump a severity up by a number of levels.
    Caps at Critical.
    e.g. bump_severity(Medium, 1) -> High
         bump_severity(High, 2)   -> Critical
    """
    idx = SEVERITY_ORDER.index(base)
    return SEVERITY_ORDER[min(idx + levels, len(SEVERITY_ORDER) - 1)]


def calculate_severity(
    base       : Severity,
    trust_level: str,
    asset_sensitivities: list[str] = [],
) -> Severity:
    """
    Calculate final severity from base severity, trust level,
    and the sensitivity of assets involved.

    Logic:
        1. Start with base severity from the rule
        2. Bump up based on trust level of the component's zone
        3. Bump up if flow carries high/critical sensitivity assets
    """
    severity = base

    # Bump based on trust level
    bump = TRUST_SEVERITY.get(trust_level, 0)
    severity = bump_severity(severity, bump)

    # Bump based on highest asset sensitivity involved
    if asset_sensitivities:
        highest = max(
            SENSITIVITY_SEVERITY.get(s, Severity.LOW)
            for s in asset_sensitivities
        )
        if highest >= Severity.HIGH and severity < Severity.CRITICAL:
            severity = bump_severity(severity, 1)

    return severity


def higher_severity(a: Severity, b: Severity) -> Severity:
    """Return the higher of two severities."""
    return a if a >= b else b