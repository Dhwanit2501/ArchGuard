"""
ArchGuard - Architecture Parser
----------------------------------------
Parses YAML or JSON architecture descriptions into a validated Python dict.
Auto-detects format from file extension.
"""

import json
import yaml
import os
from typing import Any


# Schema: required top-level keys and their types
REQUIRED_TOP_LEVEL = {
    "archguard_version": str,
    "project":           dict,
    "trust_zones":       list,
    "components":        list,
    "assets":            list,
    "data_flows":        list,
}

REQUIRED_PROJECT_FIELDS      = ["name", "id"]
REQUIRED_TRUST_ZONE_FIELDS   = ["id", "name", "trust_level"]
REQUIRED_COMPONENT_FIELDS    = ["id", "name", "type", "trust_zone"]
REQUIRED_ASSET_FIELDS        = ["id", "name", "sensitivity"]
REQUIRED_DATA_FLOW_FIELDS    = ["id", "name", "source", "destination", "protocol"]

VALID_TRUST_LEVELS    = {"untrusted", "low", "medium", "trusted", "critical"}
VALID_SENSITIVITIES   = {"low", "medium", "high", "critical"}
VALID_COMPONENT_TYPES = {
    
    # Here components can be add / modified as per architecure
    
    # Software / Service-based
    "web-application", "mobile-application", "api-gateway",
    "microservice", "database", "queue", "storage",
    "load-balancer", "function", "external-service",
    # Cloud-native
    "compute", "network-gateway", "iam-identity",
    "serverless", "object-storage", "cdn",
    # Agentic AI
    "llm", "tool-executor", "actor", "input", "output",
    "external-system", "agent", "vector-store", "memory-store",
}


class ArchGuardValidationError(Exception):
    """Raised when the architecture file fails validation."""
    pass


class ArchitectureParser:
    """
    Parses and validates ArchGuard architecture files (YAML or JSON) --> auto detects file format.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.raw: dict = {}         # raw parsed dict
        self.errors: list[str] = [] # collected validation errors

    def parse(self) -> dict:
        """
        Load and validate the architecture file.
        Returns the validated architecture dict.
        Raises ArchGuardValidationError if validation fails.
        """
        self.raw = self._load_file()
        self._validate()
        return self.raw

    # File Loading Part

    def _load_file(self) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Architecture file not found: {self.file_path}")

        ext = os.path.splitext(self.file_path)[1].lower()

        if ext in (".yaml", ".yml"):
            return self._load_yaml()
        elif ext == ".json":
            return self._load_json()
        else:
            raise ArchGuardValidationError(
                f"Unsupported file extension '{ext}'. Use .yaml, .yml, or .json"
            )

    def _load_yaml(self) -> dict:
        try:
            with open(self.file_path, "r") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ArchGuardValidationError("YAML root must be a mapping (dict).")
            return data
        except yaml.YAMLError as e:
            raise ArchGuardValidationError(f"YAML parse error: {e}")

    def _load_json(self) -> dict:
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ArchGuardValidationError("JSON root must be an object.")
            return data
        except json.JSONDecodeError as e:
            raise ArchGuardValidationError(f"JSON parse error: {e}")


    # Validation Part

    def _validate(self):
        """Run all validation checks. Raises on first batch of errors."""
        self.check_top_level()
        self.check_project()
        self.check_trust_zones()
        self.check_components()
        self.check_assets()
        self.check_data_flows()
        self.check_referential_integrity()

        if self.errors:
            error_list = "\n  - ".join(self.errors)
            raise ArchGuardValidationError(
                f"Architecture validation failed with {len(self.errors)} error(s):\n  - {error_list}"
            )

    def check_top_level(self):
        for key, expected_type in REQUIRED_TOP_LEVEL.items():
            if key not in self.raw:
                self.errors.append(f"Missing required top-level key: '{key}'")
            elif not isinstance(self.raw[key], expected_type):
                self.errors.append(
                    f"'{key}' must be of type {expected_type.__name__}, "   # __name__ converts a type object like <class 'list'> into a readable string 'list' so your error messages are clean and readable
                    f"got {type(self.raw[key]).__name__}"
                )

    def check_project(self):
        project = self.raw.get("project", {})
        for field in REQUIRED_PROJECT_FIELDS:
            if field not in project:
                self.errors.append(f"project: missing required field '{field}'")

    # Validates all trust zones by checking if:
    #   - At least one trust zone exist
    #   - Required field are present eg. id, name, trust level
    #   - Duplicate id check
    #   - Trust level is from the defined set

    def check_trust_zones(self):
        zones = self.raw.get("trust_zones", [])
        if not zones:
            self.errors.append("trust_zones: must define at least one trust zone")
            return
        seen_ids = set()
        for i, zone in enumerate(zones):
            prefix = f"trust_zones[{i}]"
            for field in REQUIRED_TRUST_ZONE_FIELDS:
                if field not in zone:
                    self.errors.append(f"{prefix}: missing required field '{field}'")
            if "id" in zone:
                if zone["id"] in seen_ids:
                    self.errors.append(f"{prefix}: duplicate id '{zone['id']}'")
                seen_ids.add(zone["id"])
            if "trust_level" in zone and zone["trust_level"] not in VALID_TRUST_LEVELS:
                self.errors.append(
                    f"{prefix}: invalid trust_level '{zone['trust_level']}'. "
                    f"Must be one of {VALID_TRUST_LEVELS}"
                )

    # Validates all componenets by checking if:
    #   - Required field are present eg. id, name, trust zone, type
    #   - Duplicate id check
    #   - Componenets are from the defined set

    def check_components(self):
        components = self.raw.get("components", [])
        if not components:
            self.errors.append("components: must define at least one component")
            return
        seen_ids = set()
        zone_ids = {z["id"] for z in self.raw.get("trust_zones", []) if "id" in z}
        for i, comp in enumerate(components):
            prefix = f"components[{i}] (id='{comp.get('id', '?')}')"
            for field in REQUIRED_COMPONENT_FIELDS:
                if field not in comp:
                    self.errors.append(f"{prefix}: missing required field '{field}'")
            if "id" in comp:
                if comp["id"] in seen_ids:
                    self.errors.append(f"{prefix}: duplicate id '{comp['id']}'")
                seen_ids.add(comp["id"])
            if "type" in comp and comp["type"] not in VALID_COMPONENT_TYPES:
                self.errors.append(
                    f"{prefix}: invalid type '{comp['type']}'. "
                    f"Must be one of {VALID_COMPONENT_TYPES}"
                )
            if "trust_zone" in comp and comp["trust_zone"] not in zone_ids:
                self.errors.append(
                    f"{prefix}: trust_zone '{comp['trust_zone']}' not defined in trust_zones"
                )



    # Validates all assets by checking if:
    #   - Required field are present eg. id, name, sensitivity
    #   - Duplicate id check
    #   - Sensitivity are from the defined set

    def check_assets(self):
        assets = self.raw.get("assets", [])
        if not assets:
            self.errors.append("assets: must define at least one asset")
            return
        seen_ids = set()
        for i, asset in enumerate(assets):
            prefix = f"assets[{i}] (id='{asset.get('id', '?')}')"
            for field in REQUIRED_ASSET_FIELDS:
                if field not in asset:
                    self.errors.append(f"{prefix}: missing required field '{field}'")
            if "id" in asset:
                if asset["id"] in seen_ids:
                    self.errors.append(f"{prefix}: duplicate id '{asset['id']}'")
                seen_ids.add(asset["id"])
            if "sensitivity" in asset and asset["sensitivity"] not in VALID_SENSITIVITIES:
                self.errors.append(
                    f"{prefix}: invalid sensitivity '{asset['sensitivity']}'. "
                    f"Must be one of {VALID_SENSITIVITIES}"
                )


    # Validates all data_flows by checking if:
    #   - Required field are present eg. id, name, src, dst, prot
    #   - Duplicate id check
    #   - Structurally valid

    def check_data_flows(self):
        flows = self.raw.get("data_flows", [])
        if not flows:
            self.errors.append("data_flows: must define at least one data flow")
            return
        seen_ids = set()
        for i, flow in enumerate(flows):
            prefix = f"data_flows[{i}] (id='{flow.get('id', '?')}')"
            for field in REQUIRED_DATA_FLOW_FIELDS:
                if field not in flow:
                    self.errors.append(f"{prefix}: missing required field '{field}'")
            if "id" in flow:
                if flow["id"] in seen_ids:
                    self.errors.append(f"{prefix}: duplicate id '{flow['id']}'")
                seen_ids.add(flow["id"])

    # Ensures the data flow graph is internally consistent by checking if:
    #   - src, dst and asset references exist
    #   - Avoid dangling references ( a concept from databases, where it ensures if an entity points to some id, it actually exists in the database)


    def check_referential_integrity(self):
        """Ensure data flow sources/destinations and asset refs point to real IDs."""
        component_ids = {c["id"] for c in self.raw.get("components", []) if "id" in c}
        asset_ids     = {a["id"] for a in self.raw.get("assets", []) if "id" in a}

        for i, flow in enumerate(self.raw.get("data_flows", [])):
            prefix = f"data_flows[{i}] (id='{flow.get('id', '?')}')"
            if "source" in flow and flow["source"] not in component_ids:
                self.errors.append(
                    f"{prefix}: source '{flow['source']}' not found in components"
                )
            if "destination" in flow and flow["destination"] not in component_ids:
                self.errors.append(
                    f"{prefix}: destination '{flow['destination']}' not found in components"
                )
            for asset_ref in flow.get("assets", []):
                if asset_ref not in asset_ids:
                    self.errors.append(
                        f"{prefix}: asset ref '{asset_ref}' not found in assets"
                    )


# Wraper function around class to keep the internals of parser hidden

def parse_architecture(file_path: str) -> dict:
    """
    Parse and validate an ArchGuard architecture file.
    Returns the validated architecture dict.
    """
    parser = ArchitectureParser(file_path)
    return parser.parse()


# For quick testing

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser.py <architecture_file.yaml|.json|.yml>")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        arch = parse_architecture(file_path)
        print(f"✅ Parsed successfully: {arch['project']['name']}")
        print(f"   Trust zones : {len(arch['trust_zones'])}")
        print(f"   Components  : {len(arch['components'])}")
        print(f"   Assets      : {len(arch['assets'])}")
        print(f"   Data flows  : {len(arch['data_flows'])}")
    except (FileNotFoundError, ArchGuardValidationError) as e:
        print(f"❌ Error: {e}")
        sys.exit(1)