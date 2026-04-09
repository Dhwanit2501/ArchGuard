"""
ArchGuard - LLM Enrichment CLI
--------------------------------
Runs AI enrichment on top of existing engine output.

Usage:
    python llm_enrichment.py <results.json> --output <enriched.json>

Arguments:
    results.json    Path to JSON output from engine.py
    --output        Path to save enriched JSON (default: <stem>_enriched.json)

Pipeline:
    1. Load existing engine results JSON
    2. Run attack path narrative generation
    3. Run threat explanation generation (top 20 by severity)
    4. Run additional context-aware risk generation
    5. Save enriched JSON with all AI fields added

Note:
    The original results file is never modified.
    AI fields are additive — all original fields are preserved.
"""

import sys
import json
import argparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Threat_Engine.llm.enrichment import (
    enrich_attack_paths,
    enrich_threats,
    generate_additional_risks,
)


def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def build_enriched_json(results: dict, enriched_paths: list,
                        threat_explanations: dict,
                        additional_risks: list) -> dict:
    """
    Build the final enriched JSON output.
    Merges AI fields into the existing results structure.
    """
    # Add ai_explanation to each threat
    enriched_threats = []
    for t in results.get("threats", []):
        threat = dict(t)
        threat["threat_context"] = threat_explanations.get(t.get("id", ""), "")
        enriched_threats.append(threat)

    return {
        "project"            : results.get("project"),
        "architecture"       : results.get("architecture"),
        "is_agentic"         : results.get("is_agentic"),
        "backend"            : results.get("backend"),
        "stride_count"       : results.get("stride_count"),
        "maestro_count"      : results.get("maestro_count"),
        "total_before_dedup" : results.get("total_before_dedup"),
        "total_after_dedup"  : results.get("total_after_dedup"),
        "threats"            : enriched_threats,
        "attack_paths"       : enriched_paths,
        "additional_risks"   : additional_risks,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ArchGuard LLM Enrichment - AI explanation layer"
    )
    parser.add_argument(
        "results",
        help="Path to JSON results file from engine.py"
    )
    parser.add_argument(
        "--output",
        help="Path to save enriched JSON output",
        default=None
    )
    parser.add_argument(
        "--paths-only",
        action="store_true",
        help="Only enrich attack paths, skip threat explanations"
    )
    parser.add_argument(
        "--max-threats",
        type=int,
        default=10,
        help="Maximum number of threats to explain (default: 10)"
    )

    args   = parser.parse_args()
    input_path  = args.results
    output_path = args.output or input_path.replace(".json", "_enriched.json")

    print()
    print("=" * 70)
    print("  ArchGuard LLM Enrichment")
    print("=" * 70)
    print(f"  Input  : {input_path}")
    print(f"  Output : {output_path}")
    print()

    # Load results
    results = load_results(input_path)
    arch_type = results.get("project", {}).get("architecture_type", "software")
    threats   = results.get("threats", [])
    paths     = results.get("attack_paths", [])
    arch      = results.get("project", {})

    # Build minimal arch dict for additional risks prompt
    arch_for_prompt = {
        "project"   : results.get("project", {}),
        "components": [
            {"id": t.get("component"), "type": "unknown"}
            for t in threats
        ]
    }

    print(f"  Architecture : {arch_type}")
    print(f"  Threats      : {len(threats)}")
    print(f"  Attack Paths : {len(paths)}")
    print()

    # 1. Enrich attack paths
    print("  Step 1/3 — Generating attack path narratives...")
    enriched_paths = enrich_attack_paths(paths, arch_type)

    # 2. Enrich threats
    if not args.paths_only:
        print()
        print(f"  Step 2/3 — Explaining top {args.max_threats} threats...")
        threat_explanations = enrich_threats(threats, arch_type, args.max_threats)
    else:
        threat_explanations = {}

    # 3. Additional risks
    if not args.paths_only:
        print()
        print("  Step 3/3 — Generating additional context-aware risks...")
        additional_risks = generate_additional_risks(arch_for_prompt, threats, arch_type)
    else:
        additional_risks = []

    # Build and save enriched output
    enriched = build_enriched_json(
        results, enriched_paths, threat_explanations, additional_risks
    )

    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2)

    print()
    print("=" * 70)
    print(f"  Enrichment complete.")
    print(f"  Paths narrated    : {len(enriched_paths)}")
    print(f"  Threats explained : {len(threat_explanations)}")
    print(f"  Additional risks  : {len(additional_risks)}")
    print(f"  Saved to          : {output_path}")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()