"""
ArchGuard - STRIDE + MAESTRO Engine Orchestrator
-------------------------------------------------
Single entry point for running the full threat analysis pipeline.

Usage:
    python -m stride.engine <architecture.yaml> [options]

Options:
    --format   table|json      Output format (default: table)
    --output   <file>          Save output to file
    --no-color                 Disable colored output
    --backend  networkx|igraph Graph backend (default: networkx)

Pipeline:
    1. Parse architecture YAML
    2. Build graph representation (networkx or igraph)
    3. Detect architecture type (standard vs agentic)
    4. Run STRIDE rules (always)
    5. Run MAESTRO rules (agentic components only)
    6. Deduplicate merged threat list
    7. Output results
    8. (Optional) Generate visualization
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import unittest.mock as _mock
if "igraph" not in sys.modules:
    sys.modules["igraph"] = _mock.MagicMock()

from parser import parse_architecture
from graph.builder import GraphBuilder
from Threat_Engine.model import Threat, Severity, StrideCategory, MaestroLayer, higher_severity

# STRIDE rules
from Threat_Engine.STRIDE import Spoofing as spoofing
from Threat_Engine.STRIDE import Tampering as tampering
from Threat_Engine.STRIDE import Repudiation as repudiation
from Threat_Engine.STRIDE import Information_disclosure as information_disclosure
from Threat_Engine.STRIDE import Denial_of_service as denial_of_service
from Threat_Engine.STRIDE import Elevation_of_privilege as elevation_of_privilege

# MAESTRO rules
from Threat_Engine.MAESTRO import L1_Foundation as layer1_foundation
from Threat_Engine.MAESTRO import L2_Data as layer2_data
from Threat_Engine.MAESTRO import L3_Agent as layer3_framework

# Component type sets
AI_COMPONENT_TYPES = {"llm", "agent", "tool-executor", "vector-store", "memory-store"}


# Deduplication

def _dedup_key(threat: Threat) -> str:
    return f"{threat.component}|{threat.root_cause}"


def deduplicate(threats: list) -> list:
    seen = {}
    for threat in threats:
        key = _dedup_key(threat)
        if key not in seen:
            seen[key] = threat
        else:
            existing           = seen[key]
            merged_sources     = list(dict.fromkeys(existing.sources + threat.sources))
            merged_severity    = higher_severity(existing.severity, threat.severity)
            merged_mitigations = list(dict.fromkeys(existing.mitigations + threat.mitigations))
            seen[key] = Threat(
                id               = existing.id,
                component        = existing.component,
                category         = existing.category,
                maestro_layer    = existing.maestro_layer,
                subcategory      = existing.subcategory,
                severity         = merged_severity,
                description      = existing.description,
                sources          = merged_sources,
                root_cause       = existing.root_cause,
                mitigations      = merged_mitigations,
                data_flow        = existing.data_flow,
                assets           = existing.assets,
                attck_techniques = existing.attck_techniques,
            )
    return list(seen.values())


# Architecture type detection

def has_ai_components(arch: dict) -> bool:
    return any(
        c.get("type") in AI_COMPONENT_TYPES
        for c in arch.get("components", [])
    )


# Visualization

def run_visualizer(graph, arch: dict, output_path: str):
    """
    Generate interactive HTML architecture diagram using pyvis.
    Runs automatically on every engine execution.
    """
    try:
        from graph.visualizer import visualize
        visualize(graph, arch, output_path)
        print(f"  [Visualizer] HTML diagram saved to: {output_path}")
        print(f"  [Visualizer] Open in any browser to explore interactively.")
    except ImportError:
        print("  [Visualizer] pyvis not installed. Run: pip install pyvis")
    except Exception as e:
        print(f"  [Visualizer] HTML generation failed: {e}")


# Main engine

def run_engine(arch_path: str, backend: str = "networkx") -> dict:
    """
    Full analysis pipeline. Returns structured results dict.
    backend: 'networkx' (default, no extra install) or 'igraph' (requires pip install igraph)
    """
    # 1. Parse
    arch = parse_architecture(arch_path)

    # 2. Build graph with selected backend
    try:
        graph = GraphBuilder(arch, backend=backend).build()
    except Exception as e:
        if backend == "igraph":
            print(f"  [Warning] igraph backend failed ({e}). Falling back to networkx.")
            graph = GraphBuilder(arch, backend="networkx").build()
        else:
            raise

    # 3. Detect architecture type
    is_agentic = has_ai_components(arch)
    arch_type  = arch.get("project", {}).get("architecture_type", "standard")

    # 4. Run STRIDE rules (always)
    stride_threats = []
    stride_threats += spoofing.run(graph, arch)
    stride_threats += tampering.run(graph, arch)
    stride_threats += repudiation.run(graph, arch)
    stride_threats += information_disclosure.run(graph, arch)
    stride_threats += denial_of_service.run(graph, arch)
    stride_threats += elevation_of_privilege.run(graph, arch)

    # 5. Run MAESTRO rules (agentic components only)
    maestro_threats = []
    if is_agentic:
        maestro_threats += layer1_foundation.run(graph, arch)
        maestro_threats += layer2_data.run(graph, arch)
        maestro_threats += layer3_framework.run(graph, arch)
        # maestro_threats += layer4_infra.run(graph, arch)
        # maestro_threats += layer5_observability.run(graph, arch)
        # maestro_threats += layer6_security.run(graph, arch)
        # maestro_threats += layer7_ecosystem.run(graph, arch)

    # 6. Deduplicate
    all_threats = stride_threats + maestro_threats
    deduped     = deduplicate(all_threats)

    # 7. Re-number threat IDs sequentially after dedup
    for idx, threat in enumerate(deduped, start=1):
        threat.id = f"T-{idx:03d}"

    return {
        "project"            : arch.get("project", {}),
        "architecture"       : arch_path,
        "is_agentic"         : is_agentic,
        "arch_type"          : arch_type,
        "backend"            : backend,
        "stride_count"       : len(stride_threats),
        "maestro_count"      : len(maestro_threats),
        "total_before_dedup" : len(all_threats),
        "total_after_dedup"  : len(deduped),
        "threats"            : deduped,
        "graph"              : graph,
        "arch"               : arch,
    }


# Output formatters

SEVERITY_ORDER = {
    Severity.CRITICAL : 0,
    Severity.HIGH     : 1,
    Severity.MEDIUM   : 2,
    Severity.LOW      : 3,
}

SEVERITY_COLOR = {
    "Critical" : "\033[91m",
    "High"     : "\033[93m",
    "Medium"   : "\033[94m",
    "Low"      : "\033[92m",
}
RESET = "\033[0m"


def print_table(results: dict, color: bool = True):
    threats = sorted(results["threats"], key=lambda t: SEVERITY_ORDER.get(t.severity, 9))
    proj    = results["project"]

    print()
    print("=" * 100)
    print(f"  ArchGuard Threat Analysis — {proj.get('name', 'Unknown')} ({proj.get('id', '')})")
    print("=" * 100)
    print(f"  Architecture : {results['architecture']}")
    print(f"  Type         : {results['arch_type']}")
    print(f"  Agentic      : {'Yes' if results['is_agentic'] else 'No'}")
    print(f"  Backend      : {results['backend']}")
    print(f"  STRIDE       : {results['stride_count']} threats")
    if results["is_agentic"]:
        print(f"  MAESTRO      : {results['maestro_count']} threats")
        print(f"  Duplicates   : {results['total_before_dedup'] - results['total_after_dedup']} removed")
    print(f"  Total        : {results['total_after_dedup']} threats")
    print("=" * 100)
    print()

    from collections import Counter
    sev_counts = Counter(t.severity.value for t in threats)
    print("  Severity Summary:")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sev_counts.get(sev, 0)
        if count:
            col = SEVERITY_COLOR.get(sev, "") if color else ""
            rst = RESET if color else ""
            print(f"    {col}{sev:<10}{rst} {count}")
    print()

    header = f"  {'ID':<8} {'Severity':<10} {'Category':<28} {'Component':<22} {'Sources':<20} Subcategory"
    print(header)
    print("  " + "-" * 98)

    for t in threats:
        col     = SEVERITY_COLOR.get(t.severity.value, "") if color else ""
        rst     = RESET if color else ""
        sources = ", ".join(t.sources)
        cat     = t.category.value if hasattr(t.category, "value") else str(t.category)
        print(
            f"  {t.id:<8} "
            f"{col}{t.severity.value:<10}{rst} "
            f"{cat:<28} "
            f"{t.component:<22} "
            f"{sources:<20} "
            f"{t.subcategory}"
        )

    print()
    print("=" * 100)


def print_json(results: dict):
    output = {
        "project"            : results["project"],
        "architecture"       : results["architecture"],
        "is_agentic"         : results["is_agentic"],
        "backend"            : results["backend"],
        "stride_count"       : results["stride_count"],
        "maestro_count"      : results["maestro_count"],
        "total_before_dedup" : results["total_before_dedup"],
        "total_after_dedup"  : results["total_after_dedup"],
        "threats": [
            {
                "id"          : t.id,
                "component"   : t.component,
                "category"    : t.category.value,
                "subcategory" : t.subcategory,
                "severity"    : t.severity.value,
                "sources"     : t.sources,
                "description" : t.description,
                "mitigations" : t.mitigations,
                "data_flow"   : t.data_flow,
                "assets"      : t.assets,
                "root_cause"  : t.root_cause,
            }
            for t in results["threats"]
        ],
    }
    print(json.dumps(output, indent=2))


# CLI entry point

def main():
    parser = argparse.ArgumentParser(
        description="ArchGuard — AI-Assisted Threat Modeling Engine"
    )
    parser.add_argument(
        "architecture",
        help="Path to architecture YAML file"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--output",
        help="Save threat output to file"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--backend",
        choices=["networkx", "igraph"],
        default="networkx",
        help="Graph backend to use (default: networkx)"
    )


    args = parser.parse_args()

    # Run engine
    results = run_engine(args.architecture, backend=args.backend)

    # Print threats
    if args.format == "json":
        if args.output:
            old_stdout = sys.stdout
            sys.stdout = open(args.output, "w")
        print_json(results)
        if args.output:
            sys.stdout.close()
            sys.stdout = old_stdout
            print(f"  Results saved to: {args.output}")
    else:
        print_table(results, color=not args.no_color)
        if args.output:
            old_stdout = sys.stdout
            sys.stdout = open(args.output, "w")
            print_table(results, color=False)
            sys.stdout.close()
            sys.stdout = old_stdout
            print(f"  Results saved to: {args.output}")

    # Run visualizer (always)
    arch_stem  = Path(args.architecture).stem
    viz_output = f"{arch_stem}_graph.html"
    run_visualizer(
        graph       = results["graph"],
        arch        = results["arch"],
        output_path = viz_output,
    )


if __name__ == "__main__":
    main()