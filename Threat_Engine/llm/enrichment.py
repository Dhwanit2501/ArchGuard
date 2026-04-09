"""
ArchGuard - LLM Enrichment Module
------------------------------------
Enriches the threat analysis output with AI-generated explanations
using the Claude API.

Three enrichment types:
    1. attack_path_attack_story   — plain English story for each attack path
    2. threat_explanation      — contextual explanation for each threat
    3. additional_risks        — context-aware risks not caught by rules

Usage:
    from stride.llm.enrichment import enrich_results
    enriched = enrich_results(results, arch)

Design principles:
    - LLM only explains what the deterministic engine already found
    - All API calls are wrapped in try/except — failures are graceful
    - Enrichment runs AFTER the full engine pipeline completes
    - Original results are never modified — enriched fields are additive
"""

import json
import time
import urllib.request
import urllib.error
import os
from dotenv import load_dotenv

load_dotenv()


API_URL = "https://api.anthropic.com/v1/messages"
MODEL   = "claude-sonnet-4-6"

API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


# Claude API call

def _call_claude(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str | None:
    """
    Call the Claude API with system and user prompts.
    Returns the text response or None on failure.
    """
    payload = json.dumps({
        "model"     : MODEL,
        "max_tokens": max_tokens,
        "system"    : system_prompt,
        "messages"  : [{"role": "user", "content": user_prompt}],
    }).encode("utf-8")

    if not API_KEY:
        print("  [LLM] ERROR: ANTHROPIC_API_KEY environment variable not set.")
        print("  [LLM] Set it with: set ANTHROPIC_API_KEY=your-key-here (Windows)")
        print("  [LLM] Or: export ANTHROPIC_API_KEY=your-key-here (Mac/Linux)")
        return None

    req = urllib.request.Request(
        API_URL,
        data    = payload,
        headers = {
            "Content-Type"      : "application/json",
            "x-api-key"         : API_KEY,
            "anthropic-version" : "2023-06-01",
        },
        method  = "POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["content"][0]["text"]
            text = text.replace("\u2014", "-").replace("\u2013", "-")
            return text
    except Exception as e:
        print(f"  [LLM] API call failed: {e}")
        return None


def _parse_json_response(text: str) -> dict | None:
    """
    Parse JSON from LLM response.
    Strips markdown code blocks if present.
    """
    if not text:
        return None
    try:
        clean = text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean.strip())
    except Exception:
        return None


# Enrichment functions

def enrich_attack_paths(attack_paths: list, architecture_type: str) -> list:
    """
    Add AI attack_story to each attack path.
    Adds: attack_story, step_walkthrough, business_impact
    """
    from Threat_Engine.llm.prompts import ATTACK_PATH_SYSTEM, attack_path_user

    enriched = []
    for path in attack_paths:
        print(f"  Generating attack_story for {path['id']}...")

        user_prompt = attack_path_user(path, architecture_type)
        response    = _call_claude(ATTACK_PATH_SYSTEM, user_prompt, max_tokens=800)
        parsed      = _parse_json_response(response)

        enriched_path = dict(path)
        if parsed:
            enriched_path["attack_story"]         = parsed.get("attack_story", "")
            enriched_path["step_walkthrough"] = parsed.get("step_walkthrough", [])
            enriched_path["business_impact"]     = parsed.get("business_impact", "")
        else:
            enriched_path["attack_story"]         = ""
            enriched_path["step_walkthrough"] = []
            enriched_path["business_impact"]     = ""

        enriched.append(enriched_path)
        time.sleep(5)  # avoid rate limiting

    return enriched


def enrich_threats(threats: list, architecture_type: str,
                   max_threats: int = 20) -> list:
    """
    Add AI explanation to each threat.
    Only enriches up to max_threats to control API costs.
    Prioritizes Critical and High severity threats.
    Adds: ai_explanation
    """
    from Threat_Engine.llm.prompts import THREAT_EXPLANATION_SYSTEM, threat_explanation_user

    # Sort by severity — enrich most critical first
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_threats = sorted(
        threats,
        key=lambda t: severity_rank.get(
            t.severity.value if hasattr(t, 'severity') else t.get('severity', 'Low'), 3
        )
    )

    # Convert Threat objects to dicts if needed
    threat_dicts = []
    for t in sorted_threats:
        if hasattr(t, '__dict__'):
            threat_dicts.append({
                "id"         : t.id,
                "component"  : t.component,
                "category"   : t.category.value if hasattr(t.category, 'value') else t.category,
                "subcategory": t.subcategory,
                "severity"   : t.severity.value if hasattr(t.severity, 'value') else t.severity,
                "root_cause" : t.root_cause,
                "sources"    : t.sources,
            })
        else:
            threat_dicts.append(t)

    enriched_map = {}
    for i, threat in enumerate(threat_dicts[:max_threats]):
        print(f"  Explaining threat {threat['id']} ({i+1}/{min(len(threat_dicts), max_threats)})...")

        user_prompt = threat_explanation_user(threat, architecture_type)
        response    = _call_claude(THREAT_EXPLANATION_SYSTEM, user_prompt, max_tokens=300)
        parsed      = _parse_json_response(response)

        enriched_map[threat["id"]] = parsed.get("threat_context", "") if parsed else ""
        time.sleep(0.3)

    return enriched_map


def generate_additional_risks(arch: dict, threats: list,
                               architecture_type: str) -> list:
    """
    Generate up to 3 additional context-aware risks not caught by rules.
    Returns list of risk dicts.
    """
    from Threat_Engine.llm.prompts import ADDITIONAL_RISKS_SYSTEM, additional_risks_user

    print("  [LLM] Generating additional context-aware risks...")

    # Convert threats to dicts if needed
    threat_dicts = []
    for t in threats:
        if hasattr(t, '__dict__'):
            threat_dicts.append({"subcategory": t.subcategory})
        else:
            threat_dicts.append(t)

    user_prompt = additional_risks_user(arch, threat_dicts, architecture_type)
    response    = _call_claude(ADDITIONAL_RISKS_SYSTEM, user_prompt, max_tokens=600)
    parsed      = _parse_json_response(response)

    if parsed:
        return parsed.get("additional_risks", [])
    return []


# Main enrichment entry point

def enrich_results(results: dict) -> dict:
    """
    Run all three enrichment types on engine results.
    Returns enriched copy of results with AI fields added.

    Args:
        results: output dict from run_engine()

    Returns:
        enriched results dict with ai_* fields added
    """
    arch_type  = results.get("arch", {}).get("project", {}).get("architecture_type", "software")
    threats    = results.get("threats", [])
    paths      = results.get("attack_paths", [])
    arch       = results.get("arch", {})

    print()
    print("  Starting AI enrichment...")
    print(f"  Architecture type: {arch_type}")
    print(f"  Threats to explain: {min(len(threats), 20)} of {len(threats)}")
    print(f"  Attack paths to narrate: {len(paths)}")
    print()

    # 1. Enrich attack paths
    enriched_paths = enrich_attack_paths(paths, arch_type) if paths else []

    # 2. Enrich threats
    threat_explanations = enrich_threats(threats, arch_type)

    # 3. Generate additional risks
    additional_risks = generate_additional_risks(arch, threats, arch_type)

    # 4. Build enriched output
    enriched = dict(results)
    enriched["attack_paths"]      = enriched_paths
    enriched["additional_risks"]  = additional_risks

    # Add ai_explanation to each threat dict in output
    # (threats remain as objects in results, enrichment added separately)
    enriched["threat_explanations"] = threat_explanations

    print()
    print(f"  [LLM] Enrichment complete.")
    print(f"  [LLM] Paths narrated    : {len(enriched_paths)}")
    print(f"  [LLM] Threats explained : {len(threat_explanations)}")
    print(f"  [LLM] Additional risks  : {len(additional_risks)}")

    return enriched