"""
ArchGuard - LLM Enrichment Module (Ollama / Local Models)
-----------------------------------------------------------
Enriches the threat analysis output using a locally hosted model
via Ollama. Drop-in replacement for enrichment.py with no API key
required and no external network calls.

Ollama must be running locally on port 11434.
Install: https://ollama.com
Pull a model: ollama pull llama3.1

Three enrichment types:
    1. attack_path_attack_story   - plain English story for each attack path
    2. threat_explanation         - contextual explanation for each threat
    3. additional_risks           - context-aware risks not caught by rules

Usage:
    python llm_enrichment.py <results.json> --output <enriched.json> --ollama

Design principles:
    - LLM only explains what the deterministic engine already found
    - All API calls are wrapped in try/except - failures are graceful
    - Enrichment runs AFTER the full engine pipeline completes
    - Original results are never modified - enriched fields are additive
"""

import json
import time
import urllib.request
import urllib.error


API_URL = "http://localhost:11434/api/chat"
MODEL   = "llama3.2:3b"


# ─────────────────────────────────────────────────────────────────────
# Core API call
# ─────────────────────────────────────────────────────────────────────

def _call_ollama(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str | None:
    """
    Call the local Ollama API with system and user prompts.
    Returns the text response or None on failure.
    """
    payload = json.dumps({
        "model"   : MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "stream"  : False,
        "options" : {
            "num_predict": max_tokens,
            "temperature": 0.3,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        API_URL,
        data    = payload,
        headers = {"Content-Type": "application/json"},
        method  = "POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["message"]["content"]
            text = text.replace("\u2014", " - ").replace("\u2013", " - ")
            return text
    except urllib.error.URLError:
        print("  [Ollama] ERROR: Cannot connect to Ollama. Is it running?")
        print("  [Ollama] Start it with: ollama serve")
        return None
    except Exception as e:
        print(f"  [Ollama] API call failed: {e}")
        return None


def _parse_json_response(text: str) -> dict | None:
    """
    Parse JSON from LLM response.
    Strips markdown code blocks if present.
    Local models are more likely to wrap JSON in backticks
    so we try multiple extraction strategies.
    """
    if not text:
        return None
    try:
        # Strategy 1 - direct parse
        clean = text.strip()
        return json.loads(clean)
    except Exception:
        pass

    try:
        # Strategy 2 - strip markdown code blocks
        clean = text.strip()
        if "```" in clean:
            parts = clean.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                try:
                    return json.loads(part)
                except Exception:
                    continue
    except Exception:
        pass

    try:
        # Strategy 3 - find first { and last }
        start = text.find("{")
        end   = text.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(text[start:end])
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────────────────────────────
# Enrichment functions
# ─────────────────────────────────────────────────────────────────────

def enrich_attack_paths(attack_paths: list, architecture_type: str) -> list:
    """
    Add AI attack_story to each attack path.
    Adds: attack_story, step_walkthrough, business_impact
    """
    from Threat_Engine.llm.prompts import ATTACK_PATH_SYSTEM, attack_path_user

    enriched = []
    for path in attack_paths:
        print(f"  [Ollama] Generating attack_story for {path['id']}...")

        user_prompt = attack_path_user(path, architecture_type)
        response    = _call_ollama(ATTACK_PATH_SYSTEM, user_prompt, max_tokens=800)
        parsed      = _parse_json_response(response)

        enriched_path = dict(path)
        if parsed:
            enriched_path["attack_story"]     = parsed.get("attack_story", "")
            enriched_path["step_walkthrough"] = parsed.get("step_walkthrough", [])
            enriched_path["business_impact"]  = parsed.get("business_impact", "")
        else:
            enriched_path["attack_story"]     = ""
            enriched_path["step_walkthrough"] = []
            enriched_path["business_impact"]  = ""
            if response:
                print(f"  [Ollama] Could not parse JSON for {path['id']} - raw response saved")
                enriched_path["raw_response"] = response[:500]

        enriched.append(enriched_path)
        time.sleep(1)

    return enriched


def enrich_threats(threats: list, architecture_type: str,
                   max_threats: int = 10) -> dict:
    """
    Add contextual explanation to each threat.
    Only enriches up to max_threats to control run time.
    Prioritizes Critical and High severity threats.
    Adds: threat_context
    """
    from Threat_Engine.llm.prompts import THREAT_EXPLANATION_SYSTEM, threat_explanation_user

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_threats = sorted(
        threats,
        key=lambda t: severity_rank.get(
            t.severity.value if hasattr(t, 'severity') else t.get('severity', 'Low'), 3
        )
    )

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
        print(f"  [Ollama] Explaining threat {threat['id']} ({i+1}/{min(len(threat_dicts), max_threats)})...")

        user_prompt = threat_explanation_user(threat, architecture_type)
        response    = _call_ollama(THREAT_EXPLANATION_SYSTEM, user_prompt, max_tokens=300)
        parsed      = _parse_json_response(response)

        enriched_map[threat["id"]] = parsed.get("threat_context", "") if parsed else ""
        time.sleep(0.5)

    return enriched_map


def generate_additional_risks(arch: dict, threats: list,
                               architecture_type: str) -> list:
    """
    Generate up to 3 additional context-aware risks not caught by rules.
    Returns list of risk dicts.
    """
    from Threat_Engine.llm.prompts import ADDITIONAL_RISKS_SYSTEM, additional_risks_user

    print("  [Ollama] Generating additional context-aware risks...")

    threat_dicts = []
    for t in threats:
        if hasattr(t, '__dict__'):
            threat_dicts.append({"subcategory": t.subcategory})
        else:
            threat_dicts.append(t)

    user_prompt = additional_risks_user(arch, threat_dicts, architecture_type)
    response    = _call_ollama(ADDITIONAL_RISKS_SYSTEM, user_prompt, max_tokens=600)
    parsed      = _parse_json_response(response)

    if parsed:
        return parsed.get("additional_risks", [])
    return []


# ─────────────────────────────────────────────────────────────────────
# Main enrichment entry point
# ─────────────────────────────────────────────────────────────────────

def enrich_results(results: dict) -> dict:
    """
    Run all three enrichment types on engine results using Ollama.
    Returns enriched copy of results with AI fields added.
    """
    arch_type = results.get("arch", {}).get("project", {}).get("architecture_type", "software")
    threats   = results.get("threats", [])
    paths     = results.get("attack_paths", [])
    arch      = results.get("arch", {})

    print()
    print("  [Ollama] Starting local model enrichment...")
    print(f"  [Ollama] Model            : {MODEL}")
    print(f"  [Ollama] Architecture type: {arch_type}")
    print(f"  [Ollama] Threats to explain: {min(len(threats), 10)} of {len(threats)}")
    print(f"  [Ollama] Attack paths to narrate: {len(paths)}")
    print()

    enriched_paths      = enrich_attack_paths(paths, arch_type) if paths else []
    threat_explanations = enrich_threats(threats, arch_type)
    additional_risks    = generate_additional_risks(arch, threats, arch_type)

    enriched                       = dict(results)
    enriched["attack_paths"]       = enriched_paths
    enriched["additional_risks"]   = additional_risks
    enriched["threat_explanations"] = threat_explanations
    enriched["llm_model"]          = MODEL
    enriched["llm_provider"]       = "ollama-local"

    print()
    print(f"  [Ollama] Enrichment complete.")
    print(f"  [Ollama] Paths narrated    : {len(enriched_paths)}")
    print(f"  [Ollama] Threats explained : {len(threat_explanations)}")
    print(f"  [Ollama] Additional risks  : {len(additional_risks)}")

    return enriched