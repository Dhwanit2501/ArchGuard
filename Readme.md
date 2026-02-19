
Readme · MD
Copy

# ArchGuard
### Threat Modeling & Attack Path Analysis Engine for Cloud, Software & Agentic AI Architectures


[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()

---

## Overview

ArchGuard is a hybrid threat modeling engine that combines deterministic STRIDE-based threat identification with MITRE ATT&CK and MITRE ATLAS technique mapping and controlled AI-assisted reasoning to support design-time security analysis of modern software, cloud, and agentic AI architectures.

The system accepts structured architecture descriptions in YAML or JSON format and produces component-level threat models, mapped attacker techniques, and plausible multi-step attack paths — making security analysis scalable, explainable, and framework-grounded.

> This project is developed as part of an independent study (CSCI-Y 790) at Indiana University, Spring 2026.

---

## Motivation

Existing threat modeling tools like Microsoft Threat Modeling Tool and OWASP Threat Dragon rely heavily on manual analysis and lack scalability. Attacker-centric frameworks like MITRE ATT&CK are typically applied post-deployment rather than at design time. ArchGuard bridges this gap by integrating both perspectives into a single, automated, design-time workflow.

---

## Architecture Types Supported

| Type | Examples | Threat Focus |
|---|---|---|
| Software / Service-Based | Microservices, REST APIs, frontend-API-database | Auth flaws, injection, privilege escalation |
| Cloud-Native | AWS/GCP components, IAM, RDS, ALB | Misconfigurations, excessive privileges, data exfiltration |
| Agentic AI | ReAct single-agent, hierarchical multi-agent | Prompt injection, tool misuse, unsafe execution |

---

## System Pipeline

```
Architecture File (YAML/JSON)
        ↓
   Parser & Validator
        ↓
  Graph Representation (NetworkX)
        ↓
  STRIDE Rule Engine
        ↓
  MITRE ATT&CK / ATLAS Mapping
        ↓
  LLM-Augmented Reasoning
        ↓
  Threat Report & Attack Paths
```

1. **Architecture Parser** — Ingests YAML/JSON architecture descriptions, validates structure and referential integrity, and returns a clean Python dictionary
2. **Graph Builder** — Converts the parsed architecture into a directed graph with components as nodes and data flows as edges
3. **STRIDE Engine** — Deterministic rule-based threat identification across all architecture elements
4. **ATT&CK / ATLAS Mapping** — Maps identified threats to relevant MITRE techniques based on architecture type
5. **LLM Reasoning Layer** — Augments rule-based output with context-aware explanations and multi-step attack path construction
6. **Report Generator** — Produces structured threat reports with CVSS-based risk prioritization

---