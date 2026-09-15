"""Centurion interchange — EBIOS RM shaped payload for CISO Assistant.

Centurion threat modelling in this repo is the GRC study that lives next to
STRIKE: assets, feared events, RO/TO couples, strategic scenarios, attack
paths, operational scenarios, and risk scenarios. Field names follow
CISO Assistant's `ebios_rm` models so an analyst can file the study without
re-typing STRIKE output.
"""

from __future__ import annotations

from typing import Any

from strike.catalog import ATTACK_TECHNIQUES, CENTURION_RISK_ORIGINS, tactic_name
from strike.engine import AssessmentResult

FORMAT = "centurion.ebios.v1"

GRAVITY = {"low": 1, "medium": 2, "high": 3}
LIKELIHOOD = {"low": 1, "medium": 2, "high": 3}


def _origin_term(origin: str) -> str:
    blob = origin.lower()
    for candidate in CENTURION_RISK_ORIGINS:
        if candidate.split()[0] in blob or candidate in blob:
            return candidate
    return "cybercriminal"


def export_centurion(result: AssessmentResult) -> dict[str, Any]:
    assets = [
        {
            "ref_id": jewel.id,
            "name": jewel.name,
            "type": "primary",
            "description": jewel.rationale,
        }
        for jewel in result.crown_jewels
    ]

    feared_events = []
    for idx, risk in enumerate(result.ranked_risks[:3], start=1):
        threat = next((t for t in result.threats if t.id == risk.threat_id), result.threats[0])
        feared_events.append(
            {
                "ref_id": f"FE-{idx}",
                "name": f"Loss of control over {result.crown_jewels[min(idx - 1, len(result.crown_jewels) - 1)].name}",
                "description": risk.title,
                "gravity": GRAVITY.get(risk.impact, 2),
                "is_selected": True,
                "assets": [a["ref_id"] for a in assets[:2]],
                "qualifications": threat.stride,
                "justification": f"Derived from STRIKE Impact ({risk.impact}) on {risk.title}.",
            }
        )
    if not feared_events and result.crown_jewels:
        feared_events.append(
            {
                "ref_id": "FE-1",
                "name": f"Compromise of {result.crown_jewels[0].name}",
                "description": "Inferred feared event from scope.",
                "gravity": 2,
                "is_selected": True,
                "assets": [result.crown_jewels[0].id],
                "qualifications": [],
                "justification": "No ranked risk yet; seeded from crown jewels.",
            }
        )

    ro_to = []
    for idx, threat in enumerate(result.threats[:3], start=1):
        ro_to.append(
            {
                "ref_id": f"ROTO-{idx}",
                "risk_origin": _origin_term(threat.risk_origin),
                "target_objective": threat.name,
                "motivation": 3 if threat.severity == "high" else 2,
                "resources": 3 if threat.severity == "high" else 2,
                "activity": 2,
                "is_selected": idx <= 3,
                "feared_events": [feared_events[min(idx - 1, len(feared_events) - 1)]["ref_id"]],
                "justification": threat.description,
            }
        )

    strategic = []
    attack_paths = []
    operational = []
    for idx, path in enumerate(result.attack_paths, start=1):
        roto_id = ro_to[min(idx - 1, len(ro_to) - 1)]["ref_id"] if ro_to else None
        sc_id = f"SS-{idx}"
        ap_id = path.id
        strategic.append(
            {
                "ref_id": sc_id,
                "name": path.name,
                "description": " → ".join(path.steps),
                "ro_to_couple": roto_id,
                "focused_feared_event": feared_events[min(idx - 1, len(feared_events) - 1)]["ref_id"]
                if feared_events
                else None,
            }
        )
        attack_paths.append(
            {
                "ref_id": ap_id,
                "name": path.name,
                "description": " → ".join(path.steps),
                "strategic_scenario": sc_id,
                "is_selected": True,
                "justification": f"STRIKE Route; likelihood {path.likelihood}.",
                "stakeholders": [],
            }
        )
        threat_names = []
        for tid in path.techniques:
            meta = ATTACK_TECHNIQUES.get(tid)
            if meta:
                threat_names.append(f"{tid} {meta['name']} ({tactic_name(meta['tactic'])})")
            else:
                threat_names.append(tid)
        operational.append(
            {
                "ref_id": f"OS-{idx}",
                "attack_path": ap_id,
                "operating_modes_description": " → ".join(path.steps),
                "likelihood": LIKELIHOOD.get(path.likelihood, 2),
                "is_selected": True,
                "threats": threat_names,
                "justification": "Operational scenario generated from STRIKE Route.",
            }
        )

    controls = [
        {
            "ref_id": item.id,
            "name": item.title,
            "description": item.action,
            "category": "technical" if item.csf_function in {"protect", "detect"} else "process",
            "csf_function": item.csf_function,
        }
        for item in result.resilience
    ]

    risk_scenarios = []
    for risk in result.ranked_risks:
        path = next((p for p in result.attack_paths if p.id == risk.path_id), None)
        threat = next((t for t in result.threats if t.id == risk.threat_id), None)
        op = next((o for o in operational if path and o["attack_path"] == path.id), None)
        risk_scenarios.append(
            {
                "ref_id": risk.id,
                "name": risk.title,
                "treatment": "mitigate",
                "assets": [a["ref_id"] for a in assets[:3]],
                "threats": [threat.name] if threat else [],
                "existing_controls": "; ".join(c["name"] for c in controls[:2]),
                "operational_scenario": op["ref_id"] if op else None,
                "current_proba": LIKELIHOOD.get(risk.likelihood, 2),
                "current_impact": GRAVITY.get(risk.impact, 2),
                "strength_of_knowledge": 1,
            }
        )

    return {
        "format": FORMAT,
        "generated_by": "STRIKE Threat",
        "methodology": "EBIOS RM (Centurion / CISO Assistant interchange)",
        "study": {
            "name": result.title,
            "description": (
                "STRIKE Threat assessment aligned to Centurion EBIOS RM workshops. "
                + (result.notes or "")
            ).strip(),
            "version": "1.0",
            "status": "in_progress",
            "quotation_method": "express",
            "ref_id": "STRIKE-1",
        },
        "assets": assets,
        "feared_events": feared_events,
        "ro_to_couples": ro_to,
        "strategic_scenarios": strategic,
        "attack_paths": attack_paths,
        "operational_scenarios": operational,
        "applied_controls": controls,
        "risk_scenarios": risk_scenarios,
        "strike": {
            "methodologies": result.methodology_names,
            "answers": result.answers,
        },
    }
