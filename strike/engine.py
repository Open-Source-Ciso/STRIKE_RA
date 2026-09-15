"""Deterministic STRIKE Threat generator.

Produces the MVP artefacts (crown jewels, top threats, attack paths, ranked
risk, resilience priorities, action plan) plus methodology tags. No LLM —
outputs are reproducible from the same answers and imports.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from strike.catalog import (
    ATTACK_TECHNIQUES,
    ATTACK_ID,
    CENTURION_RISK_ORIGINS,
    DREAD_ID,
    LINDDUN_CATEGORIES,
    LINDDUN_ID,
    PASTA_ID,
    STRIDE_CATEGORIES,
    STRIKE_STEPS,
    selected_methodologies,
    tactic_name,
)
from strike.parser import ImportedModel, detect_techniques, parse_import, split_items

HIGH_IMPACT = (
    "ransom", "breach", "pii", "card", "life", "safety", "outage", "regulator",
    "fine", "nation", "patient", "ot ", "ics", "critical", "wipe",
)
MED_IMPACT = (
    "reputat", "fraud", "downtime", "insider", "supply", "financial", "brand",
    "customer", "availability",
)
HIGH_LIKELIHOOD = (
    "phish", "internet", "public", "no mfa", "default", "known", "common",
    "exposed", "saas",
)
ASSET_HINTS = (
    "customer data", "personal data", "pii", "phi", "payment", "cardholder",
    "source code", "credential", "secret", "api key", "identity", "crown",
    "database", "backup", "ot network", "control system", "availability",
    "merchant", "wallet", "intellectual property", "trade secret",
)


@dataclass
class CrownJewel:
    id: str
    name: str
    rationale: str
    source: str


@dataclass
class ThreatItem:
    id: str
    name: str
    description: str
    stride: list[str]
    attack_tactics: list[str]
    attack_techniques: list[str]
    linddun: list[str]
    risk_origin: str
    severity: str


@dataclass
class AttackPath:
    id: str
    name: str
    steps: list[str]
    techniques: list[str]
    likelihood: str


@dataclass
class RankedRisk:
    id: str
    title: str
    threat_id: str
    path_id: str
    impact: str
    likelihood: str
    score: int
    dread: dict[str, int] | None


@dataclass
class ResiliencePriority:
    id: str
    title: str
    action: str
    csf_function: str


@dataclass
class ActionItem:
    id: str
    title: str
    owner_hint: str
    related_risk_ids: list[str]


@dataclass
class AssessmentResult:
    title: str
    methodologies: list[str]
    methodology_names: list[str]
    answers: dict[str, str]
    crown_jewels: list[CrownJewel]
    threats: list[ThreatItem]
    attack_paths: list[AttackPath]
    ranked_risks: list[RankedRisk]
    resilience: list[ResiliencePriority]
    action_plan: list[ActionItem]
    alignment: list[dict[str, str]]
    imported: dict[str, Any]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


def _blob(parts: list[str]) -> str:
    return "\n".join(p for p in parts if p).strip()


def _impact_level(text: str) -> str:
    blob = text.lower()
    if any(token in blob for token in HIGH_IMPACT):
        return "high"
    if any(token in blob for token in MED_IMPACT):
        return "medium"
    return "medium" if blob else "low"


def _likelihood(text: str) -> str:
    blob = text.lower()
    if any(token in blob for token in HIGH_LIKELIHOOD):
        return "high"
    if any(token in blob for token in ("insider", "partner", "supply", "targeted")):
        return "medium"
    return "medium" if blob else "low"


def _score(impact: str, likelihood: str) -> int:
    scale = {"low": 1, "medium": 2, "high": 3}
    return scale.get(impact, 2) * scale.get(likelihood, 2)


def _dread(impact: str, likelihood: str, path_steps: int, discoverable: bool) -> dict[str, int]:
    imap = {"low": 1, "medium": 2, "high": 3}
    damage = imap.get(impact, 2)
    exploit = imap.get(likelihood, 2)
    repro = 3 if path_steps <= 3 else 2
    affected = damage
    discover = 3 if discoverable else 2
    return {
        "damage": damage,
        "reproducibility": repro,
        "exploitability": exploit,
        "affected_users": affected,
        "discoverability": discover,
        "total": damage + repro + exploit + affected + discover,
    }


def _pick_origin(text: str, imported: ImportedModel) -> str:
    blob = text.lower()
    if imported.risk_origins:
        return imported.risk_origins[0]
    mapping = (
        (("nation", "apt", "state"), "state-sponsored"),
        (("insider", "employee", "privileged user"), "insider"),
        (("partner", "vendor", "supply", "third party"), "partner / supply chain"),
        (("hacktiv", "ideolog"), "hacktivist"),
        (("competitor", "espionage"), "competitor"),
        (("error", "mistake", "accidental"), "accidental / error"),
        (("flood", "quake", "nature"), "act of nature"),
    )
    for keys, origin in mapping:
        if any(k in blob for k in keys):
            return origin
    return CENTURION_RISK_ORIGINS[0]


def _extract_crown_jewels(scope: str, imported: ImportedModel) -> list[CrownJewel]:
    names: list[tuple[str, str]] = []
    for item in imported.assets:
        names.append((item, "import"))
    # Prefer short, named assets from scope — never a whole paragraph.
    scope_items = split_items(scope)
    for item in scope_items:
        if len(item) > 90 or len(item.split()) > 8:
            continue
        lowered = item.lower()
        if any(hint in lowered for hint in ASSET_HINTS) or len(item.split()) <= 6:
            names.append((item, "scope"))
    # Fallback sentences.
    if len(names) < 3:
        for sentence in re_split_sentences(scope):
            names.append((sentence, "scope"))
    seen: set[str] = set()
    jewels: list[CrownJewel] = []
    for name, source in names:
        key = name.lower()
        if key in seen or len(name) < 4:
            continue
        seen.add(key)
        jewels.append(
            CrownJewel(
                id=f"CJ-{len(jewels) + 1}",
                name=_clip(name, 80),
                rationale="Called out in scope or imported model as something that must keep operating.",
                source=source,
            )
        )
        if len(jewels) == 5:
            break
    defaults = [
        "Customer / user data",
        "Authentication and session integrity",
        "Core service availability",
        "Privileged credentials and keys",
        "Build and software supply chain",
    ]
    for default in defaults:
        if len(jewels) >= 3:
            break
        if default.lower() in seen:
            continue
        jewels.append(
            CrownJewel(
                id=f"CJ-{len(jewels) + 1}",
                name=default,
                rationale="Inferred baseline crown jewel because scope did not name enough assets.",
                source="inferred",
            )
        )
    return jewels[:5]


def re_split_sentences(text: str) -> list[str]:
    parts = []
    for chunk in (text or "").replace("!", ".").replace("?", ".").split("."):
        item = chunk.strip(" \n-")
        if len(item) >= 12:
            parts.append(item)
    return parts


def _clip(text: str, n: int) -> str:
    text = " ".join(text.split())
    if len(text) <= n:
        return text
    return text[: n - 1].rsplit(" ", 1)[0] + "…"


def _stride_for(text: str, imported: ImportedModel) -> list[str]:
    hits = list(imported.stride_hits)
    blob = text.lower()
    for cat in STRIDE_CATEGORIES:
        if cat["id"] in hits:
            continue
        if any(k in blob for k in cat["keywords"]):
            hits.append(cat["id"])
    if not hits:
        # A connected system almost always has spoofing, disclosure, and DoS in play.
        hits = ["S", "I", "D"]
    return list(dict.fromkeys(hits))


def _linddun_for(text: str, imported: ImportedModel) -> list[str]:
    hits = list(imported.linddun_hits)
    blob = text.lower()
    for cat in LINDDUN_CATEGORIES:
        if cat["id"] in hits:
            continue
        if any(k in blob for k in cat["keywords"]):
            hits.append(cat["id"])
    return list(dict.fromkeys(hits))


def _threats(
    threat_text: str,
    scope: str,
    imported: ImportedModel,
    methodology_ids: list[str],
    stride_hits: list[str],
    techniques: list[str],
) -> list[ThreatItem]:
    names = list(imported.threats) + split_items(threat_text)
    # Keep actor-like items; drop paragraphs and very generic fragments.
    actors: list[str] = []
    seen_actors: set[str] = set()
    for name in names:
        key = name.lower()
        if len(name) < 4 or len(name.split()) > 10 or key in seen_actors:
            continue
        seen_actors.add(key)
        actors.append(name)
        if len(actors) == 5:
            break
    if not actors:
        actors = [
            "External cybercriminals",
            "Malicious or coerced insider",
            "Compromised supplier or integrator",
        ]
    origin_blob = _blob([threat_text, imported.evidence_blob()])
    items: list[ThreatItem] = []
    stride_cycle = stride_hits or ["S", "I", "D"]
    for idx, actor in enumerate(actors[:5]):
        stride = [stride_cycle[idx % len(stride_cycle)]]
        # Attach a second category when the actor text implies it.
        extra = _stride_for(actor, ImportedModel())
        for letter in extra:
            if letter not in stride:
                stride.append(letter)
            if len(stride) == 2:
                break
        related_tech = techniques[idx : idx + 2] or techniques[:1]
        tactics = []
        for tid in related_tech:
            meta = ATTACK_TECHNIQUES.get(tid)
            if meta and meta["tactic"] not in tactics:
                tactics.append(meta["tactic"])
        if not tactics and ATTACK_ID in methodology_ids:
            tactics = ["TA0001"]
        linddun = _linddun_for(actor + " " + scope, imported) if LINDDUN_ID in methodology_ids else []
        severity = "high" if idx == 0 else ("medium" if idx < 3 else "low")
        if any(k in actor.lower() for k in ("ransom", "nation", "apt", "ot")):
            severity = "high"
        items.append(
            ThreatItem(
                id=f"TH-{idx + 1}",
                name=_clip(actor, 90),
                description=(
                    f"Adversary or source capable of abusing the scoped system. "
                    f"STRIKE maps this onto {_stride_names(stride)}."
                ),
                stride=stride,
                attack_tactics=tactics,
                attack_techniques=related_tech,
                linddun=linddun,
                risk_origin=_pick_origin(actor + " " + origin_blob, imported),
                severity=severity,
            )
        )
    return items[:5]


def _stride_names(ids: list[str]) -> str:
    lookup = {c["id"]: c["name"] for c in STRIDE_CATEGORIES}
    return ", ".join(lookup.get(i, i) for i in ids)


def _paths(
    route: str,
    imported: ImportedModel,
    techniques: list[str],
) -> list[AttackPath]:
    groups = list(imported.path_groups)
    # Numbered / arrowed lines in the route answer.
    for line in (route or "").splitlines():
        steps = [s.strip(" -") for s in re.split(r"\s*(?:->|→|>)\s*", line.strip()) if s.strip(" -")]
        if len(steps) > 1:
            groups.append(steps)
    if not groups:
        items = split_items(route)
        if len(items) >= 2:
            # Chunk into paths of up to 4 steps.
            chunk: list[str] = []
            for item in items:
                chunk.append(item)
                if len(chunk) == 4:
                    groups.append(chunk)
                    chunk = []
            if chunk:
                groups.append(chunk)
    if not groups:
        # Build a plausible path from detected techniques.
        if techniques:
            steps = []
            for tid in techniques[:4]:
                meta = ATTACK_TECHNIQUES.get(tid, {})
                steps.append(f"{tid} {meta.get('name', '')}".strip())
            groups.append(steps or ["Initial access", "Abuse trusted function", "Achieve objective"])
        else:
            groups = [
                [
                    "Phish or otherwise obtain a valid identity",
                    "Reach a privileged function or data store",
                    "Exfiltrate or disrupt a crown jewel",
                ]
            ]

    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()
    for steps in groups:
        key = tuple(s.lower() for s in steps)
        if key in seen:
            continue
        seen.add(key)
        used = []
        joined = " ".join(steps).lower()
        for tid in techniques:
            meta = ATTACK_TECHNIQUES.get(tid)
            name = (meta or {}).get("name", "").lower()
            if tid.lower() in joined or (name and name in joined) or not used:
                used.append(tid)
            if len(used) == 3:
                break
        likelihood = _likelihood(joined)
        name = _clip(steps[-1] if steps else "Attack path", 70)
        paths.append(
            AttackPath(
                id=f"AP-{len(paths) + 1}",
                name=f"Path to {name}",
                steps=steps[:6],
                techniques=list(dict.fromkeys(used)),
                likelihood=likelihood,
            )
        )
        if len(paths) == 3:
            break
    return paths


def _resilience(keep: str, jewels: list[CrownJewel], threats: list[ThreatItem]) -> list[ResiliencePriority]:
    stated = split_items(keep)
    priorities: list[ResiliencePriority] = []
    functions = ["identify", "protect", "detect", "respond", "recover"]
    for idx, item in enumerate(stated[:4]):
        priorities.append(
            ResiliencePriority(
                id=f"RP-{idx + 1}",
                title=_clip(item, 80),
                action=f"Treat “{item}” as a named resilience control, with an owner and evidence.",
                csf_function=functions[idx % len(functions)],
            )
        )
    defaults = [
        (
            "Protect identities on the path to crown jewels",
            "MFA, phishing-resistant authentication, and least privilege on accounts that can reach "
            + (jewels[0].name if jewels else "primary assets")
            + ".",
            "protect",
        ),
        (
            "Detect the first two steps of the likeliest path",
            f"Alert on the techniques bound to {(threats[0].name if threats else 'the top threat')}.",
            "detect",
        ),
        (
            "Recover without paying the impact",
            "Immutable backups, restoration drills, and a communications path that survives the outage.",
            "recover",
        ),
    ]
    for title, action, fn in defaults:
        if len(priorities) >= 4:
            break
        priorities.append(
            ResiliencePriority(
                id=f"RP-{len(priorities) + 1}",
                title=title,
                action=action,
                csf_function=fn,
            )
        )
    return priorities[:4]


def _actions(
    execute_notes: str,
    risks: list[RankedRisk],
    resilience: list[ResiliencePriority],
) -> list[ActionItem]:
    items: list[ActionItem] = []
    extra = split_items(execute_notes)
    for note in extra[:2]:
        items.append(
            ActionItem(
                id=f"AC-{len(items) + 1}",
                title=_clip(note, 90),
                owner_hint="Named owner from Execute notes",
                related_risk_ids=[r.id for r in risks[:2]],
            )
        )
    for risk in risks[:3]:
        items.append(
            ActionItem(
                id=f"AC-{len(items) + 1}",
                title=f"Reduce {risk.title}",
                owner_hint="Security owner + system owner",
                related_risk_ids=[risk.id],
            )
        )
        if len(items) >= 5:
            break
    if resilience and len(items) < 5:
        top = resilience[0]
        items.append(
            ActionItem(
                id=f"AC-{len(items) + 1}",
                title=top.title,
                owner_hint="Resilience / operations",
                related_risk_ids=[r.id for r in risks[:1]],
            )
        )
    return items[:5]


def _alignment(methodology_ids: list[str], result_parts: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    jewels = ", ".join(j.name for j in result_parts["crown_jewels"][:3]) or "—"
    threats = ", ".join(t.name for t in result_parts["threats"][:3]) or "—"
    paths = ", ".join(p.name for p in result_parts["attack_paths"][:3]) or "—"
    mapping = {
        "S": jewels,
        "T": threats,
        "R": paths,
        "I": result_parts["ranked_risks"][0].title if result_parts["ranked_risks"] else "—",
        "K": result_parts["resilience"][0].title if result_parts["resilience"] else "—",
        "E": f"{len(result_parts['action_plan'])} actions generated",
    }
    for step in STRIKE_STEPS:
        letter = step["letter"]
        names = []
        for mid in methodology_ids:
            method = next((m for m in selected_methodologies([mid]) if m["id"] == mid), None)
            if not method:
                continue
            if letter in method.get("strike_letters", list("STRIKE")):
                names.append(method["name"])
        rows.append(
            {
                "letter": letter,
                "step": step["name"],
                "artefact": mapping[letter],
                "aligned_with": ", ".join(names) or "STRIKE",
            }
        )
    return rows


def generate_assessment(
    *,
    title: str,
    answers: list[str],
    methodology_ids: list[str] | None = None,
    import_text: str = "",
    import_kind: str = "freeform",
) -> AssessmentResult:
    methods = selected_methodologies(methodology_ids)
    ids = [m["id"] for m in methods]
    padded = (list(answers) + [""] * 6)[:6]
    scope, threat, route, impact, keep, execute = padded
    imported = parse_import(import_text, import_kind)

    evidence = _blob([scope, threat, route, impact, keep, execute, imported.evidence_blob()])
    stride_hits = _stride_for(evidence, imported)
    techniques: list[str] = list(imported.techniques)
    for tid in detect_techniques(evidence):
        if tid not in techniques:
            techniques.append(tid)

    jewels = _extract_crown_jewels(scope, imported)
    threats = _threats(threat, scope, imported, ids, stride_hits, techniques)
    if LINDDUN_ID not in ids:
        for item in threats:
            item.linddun = []
    paths = _paths(route, imported, techniques)

    impact_level = _impact_level(impact + " " + scope)
    risks: list[RankedRisk] = []
    for idx, path in enumerate(paths):
        threat_item = threats[idx] if idx < len(threats) else threats[0]
        likelihood = path.likelihood
        score = _score(impact_level, likelihood)
        dread = _dread(impact_level, likelihood, len(path.steps), True) if DREAD_ID in ids else None
        if dread:
            score = max(score, round(dread["total"] / 3))
        risks.append(
            RankedRisk(
                id=f"RK-{idx + 1}",
                title=f"{threat_item.name} via {path.name}",
                threat_id=threat_item.id,
                path_id=path.id,
                impact=impact_level,
                likelihood=likelihood,
                score=score,
                dread=dread,
            )
        )
    risks.sort(key=lambda r: r.score, reverse=True)
    resilience = _resilience(keep, jewels, threats)
    actions = _actions(execute, risks, resilience)

    pasta_note = ""
    if PASTA_ID in ids:
        pasta_note = "PASTA stages 1–7 were folded into S–E rather than run as a parallel workshop."

    result_parts = {
        "crown_jewels": jewels,
        "threats": threats[:5],
        "attack_paths": paths,
        "ranked_risks": risks,
        "resilience": resilience,
        "action_plan": actions,
    }
    alignment = _alignment(ids, result_parts)

    imported_summary = {
        "kind": imported.kind,
        "assets": imported.assets,
        "threats": imported.threats,
        "techniques": imported.techniques,
        "stride_hits": imported.stride_hits,
        "feared_events": imported.feared_events,
        "path_count": len(imported.path_groups),
        "had_json": imported.json_payload is not None,
    }

    answers_map = {step["letter"]: padded[i] for i, step in enumerate(STRIKE_STEPS)}
    notes = pasta_note
    return AssessmentResult(
        title=title.strip() or "Untitled assessment",
        methodologies=ids,
        methodology_names=[m["name"] for m in methods],
        answers=answers_map,
        crown_jewels=jewels,
        threats=threats[:5],
        attack_paths=paths,
        ranked_risks=risks,
        resilience=resilience,
        action_plan=actions,
        alignment=alignment,
        imported=imported_summary,
        notes=notes,
    )


def technique_label(tid: str) -> str:
    meta = ATTACK_TECHNIQUES.get(tid)
    if not meta:
        return tid
    return f"{tid} {meta['name']} ({tactic_name(meta['tactic'])})"
