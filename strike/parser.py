"""Parse pasted threat-model input into a structured import."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from strike.catalog import (
    ATTACK_TECHNIQUES,
    LINDDUN_CATEGORIES,
    STRIDE_CATEGORIES,
    TECHNIQUE_KEYWORDS,
)

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
LABEL_RE = re.compile(
    r"^(assets?|crown jewels?|threats?|stride|attack(?:\s*paths?)?|"
    r"techniques?|feared events?|risk origins?|linddun)\s*:\s*(.+)$",
    re.IGNORECASE,
)


@dataclass
class ImportedModel:
    raw: str = ""
    kind: str = "freeform"
    assets: list[str] = field(default_factory=list)
    threats: list[str] = field(default_factory=list)
    feared_events: list[str] = field(default_factory=list)
    risk_origins: list[str] = field(default_factory=list)
    stride_hits: list[str] = field(default_factory=list)
    linddun_hits: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    path_groups: list[list[str]] = field(default_factory=list)
    json_payload: dict[str, Any] | None = None

    def evidence_blob(self) -> str:
        parts = [self.raw]
        parts.extend(self.assets)
        parts.extend(self.threats)
        parts.extend(self.feared_events)
        return "\n".join(p for p in parts if p)


def split_items(text: str) -> list[str]:
    """Split prose into short candidate items (bullets, commas, numbered lines)."""
    if not text or not text.strip():
        return []
    pieces: list[str] = []
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip().lstrip("-*•").strip()
        line = re.sub(r"^\d+[.)]\s+", "", line)
        if not line:
            continue
        if "," in line and len(line) < 180 and "://" not in line:
            for part in line.split(","):
                item = part.strip(" .;")
                if item:
                    pieces.append(item)
        else:
            pieces.append(line.strip(" .;"))
    # Deduplicate while preserving order, drop very short tokens.
    seen: set[str] = set()
    out: list[str] = []
    for item in pieces:
        key = item.lower()
        if key in seen or len(item) < 3:
            continue
        seen.add(key)
        out.append(item)
    return out


def detect_stride(text: str) -> list[str]:
    blob = text.lower()
    hits = []
    for cat in STRIDE_CATEGORIES:
        named = cat["name"].lower() in blob or f"stride-{cat['id'].lower()}" in blob
        keyed = any(k in blob for k in cat["keywords"])
        if named or keyed:
            hits.append(cat["id"])
    return hits


def detect_linddun(text: str) -> list[str]:
    blob = text.lower()
    hits = []
    for cat in LINDDUN_CATEGORIES:
        if cat["name"].lower() in blob or any(k in blob for k in cat["keywords"]):
            hits.append(cat["id"])
    return hits


def detect_techniques(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in TECHNIQUE_RE.findall(text or ""):
        tid = match.upper()
        parent = tid.split(".")[0]
        # Prefer the parent if we have it in the library; keep the original otherwise.
        canonical = parent if parent in ATTACK_TECHNIQUES else tid
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)
    blob = (text or "").lower()
    for keywords, tid in TECHNIQUE_KEYWORDS:
        if tid in seen:
            continue
        if any(k in blob for k in keywords):
            seen.add(tid)
            found.append(tid)
    return found


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return split_items(value)
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.extend(split_items(item) or [item.strip()] if item.strip() else [])
            elif isinstance(item, dict) and "name" in item:
                out.append(str(item["name"]).strip())
            elif item:
                out.append(str(item).strip())
        return [x for x in out if x]
    return []


def _path_groups(value: Any) -> list[list[str]]:
    groups: list[list[str]] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, list):
                steps = [str(s).strip() for s in item if str(s).strip()]
                if steps:
                    groups.append(steps)
            elif isinstance(item, dict):
                steps = item.get("steps") or item.get("path")
                name = item.get("name")
                if isinstance(steps, list):
                    parsed = [str(s).strip() for s in steps if str(s).strip()]
                    if parsed:
                        groups.append(parsed)
                elif name:
                    groups.append(split_items(str(name)) or [str(name)])
            elif isinstance(item, str):
                steps = [s.strip() for s in re.split(r"\s*(?:->|→|>)\s*", item) if s.strip()]
                if steps:
                    groups.append(steps)
    elif isinstance(value, str):
        for line in value.splitlines():
            steps = [s.strip() for s in re.split(r"\s*(?:->|→|>)\s*", line) if s.strip()]
            if len(steps) > 1:
                groups.append(steps)
    return groups


def parse_import(text: str, kind: str = "freeform") -> ImportedModel:
    model = ImportedModel(raw=text or "", kind=kind or "freeform")
    raw = (text or "").strip()
    if not raw:
        return model

    payload: dict[str, Any] | None = None
    if raw.startswith("{") or raw.startswith("["):
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                payload = loaded
            elif isinstance(loaded, list):
                payload = {"items": loaded}
        except json.JSONDecodeError:
            payload = None

    if payload is not None:
        model.json_payload = payload
        model.assets = _string_list(
            payload.get("assets") or payload.get("crown_jewels") or payload.get("crownJewels")
        )
        model.threats = _string_list(payload.get("threats") or payload.get("threat_sources"))
        model.feared_events = _string_list(payload.get("feared_events") or payload.get("fearedEvents"))
        model.risk_origins = _string_list(payload.get("risk_origins") or payload.get("riskOrigins"))
        model.techniques = [
            t.upper() for t in _string_list(payload.get("techniques") or payload.get("attack_techniques"))
        ]
        stride_vals = payload.get("stride") or []
        if isinstance(stride_vals, str):
            stride_vals = [stride_vals]
        for item in stride_vals:
            token = str(item).strip()
            letter = token[0].upper() if token else ""
            names = {c["name"].lower(): c["id"] for c in STRIDE_CATEGORIES}
            if token.upper() in {c["id"] for c in STRIDE_CATEGORIES}:
                model.stride_hits.append(token.upper())
            elif token.lower() in names:
                model.stride_hits.append(names[token.lower()])
            elif letter in {c["id"] for c in STRIDE_CATEGORIES}:
                model.stride_hits.append(letter)
        model.path_groups = _path_groups(
            payload.get("attack_paths") or payload.get("paths") or payload.get("routes")
        )
        blob = json.dumps(payload)
        model.techniques = list(dict.fromkeys(model.techniques + detect_techniques(blob + "\n" + raw)))
        model.stride_hits = list(dict.fromkeys(model.stride_hits + detect_stride(blob)))
        model.linddun_hits = detect_linddun(blob)
        return model

    for line in raw.splitlines():
        match = LABEL_RE.match(line.strip())
        if not match:
            continue
        label, value = match.group(1).lower(), match.group(2)
        items = split_items(value)
        if label.startswith("asset") or label.startswith("crown"):
            model.assets.extend(items)
        elif label.startswith("threat"):
            model.threats.extend(items)
        elif label.startswith("feared"):
            model.feared_events.extend(items)
        elif label.startswith("risk"):
            model.risk_origins.extend(items)
        elif label.startswith("stride"):
            model.stride_hits.extend(detect_stride(value) or [i[0].upper() for i in items if i])
        elif label.startswith("linddun"):
            model.linddun_hits.extend(detect_linddun(value))
        elif label.startswith("technique"):
            model.techniques.extend(detect_techniques(value))
        elif "attack" in label:
            for item in items:
                steps = [s.strip() for s in re.split(r"\s*(?:->|→|>)\s*", item) if s.strip()]
                if steps:
                    model.path_groups.append(steps)

    blob = raw
    model.techniques = list(dict.fromkeys(model.techniques + detect_techniques(blob)))
    model.stride_hits = list(dict.fromkeys(model.stride_hits + detect_stride(blob)))
    model.linddun_hits = list(dict.fromkeys(model.linddun_hits + detect_linddun(blob)))
    if not model.path_groups:
        model.path_groups = _path_groups(raw)
    if not model.assets:
        # Pull likely asset phrases when the user labelled nothing.
        for item in split_items(raw):
            lowered = item.lower()
            if any(
                token in lowered
                for token in ("data", "database", "key", "secret", "account", "pii", "payment", "source code")
            ):
                model.assets.append(item)
    return model
