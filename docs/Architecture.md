# Architecture

```
Browser  →  Flask (app.py)  →  session assessment
                               ├─ strike.catalog   methodologies + crosswalk
                               ├─ strike.parser    JSON / labelled / ATT&CK IDs
                               ├─ strike.engine    deterministic artefacts
                               ├─ strike.centurion centurion.ebios.v1
                               └─ strike.report    Markdown
```

## Session model

A single-user Flask session holds:

- `title`
- `methodologies` (always includes `strike`)
- `import_kind` + `import_text`
- `answers` — six strings, one per STRIKE letter

The report is **recomputed** from that session on every view/export so cookies stay small and results stay deterministic.

## Centurion interchange

`centurion.ebios.v1` mirrors CISO Assistant `ebios_rm` objects:

| STRIKE | Centurion / EBIOS RM |
|--------|----------------------|
| Crown jewels | `assets` (primary) |
| Impact | `feared_events` (gravity from impact rating) |
| Threats | `ro_to_couples` (risk origin × target objective) |
| Routes | `strategic_scenarios`, `attack_paths`, `operational_scenarios` |
| Keep operating | `applied_controls` (CSF function) |
| Ranked risk | `risk_scenarios` (treatment = mitigate) |

This is an interchange document, not a live API write into CISO Assistant.

## Out of process

Login, multi-user, evidence store, knowledge graph, and Azure hosting remain out of scope for this MVP.
