# STRIKE RA + STRIKE Threat MVP

## Goal

Replace a spreadsheet-driven security risk assessment with a guided, threat-led conversation that also **accepts and aligns** commonly used threat-modelling methodologies.

## Outcome (under 20 minutes)

- 3–5 Crown jewels
- Top 3–5 threats (STRIDE / ATT&CK / Centurion origin tagged when selected)
- 1–3 Attack paths
- Ranked risk view (optional DREAD)
- Resilience priorities
- Action plan
- Methodology alignment table
- `centurion.ebios.v1` JSON export

## Workflow

1. Start a new assessment; choose alignment lenses; optionally paste an existing model.
2. Answer guided STRIKE questions (hints adapt to selected methodologies).
3. Review generated outputs.
4. Export Markdown and Centurion JSON.

## In scope

- Single user, local/browser
- Guided STRIKE flow
- Intake of STRIDE, PASTA, LINDDUN, ATT&CK, attack trees, DREAD, Centurion/EBIOS
- Deterministic generation (no LLM required)
- Report preview + Markdown/JSON export

## Out of scope

- Login, multi-user, RBAC
- Live CISO Assistant API write
- Enterprise dashboards, knowledge graph, evidence store
- Azure deployment
- Full STRIKE OS platform
