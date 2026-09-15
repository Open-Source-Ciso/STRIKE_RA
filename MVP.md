# STRIKE RA MVP

## Goal
Replace a laborious spreadsheet-driven security risk assessment with a fast, guided, threat-led assessment that also accepts and aligns commonly used threat-modelling methodologies.

## MVP Outcome
In under 20 minutes, STRIKE RA should produce:

- 3–5 Crown Jewels
- Top 3 Threats
- 1–3 Attack Paths
- Ranked Risk View
- Resilience Priorities
- Action Plan
- Methodology alignment (STRIDE, PASTA, LINDDUN, ATT&CK, Centurion/EBIOS)
- Centurion JSON export (`centurion.ebios.v1`)

## MVP Workflow
1. Start new assessment (choose lenses, optional model paste)
2. Answer guided STRIKE questions
3. Review generated outputs
4. Export Markdown / Centurion JSON

## In Scope
- Single user
- Local/browser prototype
- Guided assessment flow
- Methodology intake and crosswalk
- Deterministic output generation
- Report preview
- Markdown/JSON export

## Out of Scope
- Login
- Multi-user collaboration
- RBAC
- Enterprise dashboards
- Knowledge graph
- Evidence store
- Live CISO Assistant API write
- Azure deployment
- Full STRIKE OS platform
