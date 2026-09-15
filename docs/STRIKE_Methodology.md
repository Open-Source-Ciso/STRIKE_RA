# STRIKE methodology

STRIKE is the native spine of STRIKE RA. Every assessment is a conversation in this order. Other methodologies (STRIDE, PASTA, LINDDUN, MITRE ATT&CK, attack trees, DREAD, Centurion / EBIOS RM) are **lenses**: they change intake, tagging, and export — not the order of the walk.

| Step | Name | Question | What we capture |
|------|------|----------|-----------------|
| **S** | Scope | Tell me about your project. | System, users, trust boundaries, crown jewels |
| **T** | Threat | What could attack it? | Actors, motivations, STRIDE/LINDDUN categories, risk origins |
| **R** | Route | How would they succeed? | Attack paths, ATT&CK techniques, operational scenarios |
| **I** | Impact | What would happen? | Business/safety harm, feared events, DREAD damage |
| **K** | Keep Operating | How do we keep operating? | Resilience controls, CSF functions, treatment |
| **E** | Execute | Generate outputs. | Ranked risk, action plan, Centurion interchange |

## STRIKE Threat

STRIKE Threat is the modelling and intelligence layer on top of that conversation:

- **Intake** — paste an existing STRIDE model, ATT&CK technique list, PASTA notes, LINDDUN/DPIA extract, or Centurion / EBIOS RM JSON.
- **Alignment** — each STRIKE step records which methodologies it satisfies (see the crosswalk on `/methodologies`).
- **Intelligence** — routes are tagged with ATT&CK tactics/techniques when those IDs or keywords appear.
- **Handoff** — Execute emits `centurion.ebios.v1` so GRC can file the study without re-typing.

Generation is deterministic (no model call) so two analysts with the same answers get the same artefacts. That is deliberate: the MVP must be defensible and testable offline.
