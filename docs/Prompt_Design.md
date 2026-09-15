# Prompt design

Each STRIKE step has a **stable question** (the conversation contract) plus **methodology hints** that appear only when that lens is selected.

| Letter | Stable prompt | Example hint |
|--------|---------------|--------------|
| S | Tell me about your project. | Centurion W1: primary assets and feared events. STRIDE: processes, stores, actors, trust boundaries. |
| T | What could attack it? | ATT&CK tactics. STRIDE categories. EBIOS risk origins. |
| R | How would they succeed? | Technique sequence / attack tree. EBIOS W3–W4. |
| I | What would happen? | DREAD damage. Gravity of feared events. |
| K | How do we keep operating? | Control that restores the violated property. W5 treatment. |
| E | Anything else the report should emphasise? | Optional owners/constraints; generation is automatic. |

Imported JSON is not a prompt; it is evidence. The parser lifts `assets`, `threats`, `stride`, `techniques`, `attack_paths`, `feared_events`, and `risk_origins` before the engine runs.

Keep prompts short. The user is filling a 20-minute assessment, not writing a thesis. Hints belong in the side panel, not in the question title.
