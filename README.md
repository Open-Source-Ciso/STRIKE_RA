<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/684a9680-4ea1-40f3-9e08-20068c5bb42b" />


# STRIKE_RA

STRIKE RA is an AI-ready, threat-led security risk assessment that replaces complex spreadsheets with a guided conversation and produces defensible, evidence-driven outputs in minutes.

**STRIKE Threat** is the modelling and intelligence layer: it takes an existing STRIDE, PASTA, LINDDUN, MITRE ATT&CK, attack-tree, or Centurion / EBIOS RM model as input, walks the same STRIKE spine, and exports a GRC-ready study.

## The STRIKE methodology

| Step | Name | Question |
|------|------|----------|
| **S** | Scope | Tell me about your project. |
| **T** | Threat | What could attack it? |
| **R** | Route | How would they succeed? |
| **I** | Impact | What would happen? |
| **K** | Keep Operating | How do we keep operating? |
| **E** | Execute | Generate outputs. |

## Align with

STRIDE · PASTA · LINDDUN · MITRE ATT&CK · Attack trees · DREAD · Centurion (EBIOS RM / CISO Assistant)

See `docs/STRIKE_Methodology.md` and the in-app `/methodologies` crosswalk.

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000 in your browser. `New Assessment` starts the guided flow; `Load sample` walks a payments-portal example with a pasted STRIDE/ATT&CK/Centurion model.

```bash
python -m pytest tests/test_strike.py -q
```
