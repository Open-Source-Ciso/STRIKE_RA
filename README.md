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

## Host it (demo URL)

Nothing is deployed yet — this is a local Flask app. It is ready to put on any Python/container host.

**Production server (same machine):**

```bash
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PORT=5000
gunicorn -b 0.0.0.0:$PORT --workers 2 --threads 4 app:app
```

**Docker:**

```bash
docker build -t strike-ra .
docker run --rm -p 8080:8080 -e SECRET_KEY=change-me strike-ra
```

**Render / Railway / Fly:** connect this GitHub repo, use the `Dockerfile` or `Procfile`. Set `SECRET_KEY` (and `SESSION_COOKIE_SECURE=true` behind HTTPS). Render can also apply `render.yaml`. Health check: `GET /health`.

The GitHub repo is **private**, so GitHub Pages will not serve this (and Pages cannot run Flask anyway). The host needs a Python process, not a static site.

