# AGENTS.md

## Cursor Cloud specific instructions

Current repository state (as of environment setup): `STRIKE_RA` is an early-stage,
documentation-only skeleton. It contains a `README.md` product description and empty
placeholder files under `docs/`, `prompts/`, and `assets/`. There is **no application
code, dependency manifest, service, test suite, lint config, or build system yet**, so
there is nothing to install, run, build, or test until source code is added.

Intended stack: Python (the `.gitignore` is the standard GitHub Python template).
Python 3.12 and Node 22 are available in the base image.

When code is added, revisit environment setup: add the real dependency install to the
update script (e.g. `requirements.txt` / `pyproject.toml`) and document how to run,
test, lint, and build the service(s) here.
