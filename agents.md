# STRIKE RA

Python 3.12, Flask. From the repo root:

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

```bash
python -m pytest tests/test_strike.py -q
```

Session cookie holds in-progress answers only; reports are regenerated on each request.
