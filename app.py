"""STRIKE RA — Threat-led Risk Assessment.

Sprint 1 MVP: a homepage and the entry point for starting a new assessment.
"""
from flask import Flask, render_template

app = Flask(__name__)

# The STRIKE methodology drives the guided assessment conversation.
STRIKE_STEPS = [
    {"letter": "S", "name": "Scope", "prompt": "Tell me about your project."},
    {"letter": "T", "name": "Threat", "prompt": "What could attack it?"},
    {"letter": "R", "name": "Route", "prompt": "How would they succeed?"},
    {"letter": "I", "name": "Impact", "prompt": "What would happen?"},
    {"letter": "K", "name": "Keep Operating", "prompt": "How do we keep operating?"},
    {"letter": "E", "name": "Execute", "prompt": "Generate outputs."},
]


@app.route("/")
def home():
    return render_template("index.html", steps=STRIKE_STEPS)


@app.route("/new")
def new_assessment():
    return render_template("new_assessment.html", steps=STRIKE_STEPS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
