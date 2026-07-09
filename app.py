"""STRIKE RA — Threat-led Risk Assessment.

MVP: a homepage plus a guided STRIKE assessment that walks the user through the
six STRIKE steps one question at a time and echoes back their captured answers.
"""
import os

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
# Session is only used to hold in-progress answers for a single local user.
app.secret_key = os.environ.get("SECRET_KEY", "strike-ra-dev-secret")

# The STRIKE methodology drives the guided assessment conversation.
STRIKE_STEPS = [
    {"letter": "S", "name": "Scope", "prompt": "Tell me about your project."},
    {"letter": "T", "name": "Threat", "prompt": "What could attack it?"},
    {"letter": "R", "name": "Route", "prompt": "How would they succeed?"},
    {"letter": "I", "name": "Impact", "prompt": "What would happen?"},
    {"letter": "K", "name": "Keep Operating", "prompt": "How do we keep operating?"},
    {"letter": "E", "name": "Execute", "prompt": "Generate outputs."},
]


def _get_answers():
    """Return the current answers list, sized to the STRIKE steps."""
    answers = session.get("answers", [])
    if len(answers) != len(STRIKE_STEPS):
        answers = (answers + [""] * len(STRIKE_STEPS))[: len(STRIKE_STEPS)]
    return answers


@app.route("/")
def home():
    return render_template("index.html", steps=STRIKE_STEPS)


@app.route("/new")
def new_assessment():
    # Starting a new assessment clears any previous answers.
    session["answers"] = [""] * len(STRIKE_STEPS)
    return redirect(url_for("assessment", step=0))


@app.route("/assessment/<int:step>", methods=["GET", "POST"])
def assessment(step):
    if step < 0 or step >= len(STRIKE_STEPS):
        return redirect(url_for("assessment", step=0))

    answers = _get_answers()

    if request.method == "POST":
        answers[step] = request.form.get("answer", "").strip()
        session["answers"] = answers

        if request.form.get("action") == "back":
            return redirect(url_for("assessment", step=step - 1))
        if step + 1 >= len(STRIKE_STEPS):
            return redirect(url_for("review"))
        return redirect(url_for("assessment", step=step + 1))

    return render_template(
        "assessment.html",
        steps=STRIKE_STEPS,
        step=STRIKE_STEPS[step],
        index=step,
        total=len(STRIKE_STEPS),
        answer=answers[step],
        is_last=(step + 1 == len(STRIKE_STEPS)),
    )


@app.route("/review")
def review():
    answers = _get_answers()
    items = [
        {**step, "answer": answers[i]} for i, step in enumerate(STRIKE_STEPS)
    ]
    return render_template("review.html", items=items)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
