"""STRIKE RA — Threat-led Risk Assessment, with STRIKE Threat modelling."""

from __future__ import annotations

import json
import os

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from strike.catalog import (
    STRIKE_STEPS,
    CROSSWALK,
    hints_for,
    methodology_list,
    selected_methodologies,
)
from strike.centurion import export_centurion
from strike.engine import generate_assessment
from strike.report import render_markdown

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "strike-ra-dev-secret")

SAMPLE = {
    "title": "Customer payments portal",
    "methodologies": ["stride", "attack", "centurion", "dread"],
    "import_kind": "json",
    "import_text": json.dumps(
        {
            "assets": [
                "Cardholder data (tokenised PAN)",
                "Merchant API keys",
                "Payout rails",
                "Customer PII",
            ],
            "threats": [
                "External cybercriminals",
                "Malicious insider in finance ops",
                "Compromised payment processor",
            ],
            "stride": ["S", "T", "I", "E"],
            "techniques": ["T1566", "T1078", "T1190", "T1567"],
            "feared_events": [
                "PCI data breach",
                "Unauthorised payouts",
                "Portal unavailability at peak",
            ],
            "risk_origins": ["cybercriminal", "insider", "partner / supply chain"],
            "attack_paths": [
                [
                    "Phish a merchant admin",
                    "Reuse valid portal credentials (no phishing-resistant MFA)",
                    "Call payout API above normal limits",
                    "Exfiltrate card tokens via reporting export",
                ],
                [
                    "Exploit public reporting endpoint",
                    "Read customer PII from analytics replica",
                    "Stage data to attacker-controlled storage",
                ],
            ],
        },
        indent=2,
    ),
    "answers": [
        "SaaS payments portal used by e-commerce merchants. Internet-facing, handles tokenised card data, customer PII, and payout instructions. Trust boundary between merchants, our API, the PSP, and finance ops.",
        "External cybercriminals after card data and payouts; a privileged insider in finance; a compromised payment processor. Phishing against merchant admins is common.",
        "Phish merchant admin -> valid accounts on the portal -> abuse payout API -> exfiltrate tokens via reporting export. Alternate path: SQLi/exploit on the public reporting endpoint -> analytics replica -> cloud storage exfil.",
        "PCI breach, regulatory fines, frozen payouts, and brand damage. Peak-time outage stops merchant checkout.",
        "Tokenisation at the PSP, WAF, MFA (not yet phishing-resistant), immutable backups, incident comms runbook, 24/7 detection on payout anomalies.",
        "PCI QSA wants an ATT&CK-tagged action plan this quarter. Finance owns payouts; Platform owns the API.",
    ],
}


def _blank_assessment() -> dict:
    return {
        "title": "",
        "methodologies": ["strike"],
        "import_kind": "freeform",
        "import_text": "",
        "answers": [""] * len(STRIKE_STEPS),
    }


def _get_assessment() -> dict:
    data = session.get("assessment")
    if not isinstance(data, dict):
        data = _blank_assessment()
    data.setdefault("title", "")
    data.setdefault("methodologies", ["strike"])
    data.setdefault("import_kind", "freeform")
    data.setdefault("import_text", "")
    answers = data.get("answers") or []
    if len(answers) != len(STRIKE_STEPS):
        answers = (list(answers) + [""] * len(STRIKE_STEPS))[: len(STRIKE_STEPS)]
    data["answers"] = answers
    if "strike" not in data["methodologies"]:
        data["methodologies"] = ["strike", *data["methodologies"]]
    session["assessment"] = data
    return data


def _save(data: dict) -> None:
    session["assessment"] = data
    session.modified = True


def _result_or_none():
    data = session.get("assessment")
    if not data or not any(data.get("answers") or []):
        return None
    return generate_assessment(
        title=data.get("title") or "Untitled assessment",
        answers=data.get("answers") or [],
        methodology_ids=data.get("methodologies") or ["strike"],
        import_text=data.get("import_text") or "",
        import_kind=data.get("import_kind") or "freeform",
    )


@app.context_processor
def inject_brand():
    return {
        "strike_steps": STRIKE_STEPS,
        "optional_methods": methodology_list(include_native=False),
    }


@app.route("/")
def home():
    return render_template("index.html", steps=STRIKE_STEPS, methods=methodology_list())


@app.route("/methodologies")
def methodologies():
    return render_template(
        "methodologies.html",
        methods=methodology_list(),
        crosswalk=CROSSWALK,
    )


@app.route("/new", methods=["GET", "POST"])
def new_assessment():
    if request.method == "GET" and request.args.get("sample") == "1":
        data = _blank_assessment()
        data.update(
            {
                "title": SAMPLE["title"],
                "methodologies": ["strike", *SAMPLE["methodologies"]],
                "import_kind": SAMPLE["import_kind"],
                "import_text": SAMPLE["import_text"],
                "answers": SAMPLE["answers"],
            }
        )
        _save(data)
        return redirect(url_for("assessment", step=0))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        chosen = request.form.getlist("methodologies")
        data = _blank_assessment()
        data["title"] = title
        data["methodologies"] = [m["id"] for m in selected_methodologies(chosen)]
        data["import_kind"] = request.form.get("import_kind") or "freeform"
        data["import_text"] = request.form.get("import_text", "").strip()
        _save(data)
        return redirect(url_for("assessment", step=0))

    data = _blank_assessment()
    _save(data)
    return render_template(
        "start.html",
        methods=methodology_list(include_native=False),
        assessment=data,
        import_kinds=[
            ("freeform", "Prose / labelled lines"),
            ("json", "JSON model"),
            ("stride", "STRIDE notes"),
            ("attack", "ATT&CK techniques"),
            ("centurion", "Centurion / EBIOS notes"),
            ("pasta", "PASTA stage notes"),
            ("linddun", "LINDDUN / privacy notes"),
        ],
    )


@app.route("/assessment/<int:step>", methods=["GET", "POST"])
def assessment(step: int):
    if step < 0 or step >= len(STRIKE_STEPS):
        return redirect(url_for("assessment", step=0))

    data = _get_assessment()
    if request.method == "POST":
        data["answers"][step] = request.form.get("answer", "").strip()
        _save(data)
        if request.form.get("action") == "back" and step > 0:
            return redirect(url_for("assessment", step=step - 1))
        if step + 1 >= len(STRIKE_STEPS):
            return redirect(url_for("report"))
        return redirect(url_for("assessment", step=step + 1))

    current = STRIKE_STEPS[step]
    return render_template(
        "assessment.html",
        steps=STRIKE_STEPS,
        step=current,
        index=step,
        total=len(STRIKE_STEPS),
        answer=data["answers"][step],
        is_last=(step + 1 == len(STRIKE_STEPS)),
        title=data.get("title") or "New assessment",
        hints=hints_for(current["letter"], data.get("methodologies") or ["strike"]),
        methods=selected_methodologies(data.get("methodologies")),
    )


@app.route("/report")
def report():
    result = _result_or_none()
    if result is None:
        flash("Start an assessment first.")
        return redirect(url_for("new_assessment"))
    centurion = export_centurion(result)
    return render_template(
        "report.html",
        result=result,
        centurion=centurion,
        centurion_json=json.dumps(centurion, indent=2),
    )


@app.route("/export/markdown")
def export_markdown():
    result = _result_or_none()
    if result is None:
        return redirect(url_for("new_assessment"))
    body = render_markdown(result)
    filename = (result.title or "strike-assessment").lower().replace(" ", "-")
    return Response(
        body,
        mimetype="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}.md"},
    )


@app.route("/export/centurion.json")
def export_centurion_json():
    result = _result_or_none()
    if result is None:
        return redirect(url_for("new_assessment"))
    payload = json.dumps(export_centurion(result), indent=2)
    filename = (result.title or "strike-assessment").lower().replace(" ", "-")
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}.centurion.json"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
