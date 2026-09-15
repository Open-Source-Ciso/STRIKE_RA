"""Tests for STRIKE Threat modelling engine, parser, Centurion export, and app."""

from __future__ import annotations

import json
import unittest

from app import SAMPLE, app
from strike.catalog import CROSSWALK, STRIKE_STEPS, selected_methodologies
from strike.centurion import FORMAT, export_centurion
from strike.engine import generate_assessment
from strike.parser import parse_import
from strike.report import render_markdown


class ParserTests(unittest.TestCase):
    def test_json_import(self):
        raw = json.dumps(
            {
                "assets": ["Payout rails"],
                "threats": ["Insider"],
                "stride": ["Spoofing", "I"],
                "techniques": ["T1566", "T1078"],
                "attack_paths": [["Phish", "Reuse session", "Exfil"]],
                "feared_events": ["PCI breach"],
            }
        )
        model = parse_import(raw, "json")
        self.assertIsNotNone(model.json_payload)
        self.assertIn("Payout rails", model.assets)
        self.assertIn("Insider", model.threats)
        self.assertIn("S", model.stride_hits)
        self.assertIn("I", model.stride_hits)
        self.assertEqual(model.techniques[:2], ["T1566", "T1078"])
        self.assertEqual(model.path_groups[0][0], "Phish")

    def test_labelled_and_technique_detection(self):
        text = "Assets: cardholder data, API keys\nATT&CK: T1566 phishing against admins, then exfil"
        model = parse_import(text, "attack")
        self.assertTrue(any("cardholder" in a.lower() for a in model.assets))
        self.assertIn("T1566", model.techniques)
        self.assertIn("T1567", model.techniques)  # exfil keyword


class EngineTests(unittest.TestCase):
    def test_mvp_artefacts_and_counts(self):
        result = generate_assessment(
            title="Payments portal",
            answers=SAMPLE["answers"],
            methodology_ids=SAMPLE["methodologies"],
            import_text=SAMPLE["import_text"],
            import_kind="json",
        )
        self.assertGreaterEqual(len(result.crown_jewels), 3)
        self.assertLessEqual(len(result.crown_jewels), 5)
        self.assertGreaterEqual(len(result.threats), 3)
        self.assertLessEqual(len(result.threats), 5)
        self.assertGreaterEqual(len(result.attack_paths), 1)
        self.assertLessEqual(len(result.attack_paths), 3)
        self.assertTrue(result.ranked_risks)
        self.assertTrue(result.resilience)
        self.assertTrue(result.action_plan)
        self.assertEqual([row["letter"] for row in result.alignment], list("STRIKE"))
        self.assertIn("STRIDE", result.methodology_names)
        self.assertIn("Centurion", result.methodology_names)
        self.assertTrue(any(t.attack_techniques for t in result.threats))
        self.assertTrue(any(r.dread for r in result.ranked_risks))
        jewel_names = [j.name.lower() for j in result.crown_jewels]
        self.assertTrue(any("cardholder" in n for n in jewel_names))
        self.assertFalse(any(n.startswith("saas payments") for n in jewel_names))
        threat_names = [t.name.lower() for t in result.threats]
        self.assertIn("external cybercriminals", threat_names)
        self.assertFalse(any("after card" in n for n in threat_names))
        for jewel in result.crown_jewels:
            self.assertLessEqual(len(jewel.name.split()), 12)
        for threat in result.threats:
            self.assertLessEqual(len(threat.name.split()), 12)

    def test_sparse_input_still_produces_baseline(self):
        result = generate_assessment(title="", answers=["", "", "", "", "", ""])
        self.assertGreaterEqual(len(result.crown_jewels), 3)
        self.assertGreaterEqual(len(result.threats), 3)
        self.assertGreaterEqual(len(result.attack_paths), 1)
        self.assertEqual(result.title, "Untitled assessment")

    def test_crosswalk_covers_every_strike_letter(self):
        letters = {row["strike"][0] for row in CROSSWALK}
        self.assertEqual(letters, set("STRIKE"))
        self.assertEqual(len(STRIKE_STEPS), 6)

    def test_markdown_contains_sections(self):
        result = generate_assessment(
            title="Demo",
            answers=SAMPLE["answers"],
            methodology_ids=["stride", "attack"],
        )
        md = render_markdown(result)
        for heading in ("Crown jewels", "Top threats", "Attack paths", "Ranked risk", "Action plan"):
            self.assertIn(heading, md)


class CenturionTests(unittest.TestCase):
    def test_export_shape_matches_ebios_objects(self):
        result = generate_assessment(
            title="Payments portal",
            answers=SAMPLE["answers"],
            methodology_ids=["centurion", "attack"],
            import_text=SAMPLE["import_text"],
            import_kind="json",
        )
        payload = export_centurion(result)
        self.assertEqual(payload["format"], FORMAT)
        for key in (
            "study",
            "assets",
            "feared_events",
            "ro_to_couples",
            "strategic_scenarios",
            "attack_paths",
            "operational_scenarios",
            "risk_scenarios",
            "applied_controls",
        ):
            self.assertIn(key, payload)
        self.assertTrue(payload["assets"])
        self.assertTrue(payload["feared_events"][0]["is_selected"])
        self.assertIn("risk_origin", payload["ro_to_couples"][0])
        self.assertEqual(payload["study"]["quotation_method"], "express")
        self.assertTrue(payload["risk_scenarios"][0]["treatment"])


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_and_methodologies(self):
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn(b"STRIKE Threat", home.data)
        self.assertIn(b"Centurion", home.data)
        page = self.client.get("/methodologies")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"EBIOS RM", page.data)
        self.assertIn(b"STRIDE", page.data)

    def test_guided_flow_and_exports(self):
        start = self.client.post(
            "/new",
            data={
                "title": "Unit portal",
                "methodologies": ["stride", "centurion", "attack"],
                "import_kind": "json",
                "import_text": SAMPLE["import_text"],
            },
            follow_redirects=False,
        )
        self.assertEqual(start.status_code, 302)
        self.assertTrue(start.headers["Location"].endswith("/assessment/0"))

        for i, answer in enumerate(SAMPLE["answers"]):
            resp = self.client.post(
                f"/assessment/{i}",
                data={"answer": answer, "action": "next"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 302)

        report = self.client.get("/report")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"Crown jewels", report.data)
        self.assertIn(b"centurion.ebios.v1", report.data)
        self.assertIn(b"Cardholder", report.data)

        md = self.client.get("/export/markdown")
        self.assertEqual(md.status_code, 200)
        self.assertIn("text/markdown", md.content_type)
        self.assertIn(b"STRIKE RA", md.data)

        centurion = self.client.get("/export/centurion.json")
        self.assertEqual(centurion.status_code, 200)
        payload = json.loads(centurion.data)
        self.assertEqual(payload["format"], "centurion.ebios.v1")
        self.assertTrue(payload["attack_paths"])

    def test_sample_loader(self):
        resp = self.client.get("/new?sample=1", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        step = self.client.get("/assessment/0")
        self.assertIn(b"payments portal", step.data.lower())


class CatalogTests(unittest.TestCase):
    def test_strike_always_selected(self):
        methods = selected_methodologies(["stride", "centurion"])
        self.assertEqual(methods[0]["id"], "strike")
        self.assertEqual([m["id"] for m in methods], ["strike", "stride", "centurion"])


if __name__ == "__main__":
    unittest.main()
