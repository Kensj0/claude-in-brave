"""Tests for /form and /batch against a fake page. No Brave needed."""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

os.environ["JARRI_BROWSER_STATE"] = tempfile.mkdtemp(prefix="cib-test-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import server  # noqa: E402


class FakePage:
    session = "s1"

    def __init__(self, fields, text_values=None):
        self.fields = fields          # name -> dict(kind, type, tag, role, checked, disabled, text, x, y, w, h)
        self.calls = []               # (method, params) for mouse, keys, text
        self.values = dict(text_values or {})
        self.menu = {"found": False, "options": []}

    def evaluate(self, js):
        if "fields.push" in js:                       # FORM_JS
            return {"url": "https://example.test/form", "title": "Test", "total": len(self.fields),
                    "fields": [{"name": n, **{k: v for k, v in f.items() if k in ("kind", "label")}} for n, f in self.fields.items()]}
        if "el.focus()" in js:                        # FOCUS_FIELD_JS
            name = self._name(js)
            if name not in self.fields:
                return {"missing": True}
            f = self.fields[name]
            return {"tag": f.get("tag", "INPUT"), "type": f.get("type", "text"), "readonly": False, "editable": False}
        if "dispatchEvent" in js:                     # CHOOSE_JS
            name = self._name(js)
            if name not in self.fields:
                return {"missing": True}
            f = self.fields[name]
            if f.get("tag") != "SELECT":
                return {"notSelect": True}
            options = f.get("options", [])
            wanted = json.loads(re.search(r'want = ("(?:[^"\\]|\\.)*")', js).group(1))
            if wanted not in options:
                return {"noOption": True, "options": options}
            self.values[name] = wanted
            return {"ok": True}
        if "getBoundingClientRect" in js and "text:" in js and "[role=option]" not in js:   # FIELD_JS
            name = self._name(js)
            if name not in self.fields:
                return {"missing": True}
            f = self.fields[name]
            return {"x": f["x"], "y": f["y"], "w": f.get("w", 80), "h": f.get("h", 20), "text": f.get("text", name),
                    "tag": f.get("tag", "INPUT"), "type": f.get("type", "text"), "role": f.get("role", ""),
                    "checked": f.get("checked", False), "disabled": f.get("disabled", False)}
        if "[role=option]" in js:                     # PICK_JS
            return self.menu
        if "document.readyState" in js:
            return "complete"
        if "location.href" in js:
            return "https://example.test/form"
        if "innerWidth" in js:
            return [400, 300]
        return ""

    def _name(self, js):
        return json.loads(re.search(r'const name = ("(?:[^"\\]|\\.)*")', js).group(1))

    def call(self, method, params=None, session=None):
        self.calls.append((method, dict(params or {})))
        return {}


class FakeClock:
    """Time moves forward on every call, so the server's polling loops always end."""

    def __init__(self):
        self.now = 0.0

    def time(self):
        self.now += 0.05
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def strftime(self, *a):
        return "00:00:00"


def install(page):
    """Patch the parts that talk to the real browser so batch() runs against the fake page."""
    patches = [
        mock.patch.object(server, "tab_connection", lambda tab: ("tab1", page)),
        mock.patch.object(server, "ensure_granted", lambda url: None),
        mock.patch.object(server, "check_paused", lambda: None),
        mock.patch.object(server, "enforce_after_move", lambda tab, page: None),
        mock.patch.object(server, "bar_update", lambda: None),
        mock.patch.object(server, "log", lambda *a: None),
        mock.patch.object(server, "current_url", lambda page: "https://example.test/form"),
        mock.patch.object(server, "time", FakeClock()),
    ]
    for p in patches:
        p.start()
    return patches


class Batch(unittest.TestCase):
    def setUp(self):
        self.page = FakePage({
            "namn": {"kind": "textbox", "type": "text", "tag": "INPUT", "x": 100, "y": 100},
            "e-post": {"kind": "textbox", "type": "email", "tag": "INPUT", "x": 100, "y": 140},
            "lösenord": {"kind": "password", "type": "password", "tag": "INPUT", "x": 100, "y": 180},
            "godkänn villkor": {"kind": "checkbox", "type": "checkbox", "tag": "INPUT", "x": 100, "y": 220, "checked": False},
            "skicka": {"kind": "button", "type": "submit", "tag": "BUTTON", "x": 100, "y": 260, "text": "Skicka"},
            "land": {"kind": "select", "type": "", "tag": "SELECT", "x": 100, "y": 300, "options": ["Sverige", "Norge"]},
        })
        self.patches = install(self.page)

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def run_steps(self, steps):
        return server.batch({"tab": None, "steps": steps})

    def test_fill_and_check_run_in_order(self):
        out = self.run_steps([
            {"action": "fill", "name": "namn", "value": "Kenny"},
            {"action": "fill", "name": "e-post", "value": "a@b.se"},
            {"action": "check", "name": "godkänn villkor", "value": True},
        ])
        self.assertTrue(out["ok"])
        self.assertEqual([r["action"] for r in out["results"]], ["fill", "fill", "check"])
        inserts = [p["text"] for m, p in self.page.calls if m == "Input.insertText"]
        self.assertEqual(inserts, ["Kenny", "a@b.se"])
        self.assertIn("fields", out)

    def test_stops_at_first_error_and_says_where(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([
                {"action": "fill", "name": "namn", "value": "Kenny"},
                {"action": "fill", "name": "finns inte", "value": "x"},
                {"action": "fill", "name": "e-post", "value": "a@b.se"},
            ])
        body = ctx.exception.body
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(body["stoppedAt"], 1)
        self.assertEqual(len(body["results"]), 1)
        self.assertEqual(body["results"][0]["filled"], "namn")

    def test_password_is_never_filled(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([{"action": "fill", "name": "lösenord", "value": "hemligt"}])
        self.assertEqual(ctx.exception.body["error"], "password_not_allowed")
        self.assertEqual([m for m, _ in self.page.calls if m == "Input.insertText"], [])

    def test_risky_button_needs_approval_and_is_not_clicked(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([{"action": "click", "name": "skicka"}])
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.body["error"], "approval_required")
        self.assertEqual([m for m, _ in self.page.calls if m == "Input.dispatchMouseEvent"], [])

    def test_check_only_clicks_when_state_differs(self):
        self.page.fields["godkänn villkor"]["checked"] = True
        self.run_steps([{"action": "check", "name": "godkänn villkor", "value": True}])
        self.assertEqual([m for m, _ in self.page.calls if m == "Input.dispatchMouseEvent"], [])

    def test_choose_reports_real_options_when_wrong(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([{"action": "choose", "name": "land", "value": "Danmark"}])
        self.assertEqual(ctx.exception.body["error"], "no_such_option")
        self.assertEqual(ctx.exception.body["options"], ["Sverige", "Norge"])

    def test_pick_clicks_the_matching_option(self):
        self.page.menu = {"found": True, "x": 50, "y": 60, "text": "Maths", "options": ["Maths", "Physics"]}
        out = self.run_steps([{"action": "pick", "name": "skicka", "value": "Maths"}])
        self.assertEqual(out["results"][0]["picked"], "Maths")
        clicks = [p for m, p in self.page.calls if m == "Input.dispatchMouseEvent" and p.get("type") == "mousePressed"]
        self.assertTrue(any(c["x"] == 50 and c["y"] == 60 for c in clicks))

    def test_pick_reports_real_options_when_missing(self):
        self.page.menu = {"found": False, "options": ["Physics", "Chemistry"]}
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([{"action": "pick", "name": "land", "value": "Maths"}])
        self.assertEqual(ctx.exception.body["error"], "no_such_option")
        self.assertEqual(ctx.exception.body["options"], ["Physics", "Chemistry"])

    def test_bad_steps_are_refused(self):
        with self.assertRaises(server.ApiError) as ctx:
            server.batch({"tab": None, "steps": []})
        self.assertEqual(ctx.exception.body["error"], "bad_steps")

    def test_unknown_action_is_refused(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.run_steps([{"action": "explode", "name": "namn"}])
        self.assertEqual(ctx.exception.body["error"], "bad_action")


if __name__ == "__main__":
    unittest.main()
