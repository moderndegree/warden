"""Escalation check: one lev yes/no, adjusted by rule signals in the summary."""
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from warden import config
from warden.cli import main
from warden.escalate import brief, escalate

from .stubs import Down, StubLev


class Escalate(unittest.TestCase):
    def setUp(self):
        self.m = config.load("router.json")
        self.g = config.load("guard.json")

    def run_(self, tried, p=0.9, lev=None, task="Fix the failing test."):
        lev = lev or StubLev(sec=p)
        return escalate(task, tried, self.m, self.g, lev), lev

    def test_lev_decides(self):
        r, lev = self.run_("Edited it three times, same AssertionError.", p=0.9)
        self.assertEqual((r["escalate"], r["p"], lev.asked), (True, 0.9, ["q"]))
        self.assertIn("stuck", r["signals"])
        r, _ = self.run_("Edited it three times, same AssertionError.", p=0.2)
        self.assertFalse(r["escalate"])

    def test_needs_person_stays_local_without_lev(self):
        r, lev = self.run_("It needs sudo, which I'm not allowed to run.", p=0.99)
        self.assertEqual((r["escalate"], r["p"], lev.asked), (False, None, []))
        self.assertIn("ask the user", r["reasons"][0])

    def test_done_stays_local_without_lev(self):
        r, lev = self.run_("Fixed it; all 95 tests pass.", p=0.99)
        self.assertEqual((r["escalate"], lev.asked), (False, []))

    def test_done_but_stuck_asks_lev(self):
        r, lev = self.run_("2 tests pass but the same error remains in the third.", p=0.9)
        self.assertEqual((r["escalate"], lev.asked), (True, ["q"]))

    def test_redacts_and_frames(self):
        _, lev = self.run_("Tried key AKIAIOSFODNN7EXAMPLE, same error.")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", lev.states[0])
        self.assertIn("WHAT THE LOCAL AGENT TRIED", lev.states[0])

    def test_lev_down(self):
        r, _ = self.run_("Same error again.", lev=Down())
        self.assertEqual((r["escalate"], r["p"]), (False, None))
        self.assertTrue(r["error"])
        self.assertIn("ERROR", brief(r))

    def test_requires_both(self):
        with self.assertRaises(ValueError):
            escalate("task", "  ", self.m, self.g, StubLev())


class EscalateCLI(unittest.TestCase):
    def cli(self, *argv, lev):
        out = io.StringIO()
        with mock.patch("warden.escalate.Lev", return_value=lev), redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_exit_codes(self):
        code, out = self.cli("escalate", "--brief", "-t", "fix it", "same error again", lev=StubLev(sec=0.9))
        self.assertEqual(code, 3)
        self.assertTrue(out.startswith("escalate p=0.90"))
        code, out = self.cli("escalate", "-t", "fix it", "same error again", lev=StubLev(sec=0.1))
        self.assertEqual((code, json.loads(out)["escalate"]), (0, False))
        code, _ = self.cli("escalate", "-t", "fix it", "same error again", lev=Down())
        self.assertEqual(code, 1)


class Seed(unittest.TestCase):
    def test_escalation_seed(self):
        from warden import labels
        s = labels.seeds("escalation")
        self.assertEqual(len(s), 60)
        self.assertEqual(len({x["id"] for x in s}), 60)
        self.assertEqual(sum(x["split"] == "tune" for x in s), 30)
        self.assertTrue(all(x["task"].strip() and x["tried"].strip() and isinstance(x["draft"], bool) for x in s))


if __name__ == "__main__":
    unittest.main()
