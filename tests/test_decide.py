"""decide: lev as a typed-decision engine over items."""
import unittest

from warden import config
from warden.decide import decide

from .stubs import Down, StubLev


class Decide(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load("guard.json")

    def test_yes_no(self):
        r = decide("Is this urgent?", "yes_no", ["a", "b"], cfg=self.cfg, lev=StubLev(sec=0.9))
        self.assertEqual([x["answer"] for x in r["results"]], [True, True])
        self.assertTrue(r["complete"])
        self.assertEqual(r["lev"]["calls"], 2)

    def test_choice_list_and_dict(self):
        r = decide("Which?", "choice", ["x"], options=["bug", "feature"], cfg=self.cfg, lev=StubLev(choice="feature"))
        self.assertEqual(r["results"][0]["answer"], "feature")
        r = decide("Which?", "choice", ["x"], options={"bug": "a defect", "feature": "a request"}, cfg=self.cfg, lev=StubLev())
        self.assertIn(r["results"][0]["answer"], ("bug", "feature"))

    def test_score(self):
        r = decide("How urgent?", "score", ["x"], levels=["low", "mid", "high"], cfg=self.cfg, lev=StubLev())
        self.assertEqual(r["results"][0]["level"], 1)

    def test_validation(self):
        for args in [("", "yes_no", ["x"]), ("q", "yes_no", []), ("q", "choice", ["x"]), ("q", "score", ["x"]), ("q", "maybe", ["x"])]:
            with self.assertRaises(ValueError):
                decide(*args, cfg=self.cfg, lev=StubLev())

    def test_item_cap(self):
        with self.assertRaises(ValueError):
            decide("q", "yes_no", ["x"] * (self.cfg["decide"]["max_items"] + 1), cfg=self.cfg, lev=StubLev())

    def test_items_are_redacted_and_framed(self):
        lev = StubLev()
        decide("q", "yes_no", ["ssn 123-45-6789"], cfg=self.cfg, lev=lev)
        self.assertNotIn("123-45-6789", lev.states[0])
        self.assertIn("data to classify", lev.states[0])

    def test_lev_down_is_incomplete(self):
        r = decide("q", "yes_no", ["a", "b"], cfg=self.cfg, lev=Down())
        self.assertFalse(r["complete"])
        self.assertEqual(r["results"], [])


if __name__ == "__main__":
    unittest.main()
