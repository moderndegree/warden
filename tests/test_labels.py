"""Labelled eval sets from the test bed: validation, latest-wins storage, seeds."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from warden import labels


class TempLabels(unittest.TestCase):
    """Points every label file at a temp dir."""
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = Path(d.name) / "state"
        p = mock.patch("warden.labels.path", side_effect=lambda kind: self.dir / f"labels-{kind}.jsonl")
        p.start()
        self.addCleanup(p.stop)


class Labels(TempLabels):
    def test_validate_routing(self):
        self.assertEqual(labels.validate("routing", {"tier": "local", "workflow": "code_build"}),
                         {"workflow": "code_build", "tier": "local", "unsure": False})
        self.assertEqual(labels.validate("routing", {"tier": "blocked", "workflow": "code_build"})["workflow"], None)
        for bad in ({"tier": "cloud", "workflow": "code_build"}, {"tier": "local", "workflow": "nope"},
                    {"tier": "local"}, "local"):
            with self.assertRaises(ValueError):
                labels.validate("routing", bad)

    def test_validate_escalation(self):
        self.assertTrue(labels.validate("escalation", {"escalate": True})["escalate"])
        with self.assertRaises(ValueError):
            labels.validate("escalation", {"escalate": "yes"})

    def test_latest_wins_and_private_file(self):
        labels.append("routing", "code-01", "x", {"tier": "local", "workflow": "code_build"})
        labels.append("routing", "code-01", "x", {"tier": "frontier", "workflow": "code_build"}, note="harder")
        got = labels.latest("routing")
        self.assertEqual((len(got), got["code-01"]["label"]["tier"], got["code-01"]["note"]), (1, "frontier", "harder"))
        f = self.dir / "labels-routing.jsonl"
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)

    def test_ids(self):
        self.assertEqual(labels.text_id("hi"), labels.text_id("hi"))
        self.assertTrue(labels.text_id("hi").startswith("live-"))
        splits = [labels.split_of(labels.text_id(str(i))) for i in range(200)]
        self.assertTrue(70 < splits.count("tune") < 130)
        with self.assertRaises(ValueError):
            labels.append("routing", "", "x", {"tier": "blocked"})


class Seeds(unittest.TestCase):
    def test_routing_seed(self):
        s = labels.seeds("routing")
        self.assertEqual(len(s), 100)
        self.assertEqual(len({x["id"] for x in s}), 100)
        self.assertTrue(all(x["split"] in ("tune", "test") and x["text"].strip() for x in s))
        self.assertLessEqual(abs(sum(x["split"] == "tune" for x in s) - 50), 3)


if __name__ == "__main__":
    unittest.main()
