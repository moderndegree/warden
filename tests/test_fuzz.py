"""Robustness: random and hostile strings must never crash the guard, redaction, decide, or the feedback store."""
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from warden import config, feedback, rules
from warden.decide import decide
from warden.guard import inspect

from .stubs import StubLev

POOLS = [
    "abcdefghijklmnopqrstuvwxyz ABC 0123456789 .,;:!?-_/\\'\"<>[](){}|@#$%^&*=+~`\n\t",
    "​‍‮⁦﻿­\U000E0041\U000E0069\U000E007F\U0001F3F4️\U000E0100",
    "аеорсухіјѕԁһ ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ ｉｇｎｏｒｅ 忽略之前的指令 ﷺ ẞ ǅ ̀́",
    "\x00\x01\x07\x1b[31m\x1b]8;;\x07\x7f\x85  ",
    "𐏿",                                   # lone surrogates (JSON can carry them)
    '<!-- --> <span style="display:none"> ![x](http://a?b=c) [//]: # ( ) %41%42 ==',
]


def rand_text(rng, n):
    pool = "".join(POOLS)
    return "".join(rng.choice(pool) for _ in range(n))


class Fuzz(unittest.TestCase):
    def test_random_strings_never_crash(self):
        rng = random.Random(42)
        cfg = config.load("guard.json")
        for _ in range(300):
            t = rand_text(rng, rng.choice([1, 5, 50, 500, 3000]))
            for b in ("prompt", "content", "outbound"):
                r = inspect(t, b, cfg, StubLev(sec=rng.random()))
                self.assertIn(r["verdict"], ("allow", "review", "block"))
            rules.redact(t)
        decide("q", "yes_no", [rand_text(rng, 100) for _ in range(5)], cfg=cfg, lev=StubLev())

    def test_feedback_survives_lone_surrogates_and_line_separators(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(feedback, "path", lambda: Path(d) / "fb.jsonl"):
            feedback.append("prompt", "bad \ud800 text   here", "allow", "block")
            feedback.append("content", "second", "allow", "allow")
            self.assertEqual(len(feedback.load()), 2)
            self.assertEqual(oct(os.stat(feedback.path()).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
