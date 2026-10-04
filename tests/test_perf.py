"""ReDoS regression: every pathological input must scan in (roughly) linear time.
Each case is 50 KB; anything quadratic takes seconds here, linear takes well under 0.5 s."""
import base64
import random
import time
import unittest

from warden import rules

N = 50_000
CASES = {
    "spaces": " " * N, "newlines": "\n" * N, "letters": "a" * N, "a-space": "a " * (N // 2), "dots": "a." * (N // 2),
    "a-dash": "a-" * (N // 2), "digits-space": "1 " * (N // 2), "span-open": '<span style="' * (N // 13),
    "comment-open": "<!--" * (N // 4), "img-open": "![" * (N // 2), "alt-open": 'alt="' * (N // 5),
    "tags": "<p hidden>" * (N // 10), "md-comment": "[//]: # (" * (N // 9), "ansi": "\x1b[" * (N // 2),
    "b64": base64.b64encode(random.Random(1).randbytes(N * 3 // 4)).decode(), "hex": "ab:" * (N // 3),
    "urlenc": "%41" * (N // 3), "email-ish": "a@" * (N // 2), "at-colon": "a:b@" * (N // 4),
    "conn": "postgres://" + "a:" * (N // 2), "env": "export A_SECRET=" * (N // 16), "curl": "curl " * (N // 5),
    "dd": "dd " * (N // 3), "md-img-url": "![a](http://x" * (N // 13), "inst": "<|im_start|>" * (N // 12),
    "instr": "what your previous " * (N // 19), "mixed-script": "аa" * (N // 2), "zw": "a\u200b" * (N // 2),
}


class Perf(unittest.TestCase):
    def test_no_quadratic_regex(self):
        slow = []
        for name, text in CASES.items():
            t0 = time.perf_counter()
            rules.scan(text)
            rules.redact(text)
            dt = time.perf_counter() - t0
            if dt > 1.0:
                slow.append(f"{name}: {dt:.2f}s")
        self.assertEqual(slow, [], "possible ReDoS: " + ", ".join(slow))


if __name__ == "__main__":
    unittest.main()
