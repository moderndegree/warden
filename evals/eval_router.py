"""EXPERIMENTAL: run the prompt samples through the router and show agent/model picks + cost.

  python3 evals/eval_router.py          # from the repo root; needs lev on :8200
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from warden.router import route  # noqa: E402

samples = [s for s in json.loads((Path(__file__).parent / "samples.json").read_text()) if s["boundary"] == "prompt"]
ok = calls = ms = 0
for s in samples:
    r = route(s["prompt"])
    got = r["security"]["status"]
    rt, pr, t = r["routing"], r["profile"], r["timings"]
    hit = got == s["expect"]
    ok, calls, ms = ok + hit, calls + t["lev_calls"], ms + t["total_ms"]
    who = (f"{pr['expert']['id']}/{pr['mode']['id']} → {r['agent']['id']} → {rt.get('model')}"
           if r["agent"] else f"stopped at {r['stopped_at']}")
    print(f"{'✓' if hit else '✗'} {s['name'][:24]:24} expect={s['expect']:6} got={got:6} {who:58} {t['lev_calls']} calls {t['total_ms']:>5} ms")
print(f"\n{ok}/{len(samples)} verdicts match · {calls} lev calls · avg {ms // len(samples)} ms")
sys.exit(0 if ok == len(samples) else 1)
