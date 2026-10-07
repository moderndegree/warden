"""Measure `warden escalate` against your escalation labels (test bed → Labels → escalation).

  python3 evals/eval_escalation.py tune [--questions] [--grid] [--misses 10]
  python3 evals/eval_escalation.py test                      # held-out: numbers only
  python3 evals/eval_escalation.py tune --drafts             # Claude's drafted labels instead of yours (preliminary)

lev is asked the configured question for every item (even where the rules would skip it), so the policies can be
replayed offline: lev only, rules only, and the shipped combination. Answers are cached in evals/cache.sqlite.
"""
import os
os.environ.setdefault("WARDEN_TELEMETRY", "0")              # eval runs are not traffic
os.environ.setdefault("WARDEN_FRAME_KEY", "warden-evals")
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyze import CachedLev  # noqa: E402
from warden import config, labels, rules  # noqa: E402
from warden.escalate import _signals, decide, state  # noqa: E402

EVALS = Path(__file__).resolve().parent
CANDIDATES = [
    "Is the local agent stuck, failing, or out of its depth on this task?",
    "Would a more capable AI model be likely to succeed where the local agent has not?",
    "Has the local agent failed to make real progress on this task?",
]


def items(split, drafts=False):
    lab = labels.latest("escalation")
    out = []
    for s in labels.seeds("escalation"):
        if s["split"] != split:
            continue
        if drafts:
            out.append({**s, "gold": s["draft"]})
        elif s["id"] in lab:
            out.append({**s, "gold": lab[s["id"]]["label"]["escalate"], "unsure": lab[s["id"]]["label"]["unsure"]})
    return out


def scores(rows, cfg, lev, question):
    q = {"q": {"type": "noul", "instructions": question}}
    return [lev.ask(state(x["task"], x["tried"], cfg), q)[0]["q"]["noul"] for x in rows]


def metrics(rows, preds):
    n = len(rows)
    tp = sum(p and x["gold"] for x, p in zip(rows, preds))
    fp = sum(p and not x["gold"] for x, p in zip(rows, preds))
    fn = sum(not p and x["gold"] for x, p in zip(rows, preds))
    acc = sum(p == x["gold"] for x, p in zip(rows, preds))
    f = lambda a, b: f"{a}/{b} ({a / b:.0%})" if b else "-"
    return f"acc {f(acc, n):16} escalate recall {f(tp, tp + fn):14} precision {f(tp, tp + fp)}"


def policies(rows, ps, cfg, thr=None):
    c = {**cfg, "threshold": thr if thr is not None else cfg["threshold"]}
    sig = [_signals(rules.normalize(x["tried"]), cfg) for x in rows]
    return {
        "lev only": [p >= c["threshold"] for p in ps],
        "rules only": [("stuck" in s) and "needs_person" not in s and not ("done" in s and "stuck" not in s) for s in sig],
        "rules + lev (shipped)": [decide(p, s, c)[0] for p, s in zip(ps, sig)],
    }, sig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["tune", "test"])
    ap.add_argument("--drafts", action="store_true", help="use Claude's drafted labels (preliminary, not yours)")
    ap.add_argument("--questions", action="store_true", help="compare candidate question phrasings (tune only)")
    ap.add_argument("--grid", action="store_true", help="threshold grid (tune only)")
    ap.add_argument("--misses", type=int, default=0)
    a = ap.parse_args()
    m, g = config.load("router.json"), config.load("guard.json")
    cfg = m["escalation"]
    lev = CachedLev(g["decision_model"], EVALS / "cache.sqlite")
    rows = items(a.split, a.drafts)
    src = "Claude's DRAFT labels (not confirmed by you)" if a.drafts else "your labels"
    print(f"[{a.split}] escalation · n={len(rows)} · {src} · escalate={sum(x['gold'] for x in rows)}")
    if not rows:
        print("  no labels in this split yet: label in the test bed (Labels → escalation), or pass --drafts")
        return
    ps = scores(rows, cfg, lev, cfg["question"])
    pol, sig = policies(rows, ps, cfg)
    for name, preds in pol.items():
        print(f"  {name:22} {metrics(rows, preds)}")
    skipped = sum("needs_person" in s or ("done" in s and "stuck" not in s) for s in sig)
    print(f"  shipped policy: {(len(rows) - skipped) / len(rows):.2f} lev calls/item ({skipped} decided by rules)")
    if a.split == "test":
        if a.questions or a.grid or a.misses:
            print("(question comparison, grid and misses are disabled on the test split: tune on 'tune' only)")
        print(f"  lev cache: {lev.hits} hits, {lev.misses} new calls")
        return
    if a.grid:
        for thr in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8):
            print(f"  threshold {thr:.1f}: lev only {metrics(rows, [p >= thr for p in ps])}")
            print(f"                 shipped  {metrics(rows, policies(rows, ps, cfg, thr)[0]['rules + lev (shipped)'])}")
    if a.questions:
        for q in CANDIDATES:
            qs = scores(rows, cfg, lev, q)
            print(f"  {q[:70]!r}\n      lev only {metrics(rows, [p >= cfg['threshold'] for p in qs])}"
                  f"\n      shipped  {metrics(rows, policies(rows, qs, cfg)[0]['rules + lev (shipped)'])}")
    if a.misses:
        wrong = [(x, p, s) for x, p, s, d in zip(rows, ps, sig, pol["rules + lev (shipped)"]) if d != x["gold"]]
        for x, p, s in wrong[:a.misses]:
            print(f"    {x['id']} gold {'esc' if x['gold'] else 'stay'} p={p:.2f} {list(s)} | {x['tried'][:120]!r}")
    print(f"  lev cache: {lev.hits} hits, {lev.misses} new calls")


if __name__ == "__main__":
    main()
