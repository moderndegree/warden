"""Measure the router against your routing labels (test bed → Labels → routing).

  python3 evals/eval_routing.py tune [--misses 20]     # tune split: shows misses
  python3 evals/eval_routing.py test                   # held-out: numbers only
  python3 evals/eval_routing.py tune --pace 200        # ms between items, to leave lev free for Sully

Items: evals/routing/seed.jsonl (fixed split) plus prompts labelled live on the Router page (split by hash).
lev answers are cached in evals/cache.sqlite (keyed by frame + question), so re-runs cost no calls unless a
question changes. Reports agent (workflow) accuracy, tier accuracy (local / frontier / blocked) and baselines.
"""
import os
os.environ.setdefault("WARDEN_FRAME_KEY", "warden-evals")      # stable frames so lev answers can be cached
import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyze import CachedLev  # noqa: E402
from warden import config, labels  # noqa: E402
from warden.router import route  # noqa: E402

EVALS = Path(__file__).resolve().parent
TIERS = labels.TIERS


def items(split):
    """Labelled items of a split: [{id, text, area, split, gold: {workflow, tier, unsure}}]."""
    lab = labels.latest("routing")
    seed = {x["id"]: x for x in labels.seeds("routing")}
    out = []
    for i, rec in lab.items():
        s = seed.get(i) or {"id": i, "text": rec["text"], "area": "live", "split": labels.split_of(i)}
        if s["split"] == split:
            out.append({**s, "gold": rec["label"], "note": rec.get("note", "")})
    return sorted(out, key=lambda x: x["id"])


def tier_of(r):
    rt = r["routing"]
    if rt["decision"] == "blocked":
        return "blocked"
    return {"local": "local", "subscription": "frontier", "free": "frontier"}.get(rt["route"], "unavailable")


def predict(rows, lev, m, g, pace=0):
    out = []
    for i, x in enumerate(rows):
        miss0 = lev.misses
        r = route(x["text"], m, g, lev)
        out.append({**x, "pred": {"tier": tier_of(r), "workflow": r["agent"] and r["agent"]["id"]},
                    "lev_calls": r["timings"]["lev_calls"], "lev_ms": r["timings"]["lev_ms"],
                    "profile": {k: (v and (v.get("id") or v.get("score"))) for k, v in r["profile"].items() if k != "skipped"}})
        if sys.stderr.isatty():
            print(f"\r{i + 1}/{len(rows)}  lev cache hits {lev.hits} misses {lev.misses}", end="", file=sys.stderr)
        if pace and lev.misses > miss0:
            time.sleep(pace / 1000)
    if sys.stderr.isatty():
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
    return out


def pct(a, b):
    return f"{a}/{b} ({a / b:.0%})" if b else "-"


def confusion(rows, get_gold, get_pred, keys):
    cm = defaultdict(Counter)
    for x in rows:
        cm[get_gold(x)][get_pred(x)] += 1
    w = max(8, *(len(k) for k in keys))
    lines = ["    " + "gold \\ pred".ljust(w) + " " + " ".join(k[:10].rjust(10) for k in keys)]
    for g in keys:
        if sum(cm[g].values()):
            lines.append("    " + g.ljust(w) + " " + " ".join(str(cm[g][p] or ".").rjust(10) for p in keys))
    return "\n".join(lines)


def report(rows, split):
    n = len(rows)
    print(f"[{split}] routing · n={n} labelled ({sum(x['gold']['unsure'] for x in rows)} marked unsure)")
    if not n:
        print("  no labels in this split yet: label in the test bed (Labels → routing)")
        return
    tier_ok = sum(x["pred"]["tier"] == x["gold"]["tier"] for x in rows)
    runnable = [x for x in rows if x["gold"]["tier"] != "blocked"]
    wf_ok = sum(x["pred"]["workflow"] == x["gold"]["workflow"] for x in runnable)
    gold_tiers = Counter(x["gold"]["tier"] for x in rows)
    gold_wf = Counter(x["gold"]["workflow"] for x in runnable)
    print(f"  tier accuracy            {pct(tier_ok, n)}   baseline always-{gold_tiers.most_common(1)[0][0]}: "
          f"{pct(gold_tiers.most_common(1)[0][1], n)}")
    if runnable:
        print(f"  agent (workflow) accuracy {pct(wf_ok, len(runnable))}   baseline always-{gold_wf.most_common(1)[0][0]}: "
              f"{pct(gold_wf.most_common(1)[0][1], len(runnable))}   (gold tier ≠ blocked)")
    both = sum(x["pred"]["tier"] == x["gold"]["tier"] and (x["gold"]["tier"] == "blocked"
               or x["pred"]["workflow"] == x["gold"]["workflow"]) for x in rows)
    print(f"  tier + agent both right  {pct(both, n)}")
    lf = [x for x in rows if x["gold"]["tier"] in ("local", "frontier") and x["pred"]["tier"] in ("local", "frontier")]
    tp = sum(x["gold"]["tier"] == x["pred"]["tier"] == "frontier" for x in lf)
    gold_f = sum(x["gold"]["tier"] == "frontier" for x in lf)
    pred_f = sum(x["pred"]["tier"] == "frontier" for x in lf)
    print(f"  local vs frontier        {pct(sum(x['gold']['tier'] == x['pred']['tier'] for x in lf), len(lf))}   "
          f"frontier recall {pct(tp, gold_f)} · precision {pct(tp, pred_f)}")
    sure = [x for x in rows if not x["gold"]["unsure"]]
    if len(sure) < n:
        print(f"  excluding unsure         tier {pct(sum(x['pred']['tier'] == x['gold']['tier'] for x in sure), len(sure))}")
    print(f"  lev calls/item {sum(x['lev_calls'] for x in rows) / n:.2f} · lev ms/item (uncached) "
          f"{sum(x['lev_ms'] for x in rows) / n:.0f}")
    print("  tier confusion")
    print(confusion(rows, lambda x: x["gold"]["tier"], lambda x: x["pred"]["tier"], [*TIERS, "unavailable"]))
    wfs = list(config.load("router.json")["agents"])
    print("  workflow confusion (gold tier ≠ blocked)")
    print(confusion(runnable, lambda x: x["gold"]["workflow"], lambda x: x["pred"]["workflow"] or "none", [*wfs, "none"]))
    areas = Counter(x["area"] for x in rows)
    print("  by area: " + " · ".join(
        f"{a} tier {sum(x['pred']['tier'] == x['gold']['tier'] for x in rows if x['area'] == a)}/{c}"
        for a, c in sorted(areas.items())))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["tune", "test"])
    ap.add_argument("--misses", type=int, default=0, help="print up to N wrong items (tune only)")
    ap.add_argument("--pace", type=int, default=0, help="ms to wait after each item that called lev")
    ap.add_argument("--json", help="write per-item predictions to this file")
    a = ap.parse_args()
    m, g = config.load("router.json"), config.load("guard.json")
    lev = CachedLev(g["decision_model"], EVALS / "cache.sqlite")
    rows = predict(items(a.split), lev, m, g, a.pace)
    report(rows, a.split)
    print(f"  lev cache: {lev.hits} hits, {lev.misses} new calls")
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1))
    if a.split == "test":
        if a.misses:
            print("(miss texts are disabled on the test split: tune on 'tune' only)")
        return
    wrong = [x for x in rows if x["pred"]["tier"] != x["gold"]["tier"]
             or (x["gold"]["tier"] != "blocked" and x["pred"]["workflow"] != x["gold"]["workflow"])]
    for x in wrong[:a.misses]:
        print(f"    {x['id']:14} gold {x['gold']['tier']}/{x['gold']['workflow']}  pred {x['pred']['tier']}/"
              f"{x['pred']['workflow']}  {x['profile']} | {x['text'][:110]!r}")


if __name__ == "__main__":
    main()
