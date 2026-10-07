"""Compare tier policies (local / frontier / blocked) on routing labels. Dev tool for the coarse router.

  python3 evals/routing_policies.py tune [--drafts] [--pace 100]     # all candidates, grids, misses
  python3 evals/routing_policies.py test [--drafts]                  # the shipped policy only, numbers only

Per item it collects (through the cached lev): the guard verdict and rule flags, expert + mode, complexity,
sensitivity, and each candidate "needs a frontier model?" question, then replays policies offline.
"""
import os
os.environ.setdefault("WARDEN_TELEMETRY", "0")              # eval runs are not traffic
os.environ.setdefault("WARDEN_FRAME_KEY", "warden-evals")
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyze import CachedLev  # noqa: E402
from eval_routing import items  # noqa: E402
from warden import config  # noqa: E402
from warden.classify import state  # noqa: E402
from warden.guard import inspect  # noqa: E402
from warden.router_logic import choose_agent, routing_questions, score_question  # noqa: E402

EVALS = Path(__file__).resolve().parent
# Rejected on tune (Claude's drafts, 2026-10-04): a third phrasing, "Does this request need a top frontier AI model
# rather than a capable small local model to be done well?", never fired (frontier recall 0/12 at any threshold).
CANDIDATES = {
    "frontier_a": "Is this a hard, multi-step task where a small local AI model would likely make mistakes?",
    "frontier_b": ("Would this request clearly benefit from a top frontier AI model, because it needs deep expertise, "
                   "careful multi-step reasoning, long careful writing, or changes across many files?"),
}


def features(rows, m, g, lev, keys, pace=0):
    out = []
    for i, x in enumerate(rows):
        miss0 = lev.misses
        gr = inspect(x["text"], "prompt", g, lev)
        f = {"verdict": gr["verdict"], "secrets": bool(gr["secrets"]), "pii": bool(gr["pii"])}
        s = state(x["text"], m)
        qs = {**routing_questions(m), **score_question(m, "complexity"), **score_question(m, "sensitivity")}
        qs.update({k: {"type": "noul", "instructions": q} for k, q in CANDIDATES.items() if k in keys})
        for k, q in qs.items():
            a = lev.ask(s, {k: q})[0][k]
            f[k] = a.get("choice", a.get("score", a.get("noul")))
        f["workflow"] = choose_agent(m, f["expert"], f["mode"])[0]
        out.append({**x, "f": f})
        if sys.stderr.isatty():
            print(f"\r{i + 1}/{len(rows)}  lev cache hits {lev.hits} misses {lev.misses}", end="", file=sys.stderr)
        if pace and lev.misses > miss0:
            time.sleep(pace / 1000)
    if sys.stderr.isatty():
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
    return out


def tier(f, m, frontier):
    """Shared shell: guard block → blocked; secrets/PII/high sensitivity → local; else the frontier signal."""
    if f["verdict"] in m["gates"]["stop_on"]:
        return "blocked"
    if f["secrets"] or f["pii"] or f["sensitivity"] >= m["sensitivity"]["force_local"]:
        return "local"
    return "frontier" if frontier(f) else "local"


def score(rows, preds):
    n = len(rows)
    ok = sum(p == x["gold"]["tier"] for x, p in zip(rows, preds))
    lf = [(x, p) for x, p in zip(rows, preds) if x["gold"]["tier"] != "blocked" and p != "blocked"]
    tp = sum(x["gold"]["tier"] == p == "frontier" for x, p in lf)
    gf = sum(x["gold"]["tier"] == "frontier" for x, _ in lf)
    pf = sum(p == "frontier" for _, p in lf)
    pct = lambda a, b: f"{a}/{b} ({a / b:.0%})" if b else "-"
    return f"tier {pct(ok, n):14} frontier recall {pct(tp, gf):13} precision {pct(tp, pf):13} frontier rate {pf / max(1, len(lf)):.0%}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["tune", "test"])
    ap.add_argument("--drafts", action="store_true")
    ap.add_argument("--pace", type=int, default=0)
    ap.add_argument("--misses", type=int, default=0)
    a = ap.parse_args()
    m, g = config.load("router.json"), config.load("guard.json")
    lev = CachedLev(g["decision_model"], EVALS / "cache.sqlite")
    rows = items(a.split, a.drafts)
    keys = set() if a.split == "test" else set(CANDIDATES)
    rows = features(rows, m, g, lev, keys, a.pace)
    src = "Claude's DRAFT labels" if a.drafts else "your labels"
    print(f"[{a.split}] tier policies · n={len(rows)} · {src}")
    cmin = m["tier"]["complexity_min"]
    shipped = lambda f: f["complexity"] >= cmin
    print(f"  {f'shipped: complexity >= {cmin}, force_local {m['sensitivity']['force_local']}':78} "
          f"{score(rows, [tier(x['f'], m, shipped) for x in rows])}")
    wf = [x for x in rows if x["gold"]["tier"] != "blocked"]
    print(f"  workflow accuracy {sum(x['f']['workflow'] == x['gold']['workflow'] for x in wf)}/{len(wf)}")
    if a.split == "test":
        print(f"  lev cache: {lev.hits} hits, {lev.misses} new calls")
        return
    print(f"  {'always local (+ guard)':78} {score(rows, [tier(x['f'], m, lambda f: False) for x in rows])}")
    for t in (1.75, 2.0, 2.25, 2.5, 2.75, 3.0):
        print(f"  {'complexity >= ' + str(t):78} {score(rows, [tier(x['f'], m, lambda f, t=t: f['complexity'] >= t) for x in rows])}")
    for k, q in CANDIDATES.items():
        for t in (0.3, 0.5, 0.7):
            print(f"  {k + f' p>={t}: ' + q[:55] + '…':78} {score(rows, [tier(x['f'], m, lambda f, k=k, t=t: f[k] >= t) for x in rows])}")
    print("\n  per item: complexity / " + " / ".join(CANDIDATES))
    for x in sorted(rows, key=lambda x: x["gold"]["tier"])[:a.misses or 0]:
        f = x["f"]
        print(f"    {x['gold']['tier']:8} cx={f['complexity']:.2f} " + " ".join(f"{f[k]:.2f}" for k in CANDIDATES)
              + f" sens={f['sensitivity']:.1f} {x['id']}")
    print(f"  lev cache: {lev.hits} hits, {lev.misses} new calls")


if __name__ == "__main__":
    main()
