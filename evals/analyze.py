"""Tuning workbench (dev tool). Scores items once (rules findings + lev score, cached on disk), then replays
the verdict policy offline so thresholds and rule changes can be compared instantly.

  python3 evals/analyze.py tune [--per-set 400] [--misses 25]    # tune split: shows miss texts
  python3 evals/analyze.py test                                   # test split: numbers + categories only
  python3 evals/analyze.py tune --grid                            # threshold grid over cached scores

The lev cache key is (frame text + question), so changing the question or framing re-asks lev automatically.
"""
import os
os.environ.setdefault("WARDEN_FRAME_KEY", "warden-evals")      # stable frames so lev answers can be cached
import argparse
import hashlib
import json
import random
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from warden import config, guard  # noqa: E402
from warden.lev import Lev  # noqa: E402

EVALS = Path(__file__).resolve().parent
SETS = ["gandalf", "jailbreak", "neuralchemy", "pairs", "safeguard", "ipi", "web"]
FLAG = {"review", "block"}


class CachedLev(Lev):
    def __init__(self, cfg, db):
        super().__init__(cfg)
        self.db = sqlite3.connect(db)
        self.db.execute("create table if not exists c (k text primary key, v text)")
        self.hits = self.misses = 0

    def ask(self, state, questions):
        k = hashlib.sha256(json.dumps([state, questions], sort_keys=True).encode()).hexdigest()
        row = self.db.execute("select v from c where k=?", (k,)).fetchone()
        if row:
            self.hits += 1
            return json.loads(row[0]), 0, {"input_tokens": 0}
        a, ms, usage = super().ask(state, questions)
        self.db.execute("insert or replace into c values (?,?)", (k, json.dumps(a)))
        self.db.commit()
        self.misses += 1
        return a, ms, usage


def load(split, per_set, seed=7):
    items = []
    for name in SETS:
        p = EVALS / "data" / f"{name}.{split}.jsonl"
        if not p.is_file():
            print(f"missing {p.name} (run evals/fetch.py)", file=sys.stderr)
            continue
        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]
        if per_set and len(rows) > per_set:
            by = defaultdict(list)
            for r in rows:
                by[r["label"]].append(r)
            rng = random.Random(seed)
            rows = []
            for lab, rs in by.items():           # stratified by label
                rng.shuffle(rs)
                rows += rs[:max(1, round(per_set * len(rs) / sum(len(v) for v in by.values())))]
        for r in rows:
            r["set"] = name
        items += rows
    return items


def score(items, cfg, lev, progress=True):
    out = []
    for i, it in enumerate(items):
        r = guard.inspect(it["text"], it["boundary"], cfg, lev, always_lev=True)
        rule_findings = [f for f in r["findings"] if f["source"] == "rules"]
        out.append({**it, "rules": rule_findings, "score": r["score"], "scores": r["scores"], "rules_verdict": r["rules_verdict"],
                    "floor": r.get("medium_floor") or 0.0})
        if progress and sys.stderr.isatty() and i % 10 == 0:
            print(f"\r{i + 1}/{len(items)}  lev cache hits {lev.hits} misses {lev.misses}", end="", file=sys.stderr)
    if progress and sys.stderr.isatty():
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
    return out


def replay(scored, cfg, medium=None, high=None, lev_on=True):
    c = json.loads(json.dumps(cfg))
    if medium is not None:
        c["thresholds"]["medium"] = medium
    if high is not None:
        c["thresholds"]["high"] = high
    for s in scored:
        fs = list(s["rules"])
        if lev_on:
            for qid, p in s["scores"].items():
                f = guard.security_finding(c, qid, p, s.get("floor", 0.0))
                if f:
                    fs.append(f)
        s["verdict"] = guard.verdict(fs)["status"]
    return scored


def metrics(scored):
    m = defaultdict(lambda: Counter())
    for s in scored:
        for key in (s["set"], f"_{s['boundary']}", "_all"):
            c = m[key]
            c[s["label"]] += 1
            if s["verdict"] in FLAG:
                c[s["label"] + "_flag"] += 1
            if s["verdict"] == "block":
                c[s["label"] + "_block"] += 1
    return m


def show(m, title):
    print(title)
    print(f"  {'set':14} {'attacks':>8} {'detect':>7} {'block':>6}   {'benign':>7} {'FP':>6} {'FPblk':>6}")
    for k in [*SETS, "_prompt", "_content", "_all"]:
        if k not in m:
            continue
        c = m[k]
        a, b = c["attack"], c["benign"]
        det = f"{c['attack_flag'] / a:.0%}" if a else "-"
        blk = f"{c['attack_block'] / a:.0%}" if a else "-"
        fp = f"{c['benign_flag'] / b:.1%}" if b else "-"
        fpb = f"{c['benign_block'] / b:.1%}" if b else "-"
        print(f"  {k:14} {a:8} {det:>7} {blk:>6}   {b:7} {fp:>6} {fpb:>6}")


def categories(scored):
    cat = defaultdict(Counter)
    for s in scored:
        cat[(s["label"], s["cat"])]["n"] += 1
        cat[(s["label"], s["cat"])]["flag"] += s["verdict"] in FLAG
    print("  per category (attacks: detected; benign: false positives)")
    for (lab, c), v in sorted(cat.items(), key=lambda kv: (kv[0][0], -kv[1]["n"])):
        if v["n"] >= 5:
            print(f"    {lab:7} {c[:34]:34} {v['flag']:5}/{v['n']:<5} {v['flag'] / v['n']:.0%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["tune", "test"])
    ap.add_argument("--per-set", type=int, default=0, help="stratified sample per set (0 = all)")
    ap.add_argument("--misses", type=int, default=0, help="print N missed attacks and N false positives (tune only)")
    ap.add_argument("--grid", action="store_true", help="threshold grid (tune only)")
    ap.add_argument("--cats", action="store_true")
    a = ap.parse_args()
    cfg = config.load("guard.json")
    lev = CachedLev(cfg["decision_model"], EVALS / "cache.sqlite")
    items = load(a.split, a.per_set)
    scored = score(items, cfg, lev)

    show(metrics(replay(scored, cfg, lev_on=False)), f"[{a.split}] rules only · n={len(scored)}")
    show(metrics(replay(scored, cfg)), f"[{a.split}] rules + lev (medium {cfg['thresholds']['medium']}, high {cfg['thresholds']['high']})")
    if a.cats:
        categories(scored)

    if a.split == "test":
        if a.misses or a.grid:
            print("(miss texts and grid search are disabled on the test split: tune on 'tune' only)")
        return
    if a.grid:
        print("  medium  high   detect   FP     FPblk")
        for med in (0.4, 0.5, 0.6, 0.7, 0.8):
            for hi in (0.8, 0.85, 0.9, 0.95):
                if hi <= med:
                    continue
                c = metrics(replay(scored, cfg, med, hi))["_all"]
                print(f"  {med:6} {hi:5}   {c['attack_flag'] / c['attack']:.1%}   {c['benign_flag'] / c['benign']:.1%}   {c['benign_block'] / c['benign']:.1%}")
        replay(scored, cfg)
    if a.misses:
        rng = random.Random(1)
        miss = [s for s in scored if s["label"] == "attack" and s["verdict"] not in FLAG]
        fps = [s for s in scored if s["label"] == "benign" and s["verdict"] in FLAG]
        rng.shuffle(miss)
        rng.shuffle(fps)
        print(f"\n  missed attacks ({len(miss)}):")
        for s in miss[:a.misses]:
            print(f"    [{s['set']}/{s['cat']}] lev={s['score']:.2f} | {s['text'][:170]!r}")
        print(f"\n  false positives ({len(fps)}):")
        for s in fps[:a.misses]:
            why = ",".join(f["id"] for f in s["rules"] if f["severity"] in ("medium", "high", "critical")) or "lev"
            print(f"    [{s['set']}/{s['cat']}] {s['verdict']} lev={s['score']:.2f} {why} | {s['text'][:150]!r}")


if __name__ == "__main__":
    main()
