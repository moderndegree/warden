"""Measure the guard. `warden eval [--no-lev] [--sets dev,feedback,gandalf,jailbreak,neuralchemy,pairs,safeguard,ipi,web]`

  dev        evals/samples.json: hand-written, USED FOR TUNING (expect allow/review/block per boundary)
  feedback   your test-bed labels (~/.local/state/warden/feedback.jsonl)
  others     the TEST split of each public set (evals/data/<set>.test.jsonl, from evals/fetch.py); never tuned on

Attack/benign sets report detection (attack flagged review or block) and false positives (benign flagged).
For tuning use evals/analyze.py on the TUNE split. Reports are written to evals/reports/.
"""
import json
import time
from pathlib import Path

from . import __version__, feedback
from .guard import inspect

EVALS = Path(__file__).resolve().parent.parent / "evals"
FLAG = {"review", "block"}


def load_set(name):
    if name == "dev":
        if not (EVALS / "samples.json").is_file():
            return None                      # installed outside the repo: dev samples aren't shipped
        return [{"text": s["prompt"], "boundary": s["boundary"], "expect": s["expect"], "name": s["name"]}
                for s in json.loads((EVALS / "samples.json").read_text())]
    if name == "feedback":
        return [{"text": r["text"], "boundary": r["boundary"], "expect": r["expected"], "name": f"feedback {r['ts']}"}
                for r in feedback.load()]
    p = EVALS / "data" / f"{name}.test.jsonl"
    if not p.is_file():
        return None
    return [{"text": r["text"], "boundary": r.get("boundary", "prompt"), "label": r["label"]}
            for r in map(json.loads, filter(str.strip, p.read_text(encoding="utf-8").split("\n"))) if r["text"].strip()]


def run_set(rows, use_lev, progress=None):
    out = {"n": len(rows), "lev_calls": 0, "ms": 0.0, "misses": []}
    exact = attack = benign = det_any = det_block = fp_any = fp_block = 0
    for i, r in enumerate(rows):
        res = inspect(r["text"], r["boundary"], use_lev=use_lev)
        out["lev_calls"] += res["lev"]["calls"]
        out["ms"] += res["ms"] or 0
        v = res["verdict"]
        if "expect" in r:
            ok = v == r["expect"]
            exact += ok
            if not ok:
                out["misses"].append({"name": r.get("name"), "expect": r["expect"], "got": v})
        elif r["label"] == "attack":
            attack += 1
            det_any += v in FLAG
            det_block += v == "block"
            if v not in FLAG and len(out["misses"]) < 15:
                out["misses"].append({"label": "attack", "got": v, "score": res["score"], "text": r["text"][:160]})
        else:
            benign += 1
            fp_any += v in FLAG
            fp_block += v == "block"
            if v in FLAG and len(out["misses"]) < 30:
                out["misses"].append({"label": "benign", "got": v, "score": res["score"], "text": r["text"][:160]})
        if progress:
            progress(i + 1, len(rows))
    if exact or any("expect" in r for r in rows):
        out["exact"] = exact
    if attack:
        out.update(attacks=attack, detected=det_any, detected_block=det_block, detection_rate=round(det_any / attack, 3))
    if benign:
        out.update(benign=benign, false_pos=fp_any, false_pos_block=fp_block, false_pos_rate=round(fp_any / benign, 3))
    out["avg_ms"] = round(out["ms"] / max(1, len(rows)), 1)
    out["avg_lev_calls"] = round(out["lev_calls"] / max(1, len(rows)), 2)
    del out["ms"]
    return out


TEST_SETS = ("gandalf", "jailbreak", "neuralchemy", "pairs", "safeguard", "ipi", "web")


def evaluate(sets=("dev", "feedback", *TEST_SETS), use_lev=True, progress=None):
    report = {"warden": __version__, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "lev": use_lev, "sets": {}}
    for name in sets:
        rows = load_set(name)
        if rows is None:
            report["sets"][name] = {"skipped": "not available (run evals/fetch.py in the repo)"}
            continue
        if not rows:
            report["sets"][name] = {"skipped": "empty"}
            continue
        report["sets"][name] = run_set(rows, use_lev, (lambda i, n, s=name: progress(s, i, n)) if progress else None)
    out = EVALS / "reports" if EVALS.is_dir() else Path("~/.local/state/warden/reports").expanduser()
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"guard-{time.strftime('%Y%m%d-%H%M%S')}{'' if use_lev else '-rules'}.json"
    path.write_text(json.dumps(report, indent=1))
    report["path"] = str(path)
    return report


def summary(report):
    lines = [f"warden {report['warden']} guard eval · lev {'on' if report['lev'] else 'OFF (rules only)'}"]
    for name, s in report["sets"].items():
        if "skipped" in s:
            lines.append(f"  {name:14} skipped: {s['skipped']}")
            continue
        parts = [f"n={s['n']}"]
        if "exact" in s:
            parts.append(f"exact {s['exact']}/{s['n']}")
        if "attacks" in s:
            parts.append(f"detected {s['detected']}/{s['attacks']} ({s['detection_rate']:.0%}, block {s['detected_block']})")
        if "benign" in s:
            parts.append(f"false pos {s['false_pos']}/{s['benign']} ({s['false_pos_rate']:.0%}, block {s['false_pos_block']})")
        parts.append(f"{s['avg_lev_calls']} lev calls/item, {s['avg_ms']} ms/item")
        lines.append(f"  {name:14} " + " · ".join(parts))
    lines.append(f"report: {report['path']}")
    return "\n".join(lines)
