"""Download evaluation sets into evals/data/<name>.<split>.jsonl  (git-ignored; local use only).

  python3 evals/fetch.py

Every set has a TUNE split (use it to choose rules, wording, thresholds) and a TEST split (only ever measured;
never look at its misses while tuning). Rows: {"text", "label": attack|benign, "boundary", "cat", "source"}.

Sources (Hugging Face; check licenses before redistributing anything):
  gandalf        Lakera/gandalf_ignore_instructions (MIT)            direct injections, prompt
  jailbreak      jackhhao/jailbreak-classification                  role-play jailbreaks + benign personas, prompt
  neuralchemy    neuralchemy/Prompt-injection-dataset, core (Apache-2.0)  categorized attacks + hard negatives
  pairs          3nesdeniz/agentic-prompt-injection-boundary-pairs (CC-BY-4.0)  attack / near-identical benign pairs
  ipi            nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (CC-BY-4.0)  injected documents vs the
                 same documents with the injection removed, content boundary (split by row parity)
  safeguard      xTRam1/safe-guard-prompt-injection                 mostly ordinary prompts (FP check), sampled
  web            SYNTHETIC content boundary: Wikipedia paragraphs from databricks/databricks-dolly-15k (CC BY-SA 3.0)
                 as carriers; half get an attack payload (from the same split's gandalf/neuralchemy/pairs attacks)
                 inserted at a random sentence, plain or disguised (HTML comment, hidden span, markdown comment,
                 white text). Tune and test use disjoint carriers and payloads.
"""
import json
import random
import time
import urllib.error
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
API = "https://datasets-server.huggingface.co/rows?dataset={ds}&config={cfg}&split={split}&offset={off}&length=100"


def rows(ds, cfg, split, limit=None):
    out, off = [], 0
    while True:
        for attempt in range(8):
            try:
                with urllib.request.urlopen(API.format(ds=ds, cfg=cfg, split=split, off=off), timeout=60) as r:
                    page = json.load(r)["rows"]
                break
            except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError):
                time.sleep(min(60, 3 * 2 ** attempt))   # the public API rate-limits bursts
        else:
            raise SystemExit(f"failed to fetch {ds} {split} at offset {off}")
        out += [p["row"] for p in page]
        if len(page) < 100 or (limit and len(out) >= limit):
            return out[:limit] if limit else out
        off += 100


def lbl(v):
    return "attack" if str(v) == "1" else "benign"


def have(name, split):
    return (DATA / f"{name}.{split}.jsonl").is_file()


def write(name, split, items):
    p = DATA / f"{name}.{split}.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for it in items:
            if it["text"] and it["text"].strip():
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
    from collections import Counter
    print(f"{p.name:28} {len(items):5}  {dict(Counter(i['label'] for i in items))}")


def find_str(o, needle):
    if isinstance(o, str):
        return o if needle in o else None
    if isinstance(o, dict):
        o = o.values()
    if isinstance(o, (list, tuple, type({}.values()))):
        for v in o:
            hit = find_str(v, needle)
            if hit:
                return hit
    return None


def main():
    DATA.mkdir(exist_ok=True)
    rng = random.Random(7)

    for split, src in (("tune", "train"), ("test", "test")):
        if not have("gandalf", split): write("gandalf", split, [{"text": r["text"], "label": "attack", "boundary": "prompt", "cat": "direct",
                                  "source": "Lakera/gandalf_ignore_instructions"} for r in rows("Lakera/gandalf_ignore_instructions", "default", src)])
        if not have("jailbreak", split): write("jailbreak", split, [{"text": r["prompt"], "label": "attack" if r["type"] == "jailbreak" else "benign",
                                    "boundary": "prompt", "cat": r["type"], "source": "jackhhao/jailbreak-classification"}
                                   for r in rows("jackhhao/jailbreak-classification", "default", src)])
        if not have("neuralchemy", split): write("neuralchemy", split, [{"text": r["text"], "label": lbl(r["label"]), "boundary": "prompt", "cat": r["category"],
                                      "source": "neuralchemy/Prompt-injection-dataset"}
                                     for r in rows("neuralchemy/Prompt-injection-dataset", "core", "train" if split == "tune" else "test")])
        if not have("pairs", split): write("pairs", split, [{"text": r["text"], "label": lbl(r["label"]),
                                "boundary": "prompt",     # every text is phrased as a request to the assistant
                                "cat": r["attack_family"] if str(r["label"]) == "1" else "benign_" + r["pair_family"],
                                "source": "3nesdeniz/agentic-prompt-injection-boundary-pairs"}
                               for r in rows("3nesdeniz/agentic-prompt-injection-boundary-pairs", "default", src)])
        if have("safeguard", split):
            continue
        sg = rows("xTRam1/safe-guard-prompt-injection", "default", src)
        rng.shuffle(sg)
        write("safeguard", split, [{"text": r["text"], "label": lbl(r["label"]), "boundary": "prompt", "cat": "safeguard",
                                    "source": "xTRam1/safe-guard-prompt-injection"} for r in sg[:600]])

    if not (have("web", "tune") and have("web", "test")):
        make_web()
    if have("ipi", "tune") and have("ipi", "test"):
        return
    ipi = {"tune": [], "test": []}
    for i, r in enumerate(rows("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", "default", "train")):
        inj = r["injection"]["injection_text"]
        doc = find_str(r["environment"], inj.strip()[:60])
        if not doc:
            continue
        split = "tune" if i % 2 == 0 else "test"
        src = "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"
        ipi[split].append({"text": doc, "label": "attack", "boundary": "content", "cat": r["attack_category"], "source": src})
        clean = doc.replace(inj, "").replace(inj.strip(), "").strip()
        if clean and clean != doc:
            ipi[split].append({"text": clean, "label": "benign", "boundary": "content", "cat": "clean_" + r["injection_vector"], "source": src})
    for split, items in ipi.items():
        write("ipi", split, items)


DISGUISES = [
    lambda p: p,
    lambda p: p,
    lambda p: f"<!-- {p} -->",
    lambda p: f'<span style="display:none">{p}</span>',
    lambda p: f"[//]: # ({p})",
    lambda p: f'<p style="color:#ffffff;font-size:1px">{p}</p>',
]


def make_web():
    import re
    rng = random.Random(13)
    docs = [r["context"] for r in rows("databricks/databricks-dolly-15k", "default", "train", limit=3000)
            if len(r.get("context") or "") >= 300]
    for split in ("tune", "test"):
        carriers = docs[0::2] if split == "tune" else docs[1::2]
        payloads = []
        for name in ("gandalf", "neuralchemy", "pairs"):
            payloads += [r["text"] for r in map(json.loads, filter(str.strip, (DATA / f"{name}.{split}.jsonl").read_text(encoding="utf-8").split("\n")))
                         if r["label"] == "attack" and 20 <= len(r["text"]) <= 400]
        rng.shuffle(carriers)
        rng.shuffle(payloads)
        items = []
        for i, doc in enumerate(carriers[:500]):
            src = "databricks/databricks-dolly-15k (+ attack payloads)"
            if i % 2:
                items.append({"text": doc, "label": "benign", "boundary": "content", "cat": "wiki", "source": src})
                continue
            d = rng.randrange(len(DISGUISES))
            sents = re.split(r"(?<=[.!?])\s+", doc)
            at = rng.randrange(len(sents) + 1)
            text = " ".join(sents[:at] + [DISGUISES[d](payloads[i % len(payloads)])] + sents[at:])
            items.append({"text": text, "label": "attack", "boundary": "content",
                          "cat": ["plain", "plain", "html_comment", "hidden_span", "md_comment", "white_text"][d], "source": src})
        write("web", split, items)


if __name__ == "__main__":
    main()
