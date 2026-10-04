"""EXPERIMENTAL routing logic: agent selection and model fit within the chosen agent."""
from .availability import missing


def routing_questions(m):
    """Expert + mode pick the agent."""
    return {
        "expert": {"type": "choice", "instructions": "Which kind of expertise does this request need most?",
                   "criteria": {k: "expertise in " + v["desc"] for k, v in m["experts"].items()}},
        "mode": {"type": "choice", "instructions": "What does the user want the assistant to do?",
                 "criteria": {k: v["desc"] for k, v in m["modes"].items()}},
    }


def score_question(m, key):
    d = m[key]
    return {key: {"type": "score", "instructions": d["instructions"], "criteria": d["levels"]}}


def choose_agent(m, expert, mode):
    for aid, a in m["agents"].items():
        if expert in a["experts"] and mode in a["modes"]:
            return aid, f"expert '{expert}' + mode '{mode}'"
    return m["fallback_agent"], f"no agent handles '{expert}' + '{mode}'; fallback"


def agent_axis(m, agent_id, expert):
    return m["agents"][agent_id].get("axis") or m["experts"][expert]["axis"]


def score_executors(m, agent_id, axis, complexity, sec, sensitivity=None, status=None):
    """Fit every executor of the agent. complexity None = not asked (single-executor agent).
    sensitivity None = not asked (only asked when the best pick would leave this machine).
    status = availability.check() result; None = assume everything is up."""
    r, sm = m["routing"], m["sensitivity"]
    need = 1 + (complexity if complexity is not None else 0)
    force_local = []
    if sec["secrets"]:
        force_local.append("secrets/credentials detected")
    if sec["pii"]:
        force_local.append("high-risk personal data (SSN, card, IBAN)")
    if sensitivity is not None and sensitivity >= sm["force_local"]:
        force_local.append(f"sensitivity {sensitivity:.1f} ≥ {sm['force_local']}")
    public_block = []
    if sec["secrets"] or sec["pii_any"]:
        public_block.append("personal data or secrets")
    if sec["status"] == "review":
        public_block.append("review verdict")
    if sensitivity is not None and sensitivity > sm["public_max"]:
        public_block.append(f"sensitivity {sensitivity:.1f} > {sm['public_max']}")

    rows = []
    for ex in m["agents"][agent_id]["executors"]:
        mod = m["models"][ex["model"]]
        cap = mod["caps"].get(axis, 0)
        gap, surplus = max(0.0, need - cap), max(0.0, cap - need)
        fit = (r["base"] - r["gap_penalty"] * gap - r["cost_weight"] * mod["cost"] - r["overkill_penalty"] * surplus
               + (r["local_bonus"] if mod["route"] == "local" else 0) + mod.get("bonus", 0))
        notes, allowed = [], True
        if force_local and mod["route"] != "local":
            allowed = False
            notes.append("must stay local: " + ", ".join(force_local))
        elif mod.get("privacy") == "public" and public_block:
            allowed = False
            notes.append("free tier may log prompts: " + ", ".join(public_block))
        down = missing(m, ex, status) if status else []
        if down:
            notes.append("unavailable: " + "; ".join(down))
        if gap > 0:
            notes.append(f"under by {gap:.1f}")
        elif surplus >= 2:
            notes.append("overkill")
        rows.append({"id": ex["model"], "label": mod["label"], "via": ex["via"], "provider": mod.get("provider", ""),
                     "route": mod["route"], "privacy": mod.get("privacy", ""), "axis": axis, "cap": cap,
                     "need": round(need, 2), "gap": round(gap, 2), "cost": mod["cost"], "fit": round(fit, 2),
                     "allowed": allowed, "available": not down, "eligible": allowed and not down, "notes": notes})
    ranked = sorted(rows, key=lambda x: (not x["eligible"], -x["fit"]))
    return rows, ranked, force_local


def decide_route(m, agent_id, ranked, force_local, sec, asked):
    """Final routing decision + human-readable reasons."""
    agent = m["agents"][agent_id]
    reasons = []
    if force_local:
        reasons.append("Keep local: " + ", ".join(force_local) + ".")
    best = ranked[0] if ranked and ranked[0]["eligible"] else None
    if best is None:
        down = [x for x in ranked if x["allowed"] and not x["available"]]
        if force_local and down:
            return {"decision": "held", "agent": agent_id, "agent_label": agent["label"], "model": None, "route": None,
                    "reasons": reasons + [f"The local option is unavailable ({x['label']}: {', '.join(x['notes'])}). "
                                          "Held: not sending to a cloud model instead." for x in down[:1]]}
        if down:
            return {"decision": "unavailable", "agent": agent_id, "agent_label": agent["label"], "model": None,
                    "route": None, "reasons": reasons + [f"{x['label']} is {', '.join(x['notes'])}." for x in down]}
        return {"decision": "no eligible model", "agent": agent_id, "agent_label": agent["label"], "model": None,
                "route": None, "reasons": reasons + ["No executor in this agent satisfies the constraints."]}
    for x in ranked:
        if x["allowed"] and not x["available"] and x["fit"] > best["fit"]:
            reasons.append(f"Fell back from {x['label']}: {'; '.join(n for n in x['notes'] if n.startswith('unavailable'))}.")
    tied = [x["label"] for x in ranked[1:] if x["eligible"] and abs(x["fit"] - best["fit"]) < 0.05]
    if tied:
        reasons.append(f"Tied with {', '.join(tied)} (fit {best['fit']}); picked by agent order. "
                       "Set a model's \"bonus\" in matrix.json to prefer one.")
    if "complexity" in asked:
        reasons.append(f"Needs level {best['need']:.1f}/5 on '{best['axis']}'; {best['label']} has {best['cap']}"
                       + (f" (short by {best['gap']})" if best["gap"] else "") + ".")
    if best["route"] != "local":
        local = next((x for x in ranked if x["route"] == "local"), None)
        if local:
            reasons.append(f"Local option ({local['label']}) scores {local['fit']} vs {best['fit']}"
                           + (f": {', '.join(local['notes'])}" if local["notes"] else "") + ".")
    if best["route"] == "free":
        reasons.append("Free router: quality varies per request and the provider may log prompts.")
    if sec["status"] == "review":
        reasons.append("Security verdict is REVIEW: confirm before sending, and run without tools/auto-approve.")
    return {"decision": best["route"], "agent": agent_id, "agent_label": agent["label"], "model": best["id"],
            "model_label": best["label"], "via": best["via"], "route": best["route"], "reasons": reasons}
