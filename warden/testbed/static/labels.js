// Label page: build the routing and escalation eval sets. No lev calls: the model's prediction is never shown
// here, so it can't anchor the label. Uses helpers from common.js.
"use strict";

const KINDS = {
  routing: {
    title: "Label routing",
    sub: "Where should this prompt go, all things considered (privacy included)? Labels are saved locally and become the routing eval set.",
    tiers: { local: ["L", "Qwen3.8 Flash on Halogen would do this well enough."],
             frontier: ["F", "Worth a frontier model (Claude / Grok): local would fall short."],
             blocked: ["B", "Shouldn't run at all: an attack or abuse."] },
  },
  escalation: {
    title: "Label escalation",
    sub: "A local agent tried this task. Should it hand off to a frontier model now? Labels are saved locally and become the escalation eval set.",
  },
};

const S = { kind: new URLSearchParams(location.search).get("kind") || "routing", data: null, order: [], pos: 0, draft: {} };

function summary(kind, l) {
  if (!l) return "—";
  if (kind === "routing") return `${l.tier}${l.workflow ? " · " + l.workflow : ""}${l.unsure ? " ?" : ""}`;
  return `${l.escalate ? "escalate" : "stay local"}${l.unsure ? " ?" : ""}`;
}

function itemText(it) {
  return S.kind === "escalation" ? `Task: ${it.task}\n\nTried: ${it.tried}` : it.text;
}

function choice(group, id, label, key, hint, on) {
  const b = el("button", { type: "button", class: "fb", "aria-pressed": String(on) }, label, key ? el("kbd", {}, key) : "");
  if (hint) b.title = hint;
  b.dataset.group = group;
  b.dataset.id = id;
  return b;
}

function controls() {
  const d = S.draft, box = $("controls");
  if (S.kind === "routing") {
    const tiers = Object.entries(KINDS.routing.tiers).map(([t, [k, h]]) => choice("tier", t, t, k, h, d.tier === t));
    const wfs = S.data.workflows.map((w, i) => choice("workflow", w.id, w.label, String(i + 1), w.desc, d.workflow === w.id));
    wfs.forEach((b) => { b.disabled = d.tier === "blocked"; });
    box.replaceChildren(
      el("h2", {}, "Tier ", el("span", { class: "hint" }, "where it runs")), el("div", { class: "row" }, ...tiers),
      el("p", { class: "detail" }, d.tier ? KINDS.routing.tiers[d.tier][1] : "Pick a tier."),
      el("h2", {}, "Workflow ", el("span", { class: "hint" }, "what kind of agent")), el("div", { class: "row" }, ...wfs),
      el("p", { class: "detail" }, d.workflow ? S.data.workflows.find((w) => w.id === d.workflow).desc : d.tier === "blocked" ? "Not needed for blocked." : "Pick a workflow."));
  } else {
    box.replaceChildren(el("h2", {}, "Hand off to a frontier model?"), el("div", { class: "row" },
      choice("escalate", "true", "escalate", "E", "Stop the local agent and hand off", d.escalate === true),
      choice("escalate", "false", "stay local", "K", "Let the local agent keep going (or retry)", d.escalate === false)));
  }
  for (const b of box.querySelectorAll("button.fb")) b.addEventListener("click", () => pick(b.dataset.group, b.dataset.id));
}

function pick(group, id) {
  if (group === "escalate") S.draft.escalate = id === "true";
  else S.draft[group] = id;
  if (group === "tier" && id === "blocked") S.draft.workflow = null;
  controls();
}

function ready() {
  const d = S.draft;
  return S.kind === "routing" ? d.tier && (d.tier === "blocked" || d.workflow) : typeof d.escalate === "boolean";
}

function show() {
  const items = S.data.items;
  const done = Object.keys(S.data.labels).filter((id) => items.some((x) => x.id === id)).length;
  $("progress").textContent = `${done} / ${items.length} labelled · saved to ${S.data.path}`;
  S.order = items.filter((x) => !$("only-open").checked || !S.data.labels[x.id] || x.id === S.current);
  if (!S.order.length) { $("item-box").hidden = true; $("done").hidden = false; return; }
  $("done").hidden = true;
  $("item-box").hidden = false;
  S.pos = Math.max(0, Math.min(S.pos, S.order.length - 1));
  const it = S.order[S.pos];
  S.current = it.id;
  const prev = S.data.labels[it.id];
  const draft = typeof it.draft === "boolean" ? { escalate: it.draft } : it.draft ? { ...it.draft } : null;
  S.draft = prev ? { ...prev.label } : draft || {};
  $("item-id").textContent = it.id;
  $("item-area").textContent = it.area || "";
  $("item-pos").textContent = `${S.pos + 1} of ${S.order.length}${prev ? " · labelled " + summary(S.kind, prev.label)
    : typeof it.draft === "boolean" ? ` · Claude's draft: ${it.draft ? "escalate" : "stay local"} (confirm or flip)` : ""}`;
  $("item").replaceChildren(el("pre", { class: "redacted" }, itemText(it)));
  $("unsure").checked = !!(prev && prev.label.unsure);
  $("note").value = prev ? prev.note || "" : "";
  controls();
  table();
}

function table() {
  $("all").tBodies[0].replaceChildren(...S.data.items.map((x) => {
    const r = el("tr", {}, el("td", {}, x.id), el("td", {}, itemText(x).slice(0, 120)), el("td", {}, summary(S.kind, S.data.labels[x.id]?.label)));
    r.addEventListener("click", () => { $("only-open").checked = false; S.pos = S.data.items.indexOf(x); show(); });
    return r;
  }));
}

async function save() {
  if (!ready()) { $("saved-msg").textContent = "Pick a label first."; return; }
  const it = S.order[S.pos];
  try {
    const r = await postJSON("/api/labels", { kind: S.kind, id: it.id, label: { ...S.draft, unsure: $("unsure").checked }, note: $("note").value });
    S.data.labels[it.id] = { label: r.label, note: $("note").value };
    $("saved-msg").textContent = `Saved ${it.id}: ${summary(S.kind, r.label)}`;
    if (!$("only-open").checked) S.pos += 1;
    S.current = null;
    show();
  } catch (e) { $("saved-msg").textContent = e.message; }
}

async function load() {
  KINDS[S.kind] || (S.kind = "routing");
  $("title").textContent = KINDS[S.kind].title;
  $("sub").textContent = KINDS[S.kind].sub;
  $("kinds").replaceChildren(...Object.keys(KINDS).map((k) => {
    const b = el("button", { type: "button", role: "radio", "aria-checked": String(k === S.kind) }, k);
    b.addEventListener("click", () => { history.replaceState(null, "", `?kind=${k}`); S.kind = k; S.pos = 0; load(); });
    return b;
  }));
  try {
    S.data = await (await fetch(`/api/labels/${S.kind}`)).json();
    $("err").hidden = true;
    if (!S.data.items.length) { $("err").textContent = `No seed items for ${S.kind} (evals/${S.kind}/seed.jsonl).`; $("err").hidden = false; }
    show();
  } catch (e) { $("err").textContent = e.message; $("err").hidden = false; }
}

document.addEventListener("keydown", (e) => {
  if (e.target.matches("input[type=text], textarea") || e.ctrlKey || e.metaKey || e.altKey || $("item-box").hidden) return;
  const k = e.key.toLowerCase();
  const tiers = { l: "local", f: "frontier", b: "blocked" };
  if (S.kind === "routing" && tiers[k]) pick("tier", tiers[k]);
  else if (S.kind === "routing" && /^[1-9]$/.test(k) && S.data.workflows[+k - 1] && S.draft.tier !== "blocked") pick("workflow", S.data.workflows[+k - 1].id);
  else if (S.kind === "escalation" && (k === "e" || k === "k")) pick("escalate", String(k === "e"));
  else if (k === "u") $("unsure").checked = !$("unsure").checked;
  else if (k === "enter") save();
  else if (k === "arrowright") { S.pos += 1; S.current = null; show(); }
  else if (k === "arrowleft") { S.pos -= 1; S.current = null; show(); }
  else return;
  e.preventDefault();
});
$("save").addEventListener("click", save);
$("skip").addEventListener("click", () => { S.pos += 1; S.current = null; show(); });
$("prev").addEventListener("click", () => { S.pos -= 1; S.current = null; show(); });
$("only-open").addEventListener("change", () => { S.pos = 0; show(); });
load();
