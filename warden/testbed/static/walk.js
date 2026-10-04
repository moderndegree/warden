// Router walk (experimental): streams /api/route/stream (NDJSON, one event per step) and animates the gated
// board. Uses helpers from common.js. All text goes through textContent; nothing reaches innerHTML.
"use strict";

const RULE_FAMILIES = {
  unicode: "Unicode tricks", injection: "Injection phrasing", commands: "Dangerous commands", encoded: "Encoded payloads",
  exfiltration: "Exfiltration", urls: "URLs", secrets: "Secrets & PII", resource: "Resource abuse",
};
const SEV = ["info", "low", "medium", "high", "critical"];
// [stage id, gate, title, subtitle]
const STAGES = [
  ["rules", "rules", "Rule scanners", "deterministic · stops here on block, zero model calls"],
  ["security", "security", "Manipulation check", "lev · one yes/no question · chunk sweep for long prompts"],
  ["expert", "routing", "Expert", "lev · choice"],
  ["mode", "routing", "Mode", "lev · choice"],
  ["agent", "routing", "Agent", "first agent whose experts and modes both match"],
  ["complexity", "routing", "Complexity", "lev · score · skipped for one-model agents"],
  ["executors", "routing", "Executors", "fit = capability vs need − cost − overkill ± constraints"],
  ["sensitivity", "routing", "Data sensitivity", "lev · score · only if the pick would leave this machine"],
  ["decision", "routing", "Decision", ""],
];
const GATES = { rules: "Gate 0 · Rules", security: "Gate 1 · Security", routing: "Gate 2 · Routing" };

let M = null, ui = {}, gen = 0, controller = null, active = null;

// ---------------------------------------------------------------- board

function tile(label, extra = "") {
  const tv = el("span", { class: "tv" }, "—");
  const t = el("div", { class: "tile " + extra, title: label }, el("span", { class: "tl" }, label), tv);
  t.tv = tv;
  return t;
}

function levelRow(key) {
  const d = M[key];
  const dmx = el("div", { class: "dmx" });
  dmx.append(el("span", {}));
  d.levels.forEach((_, i) => dmx.append(el("span", { class: "h" }, String(i))));
  dmx.append(el("span", { class: "h" }, "EV"));
  const rl = el("span", { class: "rl" }, d.label);
  const cells = d.levels.map((lv) => el("span", { class: "cell", title: lv }, lv.split(/[:,]/)[0]));
  const sc = el("span", { class: "sc" }, "—"), mark = el("i"), ev = el("div", { class: "ev" }, mark);
  dmx.append(rl, ...cells, sc, el("span", { class: "spacer" }), ev, el("span", { class: "spacer2" }));
  return { dmx, rl, cells, sc, ev, mark, levels: d.levels };
}

function buildBoard() {
  ui = { stages: {}, rules: {}, expert: {}, mode: {}, agents: {}, rows: {}, chunks: [] };
  const board = $("board");
  board.replaceChildren();
  let lastGate = null, n = 0;
  for (const [id, gate, title, sub] of STAGES) {
    if (gate !== lastGate) {
      const gh = el("div", { class: "gatehead", "data-gate": gate }, el("span", {}, GATES[gate]), el("span", { class: "gstat" }));
      board.append(gh);
      ui[`gate_${gate}`] = gh;
      lastGate = gate;
    }
    const ms = el("span", { class: "ms" }), body = el("div", { class: "stage-body" }), note = el("p", { class: "skipnote", hidden: "" });
    const box = el("section", { class: "stage", "data-n": String(++n) },
      el("div", { class: "stage-head" }, el("h2", {}, title), el("span", { class: "sub2" }, sub), ms), note, body);
    ui.stages[id] = { box, body, ms, note, gate, lev: 0 };
    board.append(box);
  }

  const rt = el("div", { class: "tiles cols-8" });
  for (const [k, label] of Object.entries(RULE_FAMILIES)) rt.append(ui.rules[k] = tile(label));
  ui.stages.rules.body.append(rt);

  ui.secTile = tile(M.security.label, "risk big-tile");
  ui.secMax = 0;
  ui.chunkRow = el("div", { class: "chunks", hidden: "" });
  ui.gateWhy = el("p", { class: "gate-why" });
  ui.stages.security.body.append(ui.secTile, ui.chunkRow, ui.gateWhy);

  for (const [group, src, cls] of [["expert", M.experts, "tiles cols-5"], ["mode", M.modes, "tiles cols-5"]]) {
    const g = el("div", { class: cls });
    for (const [k, v] of Object.entries(src)) g.append(ui[group][k] = tile(v.label));
    ui[group]._grid = g;
    ui.stages[group].body.append(g);
  }

  const tb = el("tbody");
  for (const [id, a] of Object.entries(M.agents)) {
    const tr = el("tr", {}, el("td", {}, a.label, el("div", { class: "detail" }, a.harness)),
      el("td", {}, el("div", { class: "minichips" }, ...a.experts.map((e) => el("span", { "data-e": e }, M.experts[e].label)))),
      el("td", {}, el("div", { class: "minichips" }, ...a.modes.map((mo) => el("span", { "data-m": mo }, M.modes[mo].label)))),
      el("td", { class: "n" }, String(a.executors.length)));
    ui.agents[id] = tr;
    tb.append(tr);
  }
  ui.stages.agent.body.append(el("div", { class: "scroll-x" }, el("table", { class: "rmx agents" },
    el("thead", {}, el("tr", {}, ...["Agent", "Experts", "Modes", "Models"].map((h) => el("th", {}, h)))), tb)));
  ui.agentWhy = el("p", { class: "gate-why" });
  ui.stages.agent.body.append(ui.agentWhy);

  ui.cx = levelRow("complexity");
  ui.stages.complexity.body.append(ui.cx.dmx);
  ui.sens = levelRow("sensitivity");
  ui.stages.sensitivity.body.append(ui.sens.dmx);

  ui.execBody = el("tbody");
  ui.stages.executors.body.append(el("div", { class: "scroll-x" }, el("table", { class: "rmx" },
    el("thead", {}, el("tr", {}, ...["Model", "Via", "Route", "Capability vs need", "Cap / need", "Gap", "Cost", "Fit", "Notes"].map((h) => el("th", {}, h)))),
    ui.execBody)));

  ui.decision = el("div", { class: "decision" }, "Waiting…");
  ui.stages.decision.body.append(ui.decision);
  $("trace").replaceChildren();
}

// ---------------------------------------------------------------- helpers

function trace(t, text, cls = "") {
  const li = el("li", { class: cls }, el("span", { class: "t" }, t == null ? "" : `+${Math.round(t)}`), el("span", {}, text));
  $("trace").append(li);
  li.scrollIntoView({ block: "nearest" });
}
function setNow(text, busy = true) { $("now-text").textContent = text; $("spin").hidden = !busy; }

function activate(id) {
  if (active && active !== id && !ui.stages[active].box.classList.contains("skipped")) ui.stages[active].box.className = "stage done";
  active = id;
  ui.stages[id].box.className = "stage active";
  if (window.matchMedia("(min-width: 1101px)").matches) ui.stages[id].box.scrollIntoView({ block: "nearest", behavior: "smooth" });
}
function done(id) { ui.stages[id].box.className = "stage done"; if (active === id) active = null; }
function skipStage(id, reason) {
  const s = ui.stages[id];
  s.box.className = "stage skipped";
  s.note.hidden = false;
  s.note.textContent = `Skipped · ${reason}`;
  if (active === id) active = null;
}
function addLev(id, ms) { const s = ui.stages[id]; s.lev += ms; s.ms.textContent = `lev ${s.lev} ms`; }

function applyLevel(row, a) {
  let arg = "0";
  Object.entries(a.probabilities).forEach(([i, p]) => {
    row.cells[i].style.setProperty("--p", p.toFixed(3));
    if (p > a.probabilities[arg]) arg = i;
  });
  row.cells.forEach((c, i) => c.classList.toggle("argmax", String(i) === String(arg)));
  row.sc.textContent = a.score.toFixed(2);
  row.mark.style.setProperty("--x", (a.score / (row.levels.length - 1)).toFixed(3));
  row.ev.classList.add("on");
  return row.levels[Math.min(row.levels.length - 1, Math.round(a.score))].split(/[:,]/)[0];
}

function applyChoice(group, a) {
  for (const [k, p] of Object.entries(a.probabilities)) {
    const t = ui[group][k];
    t.style.setProperty("--p", Math.min(1, p * 2).toFixed(3));
    t.tv.textContent = pct(p);
    t.classList.toggle("hot", p >= 0.15);
    t.classList.toggle("win", k === a.choice);
  }
}

function execRow(row) {
  let r = ui.rows[row.id];
  if (!r) {
    const cap = el("span", { class: "c" }), nd = el("span", { class: "nd" });
    r = { tr: el("tr", { class: "pending" }), cap, nd, capTxt: el("span", { class: "num" }), gap: el("td", { class: "n" }),
          fitbar: el("span", { class: "fitbar" }), fitTxt: el("span", {}), why: el("td", { class: "why" }) };
    r.tr.append(el("td", {}, row.label), el("td", { class: "detail" }, row.via), el("td", {}, el("span", { class: `r-${row.route}` }, row.route)),
      el("td", {}, el("span", { class: "capbar" }, cap, nd)), el("td", { class: "n" }, r.capTxt), r.gap,
      el("td", { class: "n" }, String(row.cost)), el("td", { class: "n" }, r.fitbar, r.fitTxt), r.why);
    ui.execBody.append(r.tr);
    ui.rows[row.id] = r;
  }
  r.tr.className = row.eligible ? "" : "out";
  r.cap.style.width = `${(row.cap / 5) * 100}%`;
  r.cap.classList.toggle("short", row.gap > 0);
  r.nd.style.left = `${(row.need / 5) * 100}%`;
  r.capTxt.textContent = `${row.cap} / ${row.need}`;
  r.gap.textContent = row.gap ? `−${row.gap}` : "0";
  r.fitbar.style.width = `${Math.max(0, (row.fit / (M.routing.base + M.routing.local_bonus)) * 60)}px`;
  r.fitTxt.textContent = row.fit.toFixed(2);
  r.why.textContent = row.notes.join(", ");
}

const QUESTION = {
  security: () => M.security.label + "?", expert: () => "Which expertise does this need?", mode: () => "What should the assistant do?",
  complexity: () => M.complexity.instructions, sensitivity: () => M.sensitivity.instructions,
};
function askTargets(key) {
  if (key === "security") return [ui.secTile];
  if (key.startsWith("chunk_")) return [ui.chunks[Number(key.slice(6))]];
  if (key === "expert" || key === "mode") return [ui[key]._grid];
  if (key === "complexity") return [ui.cx.rl, ...ui.cx.cells];
  if (key === "sensitivity") return [ui.sens.rl, ...ui.sens.cells];
  return [];
}

// ---------------------------------------------------------------- events

function apply(ev) {
  const S = M.security;
  switch (ev.type) {
    case "start":
      trace(ev.t, `start · ${ev.chars.toLocaleString()} chars${ev.cached ? " · CACHED replay, 0 model calls" : ""}`, ev.cached ? "ok" : "");
      break;
    case "gate":
      ui[`gate_${ev.gate}`].classList.add("on");
      trace(ev.t, GATES[ev.gate], "st");
      if (ev.gate === "rules") { activate("rules"); setNow("Gate 0: running rule scanners…"); }
      if (ev.gate === "security") activate("security");
      break;
    case "rules": {
      const t = ui.rules[ev.family];
      const worst = ev.findings.reduce((w, f) => Math.max(w, SEV.indexOf(f.severity)), -1);
      if (worst < 0) { t.classList.add("clean"); t.tv.textContent = "clean"; }
      else { t.classList.add(`sev-${SEV[worst]}`); t.tv.textContent = `${ev.findings.length} · ${SEV[worst]}`; }
      t.title = ev.findings.map((f) => `${f.severity}: ${f.title}`).join("\n") || "no findings";
      trace(ev.t, `rules.${ev.family} → ${worst < 0 ? "clean" : ev.findings.map((f) => f.id).join(", ")}`, worst >= 3 ? "bad" : worst === 2 ? "warn" : "");
      ui.stages.rules.ms.textContent = `${ev.t} ms`;
      break;
    }
    case "hidden": trace(ev.t, `hidden tag text: ${ev.text}`, "bad"); break;
    case "gate_done": {
      const gs = ui[`gate_${ev.gate}`].querySelector(".gstat");
      gs.textContent = `${ev.stopped ? "STOPPED · " : ""}${ev.status} · ${ev.lev_calls} call${ev.lev_calls === 1 ? "" : "s"} · ${ev.ms} ms`;
      ui[`gate_${ev.gate}`].classList.add(ev.stopped ? "stopped" : "passed");
      if (ev.gate === "rules" || ev.gate === "security") done(ev.gate);
      trace(ev.t, `${GATES[ev.gate]} → ${ev.stopped ? "STOP " : ""}${ev.status}`, ev.stopped ? "bad" : "ok");
      break;
    }
    case "gate_skipped":
      for (const [id, gate] of STAGES) if (gate === ev.gate && id !== "decision") skipStage(id, ev.reason);
      ui[`gate_${ev.gate}`].classList.add("skippedgate");
      ui[`gate_${ev.gate}`].querySelector(".gstat").textContent = `skipped · ${ev.reason}`;
      trace(ev.t, `${GATES[ev.gate]} skipped (${ev.reason})`, "warn");
      break;
    case "ask":
      if (["expert", "mode", "complexity", "sensitivity"].includes(ev.key)) activate(ev.key);
      for (const n of askTargets(ev.key)) n.classList.add("asking");
      setNow(`Asking lev: ${ev.key.startsWith("chunk_") ? `sweep chunk ${Number(ev.key.slice(6)) + 1}` : QUESTION[ev.key]()}`);
      break;
    case "answer": {
      for (const n of askTargets(ev.key)) n.classList.remove("asking");
      const a = ev.answer;
      let line = "", cls = "";
      if (ev.key === "security") {
        addLev("security", ev.ms);
        const p = Math.max(a.noul, ui.secMax);          // several questions: the tile shows the highest
        ui.secMax = p;
        ui.secTile.style.setProperty("--p", p.toFixed(3));
        ui.secTile.classList.toggle("win", p >= S.medium);
        ui.secTile.classList.toggle("hot", p >= S.medium);
        ui.secTile.tv.textContent = pct(p) + (p >= S.high ? " · high" : p >= S.medium ? " · medium" : "");
        line = `${ev.label || "security"} → ${pct(a.noul)}`;
        cls = a.noul >= S.high ? "bad" : a.noul >= S.medium ? "warn" : "";
      } else if (ev.key === "expert" || ev.key === "mode") {
        addLev(ev.key, ev.ms);
        applyChoice(ev.key, a);
        line = `${ev.key} → ${(ev.key === "expert" ? M.experts : M.modes)[a.choice].label} ${pct(a.probabilities[a.choice])}`;
        done(ev.key);
      } else {
        addLev(ev.key, ev.ms);
        const row = ev.key === "complexity" ? ui.cx : ui.sens;
        line = `${M[ev.key].label} → ${a.score.toFixed(2)} (${applyLevel(row, a)})`;
        done(ev.key);
      }
      trace(ev.t, `${line}  (${ev.ms} ms)`, cls);
      break;
    }
    case "skip":
      if (ev.key === "chunks") { ui.chunks.forEach((c) => { if (!c.dataset.done) c.classList.add("skipc"); }); trace(ev.t, `chunks: ${ev.reason}`, "ok"); }
      else { skipStage(ev.key, ev.reason); trace(ev.t, `${ev.key} skipped: ${ev.reason}`, "ok"); }
      break;
    case "chunks":
      ui.chunkRow.hidden = false;
      ui.chunks = Array.from({ length: ev.count }, (_, i) => el("span", { class: "c", title: `chunk ${i + 1}` }, String(i + 1)));
      ui.chunkRow.replaceChildren(el("span", { class: "lbl" }, "Long prompt · chunk sweep"), ...ui.chunks);
      trace(ev.t, `chunk sweep · ${ev.count} chunks`, "st");
      break;
    case "chunk": {
      const c = ui.chunks[ev.chunk];
      c.classList.remove("asking");
      c.dataset.done = "1";
      c.style.setProperty("--p", ev.p.toFixed(3));
      addLev("security", ev.ms);
      trace(ev.t, `chunk ${ev.chunk + 1}/${ev.of} → ${pct(ev.p)}  (${ev.ms} ms)`, ev.p >= S.high ? "bad" : ev.p >= S.medium ? "warn" : "");
      break;
    }
    case "verdict": {
      if (ev.score != null) {           // final score = max over head/tail and every swept chunk
        ui.secTile.style.setProperty("--p", ev.score.toFixed(3));
        ui.secTile.classList.toggle("win", ev.score >= S.medium);
        ui.secTile.classList.toggle("hot", ev.score >= S.medium);
        ui.secTile.tv.textContent = pct(ev.score) + (ev.score >= S.high ? " · high" : ev.score >= S.medium ? " · medium" : "")
          + (ui.chunks.length ? " (max of sweep)" : "");
      }
      const why = [];
      if (ev.categories.length) why.push(`flagged: ${ev.categories.join(", ")}`);
      if (ev.secrets) why.push("secrets → must stay local");
      if (ev.pii) why.push("high-risk PII → must stay local");
      ui.gateWhy.replaceChildren(el("span", { class: `pill s-${ev.status}` }, ev.status.toUpperCase()), " ", why.join(" · ") || "no medium-or-higher attack findings");
      trace(ev.t, `verdict → ${ev.status.toUpperCase()}`, ev.status === "block" ? "bad" : ev.status === "review" ? "warn" : "ok");
      break;
    }
    case "agent": {
      activate("agent");
      const tr = ui.agents[ev.id];
      tr.className = "win";
      for (const [id, row] of Object.entries(ui.agents)) if (id !== ev.id) row.className = "muted";
      ui.agentWhy.textContent = `${ev.label} via ${ev.harness} · ${ev.why} · capability axis: ${ev.axis}`;
      tr.querySelectorAll("[data-e],[data-m]").forEach((c) => {
        const e = c.dataset.e, m = c.dataset.m;
        if ((e && ui.expert[e].classList.contains("win")) || (m && ui.mode[m].classList.contains("win"))) c.classList.add("hit");
      });
      done("agent");
      trace(ev.t, `agent → ${ev.label} (${ev.why})`, "ok");
      break;
    }
    case "executors":
      activate("executors");
      ev.rows.forEach(execRow);
      ui.stages.executors.ms.textContent = ev.phase === "privacy" ? "re-scored with sensitivity" : `axis: ${ev.rows[0]?.axis}`;
      ev.rows.forEach((r) => trace(ev.t, `${r.id} → fit ${r.fit}${r.eligible ? "" : " ✗"}`, r.eligible ? "" : "warn"));
      done("executors");
      break;
    case "route": {
      const rt = ev.routing;
      if (rt.decision !== "blocked" && rt.decision !== "unavailable") activate("decision");
      if (rt.model && ui.rows[rt.model]) ui.rows[rt.model].tr.className = "win";
      const head = rt.decision === "blocked" ? "BLOCKED — not sent to any model"
        : rt.model ? `→ ${rt.route.toUpperCase()} · ${rt.agent_label} · ${rt.model_label}` : rt.decision.toUpperCase();
      ui.decision.className = "decision " + (rt.route || rt.decision.split(" ")[0]);
      ui.decision.replaceChildren(head, rt.via ? el("div", { class: "via" }, `run via: ${rt.via}`) : "",
        el("ul", {}, ...(rt.reasons || []).map((x) => el("li", {}, x))));
      if (rt.decision === "blocked") { ui.stages.decision.box.className = "stage done"; }
      else done("decision");
      trace(ev.t, `route → ${rt.model ? rt.route + " · " + rt.model : rt.decision}`, rt.decision === "blocked" ? "bad" : "ok");
      break;
    }
    case "availability": {
      const down = Object.values(ev.status).filter((x) => !x.up);
      trace(ev.t, down.length ? `unavailable: ${down.map((x) => `${x.label} (${x.why})`).join(", ")}` : "all executors' services available", down.length ? "warn" : "");
      break;
    }
    case "error":
      $("err").textContent = ev.error;
      $("err").hidden = false;
      trace(ev.t, `error: ${ev.error}`, "bad");
      break;
    case "result": {
      if (active) done(active);
      const r = ev.result, t = r.timings;
      const cost = r.cached ? "cached, 0 lev calls" : `${t.lev_calls} lev call${t.lev_calls === 1 ? "" : "s"}, ${t.lev_input_tokens.toLocaleString()} tokens, ${t.total_ms} ms`;
      setNow(`Done · ${r.security.status.toUpperCase()} · ${r.agent ? r.agent.label + " → " + (r.routing.model_label || r.routing.decision) : "stopped at " + r.stopped_at} · ${cost}`, false);
      trace(ev.t, `done · ${cost}`, "st");
      routeFeedback(r);
      break;
    }
  }
  if (ev.t != null) $("clock").textContent = `t = +${Math.round(ev.t)} ms`;
}

// ---------------------------------------------------------------- routing feedback (becomes a routing label)

const fb = { text: "", pred: null, label: {} };

function tierOf(r) {
  const d = r.routing?.decision;
  return d === "blocked" ? "blocked" : r.routing?.route === "local" ? "local" : r.routing?.route ? "frontier" : null;
}

function fbButtons() {
  const mk = (group, id, text, on) => {
    const b = el("button", { type: "button", class: "fb", "aria-pressed": String(on) }, text);
    b.addEventListener("click", () => {
      fb.label[group] = id;
      if (group === "tier" && id === "blocked") fb.label.workflow = null;
      fbButtons();
    });
    return b;
  };
  $("rfb-tier").replaceChildren(el("span", { class: "meta-l" }, "Tier:"),
    ...["local", "frontier", "blocked"].map((t) => mk("tier", t, t, fb.label.tier === t)));
  const wfs = Object.entries(M.agents).map(([id, a]) => mk("workflow", id, a.label, fb.label.workflow === id));
  wfs.forEach((b) => { b.disabled = fb.label.tier === "blocked"; });
  $("rfb-wf").replaceChildren(el("span", { class: "meta-l" }, "Workflow:"), ...wfs);
}

function routeFeedback(r) {
  fb.text = $("prompt").value;
  fb.pred = { tier: tierOf(r), workflow: r.agent?.id ?? null };
  fb.label = { ...fb.pred };
  $("rfb").hidden = false;
  $("rfb-msg").textContent = "Prefilled with the router's answer: change what's wrong, then save.";
  $("rfb-note").value = "";
  fbButtons();
}

$("rfb-save").addEventListener("click", async () => {
  try {
    const r = await postJSON("/api/labels", { kind: "routing", text: fb.text, label: fb.label, pred: fb.pred, note: $("rfb-note").value });
    const same = r.label.tier === fb.pred.tier && r.label.workflow === fb.pred.workflow;
    $("rfb-msg").textContent = `Saved ${r.id}: ${r.label.tier}${r.label.workflow ? " · " + r.label.workflow : ""}${same ? " (router was right)" : " (router was wrong)"}.`;
  } catch (e) { $("rfb-msg").textContent = `Not saved: ${e.message}`; }
});

// ---------------------------------------------------------------- streaming + pacing

const PACED = new Set(["rules", "answer", "chunk", "agent", "executors", "verdict", "route", "skip", "gate_skipped", "gate_done"]);

async function walk() {
  const prompt = $("prompt").value;
  if (!prompt.trim()) return;
  controller?.abort();
  controller = new AbortController();
  const my = ++gen;
  $("err").hidden = true;
  buildBoard();
  active = null;
  $("rfb").hidden = true;
  setNow("Connecting…");

  const queue = [];
  let ended = false, wake = null;
  const pump = (async () => {
    for (;;) {
      if (my !== gen) return;
      if (!queue.length) {
        if (ended) return;
        await new Promise((r) => (wake = r));
        continue;
      }
      const ev = queue.shift();
      apply(ev);
      if (PACED.has(ev.type)) await sleep(Number($("pace").value));
    }
  })();

  try {
    const res = await fetch("/api/route/stream", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: prompt }), signal: controller.signal,
    });
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done: fin } = await reader.read();
      if (fin) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (line.trim()) { queue.push(JSON.parse(line)); wake?.(); }
      }
    }
  } catch (e) {
    if (e.name === "AbortError") return;
    $("err").textContent = e.message;
    $("err").hidden = false;
    setNow("Walk failed.", false);
  } finally {
    ended = true;
    wake?.();
  }
  await pump;
}

// ---------------------------------------------------------------- setup

let samples = [];
async function init() {
  M = await (await fetch("/api/router/config")).json();
  buildBoard();
  try { samples = await (await fetch("/api/samples")).json(); } catch { samples = []; }
  const groups = {};
  samples.forEach((s, i) => { if (s.boundary === "prompt") (groups[s.expect] ??= []).push([s, i]); });
  for (const [g, list] of Object.entries(groups)) {
    const og = el("optgroup", { label: `expected: ${g}` });
    for (const [s, i] of list) og.append(el("option", { value: String(i) }, s.name));
    $("samples").append(og);
  }
}

function count() { charCount($("prompt"), $("count")); }

$("run").addEventListener("click", walk);
$("prompt").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); walk(); } });
$("prompt").addEventListener("input", count);
$("samples").addEventListener("change", (e) => {
  const s = samples[Number(e.target.value)];
  if (s) { $("prompt").value = s.prompt; count(); walk(); }
  e.target.value = "";
});
init();
