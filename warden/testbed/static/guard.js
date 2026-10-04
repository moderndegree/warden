// Guard page. Uses helpers from common.js.
"use strict";

const BOUNDARY_DESC = {
  prompt: "What a person sends an agent (typed, pasted, voice, Discord). All rules, then lev: manipulation, then extraction.",
  content: "Untrusted text an agent is about to read: web pages, email, files, tool output. Injection rules, then lev: instructions aimed at an AI (in 700-char windows and hidden markup), then manipulation. Fails closed to review if lev is down.",
  outbound: "Text about to leave this machine for a cloud model. Secrets, personal data and high-entropy tokens are redacted; no model call.",
};
const ACTION_DESC = {
  proceed: "no signal; run normally", confirm_restricted: "ask the person, then run without tools or auto-approve",
  refuse: "don't let it reach a model", pass: "no signal; the agent may read it",
  pass_flagged: "let the agent read it, wrapped in a warning", quarantine: "don't let it into the agent's context",
  send: "nothing to remove", send_redacted: "send the redacted text, never the original",
};

let boundary = "prompt", last = null, samples = [];

function setBoundary(b) {
  boundary = b;
  for (const btn of $("boundary").querySelectorAll("button")) btn.setAttribute("aria-checked", String(btn.dataset.b === b));
  $("b-desc").textContent = BOUNDARY_DESC[b];
  $("nolev").disabled = b === "outbound";
  updateCli();
}

function updateCli() {
  $("cli").textContent = `CLI: … | warden scan -b ${boundary}${$("nolev").checked && boundary !== "outbound" ? " --no-lev" : ""} --brief`
    + (boundary === "outbound" ? "    or: … | warden redact" : "");
}

function render(r) {
  last = r;
  $("out").hidden = false;
  $("verdict").replaceChildren(el("span", { class: `pill s-${r.verdict}` }, r.verdict.toUpperCase()));
  $("action").textContent = r.action.replace(/_/g, " ");
  $("action-desc").textContent = ACTION_DESC[r.action] || "";
  const per = Object.entries(r.scores || {}).map(([q, p]) => `${q} ${pct(p)}`).join(" · ");
  $("score").title = per;
  $("score").textContent = r.score == null ? (r.boundary === "outbound" ? "not asked" : r.stopped_at === "rules" ? "skipped" : "—") : pct(r.score);
  $("cost").textContent = r.cached ? "cached · 0 lev calls"
    : `${r.lev.calls} lev call${r.lev.calls === 1 ? "" : "s"} · ${r.lev.tokens.toLocaleString()} tok · ${r.ms} ms` + (r.degraded ? " · DEGRADED (lev down, rules only)" : "");

  const names = { rules: "Gate 0 · Rules", security: "Gate 1 · lev" };
  const ran = Object.fromEntries(r.gates.map((g) => [g.gate, g]));
  const wanted = r.boundary === "outbound" || $("nolev").checked ? ["rules"] : ["rules", "security"];
  $("gates").replaceChildren(...wanted.map((id) => {
    const g = ran[id];
    if (!g) return el("div", { class: "gatecard skipped" }, el("b", {}, names[id]), el("span", {}, r.stopped_at ? `skipped · stopped at ${r.stopped_at}` : "not run"));
    return el("div", { class: `gatecard g-${g.status}` + (g.stopped ? " stopped" : "") }, el("b", {}, names[id]),
      el("span", {}, `${g.stopped ? "STOPPED · " : ""}${g.status}`),
      el("span", { class: "num" }, `${g.lev_calls} call${g.lev_calls === 1 ? "" : "s"} · ${g.ms} ms`));
  }));
  if (r.boundary === "outbound") $("gates").append(el("div", { class: "gatecard skipped" }, el("b", {}, "Gate 1 · lev"), el("span", {}, "not used at this boundary")));

  $("hidden-text").hidden = !r.hidden_text;
  $("hidden-code").textContent = r.hidden_text || "";

  $("redacted-card").hidden = r.redacted == null;
  $("redacted").textContent = r.redacted ?? "";
  const rc = Object.entries(r.redactions || {});
  $("redactions").textContent = rc.length ? rc.map(([k, n]) => `${n} × ${k}`).join(" · ") : "nothing removed";

  $("find-count").textContent = r.findings.length ? String(r.findings.length) : "";
  findingsTable($("findings"), $("no-findings"), r.findings);
  $("fb-msg").textContent = "Labels are saved locally (text included) and become eval cases for `warden eval`.";
  $("raw").textContent = JSON.stringify(r, null, 2);
}

async function run() {
  const text = $("text").value;
  if (!text.trim()) return;
  $("run").disabled = true;
  $("err").hidden = true;
  try {
    render(await postJSON("/api/guard", { text, boundary, no_lev: $("nolev").checked }));
  } catch (e) {
    $("err").textContent = e.message;
    $("err").hidden = false;
  } finally {
    $("run").disabled = false;
  }
}

async function sendFeedback(x) {
  if (!last) return;
  const expected = x === "same" ? last.verdict : x;
  try {
    const r = await postJSON("/api/feedback", {
      boundary: last.boundary, text: $("text").value, got: last.verdict, expected, score: last.score,
      findings: last.findings.map((f) => f.id), note: $("fb-note").value,
    });
    $("fb-msg").textContent = r.correct ? `Saved: ${last.verdict} confirmed correct.` : `Saved: got ${last.verdict}, should be ${expected}.`;
    $("fb-note").value = "";
    stats(r.stats);
  } catch (e) {
    $("fb-msg").textContent = `Not saved: ${e.message}`;
  }
}

function stats(s) {
  $("fb-stats").textContent = s.total ? `${s.total} labelled · ${s.correct} correct` : "no labels yet";
}

async function init() {
  setBoundary("prompt");
  try { stats(await (await fetch("/api/feedback/stats")).json()); } catch { /* optional */ }
  try { samples = await (await fetch("/api/samples")).json(); } catch { samples = []; }
  for (const b of ["prompt", "content", "outbound"]) {
    const og = el("optgroup", { label: b });
    samples.forEach((s, i) => { if (s.boundary === b) og.append(el("option", { value: String(i) }, `${s.name} (expect ${s.expect})`)); });
    $("samples").append(og);
  }
}

$("boundary").addEventListener("click", (e) => { const b = e.target.closest("button")?.dataset.b; if (b) setBoundary(b); });
$("run").addEventListener("click", run);
$("nolev").addEventListener("change", updateCli);
$("text").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
$("text").addEventListener("input", () => charCount($("text"), $("count")));
$("samples").addEventListener("change", (e) => {
  const s = samples[Number(e.target.value)];
  if (s) { setBoundary(s.boundary); $("text").value = s.prompt; charCount($("text"), $("count")); run(); }
  e.target.value = "";
});
document.querySelector(".feedback").addEventListener("click", (e) => { const x = e.target.closest(".fb")?.dataset.x; if (x) sendFeedback(x); });
$("copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("redacted").textContent); $("copy").textContent = "Copied"; }
  catch { $("copy").textContent = "Copy failed"; }
  setTimeout(() => { $("copy").textContent = "Copy redacted"; }, 1500);
});
init();
