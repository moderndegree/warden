// Classify page. Uses helpers from common.js.
"use strict";

function updateCli() {
  const flags = ($("sens").checked ? " --sensitivity" : "") + ($("guard").checked ? " --guard" : "");
  $("cli").textContent = `CLI: echo "…" | warden classify --brief${flags}`;
  charCount($("text"), $("count"));
}

function bars(box, probs) {
  box.replaceChildren(...Object.entries(probs).sort((a, b) => b[1] - a[1])
    .map(([k, p], i) => bar(k, p, i === 0 ? (p >= 0.6 ? "ok" : "warn") : "")));
}

function render(r) {
  $("out").hidden = false;
  const stopped = r.stopped || r.error;
  $("expert").textContent = r.expert ? `${r.expert.label} · ${pct(r.expert.p)}` : "—";
  $("mode").textContent = r.mode ? `${r.mode.label} · ${pct(r.mode.p)}` : "—";
  $("workflow").textContent = r.workflow ? r.workflow.label : r.stopped ? "stopped by guard" : "—";
  $("why").textContent = r.workflow ? `${r.workflow.id}: ${r.workflow.why}` : r.error || "";
  $("cost").textContent = `${r.lev.calls} lev calls · ${r.lev.tokens.toLocaleString()} tok · ${r.ms} ms`;
  if (r.expert) bars($("expert-bars"), r.expert.probabilities); else $("expert-bars").replaceChildren();
  if (r.mode) bars($("mode-bars"), r.mode.probabilities); else $("mode-bars").replaceChildren();
  const extra = [];
  if (r.security) extra.push(el("p", {}, el("b", {}, `Guard: ${r.security.verdict}`), ` → ${r.security.action}`,
    r.security.findings.length ? el("div", { class: "detail" }, r.security.findings.join(", ")) : ""));
  if (r.sensitivity) extra.push(el("p", {}, el("b", {}, `Sensitivity ${r.sensitivity.score.toFixed(1)} / ${r.sensitivity.max}`),
    el("div", { class: "detail" }, r.sensitivity.level_text)));
  if (!extra.length) extra.push(el("p", { class: "empty" }, "Not asked."));
  $("extra").replaceChildren(...extra);
  $("err").hidden = !stopped || !r.error;
  if (r.error) $("err").textContent = r.error;
  $("raw").textContent = JSON.stringify(r, null, 2);
}

async function run() {
  const text = $("text").value;
  if (!text.trim()) return;
  $("run").disabled = true;
  $("err").hidden = true;
  try {
    render(await postJSON("/api/classify", { text, sensitivity: $("sens").checked, guard: $("guard").checked }));
  } catch (e) {
    $("err").textContent = e.message;
    $("err").hidden = false;
  } finally {
    $("run").disabled = false;
  }
}

for (const id of ["sens", "guard"]) $(id).addEventListener("change", updateCli);
$("text").addEventListener("input", updateCli);
$("run").addEventListener("click", run);
document.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
updateCli();
