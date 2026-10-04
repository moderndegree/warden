// Decide page. Uses helpers from common.js.
"use strict";

const PRESETS = [
  { name: "Inbox triage (yes/no)", kind: "yes_no", question: "Does this email require the user to take an action?",
    items: ["Your invoice #4411 is due Friday, please pay by bank transfer", "Weekly newsletter: 10 tips for better sleep",
      "Can you review my PR before 3pm today?", "Your package was delivered to the front porch",
      "Reminder: dentist appointment tomorrow at 9am, reply C to confirm"] },
  { name: "Issue type (choice)", kind: "choice", question: "What kind of GitHub issue is this?",
    options: "bug = a defect, crash, or wrong behavior\nfeature = a request for new functionality\nquestion = a usage or how-to question\ndocs = a documentation problem",
    items: ["App crashes when I click save on an empty file", "Please add a dark mode", "How do I install this on Windows?",
      "The README links to a page that no longer exists", "Export to CSV puts dates in the wrong column"] },
  { name: "Urgency (score)", kind: "score", question: "How urgent is this?",
    options: "not urgent\nthis month\nthis week\ntoday\nright now",
    items: ["Production database is down for all customers", "Typo in the footer of the docs site",
      "Security certificate expires in 3 days", "Customer asks for a feature next quarter"] },
  { name: "Search results relevant? (yes/no)", kind: "yes_no", question: "Is this result relevant to the query?",
    context: "Query: how to enable Vulkan in llama.cpp on AMD",
    items: ["Building llama.cpp with -DGGML_VULKAN=ON on Linux with RADV", "Best pizza dough recipes for home ovens",
      "llama.cpp ROCm vs Vulkan performance on Strix Halo", "Installing Vulkan SDK on Windows for game development"] },
];

function kindUI() {
  const k = $("kind").value;
  $("options").disabled = k === "yes_no";
  $("options-label").firstChild.textContent = k === "score" ? "Levels " : "Options ";
  $("options-label").querySelector(".hint").textContent = k === "score" ? "one per line, lowest first" : k === "choice" ? "one per line: id = description" : "not used for yes/no";
  updateCli();
}

function parsed() {
  const k = $("kind").value;
  const lines = $("options").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const items = $("items").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const body = { question: $("question").value.trim(), kind: k, items, context: $("context").value.trim() || null };
  if (k === "choice") body.options = Object.fromEntries(lines.map((l) => { const i = l.indexOf("="); return i < 0 ? [l, l] : [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));
  if (k === "score") body.levels = lines;
  return body;
}

function updateCli() {
  const b = parsed();
  const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
  let cmd = `warden decide --brief -k ${b.kind} -q ${q(b.question || "…")}`;
  if (b.options) cmd += Object.entries(b.options).map(([k, v]) => ` -o ${q(`${k}=${v}`)}`).join("");
  if (b.levels) cmd += b.levels.map((l) => ` -l ${q(l)}`).join("");
  if (b.context) cmd += ` -c ${q(b.context)}`;
  $("cli").textContent = `CLI: … one item per line | ${cmd}`;
  $("count").textContent = `${b.items.length} item${b.items.length === 1 ? "" : "s"}`;
}

function render(r, items) {
  $("out").hidden = false;
  $("n").textContent = `${r.results.length}${r.complete ? "" : ` of ${items.length}`}`;
  $("cost").textContent = `${r.lev.calls} calls · ${r.lev.tokens.toLocaleString()} tok · ${r.ms} ms`;
  $("per").textContent = r.results.length ? `${Math.round(r.lev.ms / r.results.length)} ms · ${Math.round(r.lev.tokens / r.results.length)} tok` : "—";
  $("results").tBodies[0].replaceChildren(...r.results.map((x) => {
    const p = x.p ?? Math.max(...Object.values(x.probabilities));
    const ans = r.kind === "yes_no" ? el("span", { class: x.answer ? "yes" : "no" }, x.answer ? "yes" : "no")
      : r.kind === "score" ? el("span", {}, `${x.answer.toFixed(2)} · ${parsed().levels[x.level] ?? x.level}`)
      : el("b", {}, x.answer);
    const conf = r.kind === "yes_no" ? (x.answer ? x.p : 1 - x.p) : p;
    return el("tr", {}, el("td", { class: "n" }, String(x.index + 1)),
      el("td", {}, items[x.index].length > 140 ? items[x.index].slice(0, 140) + "…" : items[x.index], x.truncated ? el("div", { class: "detail" }, "truncated to fit lev") : ""),
      el("td", {}, ans), el("td", { class: "conf" }, bar("", conf, conf >= 0.8 ? "ok" : conf >= 0.6 ? "warn" : "bad")));
  }));
  if (!r.complete) { $("err").textContent = `Incomplete: ${r.error}`; $("err").hidden = false; }
  $("raw").textContent = JSON.stringify(r, null, 2);
}

async function run() {
  const body = parsed();
  $("run").disabled = true;
  $("err").hidden = true;
  try {
    render(await postJSON("/api/decide", body), body.items);
  } catch (e) {
    $("err").textContent = e.message;
    $("err").hidden = false;
  } finally {
    $("run").disabled = false;
  }
}

PRESETS.forEach((p, i) => $("preset").append(el("option", { value: String(i) }, p.name)));
$("preset").addEventListener("change", (e) => {
  const p = PRESETS[Number(e.target.value)];
  if (!p) return;
  $("kind").value = p.kind; $("question").value = p.question; $("options").value = p.options || "";
  $("context").value = p.context || ""; $("items").value = p.items.join("\n");
  e.target.value = "";
  kindUI();
  run();
});
for (const id of ["question", "options", "context", "items"]) $(id).addEventListener("input", updateCli);
$("kind").addEventListener("change", kindUI);
$("run").addEventListener("click", run);
document.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
kindUI();
