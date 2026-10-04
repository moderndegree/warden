// Shared helpers for the test bed pages. Rendering goes through textContent / createElement only.
"use strict";

const $ = (id) => document.getElementById(id);
const pct = (p) => `${Math.round(p * 100)}%`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const k of kids) n.append(k instanceof Node ? k : document.createTextNode(String(k ?? "")));
  return n;
}

function bar(name, p, tone = "") {
  const fill = el("span", { class: `fill ${tone}` });
  fill.style.width = `${Math.max(2, p * 100)}%`;
  return el("div", { class: "bar" },
    el("span", { class: "name", title: name }, name), el("span", { class: "track" }, fill), el("span", { class: "num" }, pct(p)));
}

async function postJSON(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function nav() {
  const n = document.querySelector("nav.nav");
  if (!n) return;
  const page = n.dataset.page;
  for (const [id, href, label] of [["guard", "/", "Guard"], ["classify", "/classify.html", "Classify"], ["decide", "/decide.html", "Decide"], ["router", "/walk.html", "Router (experimental)"], ["labels", "/labels.html", "Labels"]]) {
    const a = el("a", { href }, label);
    if (id === page) a.setAttribute("aria-current", "page");
    n.append(a);
  }
}

async function health() {
  const s = $("status");
  if (!s) return;
  try {
    const r = await (await fetch("/api/health")).json();
    s.className = "status " + (r.decision_model_up ? "up" : "down");
    $("status-text").textContent = `warden ${r.warden} · ${r.decision_model} ${r.decision_model_up ? "online" : "offline (rules only)"}`;
  } catch {
    s.className = "status down";
    $("status-text").textContent = "server unreachable";
  }
}

function findingsTable(table, empty, findings) {
  empty.hidden = findings.length > 0;
  table.hidden = findings.length === 0;
  table.tBodies[0].replaceChildren(...findings.map((x) => el("tr", {},
    el("td", {}, el("span", { class: `sev sev-${x.severity}` }, x.severity)),
    el("td", {}, el("div", {}, x.title), x.detail ? el("div", { class: "detail" }, x.detail) : ""),
    el("td", {}, el("span", { class: "src" }, x.source)),
    el("td", {}, x.evidence ? el("code", {}, x.evidence) : ""))));
}

function charCount(input, out) {
  const n = input.value.length;
  out.textContent = `${n.toLocaleString()} chars · ~${Math.round(n / 3.5).toLocaleString()} tok`;
}

nav();
health();
