"use strict";

const SEVERITIES = ["critical", "high", "medium", "low"];
const VERDICTS = ["confirmed", "benign", "unsure", "unavailable", "not judged"];
const SEV_VAR = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };

const state = {
  summary: null,
  findings: [],
  filters: { severity: "", category: "", source: "", project: "", verdict: "", q: "" },
  expanded: null,
  job: null,
  seenVerdicts: new Set(),
  fresh: new Set(),
};

const $ = (id) => document.getElementById(id);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmtInt = (n) => n.toLocaleString();
const fmtPct = (x) => (x === null || x === undefined ? "–" : (x * 100).toFixed(0) + "%");
const asDate = (iso) => new Date(iso + (iso.endsWith("Z") ? "" : "Z"));

function relTime(iso) {
  if (!iso) return "never";
  const s = (Date.now() - asDate(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = asDate(iso);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
}
function fmtDay(iso) {
  if (!iso) return "";
  return asDate(iso).toLocaleDateString(undefined, { month: "short", day: "2-digit" });
}

// ---------- tooltip / toast ----------
const tip = $("tooltip");
function showTip(evt, title, lines) {
  tip.replaceChildren(h("strong", {}, title), ...lines.map((l) => h("div", {}, l)));
  tip.hidden = false;
  moveTip(evt);
}
function moveTip(evt) {
  const pad = 14;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  const r = tip.getBoundingClientRect();
  if (x + r.width > window.innerWidth - 8) x = evt.clientX - r.width - pad;
  if (y + r.height > window.innerHeight - 8) y = evt.clientY - r.height - pad;
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}
function hideTip() { tip.hidden = true; }

let toastTimer = null;
function toast(msg, ms = 4000) {
  const el = $("toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), ms);
}

function setLive(mode, text) {
  const dot = $("live-dot");
  dot.className = "live-dot" + (mode === "busy" ? " busy" : mode === "down" ? " down" : "");
  $("live-text").textContent = text;
}

// ---------- data ----------
async function api(path, opts = {}) {
  if (opts.method === "POST") opts.headers = { ...(opts.headers || {}), "X-Requested-With": "claudit" };
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

async function load() {
  try {
    const [summary, findings] = await Promise.all([api("/api/summary"), api("/api/findings")]);
    state.fresh = new Set(findings.filter((f) => f.verdict && !state.seenVerdicts.has(f.id)).map((f) => f.id));
    if (state.seenVerdicts.size === 0) state.fresh.clear();
    for (const f of findings) if (f.verdict) state.seenVerdicts.add(f.id);
    state.summary = summary;
    state.findings = findings;
    if (!state.job) setLive("ok", "live");
    render();
  } catch (err) {
    setLive("down", "offline");
    throw err;
  }
}

function filtered() {
  const f = state.filters;
  const q = f.q.trim().toLowerCase();
  return state.findings.filter((x) =>
    (!f.severity || x.severity === f.severity) &&
    (!f.category || x.category === f.category) &&
    (!f.source || x.source === f.source) &&
    (!f.project || x.project === f.project) &&
    (!f.verdict || (x.verdict || "not judged") === f.verdict) &&
    (!q || (x.preview || "").toLowerCase().includes(q) || (x.project || "").toLowerCase().includes(q))
  );
}

function countBy(rows, key) {
  const m = new Map();
  for (const r of rows) m.set(r[key], (m.get(r[key]) || 0) + 1);
  return m;
}

// ---------- render ----------
function render() {
  renderHeader();
  renderFilterOptions();
  const rows = filtered();
  renderHero(rows);
  renderCharts(rows);
  renderFeed(rows);
  renderSemantic();
  renderEval();
}

function renderHeader() {
  const s = state.summary;
  const badge = $("mode-badge");
  badge.textContent = s.demo ? "demo · synthetic" : "local · your transcripts";
  badge.classList.toggle("demo", s.demo);
  $("meta").replaceChildren(
    h("span", {}, "db ", s.db),
    h("span", {}, "src ", s.transcripts_dir),
    h("span", {}, "model ", s.model),
    h("span", {}, "scan ", relTime(s.last_scan)),
  );
  $("btn-synth").hidden = !s.demo;
}

function fillSelect(id, values, current) {
  const sel = $(id);
  const first = sel.options[0];
  sel.replaceChildren(first, ...values.map((v) => h("option", { value: v }, v)));
  sel.value = values.includes(current) ? current : "";
}

function renderFilterOptions() {
  const all = state.findings;
  const uniq = (key) => [...new Set(all.map((x) => x[key]).filter(Boolean))].sort();
  fillSelect("f-severity", SEVERITIES.filter((s) => all.some((x) => x.severity === s)), state.filters.severity);
  fillSelect("f-category", uniq("category"), state.filters.category);
  fillSelect("f-source", uniq("source"), state.filters.source);
  fillSelect("f-project", uniq("project"), state.filters.project);
  fillSelect("f-verdict", VERDICTS.filter((v) => all.some((x) => (x.verdict || "not judged") === v)), state.filters.verdict);
}

function renderHero(rows) {
  const t = state.summary.totals;
  const filtering = rows.length !== state.findings.length;
  const sessions = new Set(rows.map((r) => r.session)).size;
  const critHigh = rows.filter((r) => r.severity === "critical" || r.severity === "high").length;
  const judged = rows.filter((r) => r.verdict).length;
  const confirmed = rows.filter((r) => r.verdict === "confirmed").length;
  const benign = rows.filter((r) => r.verdict === "benign").length;

  $("hero-num").textContent = fmtInt(rows.length);
  $("hero-sub").textContent = filtering
    ? `findings matching filters · ${fmtInt(state.findings.length)} total`
    : `findings across ${fmtInt(t.sessions)} sessions · ${fmtInt(t.events)} events scanned`;

  const bySev = countBy(rows, "severity");
  const bar = $("sevbar");
  bar.replaceChildren();
  const total = rows.length || 1;
  for (const s of SEVERITIES) {
    const n = bySev.get(s) || 0;
    if (!n) continue;
    const seg = h("div", { class: "seg", style: `width:${Math.max(1.5, (n / total) * 100)}%; background:${cssVar(SEV_VAR[s])}` });
    seg.addEventListener("pointermove", (e) => showTip(e, `${n} ${s}`, [`${Math.round((n / total) * 100)}% of ${rows.length}`]));
    seg.addEventListener("pointerleave", hideTip);
    bar.append(seg);
  }
  if (!rows.length) bar.append(h("div", { class: "empty" }, "no findings in this view"));
  $("sevlegend").replaceChildren(
    ...SEVERITIES.map((s) => h("span", { class: "sev-" + s }, h("span", { class: "tag" }, s), h("b", {}, fmtInt(bySev.get(s) || 0))))
  );

  const stats = [
    ["critical + high", fmtInt(critHigh), rows.length ? `${Math.round((critHigh / rows.length) * 100)}% of view` : "—"],
    ["sessions affected", `${fmtInt(sessions)}`, `of ${fmtInt(t.sessions)} scanned`],
    ["model reviewed", judged ? fmtInt(judged) : "—", judged ? `${confirmed} confirmed · ${benign} benign` : "run judge"],
    ["last scan", relTime(state.summary.last_scan), state.summary.last_scan ? asDate(state.summary.last_scan).toLocaleString() : "—"],
  ];
  $("hero-stats").replaceChildren(
    ...stats.map(([k, v, s]) => h("div", { class: "stat" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "s" }, s)))
  );
}

// Horizontal bars: one series, value at the tip, hover tooltip on a hit area larger than the mark.
function hbars(container, items, { total }) {
  container.replaceChildren();
  if (!items.length) { container.append(h("div", { class: "empty" }, "no findings in this view")); return; }
  const W = Math.max(280, container.clientWidth || 420);
  const labelW = Math.min(170, Math.max(80, ...items.map((i) => i.label.length * 6.8)));
  const rowH = 26, barH = 14, padR = 44;
  const H = items.length * rowH + 4;
  const max = Math.max(...items.map((i) => i.value));
  const scale = (v) => (max ? (v / max) * (W - labelW - padR) : 0);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img" });
  const color = cssVar("--series");
  items.forEach((it, i) => {
    const y = i * rowH + 4;
    const w = scale(it.value);
    const x0 = labelW;
    svg.append(svgEl("line", { class: "axis", x1: x0, x2: x0, y1: y - 2, y2: y + barH + 2 }));
    const label = svgEl("text", { x: x0 - 10, y: y + barH / 2 + 4, "text-anchor": "end" });
    label.textContent = it.label;
    svg.append(label);
    const r = Math.min(3, w / 2);
    const path = svgEl("path", {
      class: "mark", fill: color,
      d: `M${x0},${y} H${x0 + w - r} a${r},${r} 0 0 1 ${r},${r} V${y + barH - r} a${r},${r} 0 0 1 -${r},${r} H${x0} Z`,
    });
    const hit = svgEl("rect", { class: "hit", x: 0, y: y - 6, width: W, height: rowH, tabindex: 0 });
    const lines = [`${it.value} finding${it.value === 1 ? "" : "s"}`];
    if (total) lines.push(`${Math.round((it.value / total) * 100)}% of ${total}`);
    hit.addEventListener("pointermove", (e) => showTip(e, it.label, lines));
    hit.addEventListener("pointerleave", hideTip);
    hit.addEventListener("blur", hideTip);
    svg.append(hit, path);
    const val = svgEl("text", { x: x0 + w + 8, y: y + barH / 2 + 4, class: "tick" });
    val.textContent = fmtInt(it.value);
    svg.append(val);
  });
  container.append(svg);
}

// Columns per day: single series, clean y ticks, sparse x labels, per-column tooltip.
function columns(container, points) {
  container.replaceChildren();
  if (!points.length) { container.append(h("div", { class: "empty" }, "no findings in this view")); return; }
  const W = Math.max(280, container.clientWidth || 420), H = 170;
  const padL = 30, padR = 6, padT = 8, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = Math.max(1, ...points.map((p) => p.value));
  const step = niceStep(max);
  const yMax = Math.ceil(max / step) * step;
  const slot = plotW / points.length;
  const barW = Math.min(20, Math.max(3, slot - 2));
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img" });
  for (let v = 0; v <= yMax; v += step) {
    const y = padT + plotH - (v / yMax) * plotH;
    svg.append(svgEl("line", { class: v === 0 ? "axis" : "grid-line", x1: padL, x2: W - padR, y1: y, y2: y }));
    const t = svgEl("text", { class: "tick", x: padL - 8, y: y + 4, "text-anchor": "end" });
    t.textContent = fmtInt(v);
    svg.append(t);
  }
  const labelEvery = Math.max(1, Math.ceil(points.length / 5));
  const color = cssVar("--series");
  points.forEach((p, i) => {
    const x = padL + i * slot + (slot - barW) / 2;
    const hgt = (p.value / yMax) * plotH;
    const y = padT + plotH - hgt;
    const r = Math.min(3, barW / 2, hgt);
    if (p.value > 0) {
      svg.append(svgEl("path", {
        class: "mark", fill: color,
        d: `M${x},${padT + plotH} V${y + r} a${r},${r} 0 0 1 ${r},-${r} H${x + barW - r} a${r},${r} 0 0 1 ${r},${r} V${padT + plotH} Z`,
      }));
    }
    const hit = svgEl("rect", { class: "hit", x: padL + i * slot, y: padT, width: slot, height: plotH, tabindex: 0 });
    hit.addEventListener("pointermove", (e) => showTip(e, `${p.value} finding${p.value === 1 ? "" : "s"}`, [p.label]));
    hit.addEventListener("pointerleave", hideTip);
    svg.append(hit);
    if (i % labelEvery === 0 || i === points.length - 1) {
      const t = svgEl("text", { class: "tick", x: x + barW / 2, y: H - 8, "text-anchor": "middle" });
      t.textContent = p.short;
      svg.append(t);
    }
  });
  container.append(svg);
}

function niceStep(max) {
  const raw = max / 4;
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const m of [1, 2, 5, 10]) if (m * pow >= raw) return m * pow;
  return 10 * pow;
}

function renderCharts(rows) {
  const total = rows.length;
  const byCat = [...countBy(rows, "category")].sort((a, b) => b[1] - a[1]);
  hbars($("c-category"), byCat.map(([k, v]) => ({ label: k, value: v })), { total });
  const bySrc = [...countBy(rows, "source")].sort((a, b) => b[1] - a[1]);
  hbars($("c-source"), bySrc.map(([k, v]) => ({ label: k, value: v })), { total });

  const days = new Map();
  for (const r of rows) if (r.ts) { const d = r.ts.slice(0, 10); days.set(d, (days.get(d) || 0) + 1); }
  const keys = [...days.keys()].sort();
  const points = [];
  if (keys.length) {
    const start = new Date(keys[0] + "T00:00:00Z"), end = new Date(keys[keys.length - 1] + "T00:00:00Z");
    for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
      const k = d.toISOString().slice(0, 10);
      points.push({ label: k, short: k.slice(5), value: days.get(k) || 0 });
    }
  }
  columns($("c-timeline"), points);
}

function shortProject(p) {
  if (!p) return "";
  const parts = p.split("/").filter(Boolean);
  return parts.length > 2 ? "…/" + parts.slice(-2).join("/") : p;
}

function renderFeed(rows) {
  const LIMIT = 400;
  const feed = $("feed");
  $("table-count").textContent = rows.length > LIMIT ? `${LIMIT} of ${fmtInt(rows.length)}` : `${fmtInt(rows.length)} rows`;
  if (!rows.length) { feed.replaceChildren(h("div", { class: "empty" }, "no findings in this view")); return; }
  const out = [];
  for (const r of rows.slice(0, LIMIT)) {
    const verdict = r.verdict
      ? h("span", { class: "pill " + r.verdict + (state.fresh.has(r.id) ? " fresh" : "") }, r.verdict)
      : h("span", { class: "muted" }, "—");
    const row = h("div", { class: "row", role: "button", tabindex: 0,
      onclick: () => { state.expanded = state.expanded === r.id ? null : r.id; renderFeed(filtered()); } },
      h("span", { class: "t", title: r.ts ? asDate(r.ts).toLocaleString() : "" }, `${fmtDay(r.ts)} ${fmtTime(r.ts)}`),
      h("span", { class: "tag sev-" + r.severity }, r.severity === "critical" ? "crit" : r.severity === "medium" ? "med" : r.severity),
      h("span", { class: "cat", title: r.category }, r.category),
      h("span", { class: "prev", title: r.preview }, r.preview),
      h("span", { class: "src", title: r.path || "" }, r.source),
      h("span", { class: "proj", title: r.path ? `${r.project}\n${r.path}` : r.project }, r.path ? shortProject(r.path) : shortProject(r.project)),
      h("span", {}, verdict),
    );
    out.push(row);
    if (state.expanded === r.id) {
      out.push(h("div", { class: "detail" },
        h("div", {}, h("b", {}, "finding "), h("span", { class: "mono" }, r.id), "  ·  session ", h("span", { class: "mono" }, r.session || "")),
        h("div", {}, h("b", {}, "project "), h("span", { class: "mono" }, r.project || ""), r.path ? ["  ·  ", h("b", {}, "file "), h("span", { class: "mono" }, r.path)] : null),
        r.verdict
          ? h("div", {}, h("b", {}, `${r.judged_by === "rules" ? "rule" : "model"}: ${r.verdict}`), " — ", r.reason || "")
          : h("div", { class: "muted" }, "not yet reviewed"),
        h("div", { class: "muted mono" }, `raw value, locally: claudit reveal ${r.id}`),
      ));
    }
  }
  feed.replaceChildren(...out);
}

function renderSemantic() {
  const items = state.summary.semantic || [];
  $("semantic-card").hidden = !items.length;
  $("semantic").querySelector("tbody").replaceChildren(
    ...items.map((x) => h("tr", {},
      h("td", {}, `${fmtDay(x.ts)} ${fmtTime(x.ts)}`), h("td", {}, x.kind),
      h("td", {}, h("span", { class: "tag sev-" + x.severity }, x.severity)),
      h("td", { style: "white-space: normal; font-family: var(--sans)" }, x.summary), h("td", { title: x.project }, shortProject(x.project))))
  );
}

function renderEval() {
  const e = state.summary.evaluation;
  $("eval-card").hidden = !e;
  if (!e) return;
  $("eval-sub").textContent = `${e.plants} planted secrets in ${e.sessions} synthetic sessions`;
  const rows = [...e.per_category, e.overall];
  $("eval-detect").querySelector("tbody").replaceChildren(
    ...rows.map((r) => h("tr", { class: r.category === "ALL" ? "total" : "" },
      h("td", {}, r.category), h("td", { class: "num" }, r.tp), h("td", { class: "num" }, r.fp), h("td", { class: "num" }, r.fn),
      h("td", { class: "num" }, fmtPct(r.precision)), h("td", { class: "num" }, fmtPct(r.recall)), h("td", { class: "num" }, fmtPct(r.f1))))
  );
  const j = e.judge;
  $("eval-judge-wrap").hidden = !j;
  if (j) {
    $("eval-acc").textContent = j.accuracy === null ? "" : `accuracy ${fmtPct(j.accuracy)} over ${j.judged} judged`;
    $("eval-judge").querySelector("tbody").replaceChildren(
      ...j.rows.map((r) => h("tr", {}, h("td", {}, r.expected), ...VERDICTS.map((v) => h("td", { class: "num" }, r[v]))))
    );
  }
}

// ---------- actions ----------
async function runScan() {
  const btn = $("btn-scan");
  btn.disabled = true;
  setLive("busy", "scanning");
  try {
    const s = await api("/api/scan", { method: "POST" });
    toast(s.lines ? `scanned ${fmtInt(s.lines)} new lines · ${fmtInt(s.findings)} new findings` : "nothing new since last scan");
    await load();
  } catch (err) {
    toast("scan failed: " + err.message, 6000);
  } finally {
    btn.disabled = false;
    if (!state.job) setLive("ok", "live");
  }
}

async function runJudge() {
  const btn = $("btn-judge");
  btn.disabled = true;
  const semantic = $("opt-semantic").checked;
  try {
    const { job } = await api(`/api/judge?semantic=${semantic}`, { method: "POST" });
    state.job = job;
    setLive("busy", "judging");
    $("job").hidden = false;
    $("job-status").textContent = "starting";
    $("job-log").textContent = "";
    pollJob();
  } catch (err) {
    toast("could not start judge: " + err.message, 6000);
    btn.disabled = false;
  }
}

async function pollJob() {
  const j = await api(`/api/jobs/${state.job}`);
  const log = $("job-log");
  log.textContent = j.log.slice(-60).join("\n");
  log.scrollTop = log.scrollHeight;
  if (j.status === "running") {
    $("job-status").textContent = `${j.log.length} steps`;
    await load();
    setTimeout(pollJob, 1500);
    return;
  }
  state.job = null;
  $("btn-judge").disabled = false;
  if (j.status === "error") {
    $("job-status").textContent = "failed";
    setLive("down", "judge failed");
    toast("judge failed: " + j.error, 8000);
  } else {
    const s = j.result.judge;
    $("job-status").textContent = `done · ${(s.duration_ms / 1000).toFixed(0)}s model time`;
    toast(`reviewed ${s.judged}: ${s.confirmed} confirmed · ${s.benign} benign · ${s.unsure} unsure`, 8000);
    setLive("ok", "live");
  }
  await load();
}

async function runSynth() {
  if (!confirm("Regenerate the synthetic demo data and rescan? Existing findings and verdicts will be cleared.")) return;
  const btn = $("btn-synth");
  btn.disabled = true;
  setLive("busy", "generating");
  try {
    const r = await api("/api/synth", { method: "POST" });
    state.seenVerdicts.clear();
    toast(`generated ${r.sessions} sessions · ${r.plants} planted secrets · ${r.scan.findings} findings`);
    await load();
  } catch (err) {
    toast("failed: " + err.message, 6000);
  } finally {
    btn.disabled = false;
    if (!state.job) setLive("ok", "live");
  }
}

// ---------- wiring ----------
for (const [id, key] of [["f-severity", "severity"], ["f-category", "category"], ["f-source", "source"], ["f-project", "project"], ["f-verdict", "verdict"]]) {
  $(id).addEventListener("change", (e) => { state.filters[key] = e.target.value; render(); });
}
$("f-q").addEventListener("input", (e) => { state.filters.q = e.target.value; render(); });
$("f-clear").addEventListener("click", () => {
  state.filters = { severity: "", category: "", source: "", project: "", verdict: "", q: "" };
  $("f-q").value = "";
  render();
});
$("btn-scan").addEventListener("click", runScan);
$("btn-judge").addEventListener("click", runJudge);
$("btn-synth").addEventListener("click", runSynth);
let resizeTimer = null;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => renderCharts(filtered()), 150); });

load().catch((err) => toast("failed to load: " + err.message, 8000));
