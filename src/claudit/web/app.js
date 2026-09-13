"use strict";

const SEVERITIES = ["critical", "high", "medium", "low"];
const VERDICTS = ["confirmed", "benign", "unsure", "unavailable", "not judged"];
const SEV_VAR = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };
// Internal names never reach the screen.
const SOURCE_LABEL = {
  tool_result: "files & output Claude read", tool_input: "text Claude wrote or ran", user_prompt: "you typed or pasted",
  assistant_text: "Claude's replies", assistant_thinking: "Claude's thinking", attachment: "attached files",
};
const REVIEW_LABEL = { confirmed: "real", benign: "not real", unsure: "unsure", unavailable: "unavailable", unjudged: "not reviewed", "not judged": "not reviewed" };
const srcLabel = (v) => SOURCE_LABEL[v] || v;
const reviewLabel = (v) => REVIEW_LABEL[v] || v;
const catLabel = (v) => (v || "").replace(/[_-]+/g, " ");
const sevShort = (v) => (v === "critical" ? "crit" : v === "medium" ? "med" : v);
const sevRank = (v) => SEVERITIES.indexOf(v);

const state = {
  summary: null,
  findings: [],
  secrets: [],        // every distinct secret, all states; the checklist filters by state client-side
  secretsState: "open",
  tab: "overview",
  secretOpen: null,
  health: null,
  metrics: null,
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
    const [summary, findings, secrets, health, metrics] = await Promise.all([
      api("/api/summary"), api("/api/findings"), api("/api/secrets?state=all"),
      api("/api/health").catch(() => null), api("/api/metrics").catch(() => null)]);
    state.secrets = secrets;
    state.health = health;
    state.metrics = metrics;
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
  renderOverview();
  renderSecrets();
  renderCharts(state.findings);
  renderFeed(rows);
  renderModel();
  renderSemantic();
  renderEval();
  renderOps();
  renderTabs();
}

// ---------- tabs ----------
const TABS = ["overview", "secrets", "findings", "model", "operations"];
function showTab(name) {
  if (!TABS.includes(name)) name = "overview";
  state.tab = name;
  for (const el of document.querySelectorAll("[data-tab]:not(.tab)")) el.classList.toggle("tab-off", el.dataset.tab !== name);
  for (const b of document.querySelectorAll(".tab")) b.classList.toggle("active", b.dataset.tab === name);
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  if (name === "overview" || name === "findings") renderCharts(state.findings);
}
function renderTabs() {
  const open = state.secrets.filter((x) => x.state === "open").length;
  const judged = (state.summary.totals || {}).judged || 0;
  $("tab-n-secrets").textContent = open ? fmtInt(open) : "";
  $("tab-n-findings").textContent = state.findings.length ? fmtInt(state.findings.length) : "";
  $("tab-n-model").textContent = state.job ? "running" : judged ? fmtInt(judged) : "";
}

// The Model tab is either a live/last job log, or a plain statement of what judging would do.
function renderModel() {
  const judged = (state.summary.totals || {}).judged || 0;
  const empty = !state.job && !judged;
  $("model-empty").hidden = !empty;
  if (empty) {
    const n = state.findings.length;
    $("model-empty-body").replaceChildren(
      h("div", {}, n
        ? `Nothing reviewed yet. Review sends each ambiguous value to ${state.summary.model} on this machine and sorts it into real, not real or unsure — about ten seconds per call. Vendor-format keys sitting in production files are marked real by rule without a call.`
        : "Nothing to review yet. Scan first."),
      n ? h("button", { class: "btn accent small", onclick: runJudge }, "review now") : null,
    );
  }
  const models = (state.metrics && state.metrics.by_model) || [];
  $("models-card").hidden = !models.length;
  $("models").querySelector("tbody").replaceChildren(
    ...models.map((m) => h("tr", {}, h("td", {}, m.model), h("td", { class: "num" }, fmtInt(m.n)),
      h("td", { class: "num" }, m.p50_ms ?? "—"), h("td", { class: "num" }, m.p95_ms ?? "—"),
      h("td", { class: "num" }, m.confirmed), h("td", { class: "num" }, m.benign), h("td", { class: "num" }, m.unsure),
      h("td", { class: "num" }, m.unparseable)))
  );
}

function renderOps() {
  const hz = state.health, m = state.metrics;
  if (!hz) { $("ops-panel").hidden = true; return; }
  $("ops-panel").hidden = false;
  const dot = (ok) => h("span", { class: "hdot " + (ok ? "ok" : "down") });
  const row = (k, v) => h("div", { class: "ops-row" }, h("span", {}, k), h("span", { class: "v" }, v));
  const fill = (id, ...kids) => $(id).replaceChildren(...kids.flat().filter((c) => c !== null && c !== undefined));

  const s = state.summary;
  fill("ops-config",
    h("div", { class: "k" }, "configuration"),
    row("database", h("span", { class: "v mono", title: s.db }, s.db)),
    row("transcripts", h("span", { class: "v mono", title: s.transcripts_dir }, s.transcripts_dir)),
    row("model", s.model),
    row("last scan", relTime(s.last_scan)),
  );
  fill("ops-health",
    h("div", { class: "k" }, "health"),
    row(h("span", {}, dot(hz.db.ok), "database"), hz.db.ok ? "ok" : "down"),
    row(h("span", {}, dot(hz.ollama.ok), "ollama"), hz.ollama.ok ? `${hz.ollama.ms} ms` : "unreachable"),
    row(h("span", {}, dot(hz.guard.ok), "guard"), hz.guard.ok ? `${hz.guard.ms} ms` : "not running"),
  );

  const g = hz.guard.status;
  fill("ops-guard",
    h("div", { class: "k" }, "guard · kept on this machine"),
    h("div", { class: "ops-big" }, g ? fmtInt(g.values_masked) : "—"),
    g ? row("restored in replies", fmtInt(g.values_restored)) : h("div", { class: "muted" }, "start with: claudit guard"),
    g ? row("suspected misses", fmtInt(g.suspected_misses)) : null,
    g ? row("blocked writes", fmtInt(g.blocked_writes)) : null,
  );

  const lat = m && m.latency;
  fill("ops-latency",
    h("div", { class: "k" }, "latency"),
    lat ? row("judge p50 / p95", lat.judge_calls.n ? `${lat.judge_calls.p50_ms} / ${lat.judge_calls.p95_ms} ms  (n ${lat.judge_calls.n})` : "—") : null,
    lat ? row("semantic p50 / p95", lat.semantic_segments.n ? `${lat.semantic_segments.p50_ms} / ${lat.semantic_segments.p95_ms} ms  (n ${lat.semantic_segments.n})` : "—") : null,
    lat ? row("scan p50 / max", lat.scans.n ? `${lat.scans.p50_ms} / ${lat.scans.max_ms} ms  (n ${lat.scans.n})` : "—") : null,
    ((m && m.by_model) || []).map((r) =>
      row(`· ${r.model}`, `${r.p50_ms} / ${r.p95_ms} ms  (n ${r.n}${r.unparseable ? `, ${r.unparseable} unparseable` : ""})`)),
  );

  const runs = (m && m.runs) || [];
  fill("ops-runs",
    h("div", { class: "k" }, "recent runs"),
    ...(runs.length ? runs.slice(0, 6).map((r) => row(`${fmtDay(r.started_at)} ${fmtTime(r.started_at)}  ${r.kind}`, `${fmtInt(r.duration_ms)} ms`))
                    : [h("div", { class: "muted" }, "no runs yet")]),
  );
  $("ops-sub").textContent = runs.length ? `${runs.length} runs recorded` : "";
}

function renderHeader() {
  const s = state.summary;
  const badge = $("mode-badge");
  badge.textContent = s.demo ? "demo · synthetic" : "local · your transcripts";
  badge.classList.toggle("demo", s.demo);
  $("btn-synth").hidden = !s.demo;
  const g = state.health && state.health.guard;
  const gb = $("guard-badge");
  gb.hidden = !state.health;
  if (state.health) {
    const up = !!(g && g.ok);
    gb.className = "chip " + (up ? "guard" : "unguarded");
    gb.textContent = up ? `guarded · ${fmtInt((g.status && g.status.values_masked) || 0)} masked` : "no guard";
    gb.title = up ? "claudit guard is masking secrets before requests leave this machine" : "start with: claudit guard";
  }
}

function fillSelect(id, values, current, label = (v) => v) {
  const sel = $(id);
  const first = sel.options[0];
  sel.replaceChildren(first, ...values.map((v) => h("option", { value: v }, label(v))));
  sel.value = values.includes(current) ? current : "";
}

function renderFilterOptions() {
  const all = state.findings;
  const uniq = (key) => [...new Set(all.map((x) => x[key]).filter(Boolean))].sort();
  fillSelect("f-severity", SEVERITIES.filter((s) => all.some((x) => x.severity === s)), state.filters.severity);
  fillSelect("f-category", uniq("category"), state.filters.category, catLabel);
  fillSelect("f-source", uniq("source"), state.filters.source, srcLabel);
  fillSelect("f-project", uniq("project"), state.filters.project, shortProject);
  fillSelect("f-verdict", VERDICTS.filter((v) => all.some((x) => (x.verdict || "not judged") === v)), state.filters.verdict, reviewLabel);
}

function renderOverview() {
  const t = state.summary.totals;
  const all = state.secrets;
  const open = all.filter((x) => x.state === "open");
  const reviewed = all.filter((x) => x.verdict !== "unjudged");
  const unreviewed = open.filter((x) => x.verdict === "unjudged");
  const real = open.filter((x) => x.verdict === "confirmed");
  const resolved = all.filter((x) => x.state !== "open");
  const critHigh = open.filter((x) => x.severity === "critical" || x.severity === "high").length;
  const sessions = new Set(state.findings.map((r) => r.session)).size;
  const plural = (n, one, many) => `${fmtInt(n)} ${n === 1 ? one : many}`;
  const go = (label, fn) => h("button", { class: "btn accent", onclick: fn }, label);

  // The whole state of affairs in one sentence, one tone, one action.
  let tone, head, sub, action = null;
  if (!state.findings.length) {
    tone = t.events ? "ok" : "idle";
    head = t.events ? "Nothing sensitive was found in your transcripts." : "Nothing scanned yet.";
    sub = t.events
      ? `${fmtInt(t.events)} messages across ${plural(t.sessions, "session", "sessions")} were checked against ${fmtInt(235)} patterns.`
      : "Scan reads your Claude Code transcripts on this machine and keeps a fingerprint of each secret, never the value.";
    if (!t.events) action = go("scan now", runScan);
  } else if (unreviewed.length) {
    tone = "warn";
    head = `${plural(all.length, "secret or personal record was", "secrets and personal records were")} shared with Claude across ${sessions} of your ${plural(t.sessions, "session", "sessions")}.`;
    sub = `${unreviewed.length === all.length ? "None have" : `${fmtInt(unreviewed.length)} have not`} been reviewed yet. The local model sorts them into real, not real and unsure — about ten seconds each, and nothing leaves this machine.`;
    action = go("review now", runJudge);
  } else if (real.length) {
    tone = "crit";
    head = `${plural(real.length, "real secret needs", "real secrets need")} rotating.`;
    sub = `Rotate ${real.length === 1 ? "it" : "them"} at the provider, then mark ${real.length === 1 ? "it" : "them"} rotated here. ${critHigh ? `${fmtInt(critHigh)} ${critHigh === 1 ? "is" : "are"} critical or high.` : ""}`;
    action = go("see the list", () => showTab("secrets"));
  } else {
    tone = "ok";
    head = "All clear.";
    sub = `${plural(all.length, "value was", "values were")} shared; ${fmtInt(resolved.length)} resolved by you, the rest judged not real.`;
  }
  $("status-band").replaceChildren(
    h("span", { class: "sdot " + tone }),
    h("div", { class: "status-text" }, h("div", { class: "status-head" }, head), h("div", { class: "status-sub" }, sub)),
    action,
  );

  // Shared -> reviewed -> real -> resolved. Four numbers that read left to right.
  const cells = [
    ["shared", fmtInt(all.length), `distinct values · ${fmtInt(critHigh)} critical or high`],
    ["reviewed", fmtInt(reviewed.length), all.length ? `of ${fmtInt(all.length)}, by the local model` : "—"],
    ["confirmed real", fmtInt(real.length), real.length ? "still open, need rotating" : reviewed.length ? "none open" : "not known yet"],
    ["resolved", fmtInt(resolved.length), "rotated or dismissed by you"],
  ];
  $("funnel").replaceChildren(
    ...cells.map(([k, v, sub2], i) => h("div", { class: "fcell" + (i === 2 && real.length ? " hot" : "") },
      h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "s" }, sub2)))
  );

  // The five worst open items, with their actions, without opening a tab.
  const worst = [...open].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.verdict === "confirmed") - (a.verdict === "confirmed") || b.findings - a.findings);
  const top = worst.slice(0, 5);
  $("attention-sub").textContent = open.length > top.length ? `${top.length} of ${fmtInt(open.length)} open` : open.length ? `${open.length} open` : "";
  const list = $("attention");
  if (!top.length) {
    list.replaceChildren(h("div", { class: "empty-state" }, state.findings.length ? "nothing open — every value is rotated or dismissed" : "nothing to act on"));
  } else {
    list.replaceChildren(...top.map((x) => h("div", { class: "arow" },
      h("span", { class: "tag sev-" + x.severity }, sevShort(x.severity)),
      h("span", { class: "acat" }, catLabel(x.category)),
      h("span", { class: "aprev mono", title: x.preview }, x.preview),
      h("span", { class: "pill " + (x.verdict === "unjudged" ? "unsure" : x.verdict) }, reviewLabel(x.verdict)),
      h("span", { class: "muted mono" }, `${x.sessions} session${x.sessions === 1 ? "" : "s"}`),
      h("span", { class: "acts" },
        h("button", { class: "btn ghost", onclick: () => setSecretState(x.fingerprint, "rotated") }, "rotated"),
        h("button", { class: "btn ghost", onclick: () => setSecretState(x.fingerprint, "dismissed") }, "dismiss")),
    )), open.length > top.length ? h("a", { class: "more", href: "#secrets", onclick: (e) => { e.preventDefault(); showTab("secrets"); } }, `all ${fmtInt(open.length)} open secrets →`) : null);
  }
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
  hbars($("c-category"), byCat.map(([k, v]) => ({ label: catLabel(k), value: v })), { total });
  const bySrc = [...countBy(rows, "source")].sort((a, b) => b[1] - a[1]);
  hbars($("c-source"), bySrc.map(([k, v]) => ({ label: srcLabel(k), value: v })), { total });

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

async function setSecretState(fp, newState) {
  try {
    await api(`/api/secrets/${fp}/state`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ state: newState }) });
    toast(`${fp.slice(0, 12)}… marked ${newState}`);
    await load();
  } catch (err) {
    toast("could not update: " + err.message, 6000);
  }
}

function renderSecrets() {
  const rows = state.secretsState === "all" ? state.secrets : state.secrets.filter((x) => x.state === state.secretsState);
  const el = $("secrets");
  $("secrets-count").textContent = `${rows.length} ${state.secretsState === "all" ? "" : state.secretsState} secret${rows.length === 1 ? "" : "s"}`;
  const unjudged = rows.filter((x) => x.verdict === "unjudged").length;
  const note = $("secrets-note");
  note.hidden = !unjudged;
  if (unjudged) {
    note.replaceChildren(`${fmtInt(unjudged)} of these have not been reviewed — the local model has not looked at them yet. `,
      h("a", { href: "#model", onclick: (e) => { e.preventDefault(); runJudge(); } }, "review now"));
  }
  if (!rows.length) {
    el.replaceChildren(h("div", { class: "empty-state" }, state.secrets.length
      ? `no ${state.secretsState} secrets`
      : state.findings.length ? "no secrets" : "nothing detected yet — run a scan"));
    return;
  }
  const out = [];
  for (const s of rows) {
    const acts = h("span", { class: "acts" });
    for (const [label, target] of [["rotated", "rotated"], ["dismiss", "dismissed"], ["reopen", "open"]]) {
      if (target === s.state) continue;
      acts.append(h("button", { class: "btn ghost", onclick: (e) => { e.stopPropagation(); setSecretState(s.fingerprint, target); } }, label));
    }
    const row = h("div", { class: "srow" + (s.state === "open" ? "" : " done"), role: "button", tabindex: 0,
      onclick: () => { state.secretOpen = state.secretOpen === s.fingerprint ? null : s.fingerprint; renderSecrets(); } },
      h("span", { class: "tag sev-" + s.severity }, sevShort(s.severity)),
      h("span", { class: "cat", title: s.category }, catLabel(s.category)),
      h("span", { class: "prev", title: s.preview }, s.preview),
      h("span", {}, h("span", { class: "pill " + (s.verdict === "unjudged" ? "unsure" : s.verdict) }, reviewLabel(s.verdict))),
      h("span", {}, `${s.sessions} · ${s.findings}×`),
      h("span", { class: "t" }, `${fmtDay(s.first_seen)} · ${fmtDay(s.last_seen)}`),
      h("span", { class: "src", title: (s.sources || []).map(srcLabel).join(", ") }, (s.sources || []).map(srcLabel).join(", ")),
      acts,
    );
    out.push(row);
    if (state.secretOpen === s.fingerprint) {
      out.push(h("div", { class: "rotation" },
        h("div", {}, h("b", {}, "what to do: "), s.rotation),
        h("div", { class: "muted" }, `fingerprint ${s.fingerprint}  ·  projects: ${(s.projects || []).map(shortProject).join(", ")}`),
        s.note ? h("div", { class: "muted" }, `note: ${s.note}`) : null,
      ));
    }
  }
  el.replaceChildren(...out);
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
  if (!rows.length) {
    const filtering = rows.length !== state.findings.length;
    feed.replaceChildren(h("div", { class: "empty-state" },
      filtering ? "no findings match these filters" : `no findings yet — scan reads ${state.summary.transcripts_dir}`,
      filtering ? h("button", { class: "btn small", onclick: () => $("f-clear").click() }, "clear filters")
                : h("button", { class: "btn accent small", onclick: runScan }, "scan")));
    return;
  }
  const out = [];
  for (const r of rows.slice(0, LIMIT)) {
    const verdict = r.verdict
      ? h("span", { class: "pill " + r.verdict + (state.fresh.has(r.id) ? " fresh" : "") }, reviewLabel(r.verdict))
      : h("span", { class: "muted" }, "—");
    const row = h("div", { class: "row", role: "button", tabindex: 0,
      onclick: () => { state.expanded = state.expanded === r.id ? null : r.id; renderFeed(filtered()); } },
      h("span", { class: "t", title: r.ts ? asDate(r.ts).toLocaleString() : "" }, `${fmtDay(r.ts)} ${fmtTime(r.ts)}`),
      h("span", { class: "tag sev-" + r.severity }, sevShort(r.severity)),
      h("span", { class: "cat", title: r.category }, catLabel(r.category)),
      h("span", { class: "prev", title: r.preview }, r.preview),
      h("span", { class: "src", title: r.path || "" }, srcLabel(r.source)),
      h("span", { class: "proj", title: r.path ? `${r.project}\n${r.path}` : r.project }, r.path ? shortProject(r.path) : shortProject(r.project)),
      h("span", {}, verdict),
    );
    out.push(row);
    if (state.expanded === r.id) {
      out.push(h("div", { class: "detail" },
        h("div", {}, h("b", {}, "finding "), h("span", { class: "mono" }, r.id), "  ·  session ", h("span", { class: "mono" }, r.session || "")),
        h("div", {}, h("b", {}, "project "), h("span", { class: "mono" }, r.project || ""), r.path ? ["  ·  ", h("b", {}, "file "), h("span", { class: "mono" }, r.path)] : null),
        r.verdict
          ? h("div", {}, h("b", {}, `${r.judged_by === "rules" ? "by rule" : "by the model"}: ${reviewLabel(r.verdict)}`), " — ", r.reason || "")
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
    showTab("model");
    $("model-empty").hidden = true;
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
$("secrets-state").addEventListener("change", (e) => { state.secretsState = e.target.value; renderSecrets(); });
for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => showTab(b.dataset.tab));
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
showTab(location.hash.slice(1) || "overview");
$("btn-scan").addEventListener("click", runScan);
$("btn-judge").addEventListener("click", runJudge);
$("btn-synth").addEventListener("click", runSynth);
let resizeTimer = null;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => renderCharts(state.findings), 150); });

load().catch((err) => toast("failed to load: " + err.message, 8000));
