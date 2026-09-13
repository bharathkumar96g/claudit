"use strict";
/* claudit dashboard. No framework, no build step. Every value on screen is a masked preview. */

const SEVERITIES = ["critical", "high", "medium", "low"];
const VERDICTS = ["confirmed", "benign", "unsure", "unavailable", "not judged"];
const SEV_VAR = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };

// Internal names never reach the screen. Verdicts come from a 7B model, so the words stay hedged.
const SOURCE_LABEL = {
  user_prompt: "you typed it", tool_result: "the assistant read it", tool_input: "the assistant wrote it",
  assistant_text: "the assistant said it", assistant_thinking: "the assistant's thinking", attachment: "attached file",
};

// Plain definitions for first-time users. Shown behind an (i) next to a label, or as a tooltip on a pill.
const DEFINE = {
  "likely real": "The local model found nothing saying this value is fake, an example or a placeholder. Treat it as live until you rotate it.",
  "likely fake": "The text around it says it is a test, example or placeholder value. Prose can steer the model, so check when in doubt.",
  "needs you": "The model saw signs pointing both ways. Open it and decide.",
  "unreviewed": "The local model has not looked at this value yet.",
  "model offline": "The model could not be reached when this value came up for review.",
  "reappeared": "You marked this rotated, but the same value showed up in a later session. Either it is still in use somewhere, or the rotation missed a consumer.",
  ledger: "One line per secret. Each dot is one appearance and its color says how the value entered the session. The green flag is the day you marked it rotated; a red ring is an appearance after that.",
  origin: "How the value entered a session: you typed or pasted it, the assistant read it from a file or command output, or the assistant wrote it into a file or a command.",
  type: "The pattern that matched — a private key, a cloud access key, a card number, and so on.",
  severity: "How bad it is if the value is real. Critical: private keys and cloud credentials. High: API tokens and card numbers. Medium: generic secrets and personal data. Low: the rest.",
  review: "The verdict of a model running on this machine, given a redacted window of context around the value. Vendor-format keys in production files are marked likely real by rule, without a model call.",
  fingerprint: "A SHA-256 hash of the value. It lets the same secret be recognised across sessions and rescans without ever storing the value.",
  coverage: "The guard replaces vendor-format credentials with pseudonyms before a request leaves this machine. Personal data and generic passwords have no reliable format, so they are audited but not masked.",
  since: "Every value has a stable fingerprint, so two scans can be compared: values seen for the first time, and values seen again after you marked them rotated.",
  "sessions · times": "How many distinct sessions the value appeared in, and how many times in total.",
  guard: "A local proxy between your coding assistant and the model provider. It swaps secrets for format-preserving pseudonyms on the way out and restores them in the streamed reply.",
  "local review": "Sends each ambiguous value, with a redacted window of context, to a model running on this machine. Nothing leaves the machine.",
  contents: "Also ask the model to read prompts and file contents for sensitive information that has no pattern: customer data, internal names, financial figures. Slower.",
  transcripts: "The session logs your coding assistant keeps on this machine. claudit reads them; it never writes to them.",
};
function info(key) {
  const el = h("span", { class: "info", tabindex: 0, role: "img", "aria-label": DEFINE[key] || key }, "i");
  el.addEventListener("pointermove", (e) => showTip(e, key, [DEFINE[key] || ""]));
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("blur", hideTip);
  return el;
}
const pill = (cls, label) => h("span", { class: "pill " + cls, title: DEFINE[label] || "" }, label);
const SOURCE_VAR = {
  user_prompt: "--accent", tool_result: "--series", tool_input: "--wrote", assistant_text: "--said",
  assistant_thinking: "--said", attachment: "--low",
};
const REVIEW_LABEL = {
  confirmed: "likely real", benign: "likely fake", unsure: "needs you", unavailable: "model offline",
  unjudged: "unreviewed", "not judged": "unreviewed",
};
const VERDICT_RANK = { confirmed: 0, unsure: 1, unjudged: 2, unavailable: 2, benign: 3 };
const srcLabel = (v) => SOURCE_LABEL[v] || v;
const reviewLabel = (v) => REVIEW_LABEL[v] || v;
const catLabel = (v) => (v || "").replace(/[_-]+/g, " ");
const sevShort = (v) => (v === "critical" ? "crit" : v === "medium" ? "med" : v);
const sevRank = (v) => SEVERITIES.indexOf(v);
const plural = (n, one, many) => `${fmtInt(n)} ${n === 1 ? one : many}`;

const state = {
  summary: null,
  findings: [],
  secrets: [],          // every distinct value, all states; filtered client-side
  secretsState: "open",
  view: "grouped",
  secretOpen: null,
  health: null,
  metrics: null,
  filters: { severity: "", category: "", source: "", project: "", verdict: "", q: "" },
  expanded: null,
  job: null,
  seenVerdicts: new Set(),
  fresh: new Set(),
  tab: "overview",
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
const fmtInt = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString());
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
  return asDate(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
}
function fmtDay(iso) {
  if (!iso) return "";
  return asDate(iso).toLocaleDateString(undefined, { month: "short", day: "2-digit" });
}
function fmtWhen(iso) {
  if (!iso) return "";
  return fmtDay(iso) + " " + fmtTime(iso);
}
const daysBetween = (a, b) => Math.max(0, Math.round((asDate(b) - asDate(a)) / 86400000));

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
    if (!state.job) setLive("ok", "connected");
    render();
  } catch (err) {
    setLive("down", "disconnected");
    throw err;
  }
}

// Appearances of one value, oldest first, straight from the findings we already hold.
function appearancesOf(fp) {
  return state.findings.filter((f) => f.fingerprint === fp).sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
}

function rankSecrets(list) {
  return [...list].sort((a, b) =>
    (b.reappeared ? 1 : 0) - (a.reappeared ? 1 : 0) ||
    VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
    sevRank(a.severity) - sevRank(b.severity) ||
    ((b.sources || []).includes("user_prompt") ? 1 : 0) - ((a.sources || []).includes("user_prompt") ? 1 : 0) ||
    b.sessions - a.sessions);
}

function matchesFilters(secret) {
  const f = state.filters, q = f.q.trim().toLowerCase();
  return (!f.severity || secret.severity === f.severity) &&
    (!f.category || secret.category === f.category) &&
    (!f.source || (secret.sources || []).includes(f.source)) &&
    (!f.project || (secret.projects || []).includes(f.project)) &&
    (!f.verdict || (f.verdict === "not judged" ? "unjudged" : f.verdict) === secret.verdict) &&
    (!q || (secret.preview || "").toLowerCase().includes(q) || catLabel(secret.category).includes(q) ||
      (secret.projects || []).some((p) => (p || "").toLowerCase().includes(q)));
}

function filteredFindings() {
  const f = state.filters, q = f.q.trim().toLowerCase();
  return state.findings.filter((x) =>
    (!f.severity || x.severity === f.severity) &&
    (!f.category || x.category === f.category) &&
    (!f.source || x.source === f.source) &&
    (!f.project || x.project === f.project) &&
    (!f.verdict || (x.verdict || "not judged") === f.verdict) &&
    (!q || (x.preview || "").toLowerCase().includes(q) || (x.project || "").toLowerCase().includes(q) || catLabel(x.category).includes(q)));
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
  renderOverview();
  renderSecrets();
  renderCharts(state.findings);
  renderModel();
  renderSemantic();
  renderEval();
  renderSystem();
  renderTabs();
}

// ---------- tabs ----------
const TABS = ["overview", "secrets", "model", "operations"];
function showTab(name) {
  if (!TABS.includes(name)) name = "overview";
  state.tab = name;
  for (const el of document.querySelectorAll("[data-tab]:not(.tab)")) el.classList.toggle("tab-off", el.dataset.tab !== name);
  for (const b of document.querySelectorAll(".tab")) b.classList.toggle("active", b.dataset.tab === name);
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  if (name === "overview" && state.summary) { renderCharts(state.findings); renderLedger(); }
}
function renderTabs() {
  const open = state.secrets.filter((x) => x.state === "open" || x.reappeared).length;
  const judged = (state.summary.totals || {}).judged || 0;
  $("tab-n-secrets").textContent = open ? fmtInt(open) : "";
  $("tab-n-model").textContent = state.job ? "running" : judged ? fmtInt(judged) : "";
}

function renderHeader() {
  const s = state.summary;
  const badge = $("mode-badge");
  badge.textContent = s.demo ? "demo data" : "this machine";
  badge.classList.toggle("demo", s.demo);
  $("btn-synth").hidden = !s.demo;
  const g = state.health && state.health.guard;
  const gb = $("guard-badge");
  gb.hidden = !state.health;
  if (state.health) {
    const up = !!(g && g.ok);
    gb.className = "chip " + (up ? "guard" : "unguarded");
    gb.textContent = up ? `guard on · ${fmtInt((g.status && g.status.values_masked) || 0)} masked since start` : "guard off";
    gb.title = up ? "claudit guard is replacing secrets with pseudonyms before requests leave this machine" : "start with: claudit guard";
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

// ---------- overview ----------
function renderOverview() {
  const s = state.summary, t = s.totals;
  const all = state.secrets;
  const open = all.filter((x) => x.state === "open" || x.reappeared);
  const unreviewed = open.filter((x) => x.verdict === "unjudged");
  const real = open.filter((x) => x.verdict === "confirmed");
  const needsYou = open.filter((x) => x.verdict === "unsure");
  const reappeared = all.filter((x) => x.reappeared);
  const sessions = new Set(state.findings.map((r) => r.session)).size;
  const go = (label, fn) => h("button", { class: "btn accent", onclick: fn }, label);

  // What changed since the last scan: fingerprints make rescans diffable.
  const since = s.since;
  const el = $("since");
  if (since && since.previous_scan_at) {
    el.replaceChildren(info("since"), " ",
      "since your previous scan ", h("b", {}, relTime(since.previous_scan_at)), "  ·  ",
      `${plural(since.sessions_touched, "session", "sessions")} read`, "  ·  ",
      h("span", { class: since.new_secrets ? "delta" : "" }, plural(since.new_secrets, "new secret", "new secrets")),
      since.reappeared_after_rotation ? ["  ·  ", h("span", { class: "bad" }, `${fmtInt(since.reappeared_after_rotation)} reappeared after rotation`)] : null,
    );
  } else if (since) {
    el.replaceChildren("first scan ", h("b", {}, relTime(since.latest_scan_at)), `  ·  ${plural(t.sessions, "session", "sessions")}  ·  ${fmtInt(t.events)} messages`);
  } else if (s.last_scan) {
    el.replaceChildren("last read ", h("b", {}, relTime(s.last_scan)), `  ·  ${plural(t.sessions, "session", "sessions")}  ·  ${fmtInt(t.events)} messages`);
  } else {
    el.replaceChildren("nothing scanned yet");
  }

  // The state of affairs in one sentence, one tone, one action.
  let tone, head, sub, action = null;
  if (!state.findings.length) {
    tone = t.events ? "ok" : "idle";
    head = t.events ? `No pattern matched in ${fmtInt(t.events)} messages.` : "Nothing scanned yet.";
    sub = t.events
      ? `${plural(t.sessions, "session was", "sessions were")} checked against 235 secret and personal-data patterns. Patternless content (customer data, internal names) is only found when the review also reads contents.`
      : "Scanning reads your coding assistant's transcripts on this machine and keeps a fingerprint of each match, never the value.";
    if (!t.events) action = go("scan transcripts", runScan);
  } else if (reappeared.length) {
    tone = "crit";
    head = `${plural(reappeared.length, "secret", "secrets")} reappeared after you marked ${reappeared.length === 1 ? "it" : "them"} rotated.`;
    sub = "Either the old value is still in use somewhere, or the rotation did not reach every consumer. It is back on the open list.";
    action = go("see it", () => showTab("secrets"));
  } else if (unreviewed.length) {
    tone = "warn";
    head = `${plural(all.length, "secret or personal detail", "secrets and personal details")} appeared in ${sessions} of your ${plural(t.sessions, "coding session", "coding sessions")}.`;
    sub = `${unreviewed.length === open.length ? "None have" : `${fmtInt(unreviewed.length)} have not`} been reviewed. The local model sorts them into likely real, likely fake and needs-you — about ten seconds each, and nothing leaves this machine.`;
    action = go("run local review", runJudge);
  } else if (real.length || needsYou.length) {
    tone = real.length ? "crit" : "warn";
    head = real.length
      ? `${plural(real.length, "likely-real secret is", "likely-real secrets are")} still open.`
      : `${plural(needsYou.length, "value needs", "values need")} a human decision.`;
    sub = real.length
      ? `Rotate ${real.length === 1 ? "it" : "them"} at the provider, then mark ${real.length === 1 ? "it" : "them"} rotated here.${needsYou.length ? ` ${fmtInt(needsYou.length)} more could go either way and need you.` : ""}`
      : "The model saw markers pointing both ways. Open each one; the excerpt around it decides.";
    action = go("see the list", () => showTab("secrets"));
  } else {
    tone = "ok";
    head = "Nothing open.";
    sub = `${plural(all.length, "value", "values")} detected so far: ${fmtInt(s.secrets.rotated)} rotated, ${fmtInt(s.secrets.dismissed)} dismissed, the rest judged likely fake.`;
  }
  $("status-band").replaceChildren(
    h("span", { class: "sdot " + tone }),
    h("div", { class: "status-text" }, h("div", { class: "status-head" }, head), h("div", { class: "status-sub" }, sub)),
    action,
  );

  renderLedger();
  renderCoverage(open);
}

// The ledger: each open secret's life on one time axis. Dots are appearances colored by origin,
// a green flag is the day you marked it rotated, a red ring is an appearance after that flag.
function renderLedger() {
  const open = rankSecrets(state.secrets.filter((x) => x.state === "open" || x.reappeared));
  const top = open.slice(0, 6);
  const box = $("ledger");
  $("ledger-sub").textContent = open.length > top.length ? `${top.length} of ${fmtInt(open.length)} open, worst first` : open.length ? `${open.length} open, worst first` : "";
  $("ledger-info").replaceChildren(info("ledger"));
  $("ledger-legend").replaceChildren(
    ...Object.entries(SOURCE_LABEL).filter(([k]) => state.findings.some((f) => f.source === k)).map(([k, v]) =>
      h("span", {}, h("i", { style: `background:${cssVar(SOURCE_VAR[k])}` }), v)),
    h("span", {}, h("i", { class: "flag" }), "marked rotated"),
    h("span", {}, h("i", { class: "ring" }), "seen after rotation"),
  );
  if (!top.length) {
    box.replaceChildren(h("div", { class: "empty-state" }, state.findings.length ? "nothing open — every value is rotated, dismissed or judged fake" : "nothing to show until a scan finds something"));
    return;
  }
  const apps = new Map(top.map((x) => [x.fingerprint, appearancesOf(x.fingerprint)]));
  const times = [...apps.values()].flat().map((a) => a.ts).filter(Boolean);
  const axis = { min: times.length ? Math.min(...times.map((x) => asDate(x).getTime())) : Date.now() - 86400000, max: Date.now() };
  if (axis.max - axis.min < 3 * 86400000) axis.min = axis.max - 3 * 86400000;
  const rows = top.map((x) => {
    const acts = h("span", { class: "acts" },
      h("button", { class: "btn ghost", onclick: () => setSecretState(x.fingerprint, "rotated") }, "mark rotated"),
      h("button", { class: "btn ghost", onclick: () => setSecretState(x.fingerprint, "dismissed") }, "not a secret"));
    const strip = h("div", { class: "strip" });
    return h("div", { class: "lrow" },
      h("div", { class: "who", role: "button", tabindex: 0, title: "open in the secrets tab",
        onclick: () => { state.secretOpen = x.fingerprint; state.secretsState = x.state === "open" ? "open" : "all"; $("secrets-state").value = state.secretsState; showTab("secrets"); renderSecrets(); } },
        h("span", { class: "tag sev-" + x.severity }, sevShort(x.severity)),
        h("span", { class: "kind" }, catLabel(x.category)),
        h("span", { class: "prev", title: x.preview }, x.preview)),
      strip,
      h("div", { class: "side" },
        pill(x.reappeared ? "reappeared" : x.verdict === "unjudged" ? "unsure" : x.verdict, x.reappeared ? "reappeared" : reviewLabel(x.verdict)),
        acts),
    );
  });
  const ticks = h("div", { class: "ticks" });
  const span = axis.max - axis.min;
  const nTicks = 4;
  for (let i = 0; i <= nTicks; i++) {
    const tms = axis.min + (span * i) / nTicks;
    ticks.append(h("span", { class: i === nTicks ? "now" : "", style: `left:${(i / nTicks) * 100}%` }, i === nTicks ? "now" : fmtDay(new Date(tms).toISOString())));
  }
  box.replaceChildren(...rows, h("div", { class: "laxis" }, h("span"), ticks, h("span")),
    open.length > top.length ? h("a", { class: "more", href: "#secrets", onclick: (e) => { e.preventDefault(); showTab("secrets"); } }, `all ${fmtInt(open.length)} open secrets →`) : null);
  // Strips need their width: draw now that the rows are in the document, and again after layout settles.
  const draw = () => rows.forEach((row, i) => lifetimeStrip(row.querySelector(".strip"), top[i], apps.get(top[i].fingerprint), axis));
  draw();
  requestAnimationFrame(draw);
}

function lifetimeStrip(container, secret, apps, axis) {
  const W = Math.max(200, container.clientWidth || 400), H = 30, mid = 15;
  const span = Math.max(1, axis.max - axis.min);
  const X = (iso) => 8 + ((asDate(iso).getTime() - axis.min) / span) * (W - 16);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img" });
  svg.append(svgEl("line", { class: "axis", x1: 8, x2: W - 8, y1: mid, y2: mid }));
  const first = apps[0] && apps[0].ts, last = apps[apps.length - 1] && apps[apps.length - 1].ts;
  if (first && last) {
    svg.append(svgEl("line", { x1: X(first), x2: X(last), y1: mid, y2: mid, stroke: cssVar(SEV_VAR[secret.severity]), "stroke-width": 3, "stroke-opacity": 0.55, "stroke-linecap": "round" }));
  }
  const rotatedAt = secret.state !== "open" && secret.updated_at ? secret.updated_at : null;
  if (rotatedAt) {
    const x = X(rotatedAt);
    svg.append(svgEl("line", { x1: x, x2: x, y1: 3, y2: H - 3, stroke: cssVar("--ok"), "stroke-width": 2 }));
  }
  for (const a of apps) {
    if (!a.ts) continue;
    const x = X(a.ts);
    const after = rotatedAt && a.ts > rotatedAt;
    const dot = svgEl("circle", { cx: x, cy: mid, r: after ? 5 : 4, fill: after ? "none" : cssVar(SOURCE_VAR[a.source] || "--low"), stroke: after ? cssVar("--crit") : "none", "stroke-width": 2 });
    const hit = svgEl("circle", { cx: x, cy: mid, r: 9, fill: "transparent", tabindex: 0 });
    const lines = [srcLabel(a.source), a.path || a.project || "", a.verdict ? `${reviewLabel(a.verdict)}${a.judged_by === "rules" ? " (by rule)" : ""}` : "unreviewed"];
    hit.addEventListener("pointermove", (e) => showTip(e, fmtWhen(a.ts), lines.filter(Boolean)));
    hit.addEventListener("pointerleave", hideTip);
    svg.append(dot, hit);
  }
  container.replaceChildren(svg);
}

// Honest coverage: how many open values the guard would have masked, and whether it is running.
function renderCoverage(open) {
  const classes = new Set(state.summary.guard_classes || []);
  const box = $("coverage");
  if (!open.length) { box.hidden = true; return; }
  box.hidden = false;
  const maskable = open.filter((x) => classes.has(x.category)).length;
  const not = open.length - maskable;
  const g = state.health && state.health.guard, up = !!(g && g.ok);
  box.replaceChildren(
    h("span", {}, "of ", h("b", {}, fmtInt(open.length)), " open, ", h("b", {}, fmtInt(maskable)), " are classes the guard masks before a request leaves this machine; ",
      h("b", {}, fmtInt(not)), " are not (personal data and generic passwords stay audit-only)."),
    h("span", { class: "bar", title: `${maskable} maskable · ${not} not maskable` },
      h("i", { class: "m", style: `width:${(maskable / open.length) * 100}%` }), h("i", { class: "n", style: `width:${(not / open.length) * 100}%` })),
    h("span", {}, up ? h("b", {}, "guard on") : ["guard ", h("b", {}, "off"), " — ", h("code", { class: "mono" }, "claudit guard")], " ", info("coverage")),
  );
}

// ---------- charts ----------
function hbars(container, items, { total, colorOf }) {
  container.replaceChildren();
  if (!items.length) { container.append(h("div", { class: "empty" }, "nothing yet")); return; }
  const W = Math.max(280, container.clientWidth || 420);
  const labelW = Math.min(170, Math.max(80, ...items.map((i) => i.label.length * 6.8)));
  const rowH = 26, barH = 14, padR = 44;
  const H = items.length * rowH + 4;
  const max = Math.max(...items.map((i) => i.value));
  const scale = (v) => (max ? (v / max) * (W - labelW - padR) : 0);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img" });
  const series = cssVar("--series");
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
      class: "mark", fill: colorOf ? colorOf(it) : series,
      d: `M${x0},${y} H${x0 + w - r} a${r},${r} 0 0 1 ${r},${r} V${y + barH - r} a${r},${r} 0 0 1 -${r},${r} H${x0} Z`,
    });
    const hit = svgEl("rect", { class: "hit", x: 0, y: y - 6, width: W, height: rowH, tabindex: 0 });
    const lines = [`${it.value} appearance${it.value === 1 ? "" : "s"}`];
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

function columns(container, points) {
  container.replaceChildren();
  if (!points.length) { container.append(h("div", { class: "empty" }, "nothing yet")); return; }
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
    hit.addEventListener("pointermove", (e) => showTip(e, `${p.value} appearance${p.value === 1 ? "" : "s"}`, [p.label]));
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
  hbars($("c-source"), bySrc.map(([k, v]) => ({ label: srcLabel(k), value: v, key: k })), { total, colorOf: (it) => cssVar(SOURCE_VAR[it.key] || "--series") });

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

// ---------- secrets tab ----------
async function setSecretState(fp, newState) {
  try {
    await api(`/api/secrets/${fp}/state`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ state: newState }) });
    toast(newState === "rotated" ? "marked rotated — it reopens by itself if the value is seen again" : newState === "dismissed" ? "dismissed as not a secret" : "reopened");
    await load();
  } catch (err) {
    toast("could not update: " + err.message, 6000);
  }
}
function shortProject(p) {
  if (!p) return "";
  const parts = p.split("/").filter(Boolean);
  return parts.length > 2 ? "…/" + parts.slice(-2).join("/") : p;
}

function renderSecrets() {
  const grouped = state.view === "grouped";
  $("secrets-head").hidden = !grouped; $("secrets").hidden = !grouped;
  $("feed-head").hidden = grouped; $("feed").hidden = grouped;
  $("secrets-title").textContent = grouped ? "secrets" : "every appearance";
  if (!grouped) { renderFeed(filteredFindings()); return; }

  const inState = state.secretsState === "all" ? state.secrets : state.secrets.filter((x) => x.state === state.secretsState || (state.secretsState === "open" && x.reappeared));
  const rows = rankSecrets(inState.filter(matchesFilters));
  const el = $("secrets");
  $("secrets-count").textContent = `${fmtInt(rows.length)} ${state.secretsState === "all" ? "" : state.secretsState} ${rows.length === 1 ? "value" : "values"}${rows.length !== inState.length ? ` of ${fmtInt(inState.length)}` : ""}`;
  const unjudged = rows.filter((x) => x.verdict === "unjudged").length;
  const note = $("secrets-note");
  note.hidden = !unjudged;
  if (unjudged) {
    note.replaceChildren(`${fmtInt(unjudged)} of these are unreviewed — the local model has not looked at them yet. `,
      h("a", { href: "#model", onclick: (e) => { e.preventDefault(); runJudge(); } }, "run local review"));
  }
  if (!rows.length) {
    el.replaceChildren(h("div", { class: "empty-state" },
      inState.length ? "nothing matches these filters" : state.secrets.length ? `no ${state.secretsState} values` : state.findings.length ? "no secrets" : "nothing detected yet — scan first",
      inState.length ? h("button", { class: "btn small", onclick: () => $("f-clear").click() }, "clear filters") : null));
    return;
  }
  const out = [];
  for (const s of rows) {
    const acts = h("span", { class: "acts" });
    for (const [label, target] of [["mark rotated", "rotated"], ["not a secret", "dismissed"], ["reopen", "open"]]) {
      if (target === s.state && !s.reappeared) continue;
      if (target === "open" && s.state === "open") continue;
      acts.append(h("button", { class: "btn ghost", onclick: (e) => { e.stopPropagation(); setSecretState(s.fingerprint, target); } }, label));
    }
    const pillClass = s.reappeared ? "reappeared" : s.verdict === "unjudged" ? "unsure" : s.verdict;
    const row = h("div", { class: "srow" + (s.state === "open" || s.reappeared ? "" : " done"), role: "button", tabindex: 0,
      onclick: () => { state.secretOpen = state.secretOpen === s.fingerprint ? null : s.fingerprint; renderSecrets(); } },
      h("span", { class: "tag sev-" + s.severity }, sevShort(s.severity)),
      h("span", { class: "cat", title: s.category }, catLabel(s.category)),
      h("span", { class: "prev", title: s.preview }, s.preview),
      h("span", {}, pill(pillClass, s.reappeared ? "reappeared" : reviewLabel(s.verdict))),
      h("span", {}, `${s.sessions} · ${s.findings}×`),
      h("span", { class: "t" }, `${fmtDay(s.first_seen)} · ${fmtDay(s.last_seen)}`),
      h("span", { class: "src", title: (s.sources || []).map(srcLabel).join(", ") }, (s.sources || []).map(srcLabel).join(", ")),
      acts,
    );
    out.push(row);
    if (state.secretOpen === s.fingerprint) out.push(...secretDetail(s));
  }
  el.replaceChildren(...out);
}

// One secret's history: its lifetime strip, every appearance with where it sat, and what to do.
function secretDetail(s) {
  const apps = appearancesOf(s.fingerprint);
  const times = apps.map((a) => a.ts).filter(Boolean).map((x) => asDate(x).getTime());
  const axis = { min: times.length ? Math.min(...times) : Date.now() - 86400000, max: Date.now() };
  if (axis.max - axis.min < 3 * 86400000) axis.min = axis.max - 3 * 86400000;
  const strip = h("div", { class: "detail-strip" });
  lifetimeStrip(strip, s, apps, axis);
  requestAnimationFrame(() => lifetimeStrip(strip, s, apps, axis));
  const days = s.first_seen && s.last_seen ? daysBetween(s.first_seen, s.last_seen) : null;
  const life = days === null ? "" : `${days} day${days === 1 ? "" : "s"} between first and last appearance`;
  const table = h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "when"), h("th", {}, "origin"), h("th", {}, "where"), h("th", {}, "review"))),
    h("tbody", {}, ...apps.map((a) => h("tr", { class: s.state === "rotated" && s.updated_at && a.ts > s.updated_at ? "after" : "" },
      h("td", { class: "mono" }, fmtWhen(a.ts)),
      h("td", {}, srcLabel(a.source)),
      h("td", { class: "mono", title: a.path || "" }, a.path || shortProject(a.project) || "—"),
      h("td", {}, a.verdict ? [pill(a.verdict, reviewLabel(a.verdict)), a.reason ? h("div", { class: "muted" }, a.reason) : null] : h("span", { class: "muted" }, "unreviewed"))))));
  return [
    strip,
    h("div", { class: "apps" },
      h("div", { class: "muted", style: "margin-bottom:6px" }, `${plural(apps.length, "appearance", "appearances")} in ${plural(s.sessions, "session", "sessions")}${life ? " · " + life : ""}${s.state !== "open" ? ` · marked ${s.state} ${relTime(s.updated_at)}` : ""}`),
      table,
      h("div", { class: "rotation", style: "padding-left:0" },
        h("div", {}, h("b", {}, "what to do: "), s.rotation),
        h("div", { class: "muted" }, "fingerprint ", info("fingerprint"), ` ${s.fingerprint.slice(0, 16)}…  ·  raw value, on this machine only: claudit reveal <id>`),
        s.note ? h("div", { class: "muted" }, `note: ${s.note}`) : null)),
  ];
}

function renderFeed(rows) {
  const LIMIT = 400;
  const feed = $("feed");
  $("secrets-count").textContent = rows.length > LIMIT ? `${LIMIT} of ${fmtInt(rows.length)}` : `${fmtInt(rows.length)} appearance${rows.length === 1 ? "" : "s"}`;
  $("secrets-note").hidden = true;
  if (!rows.length) {
    const filtering = rows.length !== state.findings.length;
    feed.replaceChildren(h("div", { class: "empty-state" },
      filtering ? "nothing matches these filters" : "nothing detected yet — scan first",
      filtering ? h("button", { class: "btn small", onclick: () => $("f-clear").click() }, "clear filters")
                : h("button", { class: "btn accent small", onclick: runScan }, "scan transcripts")));
    return;
  }
  const out = [];
  for (const r of rows.slice(0, LIMIT)) {
    const verdict = r.verdict
      ? pill(r.verdict + (state.fresh.has(r.id) ? " fresh" : ""), reviewLabel(r.verdict))
      : h("span", { class: "muted" }, "—");
    const row = h("div", { class: "row", role: "button", tabindex: 0,
      onclick: () => { state.expanded = state.expanded === r.id ? null : r.id; renderFeed(filteredFindings()); } },
      h("span", { class: "t", title: r.ts ? asDate(r.ts).toLocaleString() : "" }, fmtWhen(r.ts)),
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
        h("div", {}, h("b", {}, "appearance "), h("span", { class: "mono" }, r.id), "  ·  session ", h("span", { class: "mono" }, r.session || "")),
        h("div", {}, h("b", {}, "project "), h("span", { class: "mono" }, r.project || ""), r.path ? ["  ·  ", h("b", {}, "file "), h("span", { class: "mono" }, r.path)] : null),
        r.verdict
          ? h("div", {}, h("b", {}, `${r.judged_by === "rules" ? "by rule" : "by the model"}: ${reviewLabel(r.verdict)}`), " — ", r.reason || "")
          : h("div", { class: "muted" }, "unreviewed"),
        h("div", { class: "muted mono" }, `raw value, on this machine only: claudit reveal ${r.id}`),
      ));
    }
  }
  feed.replaceChildren(...out);
}

// ---------- review tab ----------
function renderModel() {
  const judged = (state.summary.totals || {}).judged || 0;
  const empty = !state.job && !judged;
  $("model-empty").hidden = !empty;
  if (empty) {
    const n = state.findings.length;
    $("model-empty-body").replaceChildren(
      h("div", {}, n
        ? `Nothing reviewed yet. The review sends each ambiguous value, with a redacted window of context, to ${state.summary.model} on this machine and sorts it into likely real, likely fake or needs-you — about ten seconds per call. Vendor-format keys sitting in production files are marked likely real by rule without a call.`
        : "Nothing to review yet. Scan first."),
      n ? h("button", { class: "btn accent small", onclick: runJudge }, "run local review") : null,
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

function renderSemantic() {
  const items = state.summary.semantic || [];
  $("semantic-card").hidden = !items.length;
  $("semantic").querySelector("tbody").replaceChildren(
    ...items.map((x) => h("tr", {},
      h("td", {}, fmtWhen(x.ts)), h("td", {}, catLabel(x.kind)),
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
      h("td", {}, catLabel(r.category)), h("td", { class: "num" }, r.tp), h("td", { class: "num" }, r.fp), h("td", { class: "num" }, r.fn),
      h("td", { class: "num" }, fmtPct(r.precision)), h("td", { class: "num" }, fmtPct(r.recall)), h("td", { class: "num" }, fmtPct(r.f1))))
  );
  const j = e.judge;
  $("eval-judge-wrap").hidden = !j;
  if (j) {
    $("eval-acc").textContent = j.accuracy === null ? "" : `accuracy ${fmtPct(j.accuracy)} over ${j.judged} reviewed`;
    const expectedLabel = { confirmed: "real secret", "benign/seen": "fake, familiar wording", "benign/heldout": "fake, held-out wording" };
    $("eval-judge").querySelector("tbody").replaceChildren(
      ...j.rows.map((r) => h("tr", {}, h("td", {}, expectedLabel[r.expected] || r.expected), ...VERDICTS.map((v) => h("td", { class: "num" }, r[v]))))
    );
  }
}

// ---------- system tab ----------
function renderSystem() {
  const s = state.summary, hz = state.health;
  const dot = (ok) => h("span", { class: "hdot " + (ok ? "ok" : "down") });
  const row = (ok, k, ...txt) => h("div", { class: "sysrow" }, dot(ok), h("span", { class: "k" }, k, DEFINE[k] ? info(k) : null), h("span", { class: "txt" }, ...txt));
  const g = hz && hz.guard, gs = g && g.status;
  $("sys-rows").replaceChildren(
    row(!!s.last_scan, "transcripts",
      s.demo ? [h("b", {}, "synthetic demo data"), ", generated on this machine. "] : s.transcripts_default
        ? [h("b", {}, "Claude Code"), ", default location. "] : [h("b", {}, "Claude Code"), ", custom location ", h("code", { title: s.transcripts_dir }, s.transcripts_dir), ". "],
      `${plural(s.totals.sessions, "session", "sessions")}, ${fmtInt(s.totals.events)} messages, last read ${relTime(s.last_scan)}.`),
    row(!!(hz && hz.ollama.ok), "local model",
      hz && hz.ollama.ok ? [h("b", {}, s.model), ` via Ollama on this machine, answering in ${hz.ollama.ms} ms.`] : [h("b", {}, "unreachable"), ". Start the Ollama app; reviews resume where they stopped."]),
    row(!!(g && g.ok), "guard",
      g && g.ok
        ? [h("b", {}, "on"), `. ${fmtInt(gs ? gs.values_masked : 0)} values replaced with pseudonyms before requests left this machine, ${fmtInt(gs ? gs.values_restored : 0)} restored in replies`, gs && gs.blocked_writes ? `, ${fmtInt(gs.blocked_writes)} file writes blocked` : "", "."]
        : [h("b", {}, "off"), ". Requests from your coding assistant reach the provider unmasked. Start it with ", h("code", {}, "claudit guard"), " and point the assistant at it."]),
  );
  renderOps();
}

function renderOps() {
  const hz = state.health, m = state.metrics, s = state.summary;
  const row = (k, v) => h("div", { class: "ops-row" }, h("span", {}, k), h("span", { class: "v" }, v));
  const fill = (id, ...kids) => $(id).replaceChildren(...kids.flat().filter((c) => c !== null && c !== undefined));
  fill("ops-config",
    h("div", { class: "k" }, "storage"),
    row("database", h("span", { class: "v mono", title: s.db }, "local file")),
    row("transcripts", h("span", { class: "v mono", title: s.transcripts_dir }, s.transcripts_dir)),
    row("model", s.model),
  );
  const g = hz && hz.guard && hz.guard.status;
  fill("ops-guard",
    h("div", { class: "k" }, "guard counters · since it started"),
    g ? row("masked", fmtInt(g.values_masked)) : h("div", { class: "muted" }, "not running"),
    g ? row("restored in replies", fmtInt(g.values_restored)) : null,
    g ? row("suspected misses", fmtInt(g.suspected_misses)) : null,
    g ? row("blocked writes", fmtInt(g.blocked_writes)) : null,
  );
  const lat = m && m.latency;
  fill("ops-latency",
    h("div", { class: "k" }, "latency"),
    lat ? row("review p50 / p95", lat.judge_calls.n ? `${lat.judge_calls.p50_ms} / ${lat.judge_calls.p95_ms} ms  (n ${lat.judge_calls.n})` : "—") : null,
    lat ? row("contents p50 / p95", lat.semantic_segments.n ? `${lat.semantic_segments.p50_ms} / ${lat.semantic_segments.p95_ms} ms  (n ${lat.semantic_segments.n})` : "—") : null,
    lat ? row("scan p50 / max", lat.scans.n ? `${lat.scans.p50_ms} / ${lat.scans.max_ms} ms  (n ${lat.scans.n})` : "—") : null,
    ((m && m.by_model) || []).map((r) => row(`· ${r.model}`, `${r.p50_ms} / ${r.p95_ms} ms  (n ${r.n}${r.unparseable ? `, ${r.unparseable} errors` : ""})`)),
  );
  const runs = (m && m.runs) || [];
  fill("ops-runs",
    h("div", { class: "k" }, "recent runs"),
    runs.length ? runs.slice(0, 6).map((r) => row(`${fmtWhen(r.started_at)} ${r.kind}`, `${fmtInt(r.duration_ms)} ms`)) : h("div", { class: "muted" }, "no runs yet"),
  );
}

// ---------- actions ----------
async function runScan() {
  const btn = $("btn-scan");
  btn.disabled = true;
  setLive("busy", "scanning");
  try {
    const s = await api("/api/scan", { method: "POST" });
    toast(s.lines ? `read ${fmtInt(s.lines)} new lines · ${fmtInt(s.findings)} new appearances` : "nothing new since the last scan");
    await load();
  } catch (err) {
    toast("scan failed: " + err.message, 6000);
  } finally {
    btn.disabled = false;
    if (!state.job) setLive("ok", "connected");
  }
}

async function runJudge() {
  const btn = $("btn-judge");
  btn.disabled = true;
  const semantic = $("opt-semantic").checked;
  try {
    const { job } = await api(`/api/judge?semantic=${semantic}`, { method: "POST" });
    state.job = job;
    setLive("busy", "reviewing");
    showTab("model");
    $("model-empty").hidden = true;
    $("job").hidden = false;
    $("job-status").textContent = "starting";
    $("job-log").textContent = "";
    pollJob();
  } catch (err) {
    toast("could not start the review: " + err.message, 6000);
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
    setLive("down", "review failed");
    toast("review failed: " + j.error, 8000);
  } else {
    const s = j.result.judge;
    $("job-status").textContent = `done · ${(s.duration_ms / 1000).toFixed(0)}s model time`;
    toast(`reviewed ${s.judged}: ${s.confirmed} likely real · ${s.benign} likely fake · ${s.unsure} need you`, 8000);
    setLive("ok", "connected");
  }
  await load();
}

async function runSynth() {
  if (!confirm("Regenerate the demo data and rescan? Existing findings and verdicts will be cleared.")) return;
  const btn = $("btn-synth");
  btn.disabled = true;
  setLive("busy", "generating");
  try {
    const r = await api("/api/synth", { method: "POST" });
    state.seenVerdicts.clear();
    toast(`generated ${r.sessions} sessions · ${r.plants} planted secrets · ${r.scan.findings} appearances`);
    await load();
  } catch (err) {
    toast("failed: " + err.message, 6000);
  } finally {
    btn.disabled = false;
    if (!state.job) setLive("ok", "connected");
  }
}

// ---------- wiring ----------
for (const [id, key] of [["f-severity", "severity"], ["f-category", "category"], ["f-source", "source"], ["f-project", "project"], ["f-verdict", "verdict"]]) {
  $(id).addEventListener("change", (e) => { state.filters[key] = e.target.value; renderSecrets(); });
}
$("f-q").addEventListener("input", (e) => { state.filters.q = e.target.value; renderSecrets(); });
$("f-clear").addEventListener("click", () => {
  state.filters = { severity: "", category: "", source: "", project: "", verdict: "", q: "" };
  $("f-q").value = "";
  renderFilterOptions();
  renderSecrets();
});
$("secrets-state").addEventListener("change", (e) => { state.secretsState = e.target.value; renderSecrets(); });
for (const b of document.querySelectorAll(".segbtn")) {
  b.addEventListener("click", () => {
    state.view = b.dataset.view;
    for (const x of document.querySelectorAll(".segbtn")) x.classList.toggle("active", x === b);
    renderSecrets();
  });
}
for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => showTab(b.dataset.tab));
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
$("btn-scan").addEventListener("click", runScan);
$("btn-judge").addEventListener("click", runJudge);
$("btn-synth").addEventListener("click", runSynth);
let resizeTimer = null;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { renderCharts(state.findings); if (state.summary) renderLedger(); }, 150); });

for (const [id, keys] of [["secrets-head", ["severity", "type", null, "review", "sessions · times", null, "origin", null]], ["feed-head", [null, "severity", "type", null, "origin", null, "review"]]]) {
  const cells = $(id).children;
  keys.forEach((k, i) => { if (k && cells[i]) cells[i].append(info(k)); });
}
document.querySelector("label.toggle").append(info("contents"));
showTab(location.hash.slice(1) || "overview");
load().catch((err) => toast("failed to load: " + err.message, 8000));
