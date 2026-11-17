"use strict";

const $ = (id) => document.getElementById(id);
const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const eventTypes = ["EXEC", "OPEN", "CONNECT", "DUP2", "SETUID", "PTRACE"];
const pages = {overview: "Overview", coverage: "Rule coverage", lab: "Simulation lab"};
const formatNumber = new Intl.NumberFormat();
const compactNumber = new Intl.NumberFormat(undefined, {notation: "compact"});
const formatTime = new Intl.DateTimeFormat(undefined, {timeStyle: "medium"});
const formatDate = new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"});
const reviewKey = "runtime-watch.reviewed";
const filterByMode = {alerts: "", events: ""};
let mode = "alerts";
let paused = false;
let stats = null;
let snapshot = null;
let feed = null;
let scope = null;
let focusFeed = false;
let currentMatches = [];
let rules = null;
let coverageSignature = "";
let loadingCoverage = false;
let scenarios = null;
let simulationsEnabled = false;
let loadingScenarios = false;
let running = false;
let stopRequested = false;
const history = [];

function loadReviewed() {
  try {
    const entries = JSON.parse(localStorage.getItem(reviewKey));
    return new Set(Array.isArray(entries) ? entries.filter((entry) => typeof entry === "string").slice(-1000) : []);
  } catch {
    return new Set();
  }
}

const reviewed = loadReviewed();

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function button(text, action, className = "button quiet") {
  const element = node("button", text, className);
  element.type = "button";
  element.addEventListener("click", action);
  return element;
}

async function api(path, options) {
  const response = await fetch(path, {signal: AbortSignal.timeout(17000), ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function activePage() {
  const page = location.hash.slice(1);
  return Object.hasOwn(pages, page) ? page : "overview";
}

function showPage() {
  const active = activePage();
  for (const page of Object.keys(pages)) $(page + "-view").hidden = active !== page;
  window.scrollTo(0, 0);
  $("breadcrumb").textContent = pages[active];
  document.querySelectorAll("nav a").forEach((link) => {
    if (link.hash === `#${active}`) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (active === "overview") {
    renderFeed();
    drawChart();
    if (focusFeed) jumpToFeed();
  } else if (active === "coverage") {
    if (!rules) loadCoverage();
    else renderCoverage();
  } else if (!scenarios) {
    loadScenarios();
  }
}

function status(state, label, note = "") {
  $("connection").dataset.state = state;
  $("connection").lastElementChild.textContent = label;
  $("connection-note").hidden = !note;
  $("connection-note").textContent = note;
  if (state === "offline") {
    $("probe-count").textContent = "Sensor unavailable";
  }
}

function duration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds / 60) % 60}m`;
}

function drawChart() {
  const chart = $("chart");
  const {width, height} = chart.getBoundingClientRect();
  if (!width) return;
  const ratio = window.devicePixelRatio || 1;
  chart.width = Math.round(width * ratio);
  chart.height = Math.round(height * ratio);
  const ctx = chart.getContext("2d");
  ctx.scale(ratio, ratio);

  const minutes = Number($("chart-range").value);
  const metric = Number($("chart-metric").value);
  const group = {2: 1, 5: 2, 15: 6}[minutes];
  const bins = minutes * 12;
  const activity = stats?.activity_history ?? stats?.activity ?? [];
  const values = Array.from({length: bins / group}, (_, index) => {
    const start = activity.length - bins + index * group;
    let sum = 0;
    for (let i = 0; i < group; i++) sum += activity[start + i]?.[metric] ?? 0;
    return sum;
  });
  const label = metric ? "Alerts" : "Events";
  $("chart-unit").textContent = `${label} per ${group * 5} seconds`;
  $("chart-from").textContent = `${minutes} min ago`;

  const peak = Math.max(...values);
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(peak, 4) / 4));
  const step = Math.ceil(Math.max(peak, 4) / (4 * magnitude)) * magnitude;
  const startX = 39;
  const top = 10;
  const bottom = height - 9;
  ctx.font = "11px system-ui";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let i = 0; i <= 4; i++) {
    const y = bottom - i * (bottom - top) / 4;
    ctx.fillStyle = "#596782";
    ctx.fillText(compactNumber.format(i * step), startX - 8, y);
    ctx.strokeStyle = "#e7ebf3";
    ctx.beginPath();
    ctx.moveTo(startX, y);
    ctx.lineTo(width - 2, y);
    ctx.stroke();
  }
  const bin = (width - startX - 3) / values.length;
  const fill = ctx.createLinearGradient(0, top, 0, bottom);
  fill.addColorStop(0, metric ? "#e16886" : "#6464ec");
  fill.addColorStop(1, metric ? "#f3b2c0" : "#b1b1fa");
  ctx.fillStyle = fill;
  values.forEach((value, index) => {
    const bar = (bottom - top) * value / (step * 4);
    ctx.fillRect(startX + index * bin + 2, bottom - bar, Math.max(1, bin - 4), bar);
  });
  chart.setAttribute("aria-label", `${label} per ${group * 5} seconds. Peak ${peak} in the last ${minutes} minutes.`);
}

function renderStats() {
  $("events-count").textContent = formatNumber.format(stats.events);
  $("alerts-count").textContent = formatNumber.format(stats.alerts);
  $("critical-count").textContent = formatNumber.format(stats.severity.CRITICAL);
  $("uptime").textContent = duration(stats.uptime_sec);
  $("rules-count").textContent = `${Object.keys(stats.rule_activity ?? {}).length} of ${stats.rules} rules observed`;
  $("lost-count").textContent = `${formatNumber.format(stats.dropped)} perf records lost`;
  $("lost-count").classList.toggle("warning-text", stats.dropped > 0);
  const probeLabel = stats.ready ? `${stats.probes} probes attached` : "Waiting for probes";
  $("probe-count").textContent = probeLabel;
  $("last-sync").textContent = formatTime.format(new Date());
  const segments = $("severity-track").querySelectorAll("span");
  levels.forEach((level, index) => {
    const count = stats.severity[level];
    $("severity-" + level).textContent = formatNumber.format(count);
    segments[index].hidden = !count;
    segments[index].style.flexBasis = `${stats.alerts ? 100 * count / stats.alerts : 0}%`;
  });
  if (activePage() === "coverage") renderCoverage();
  if (activePage() === "overview") drawChart();
}

function ruleName(rule) {
  return rule.replaceAll("_", " ").replace(/\bssh\b/g, "SSH").replace("webserver", "web server")
    .replace(/^./, (first) => first.toUpperCase());
}

function pill(text, severity) {
  const badge = node("span", text, "pill");
  if (severity) badge.dataset.level = severity;
  return badge;
}

function eventDetail(record) {
  switch (record.type) {
    case "EXEC":
    case "OPEN": return record.path || "Path unavailable";
    case "CONNECT": return `${record.dst_ip}:${record.dst_port} · FD ${record.fd} · result ${record.result}`;
    case "DUP2": return `FD ${record.oldfd} → FD ${record.newfd}`;
    case "SETUID": return `Requested UID ${record.new_uid}`;
    case "PTRACE": return `Target PID ${record.target_pid} · request ${record.request}`;
    default: return "Details unavailable";
  }
}

function reviewId(record, session) {
  return `${session}/${record.alert_id}`;
}

function toggleReview(record, session) {
  const key = reviewId(record, session);
  if (!reviewed.delete(key)) reviewed.add(key);
  if (reviewed.size > 1000) reviewed.delete(reviewed.values().next().value);
  try {
    localStorage.setItem(reviewKey, JSON.stringify([...reviewed]));
  } catch {
    // The current tab can still hold review state when browser storage is disabled.
  }
  renderFeed();
}

function download(name, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `runtime-watch-${name}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function jumpToFeed() {
  focusFeed = false;
  $("investigation").scrollIntoView({block: "start"});
  $("search").focus({preventScroll: true});
}

function openFeed(next, selection, severity = "") {
  scope = selection;
  $("search").value = "";
  $("review-filter").value = "";
  filterByMode[next] = severity;
  if (snapshot && scope?.session && feed?.stats.session !== scope.session) {
    setPaused(false);
  }
  changeMode(next);
  if (activePage() === "overview") jumpToFeed();
  else {
    focusFeed = true;
    location.hash = "overview";
  }
}

function showEvidence(record, source, session) {
  const view = $("detail-content");
  const actions = $("detail-actions");
  view.replaceChildren();
  actions.replaceChildren();
  $("detail-title").textContent = record.rule ? ruleName(record.rule) : `${record.type} event`;

  const related = [];
  if (record.rule) {
    const review = button("", () => {
      toggleReview(record, session);
      updateReviewButton();
    });
    function updateReviewButton() {
      const checked = reviewed.has(reviewId(record, session));
      review.textContent = checked ? "Reviewed · undo" : "Mark reviewed";
    }
    updateReviewButton();
    actions.append(review);
    view.append(node("p", record.detail), node("h3", "Detection"), node("pre", JSON.stringify(record, null, 2)));
    for (const [label, id] of [["Triggering event", record.event_id], ["Correlated connection", record.connect_event_id]]) {
      if (!id) continue;
      const evidence = source?.events.find((item) => item.event_id === id);
      if (evidence) related.push(evidence);
      view.append(node("h3", label), evidence
        ? node("pre", JSON.stringify(evidence, null, 2))
        : node("p", `Event #${id} is outside the recent event buffer.`, "subtle"));
    }
  } else {
    view.append(node("p", eventDetail(record)), node("pre", JSON.stringify(record, null, 2)));
  }
  const process = record.process_start ?? related[0]?.process_start;
  if (session === stats?.session && process != null) {
    actions.append(button(`Events for PID ${record.pid}`, () => {
      $("detail").close();
      openFeed("events", {pid: record.pid, start: process, session});
    }));
  }
  actions.append(button("Export evidence", () => download("evidence", {session, record, related_events: related})));
  $("detail").showModal();
}

function renderFeed() {
  if ($("overview-view").hidden) return;
  const alerts = mode === "alerts";
  const columns = alerts ? ["Time", "Severity", "Detection", "Process", "MITRE ATT&CK"] :
    ["Time", "Type", "Activity", "Process", "UID"];
  const header = node("tr");
  header.append(...columns.map((label) => node("th", label)));
  $("table-head").replaceChildren(header);

  const records = feed?.[mode] ?? [];
  const session = feed?.stats.session;
  const query = $("search").value.trim().toLowerCase();
  const value = $("filter").value;
  const review = $("review-filter").value;
  const filterScope = alerts ? Boolean(scope?.rule) : scope?.pid != null;
  $("scope").hidden = !filterScope;
  if (filterScope) $("scope-label").textContent = scope.rule ? `Rule · ${ruleName(scope.rule)}` : `Process · PID ${scope.pid}`;
  currentMatches = records.filter((record) => {
    if (value && record[alerts ? "severity" : "type"] !== value) return false;
    if (filterScope && scope.rule && record.rule !== scope.rule) return false;
    if (filterScope && scope.pid != null &&
        (session !== scope.session || record.pid !== scope.pid || record.process_start !== scope.start)) return false;
    if (alerts && review && reviewed.has(reviewId(record, session)) !== (review === "reviewed")) return false;
    const text = [record.pid, record.comm, record.cgroup_id, alerts ? ruleName(record.rule) : eventDetail(record),
      alerts ? record.detail : record.type, record.rule, record.mitre].join(" ").toLowerCase();
    return !query || text.includes(query);
  });
  const rows = currentMatches.slice(0, 100).map((record) => {
    const row = node("tr");
    const timestamp = alerts ? new Date(record.timestamp) : new Date(record.ts * 1000);
    const timeCell = node("td", formatTime.format(timestamp), "subtle");
    timeCell.title = timestamp.toISOString();
    const category = node("td");
    category.append(pill(alerts ? record.severity : record.type, record.severity));
    const title = node("td");
    const currentFeed = feed;
    title.append(button(alerts ? ruleName(record.rule) : eventDetail(record),
      () => showEvidence(record, currentFeed, session), "cell-button"));
    if (alerts) {
      title.append(node("small", record.detail));
      if (reviewed.has(reviewId(record, session))) title.append(node("small", "Reviewed", "reviewed-label"));
    }
    const process = node("td", `${record.comm} · ${record.pid}`);
    row.append(timeCell, category, title, process, node("td", alerts ? record.mitre : record.uid, "subtle"));
    return row;
  });
  if (!rows.length) {
    const row = node("tr");
    const cell = node("td", !feed ? "Waiting for sensor data…" :
      filterScope || records.length ? "No recent records match your filters." :
        alerts ? "No alerts in this session. Run a simulation to verify a rule." :
          "Waiting for the first kernel events.", "empty");
    cell.colSpan = columns.length;
    row.append(cell);
    rows.push(row);
  }
  $("table-body").replaceChildren(...rows);
  $("feed-count").textContent = `${Math.min(currentMatches.length, 100)} shown · ${currentMatches.length} matching · ${records.length} recent ${mode}${paused ? " · Paused" : ""}`;
  $("export-feed").disabled = !currentMatches.length;
}

function changeMode(next) {
  mode = next;
  const alerts = mode === "alerts";
  $("alert-tab").setAttribute("aria-pressed", String(alerts));
  $("event-tab").setAttribute("aria-pressed", String(!alerts));
  $("review-filter").hidden = !alerts;
  $("filter").setAttribute("aria-label", alerts ? "Filter by severity" : "Filter by event type");
  $("filter").replaceChildren(new Option(alerts ? "All severities" : "All event types", ""),
    ...(alerts ? levels : eventTypes).map((value) => new Option(value, value)));
  $("filter").value = filterByMode[mode];
  renderFeed();
}

function setPaused(value) {
  paused = value;
  if (!paused) feed = snapshot;
  $("pause").textContent = paused ? "Resume feed" : "Pause feed";
  $("pause").setAttribute("aria-pressed", String(paused));
  renderFeed();
}

async function refresh() {
  try {
    const previousSession = stats?.session;
    if (activePage() === "overview") {
      snapshot = await api("/api/snapshot");
      stats = snapshot.stats;
      if (!paused && !$("table-body").contains(document.activeElement)) {
        feed = snapshot;
        if (scope?.session && scope.session !== stats.session) scope = null;
        renderFeed();
      }
    } else {
      stats = await api("/api/stats");
    }
    if (previousSession && previousSession !== stats.session) {
      rules = null;
      coverageSignature = "";
      if (activePage() === "coverage") loadCoverage();
    }
    status(stats.ready ? "live" : "connecting", stats.ready ? "Sensor live" : "Starting sensor");
    renderStats();
  } catch {
    status("offline", "Sensor offline", "Dashboard could not reach the sensor. Check the detector service and its logs.");
  } finally {
    setTimeout(refresh, 1500);
  }
}

async function loadCoverage() {
  if (loadingCoverage) return;
  loadingCoverage = true;
  $("coverage-totals").textContent = "Loading rule coverage…";
  $("coverage-grid").replaceChildren();
  try {
    rules = await api("/api/rules");
    renderCoverage();
  } catch {
    $("coverage-totals").textContent = "Could not load rule coverage.";
    $("coverage-grid").append(button("Retry", loadCoverage));
  } finally {
    loadingCoverage = false;
  }
}

function renderCoverage() {
  if (!rules) return;
  const activity = stats?.rule_activity ?? {};
  const signature = JSON.stringify([stats?.session, activity]);
  if (coverageSignature === signature) return;
  coverageSignature = signature;
  const observed = Object.keys(activity).length;
  $("coverage-totals").textContent = stats ? `${observed} of ${rules.length} rules observed` : "Waiting for sensor counts";
  $("coverage-progress").max = Math.max(1, rules.length);
  $("coverage-progress").value = observed;
  $("coverage-grid").replaceChildren(...rules.map((rule) => {
    const totals = activity[rule.name];
    const card = node("article", undefined, "panel rule-card");
    const meta = node("div", undefined, "rule-meta");
    meta.append(pill(rule.severity, rule.severity), node("small", rule.mitre));
    const details = node("div", undefined, "rule-details");
    details.append(node("strong", totals ? `${formatNumber.format(totals.count)} ${totals.count === 1 ? "alert" : "alerts"}` :
      stats ? "No alerts observed" : "Waiting for sensor"));
    if (totals) details.append(node("small", `Last seen ${formatDate.format(new Date(totals.last_seen))}`));
    card.append(meta, node("h2", ruleName(rule.name)), node("p", rule.description), details);
    if (totals) card.append(button("View recent alerts", () => openFeed("alerts", {rule: rule.name}), "text-button"));
    return card;
  }));
}

function setRunControls() {
  $("run-suite").disabled = !simulationsEnabled || !scenarios?.length || running;
  $("scenarios").querySelectorAll(".run-scenario").forEach((run) => { run.disabled = !simulationsEnabled || running; });
}

async function loadScenarios() {
  if (loadingScenarios) return;
  loadingScenarios = true;
  const list = $("scenarios");
  list.replaceChildren(node("p", "Loading scenarios…", "empty"));
  try {
    const response = await api("/api/simulations");
    scenarios = response.scenarios;
    simulationsEnabled = response.enabled;
    list.replaceChildren();
    if (!simulationsEnabled) list.append(node("p", "Browser simulations are disabled on this deployment.", "empty"));
    for (const scenario of scenarios) {
      const row = node("div", undefined, "scenario");
      const description = node("div");
      description.append(node("h3", scenario.title), node("p", scenario.description),
        pill(scenario.severity, scenario.severity), node("small", scenario.mitre));
      const run = button("Run", () => runScenarios([scenario]), "button quiet run-scenario");
      run.setAttribute("aria-label", `Run ${scenario.title}`);
      row.append(description, run);
      list.append(row);
    }
    setRunControls();
  } catch {
    const message = node("div", undefined, "empty");
    message.append(node("p", "Could not load simulations."), button("Retry", loadScenarios));
    list.replaceChildren(message);
  } finally {
    loadingScenarios = false;
  }
}

function runOutcome(entry) {
  const {result} = entry;
  if (!result) return "Request failed";
  if (result.exit_code !== 0) return `Exited with code ${result.exit_code}`;
  return result.detections.length === result.expected_rules.length ? "All expected rules fired" :
    `Observed ${result.detections.length} of ${result.expected_rules.length} expected rules`;
}

function showRun(entry) {
  const output = $("run-result");
  const {result} = entry;
  output.replaceChildren(node("h3", entry.title), node("p", runOutcome(entry)));
  if (!result) {
    output.append(node("p", entry.error, "warning-text"));
    return;
  }
  const list = node("ul");
  for (const name of result.expected_rules) {
    const evidence = result.detections.find((alert) => alert.rule === name);
    const row = node("li");
    if (evidence) {
      row.append(button(ruleName(name), () => showEvidence(evidence, result, result.session), "cell-button"),
        node("small", " · observed"));
    } else {
      row.textContent = `${ruleName(name)} · no match observed`;
    }
    list.append(row);
  }
  output.append(list);
  if (result.output) output.append(node("pre", result.output));
}

function addRun(entry) {
  history.unshift(entry);
  if (history.length > 30) history.pop();
  $("export-runs").disabled = false;
  $("run-history").replaceChildren(...history.map((run) => {
    const row = button(undefined, () => showRun(run), "history-row");
    row.append(node("strong", run.title), node("small", `${formatTime.format(new Date(run.completed_at))} · ${runOutcome(run)}`));
    return row;
  }));
  showRun(entry);
}

async function runScenarios(queue) {
  if (running || !simulationsEnabled || !queue.length) return;
  running = true;
  stopRequested = false;
  const suite = queue.length > 1;
  const output = $("run-result");
  $("suite-progress").hidden = !suite;
  $("stop-suite").hidden = !suite;
  $("stop-suite").disabled = false;
  $("suite-bar").max = queue.length;
  $("suite-bar").value = 0;
  setRunControls();
  let completed = 0;
  let passed = 0;
  try {
    for (const scenario of queue) {
      if (stopRequested) break;
      if (suite) $("suite-status").textContent = `Running ${completed + 1} of ${queue.length} · ${scenario.title}`;
      output.replaceChildren(node("p", `Running ${scenario.title}…`, "subtle"));
      if (!suite && window.matchMedia("(max-width: 680px)").matches) output.scrollIntoView({block: "nearest"});
      const entry = {scenario: scenario.id, title: scenario.title, expected_rules: scenario.rules};
      try {
        entry.result = await api(`/api/attack/${scenario.id}`, {method: "POST", headers: {"X-Lab-Action": "simulate"}});
        if (entry.result.exit_code === 0 && entry.result.detections.length === entry.result.expected_rules.length) passed++;
      } catch (error) {
        entry.error = error.message;
      }
      entry.completed_at = new Date().toISOString();
      addRun(entry);
      $("suite-bar").value = ++completed;
    }
  } finally {
    if (suite) $("suite-status").textContent = `${completed < queue.length ? "Stopped" : "Finished"} · ${completed} of ${queue.length} run · ${passed} fully verified`;
    $("stop-suite").hidden = true;
    running = false;
    setRunControls();
  }
}

$("search").addEventListener("input", renderFeed);
$("filter").addEventListener("change", () => {
  filterByMode[mode] = $("filter").value;
  renderFeed();
});
$("review-filter").addEventListener("change", renderFeed);
$("alert-tab").addEventListener("click", () => changeMode("alerts"));
$("event-tab").addEventListener("click", () => changeMode("events"));
$("clear-scope").addEventListener("click", () => {
  scope = null;
  renderFeed();
});
$("critical-filter").addEventListener("click", () => openFeed("alerts", null, "CRITICAL"));
document.querySelectorAll("[data-severity]").forEach((item) =>
  item.addEventListener("click", () => openFeed("alerts", null, item.dataset.severity)));
$("pause").addEventListener("click", () => setPaused(!paused));
$("export-feed").addEventListener("click", () => download(mode, {
  session: feed.stats.session, view: mode, exported_at: new Date().toISOString(),
  records: mode === "alerts" ? currentMatches.map((record) => ({
    ...record, reviewed: reviewed.has(reviewId(record, feed.stats.session))
  })) : currentMatches
}));
$("export-runs").addEventListener("click", () => download("simulation-runs", {runs: history}));
$("run-suite").addEventListener("click", () => runScenarios(scenarios));
$("stop-suite").addEventListener("click", () => {
  stopRequested = true;
  $("stop-suite").disabled = true;
  $("suite-status").textContent = "Finishing the current scenario before stopping…";
});
$("chart-range").addEventListener("change", drawChart);
$("chart-metric").addEventListener("change", drawChart);
window.addEventListener("hashchange", showPage);
new ResizeObserver(drawChart).observe($("chart"));
changeMode(mode);
showPage();
refresh();
