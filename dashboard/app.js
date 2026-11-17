"use strict";

const $ = (id) => document.getElementById(id);
const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const eventTypes = ["EXEC", "OPEN", "CONNECT", "DUP2", "SETUID", "PTRACE"];
const pages = ["overview", "coverage", "lab"];
const formatNumber = new Intl.NumberFormat();
const compactNumber = new Intl.NumberFormat(undefined, {notation: "compact"});
const formatTime = new Intl.DateTimeFormat(undefined, {timeStyle: "medium", hourCycle: "h23", timeZone: "UTC"});
const formatDate = new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short", hourCycle: "h23", timeZone: "UTC"});
const reviewKey = "runtime-watch.reviewed";
const filterByMode = {alerts: "", events: ""};
const localPreview = location.protocol === "file:";
const pageSize = 50;
let mode = "alerts";
let paused = false;
let stats = null;
let snapshot = null;
let feed = null;
let scope = null;
let focusFeed = false;
let currentMatches = [];
let pageIndex = 0;
let selection = null;
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
  if (localPreview) throw new Error("Open the dashboard through the Ubuntu VM’s published HTTP port.");
  const response = await fetch(path, {signal: AbortSignal.timeout(17000), ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function activePage() {
  const page = location.hash.slice(1);
  return pages.includes(page) ? page : "overview";
}

function showPage() {
  const active = activePage();
  for (const page of pages) $(page + "-view").hidden = active !== page;
  window.scrollTo(0, 0);
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
  const indicator = $("connection").lastElementChild;
  if (indicator.textContent !== label) indicator.textContent = label;
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
  const palette = getComputedStyle(chart);
  const labelColor = palette.getPropertyValue("--muted").trim();
  const gridColor = palette.getPropertyValue("--line").trim();

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
    ctx.fillStyle = labelColor;
    ctx.fillText(compactNumber.format(i * step), startX - 8, y);
    ctx.strokeStyle = gridColor;
    ctx.beginPath();
    ctx.moveTo(startX, y);
    ctx.lineTo(width - 2, y);
    ctx.stroke();
  }
  const bin = (width - startX - 3) / values.length;
  ctx.fillStyle = palette.getPropertyValue(metric ? "--chart-alerts" : "--accent").trim();
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
  $("probe-count").textContent = localPreview ? "Preview only" : probeLabel;
  $("last-sync").textContent = localPreview ? "—" : formatTime.format(new Date());
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
    case "CONNECT": {
      const address = record.dst_ip.includes(":") ? `[${record.dst_ip}]` : record.dst_ip;
      return `${address}:${record.dst_port} · FD ${record.fd} · result ${record.result}`;
    }
    case "DUP2": return `FD ${record.oldfd} → FD ${record.newfd}`;
    case "SETUID": return `Requested UID ${record.new_uid}`;
    case "PTRACE": return `Target namespace PID ${record.target_pid} · request ${record.request}`;
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
  clearSelection();
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

function renderEvidence(view, record, source, session) {
  const related = [];
  const summary = node("div", undefined, "evidence-summary");
  const badges = node("div", undefined, "evidence-badges");
  badges.append(pill(record.severity ?? record.type, record.severity));
  if (record.mitre) badges.append(node("span", record.mitre, "mono subtle"));
  summary.append(node("h3", record.rule ? ruleName(record.rule) : eventDetail(record), "evidence-heading"), badges);
  if (record.rule) summary.append(node("p", record.detail));

  const trigger = record.rule ? source?.events.find((event) => event.event_id === record.event_id) : record;
  const fields = node("dl", undefined, "evidence-grid");
  for (const [label, value] of [
    ["Process", record.comm], ["Host PID", record.pid], ["Parent PID", record.ppid],
    ["UID", record.uid], ["Cgroup ID", record.cgroup_id], ["Parent process", trigger?.parent_comm]
  ]) {
    if (value == null || value === "") continue;
    const field = node("div");
    field.append(node("dt", label), node("dd", value));
    fields.append(field);
  }

  const actions = node("div", undefined, "evidence-actions");
  if (record.rule) {
    const review = button("", () => {
      toggleReview(record, session);
      updateReviewButton();
    });
    function updateReviewButton() {
      const checked = reviewed.has(reviewId(record, session));
      review.textContent = checked ? "Undo review" : "Mark reviewed";
    }
    updateReviewButton();
    actions.append(review);
  }

  function closeAndPivot() {
    if ($("detail").open) $("detail").close();
    openFeed("events", {pid: record.pid, start: record.process_start ?? trigger.process_start, session});
  }
  if (session === stats?.session && (record.process_start ?? trigger?.process_start) != null) {
    actions.append(button("Process events", closeAndPivot));
  }

  const evidence = node("section", undefined, "evidence-section");
  evidence.append(node("h3", record.rule ? "Event timeline (UTC)" : "Event details (UTC)"));
  const timeline = node("ol", undefined, "timeline");
  for (const [label, id] of [["TCP connection", record.connect_event_id],
    [record.rule ? "Triggering event" : record.type, record.event_id]]) {
    if (id == null) continue;
    const event = record.rule ? source?.events.find((item) => item.event_id === id) : record;
    const row = node("li");
    row.append(node("strong", label));
    if (event) {
      if (record.rule) related.push(event);
      row.append(node("time", formatTime.format(new Date(event.ts * 1000))), node("p", eventDetail(event)));
    } else {
      row.append(node("p", `Event #${id} is outside the recent buffer.`));
    }
    timeline.append(row);
  }
  evidence.append(timeline);

  const exportData = {session, record, related_events: related};
  const raw = node("details");
  raw.append(node("summary", "Raw JSON"), node("pre", JSON.stringify(exportData, null, 2)));
  evidence.append(raw);
  actions.append(button("Export evidence", () => download("evidence", exportData)));
  view.replaceChildren(summary, fields, actions, evidence);
}

function showEvidence(record, source, session) {
  renderEvidence($("detail-content"), record, source, session);
  $("detail").showModal();
}

function recordKey(record) {
  return `${mode}/${record.alert_id ?? record.event_id}`;
}

function clearSelection() {
  selection = null;
  $("inspector-ref").textContent = "";
  $("inspector-content").replaceChildren(node("p", "Select a record to inspect its evidence.", "empty"));
}

function selectRecord(record, source, bringIntoView = false) {
  const session = source.stats.session;
  selection = {key: recordKey(record), session};
  const reference = record.rule ? `Alert #${record.alert_id}` : `Event #${record.event_id}`;
  $("inspector-ref").textContent = reference;
  renderEvidence($("inspector-content"), record, source, session);
  $("inspector-content").scrollTop = 0;
  for (const row of $("table-body").querySelectorAll("tr[data-record]")) {
    const selected = row.dataset.record === selection.key;
    row.dataset.selected = String(selected);
    row.querySelector("button").setAttribute("aria-pressed", String(selected));
  }
  if (bringIntoView && window.matchMedia("(max-width: 1100px)").matches) {
    $("inspector").scrollIntoView({block: "start"});
    $("inspector-title").focus({preventScroll: true});
  }
}

function resizePage(index = 0) {
  pageIndex = index;
  $("queue-scroll").scrollTop = 0;
  renderFeed();
}

function renderFeed() {
  if ($("overview-view").hidden) return;
  const alerts = mode === "alerts";
  const columns = alerts ? ["Severity", "Time (UTC)", "Detection", "Process", "ATT&CK", "Review"] :
    ["Type", "Time (UTC)", "Activity", "Process", "UID"];
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
  if (alerts && $("sort-feed").value === "severity") {
    currentMatches.sort((left, right) => levels.indexOf(left.severity) - levels.indexOf(right.severity));
  }
  pageIndex = Math.min(pageIndex, Math.max(0, Math.ceil(currentMatches.length / pageSize) - 1));
  const first = pageIndex * pageSize;
  const page = currentMatches.slice(first, first + pageSize);

  if (selection?.session !== session || (selection && !selection.key.startsWith(mode + "/"))) clearSelection();
  if (!selection && page.length) selectRecord(page[0], feed);

  const displayedFeed = feed;
  const rows = page.map((record) => {
    const row = node("tr");
    row.dataset.record = recordKey(record);
    row.dataset.selected = String(selection?.key === row.dataset.record);
    const timestamp = alerts ? new Date(record.timestamp) : new Date(record.ts * 1000);
    const timeCell = node("td", formatTime.format(timestamp), "mono subtle");
    timeCell.title = timestamp.toISOString();
    const category = node("td");
    category.append(pill(alerts ? record.severity : record.type, record.severity));
    const title = node("td");
    const open = button(alerts ? ruleName(record.rule) : eventDetail(record),
      () => selectRecord(record, displayedFeed, true), "cell-button");
    open.setAttribute("aria-pressed", row.dataset.selected);
    title.append(open);
    if (alerts) title.append(node("small", record.detail, "row-detail"));
    title.append(node("small", `${record.comm} · ${record.pid}`, "mobile-process mono"));
    const process = node("td", `${record.comm} · ${record.pid}`, "mono");
    process.title = `${record.comm} · PID ${record.pid}`;
    row.append(category, timeCell, title, process, node("td", alerts ? record.mitre : record.uid, "mono subtle"));
    if (alerts) {
      const cell = node("td");
      const isReviewed = reviewed.has(reviewId(record, session));
      const label = node("span", undefined, "status-label");
      label.dataset.reviewed = String(isReviewed);
      label.append(node("i", undefined, "review-dot"), node("span", isReviewed ? "Reviewed" : "Unreviewed"));
      cell.append(label);
      row.append(cell);
    }
    row.addEventListener("click", (event) => {
      if (!event.target.closest("button") && !window.getSelection().toString()) selectRecord(record, displayedFeed, true);
    });
    return row;
  });
  if (!rows.length) {
    const row = node("tr");
    const cell = node("td", !feed ? "Waiting for sensor data…" :
      filterScope || records.length ? "No recent records match your filters." :
        alerts ? "No alerts in this session." : "Waiting for the first kernel events.", "empty");
    cell.colSpan = columns.length;
    row.append(cell);
    rows.push(row);
  }
  $("table-body").replaceChildren(...rows);
  $("feed-count").textContent = page.length ?
    `${first + 1}–${first + page.length} of ${currentMatches.length} matching${paused ? " · Paused" : ""}` :
    `0 matching${paused ? " · Paused" : ""}`;
  $("page-prev").disabled = pageIndex === 0;
  $("page-next").disabled = first + pageSize >= currentMatches.length;
  $("export-feed").disabled = !currentMatches.length;
}

function changeMode(next) {
  mode = next;
  const alerts = mode === "alerts";
  $("alert-tab").setAttribute("aria-pressed", String(alerts));
  $("event-tab").setAttribute("aria-pressed", String(!alerts));
  $("review-filter").hidden = !alerts;
  $("sort-feed").hidden = !alerts;
  $("filter").setAttribute("aria-label", alerts ? "Filter by severity" : "Filter by event type");
  $("filter").replaceChildren(new Option(alerts ? "All severities" : "All event types", ""),
    ...(alerts ? levels : eventTypes).map((value) => new Option(value, value)));
  $("filter").value = filterByMode[mode];
  resizePage();
}

function setPaused(value) {
  paused = value;
  if (!paused) feed = snapshot;
  $("pause").querySelector("span").textContent = paused ? "Resume feed" : "Pause feed";
  $("pause").querySelector("use").setAttribute("href", paused ? "#i-play" : "#i-pause");
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
  const table = node("table");
  const headings = node("tr");
  headings.append(...["Rule", "Severity", "ATT&CK", "Alerts", "Last seen (UTC)"].map((label) => node("th", label)));
  const head = node("thead");
  head.append(headings);
  const rows = node("tbody");
  rows.append(...rules.map((rule) => {
    const totals = activity[rule.name];
    const name = node("td");
    const severity = node("td");
    name.append(totals
      ? button(ruleName(rule.name), () => openFeed("alerts", {rule: rule.name}), "text-button")
      : node("strong", ruleName(rule.name)),
      node("small", rule.description));
    severity.append(pill(rule.severity, rule.severity));
    const row = node("tr");
    row.append(name, severity, node("td", rule.mitre, "mono"),
      node("td", stats ? formatNumber.format(totals?.count ?? 0) : "—", "mono"),
      node("td", totals ? formatDate.format(new Date(totals.last_seen)) : "—", "subtle"));
    return row;
  }));
  table.append(head, rows);
  $("coverage-grid").replaceChildren(table);
}

function setRunControls() {
  const picker = $("scenario-select");
  const canRun = simulationsEnabled && Boolean(scenarios?.length) && !running;
  picker.disabled = !localPreview && (!scenarios?.length || running);
  $("run-selected").disabled = !canRun || !picker.value;
  $("run-suite").disabled = !canRun;
  $("scenarios").querySelectorAll(".run-scenario").forEach((run) => { run.disabled = !simulationsEnabled || running; });
}

async function loadScenarios() {
  if (loadingScenarios) return;
  const list = $("scenarios");
  if (localPreview) {
    $("scenario-preview").hidden = false;
    list.hidden = true;
    setRunControls();
    return;
  }
  loadingScenarios = true;
  list.replaceChildren(node("p", "Loading scenarios…", "empty"));
  try {
    const response = await api("/api/simulations");
    scenarios = response.scenarios;
    simulationsEnabled = response.enabled;
    $("scenario-select").replaceChildren(new Option("Select a scenario", ""),
      ...scenarios.map((scenario) => new Option(scenario.title, scenario.id)));
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
    row.append(node("strong", run.title), node("small", `${formatTime.format(new Date(run.completed_at))} UTC · ${runOutcome(run)}`));
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

$("search").addEventListener("input", () => resizePage());
$("filter").addEventListener("change", () => {
  filterByMode[mode] = $("filter").value;
  resizePage();
});
$("review-filter").addEventListener("change", () => resizePage());
$("sort-feed").addEventListener("change", () => resizePage());
$("page-prev").addEventListener("click", () => resizePage(pageIndex - 1));
$("page-next").addEventListener("click", () => resizePage(pageIndex + 1));
$("alert-tab").addEventListener("click", () => changeMode("alerts"));
$("event-tab").addEventListener("click", () => changeMode("events"));
$("clear-scope").addEventListener("click", () => {
  scope = null;
  resizePage();
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
$("scenario-select").addEventListener("change", () => {
  const selected = $("scenario-select").value;
  if (localPreview) {
    $("scenario-command").hidden = !selected;
    $("scenario-command").textContent = selected ? `./attacks/run_local_attacks.sh ${selected}` : "";
  }
  setRunControls();
});
$("run-selected").addEventListener("click", () => {
  const scenario = scenarios?.find((item) => item.id === $("scenario-select").value);
  if (scenario) runScenarios([scenario]);
});
$("run-suite").addEventListener("click", () => runScenarios(scenarios));
$("stop-suite").addEventListener("click", () => {
  stopRequested = true;
  $("stop-suite").disabled = true;
  $("suite-status").textContent = "Finishing the current scenario before stopping…";
});
$("chart-range").addEventListener("change", drawChart);
$("chart-metric").addEventListener("change", drawChart);
$("sidebar-toggle").addEventListener("click", () => {
  const toggle = $("sidebar-toggle");
  const collapsed = toggle.getAttribute("aria-expanded") === "true";
  $("app-shell").classList.toggle("sidebar-collapsed", collapsed);
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
});
window.addEventListener("hashchange", showPage);
new ResizeObserver(drawChart).observe($("chart"));
window.addEventListener("keydown", (event) => {
  if (event.key === "/" && activePage() === "overview" && !$("detail").open &&
      !event.target.closest("input, select, textarea, [contenteditable]")) {
    event.preventDefault();
    $("search").focus();
  }
});

function setupPreview() {
  const samples = [
    ["cron_persistence", "MEDIUM", "T1053.003", "crontab", 31592, "OPEN", {path: "/var/spool/cron/crontabs/deploy"}, "Requested write access to a user crontab"],
    ["netcat_execution", "MEDIUM", "T1059/T1071", "bash", 31714, "EXEC", {path: "/usr/bin/nc"}, "Requested execution of /usr/bin/nc"],
    ["shell_profile_write", "MEDIUM", "T1546.004", "python3", 31981, "OPEN", {path: "/home/deploy/.bashrc"}, "Requested write access to /home/deploy/.bashrc"],
    ["systemd_unit_write", "HIGH", "T1543.002", "python3", 31981, "OPEN", {path: "/etc/systemd/system/sync.service"}, "Requested write access to sync.service"],
    ["ssh_private_key_access", "MEDIUM", "T1552.004", "tar", 32204, "OPEN", {path: "/home/deploy/.ssh/id_ed25519"}, "Requested read access to a private key"],
    ["exec_from_tmp", "HIGH", "T1036/T1059", "bash", 32506, "EXEC", {path: "/tmp/update-agent"}, "Execution requested from a temporary directory"],
    ["suspicious_port_connect", "HIGH", "T1071", "bash", 32506, "CONNECT",
      {dst_ip: "198.51.100.24", dst_port: 4444, fd: 3, result: 0, socket_inode: "72418"}, "TCP connection to 198.51.100.24:4444"],
    ["reverse_shell_pattern", "CRITICAL", "T1059/T1071", "bash", 32506, "DUP2",
      {oldfd: 3, newfd: 1, socket_inode: "72418", connect_event_id: 7}, "TCP socket redirected to stdout after connecting to 198.51.100.24:4444"],
  ];
  const now = Math.floor(Date.now() / 1000);
  const alerts = [];
  const events = [];
  const severity = Object.fromEntries(levels.map((level) => [level, 0]));
  const ruleActivity = {};
  rules = [];
  samples.forEach(([rule, level, mitre, comm, pid, type, fields, detail], index) => {
    const ts = now - (samples.length - index) * 11 - (index === samples.length - 1 ? 10 : 0);
    const base = {comm, pid, ppid: 32411, uid: 1001, cgroup_id: "11483", process_start: pid * 1000};
    const eventId = index + 1;
    const timestamp = new Date(ts * 1000).toISOString();
    events.unshift({...base, ...fields, ts, type, event_id: eventId, parent_comm: "sshd"});
    alerts.unshift({...base, alert_id: eventId, event_id: eventId, timestamp, rule, severity: level,
      mitre, detail, connect_event_id: fields.connect_event_id});
    severity[level]++;
    ruleActivity[rule] = {count: 1, last_seen: timestamp};
    rules.push({name: rule, severity: level, mitre, description: detail});
  });
  const counts = [26, 34, 28, 40, 43, 30, 37, 33, 44, 40, 30, 37, 32, 40, 29, 38, 62, 45, 52, 91, 48, 39, 58, 28];
  const activity = Array.from({length: 180}, (_, index) => [counts[index % counts.length], 0]);
  for (const event of events) activity[179 - Math.floor((now - event.ts) / 5)][1]++;
  stats = {events: activity.reduce((total, [count]) => total + count, 0), alerts: alerts.length, severity,
    session: "sample-preview", activity_history: activity, dropped: 0, uptime_sec: 900,
    rules: rules.length, rule_activity: ruleActivity};
  snapshot = feed = {stats, alerts, events};
}

if (localPreview) setupPreview();
changeMode(mode);
showPage();
if (localPreview) {
  status("preview", "Sample data", "Local preview with sample telemetry. Open the dashboard at the Ubuntu VM’s published address to monitor the sensor.");
  renderStats();
} else {
  refresh();
}
