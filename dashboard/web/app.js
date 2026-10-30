"use strict";
const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const HOUR = 3600000;
const names = {
  "chompedr-ssh.service": "SSH",
  "chompedr-processes.service": "Processes",
  "chompedr-files.service": "Files",
  "chompedr-response.service": "Responses",
  "chompedr-dashboard.service": "Dashboard"
};
const descriptions = {
  "chompedr-ssh.service": "Authentication events and grouped failure detection.",
  "chompedr-processes.service": "Periodic /proc snapshots and executable location review.",
  "chompedr-files.service": "Metadata changes on selected files and directories.",
  "chompedr-response.service": "Response queue, approvals and action execution.",
  "chompedr-dashboard.service": "Local web interface and authenticated response decisions."
};
const COLLECTOR_UNITS = ["chompedr-ssh.service", "chompedr-processes.service", "chompedr-files.service"];
const views = {
  responses: ["Response management", "Review actions, approve requests, and inspect execution history.", "Responses"],
  alerts: ["Alert activity", "Investigate detections from your competition endpoint.", "Alerts"],
  rules: ["Detection rules", "Inspect bundled detections and their source definitions.", "Detection rules"],
  collectors: ["Endpoint collectors", "Inspect service state, restarts, and launch configuration.", "Collectors"],
  logs: ["Collector diagnostics", "Review the signals behind collection and detection.", "Diagnostics"]
};
const viewOrder = ["alerts", "responses", "rules", "collectors", "logs"];
const searchFor = {alerts: "alert-search", responses: "response-search", rules: "rule-search", logs: "log-search"};
const severityOrder = ["critical", "high", "medium", "low"];
const severityRank = {critical: 4, high: 3, medium: 2, low: 1};
const statusLabels = {pending: "Pending", queued: "Queued", executing: "Executing", succeeded: "Succeeded", failed: "Failed",
  rejected: "Rejected", dry_run: "Dry run", active: "Active", paused: "Paused", disabled: "Disabled"};
// Only triage state and the notification preference are stored; the management token never is.
const STORAGE = {reviewed: "chomp.reviewed.v1", notify: "chomp.notify.v1"};
const PROBLEM = /\b(error|errors|fail|failed|failure|denied|warn|warning|panic|refused|unavailable|timed out)\b/i;

let data = null;
let paused = false;
let loading = false;
let lastSuccess = 0;
let activeView = "alerts";
let deciding = false;
let hourFilter = null;
let knownAlerts = null;
let detailCopy = "";
let toastTimer = 0;
const newAlerts = new Set();
const sort = {key: "time", dir: -1};
const signatures = {};
const reviewed = new Set(storageGet(STORAGE.reviewed, []));
let notify = storageGet(STORAGE.notify, false) === true;

function storageGet(key, fallback) {
  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : JSON.parse(value);
  } catch (error) {
    return fallback;
  }
}
function storageSet(key, value) {
  try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (error) { /* storage disabled */ }
}
function saveReviewed() {
  // Keep storage bounded: drop reviewed keys no longer in the retained window.
  if (data && !data.loading && reviewed.size > 1000) {
    const present = new Set(data.alerts.map(alertKey));
    for (const key of reviewed) if (!present.has(key)) reviewed.delete(key);
  }
  storageSet(STORAGE.reviewed, [...reviewed].slice(-2000));
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
function svg(tag, attributes) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes || {})) element.setAttribute(name, String(value));
  return element;
}
function text(value, fallback = "—") {
  return typeof value === "string" || typeof value === "number" ? String(value) : fallback;
}
function badge(value) {
  const safe = ["critical", "high", "medium", "low", "active", "inactive", "failed"].includes(value) ? value : "unknown";
  return node("span", text(value, "unknown"), "badge " + safe);
}
function statusBadge(value) {
  const tone = {pending: "medium", queued: "low", executing: "low", succeeded: "active", active: "active",
    failed: "failed", rejected: "inactive", paused: "medium"}[value] || "unknown";
  return node("span", statusLabels[value] || text(value, "unknown"), "badge " + tone);
}
function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.hidden = true; }, 3200);
}
function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const link = node("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    toast("Copied to clipboard.");
  } catch (error) {
    const range = document.createRange();
    range.selectNodeContents($("detail-content"));
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    toast("Clipboard unavailable; the content is selected for manual copy.");
  }
}

/* ---------- Detail dialog ---------- */
function detail(label, title, content, extras = {}) {
  $("detail-label").textContent = label;
  $("detail-title").textContent = text(title, "Details");
  detailCopy = typeof content === "string" ? content : JSON.stringify(content, null, 2);
  $("detail-content").textContent = detailCopy;
  const summary = $("detail-summary");
  const fields = (extras.fields || []).filter(([, value]) => value !== undefined && value !== null && value !== "");
  summary.replaceChildren(...fields.map(([name, value]) => {
    const pair = node("div");
    const dd = node("dd");
    if (value instanceof Node) dd.append(value); else dd.textContent = String(value);
    pair.append(node("dt", name), dd);
    return pair;
  }));
  summary.hidden = fields.length === 0;
  const actions = $("detail-actions");
  actions.replaceChildren(...(extras.actions || []).map(([name, handler]) => {
    const button = node("button", name, "button");
    button.addEventListener("click", handler);
    return button;
  }));
  actions.hidden = !(extras.actions || []).length;
  if (!$("detail").open) $("detail").showModal();
  $("detail").scrollTop = 0;
}
function closeDetail() { if ($("detail").open) $("detail").close(); }

/* ---------- Time helpers ---------- */
function timeValue(alert) {
  const timestamp = alert.event && alert.event.timestamp;
  if (typeof timestamp === "string") return new Date(timestamp);
  return new Date(Number(alert.observed_at_us) / 1000);
}
function formatTime(value) {
  const date = value instanceof Date ? value : new Date(Number(value) / 1000);
  return Number.isFinite(date.getTime()) ? date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "Unknown time";
}
function fullTime(value) {
  return Number.isFinite(value.getTime()) ? value.toLocaleString() : "Unknown timestamp";
}
function ago(value) {
  const ms = Date.now() - (value instanceof Date ? value.getTime() : value);
  if (!Number.isFinite(ms)) return "";
  if (ms < 0) return "just now";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h " + Math.floor((seconds % 3600) / 60) + "m ago";
  return Math.floor(seconds / 86400) + "d ago";
}
function hourLabel(ms) {
  return new Date(ms).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
}
function sourceUnavailable(source) {
  return data && data.sources[source] && !data.sources[source].ok;
}

/* ---------- Alert helpers ---------- */
function alertKey(alert) {
  if (typeof alert.journal_cursor === "string") return alert.journal_cursor;
  return [alert.rule_id, alert.observed_at_us, text(alert.alert_id, "")].join("|");
}
function evidence(alert) {
  const event = alert.event || {};
  const candidates = [
    ["Source IP", event.source && event.source.ip],
    ["File", event.file && event.file.path],
    ["Process", event.process && event.process.executable],
    ["User", event.user && event.user.name]
  ];
  for (const [kind, value] of candidates) {
    if (typeof value === "string" || typeof value === "number") return {kind, value: String(value)};
  }
  return null;
}
function alertFilters() {
  return {
    search: $("alert-search").value.toLowerCase().trim(),
    severity: $("severity").value,
    collector: $("collector").value,
    range: $("range").value,
    hideReviewed: $("hide-reviewed").checked
  };
}
function matchingAlerts(options = {}) {
  const filters = alertFilters();
  const now = Date.now();
  return (data ? data.alerts : []).filter((alert) => {
    if (filters.severity === "high+") {
      if (alert.severity !== "high" && alert.severity !== "critical") return false;
    } else if (filters.severity && alert.severity !== filters.severity) return false;
    if (filters.collector && alert.collector_unit !== filters.collector) return false;
    if (filters.hideReviewed && reviewed.has(alertKey(alert))) return false;
    if (!options.ignoreTime) {
      const time = timeValue(alert).getTime();
      if (filters.range && !(time >= now - Number(filters.range) * HOUR)) return false;
      if (hourFilter !== null && !(time >= hourFilter && time < hourFilter + HOUR)) return false;
    }
    return !filters.search || JSON.stringify(alert).toLowerCase().includes(filters.search);
  });
}
function sortedAlerts(rows) {
  const value = {
    time: (alert) => timeValue(alert).getTime() || 0,
    severity: (alert) => severityRank[alert.severity] || 0,
    detection: (alert) => text(alert.rule_name, text(alert.rule_id, "")).toLowerCase(),
    evidence: (alert) => { const item = evidence(alert); return item ? item.value.toLowerCase() : "~"; },
    source: (alert) => (names[alert.collector_unit] || text(alert.collector_unit, "")).toLowerCase()
  }[sort.key];
  return rows.map((alert, index) => [alert, value(alert), index]).sort((a, b) => {
    if (a[1] < b[1]) return -sort.dir;
    if (a[1] > b[1]) return sort.dir;
    return a[2] - b[2];
  }).map(([alert]) => alert);
}
function setAlertFilter(changes) {
  if ("search" in changes) $("alert-search").value = changes.search;
  if ("severity" in changes) $("severity").value = changes.severity;
  if ("collector" in changes) $("collector").value = changes.collector;
  if ("range" in changes) $("range").value = changes.range;
  if ("hour" in changes) hourFilter = changes.hour;
  if ("hideReviewed" in changes) $("hide-reviewed").checked = changes.hideReviewed;
  renderAlertView();
}
function clearAlertFilters() {
  setAlertFilter({search: "", severity: "", collector: "", range: "", hour: null, hideReviewed: false});
}
function pivot(changes) {
  closeDetail();
  setView("alerts");
  setAlertFilter(Object.assign({search: "", severity: "", collector: "", range: "", hour: null}, changes));
}
function showEmpty(title, message) {
  const container = $("alert-empty");
  container.querySelector("h3").textContent = title;
  container.querySelector("p").textContent = message;
}
function toggleReviewed(alert, state) {
  const key = alertKey(alert);
  if (state) { reviewed.add(key); newAlerts.delete(key); } else reviewed.delete(key);
  saveReviewed();
  updateTitle();
  renderAlertView();
  renderSummaryMetrics();
}
function openAlert(alert) {
  const key = alertKey(alert);
  if (newAlerts.delete(key)) { updateTitle(); renderAlerts(); }
  const event = alert.event || {};
  const date = timeValue(alert);
  const item = evidence(alert);
  const process = event.process || {};
  const ruleTotal = data ? data.alerts.filter((other) => other.rule_id === alert.rule_id).length : 0;
  const fields = [
    ["Severity", badge(alert.severity)],
    ["Rule ID", text(alert.rule_id)],
    ["Observed", fullTime(date) + " (" + ago(date) + ")"],
    ["Host", text(event.host, data ? data.host : "—")],
    ["Event type", event.event && text(event.event.type, "")],
    ["Outcome", event.event && text(event.event.outcome, "")],
    ["Source IP", event.source && text(event.source.ip, "")],
    ["User", event.user && text(event.user.name, "")],
    ["Process", typeof process.executable === "string" ? process.executable + (process.pid !== undefined ? " (PID " + process.pid + ")" : "") : ""],
    ["File", event.file && text(event.file.path, "")],
    ["Collector", names[alert.collector_unit] || text(alert.collector_unit)],
    ["Declared responses", Array.isArray(alert.response) && alert.response.length ?
      alert.response.map((response) => text(response.action, "?") + " · " + text(response.mode, "dry_run")).join(", ") : ""],
    ["Review state", reviewed.has(key) ? "Reviewed in this browser" : "Not reviewed"]
  ];
  const actions = [];
  if (item) actions.push(["Filter by " + item.kind.toLowerCase(), () => pivot({search: item.value})]);
  actions.push(["All alerts for this rule (" + ruleTotal + ")", () => pivot({search: text(alert.rule_id, "")})]);
  if (event.host) actions.push(["Same host", () => pivot({search: String(event.host)})]);
  actions.push([reviewed.has(key) ? "Mark unreviewed" : "✓ Mark reviewed", () => { toggleReviewed(alert, !reviewed.has(key)); openAlert(alert); }]);
  detail("EVENT DETAIL", text(alert.rule_name, text(alert.rule_id)), alert, {fields, actions});
}

/* ---------- Alert rendering ---------- */
function renderAlertView() {
  renderAlerts();
  renderInsights();
  renderChips();
}
function renderChips() {
  const filters = alertFilters();
  const chips = [];
  if (filters.search) chips.push(["Search: " + filters.search, () => setAlertFilter({search: ""})]);
  if (filters.severity) chips.push(["Severity: " + (filters.severity === "high+" ? "high & critical" : filters.severity), () => setAlertFilter({severity: ""})]);
  if (filters.collector) chips.push(["Collector: " + names[filters.collector], () => setAlertFilter({collector: ""})]);
  if (filters.range) chips.push(["Last " + filters.range + "h", () => setAlertFilter({range: ""})]);
  if (hourFilter !== null) chips.push(["Hour: " + hourLabel(hourFilter) + "–" + hourLabel(hourFilter + HOUR), () => setAlertFilter({hour: null})]);
  if (filters.hideReviewed) chips.push(["Hiding reviewed", () => setAlertFilter({hideReviewed: false})]);
  const container = $("alert-chips");
  container.hidden = chips.length === 0;
  const items = chips.map(([label, clear]) => {
    const chip = node("button", label + "  ✕", "chip");
    chip.setAttribute("aria-label", "Remove filter " + label);
    chip.addEventListener("click", clear);
    return chip;
  });
  if (chips.length > 1) {
    const all = node("button", "Clear all", "text-button");
    all.addEventListener("click", clearAlertFilters);
    items.push(all);
  }
  container.replaceChildren(...items);
}
function renderAlerts() {
  const rows = sortedAlerts(matchingAlerts());
  const fragment = document.createDocumentFragment();
  for (const alert of rows) {
    const event = alert.event || {};
    const key = alertKey(alert);
    const isReviewed = reviewed.has(key);
    const row = node("tr", null, "alert-row" + (isReviewed ? " reviewed" : "") + (newAlerts.has(key) ? " is-new" : ""));
    const check = node("td", null, "check-col");
    const box = node("input");
    box.type = "checkbox";
    box.checked = isReviewed;
    box.setAttribute("aria-label", "Mark reviewed: " + text(alert.rule_name, text(alert.rule_id)));
    box.addEventListener("change", () => toggleReviewed(alert, box.checked));
    check.append(box);
    const date = timeValue(alert);
    const when = node("td", formatTime(date), "time");
    when.title = fullTime(date);
    when.append(node("span", Number.isFinite(date.getTime()) ? ago(date) : "", "secondary"));
    const severity = node("td");
    severity.append(badge(alert.severity));
    const detection = node("td");
    if (newAlerts.has(key)) detection.append(node("span", "NEW", "new-pill"));
    const button = node("button", text(alert.rule_name, text(alert.rule_id)), "rule-button");
    button.addEventListener("click", () => openAlert(alert));
    detection.append(button, node("span", text(alert.rule_id), "secondary"));
    const evidenceCell = node("td", text(event.host, data ? data.host : "—"));
    const item = evidence(alert);
    const evidenceText = item ? item.kind + ": " + item.value : "View full event";
    const secondary = node("span", evidenceText, "secondary");
    secondary.title = evidenceText;
    evidenceCell.append(secondary);
    row.append(check, when, severity, detection, evidenceCell,
      node("td", names[alert.collector_unit] || text(alert.collector_unit), "source"));
    row.addEventListener("click", (clickEvent) => {
      if (!clickEvent.target.closest("button, input, a")) openAlert(alert);
    });
    fragment.append(row);
  }
  $("alert-table").replaceChildren(fragment);
  $("alert-empty").hidden = rows.length > 0;
  if (!rows.length) {
    if (!data || data.loading) showEmpty("Waiting for endpoint data", "The first snapshot is being collected.");
    else if (sourceUnavailable("alerts")) showEmpty("Alert feed unavailable", "Review the source error above. An empty feed does not establish that the endpoint is quiet.");
    else if (data.alerts.length) showEmpty("No matching detections", "Try another search or clear the filters (press x).");
    else showEmpty("No alerts in the retained window", "Generate a harmless file or process test to verify collection. No alerts alone does not prove complete coverage.");
  }
  const total = data ? data.alerts.length : 0;
  const unreviewed = data ? data.alerts.filter((alert) => !reviewed.has(alertKey(alert))).length : 0;
  $("alert-count").textContent = rows.length + " of " + total + " alerts shown · " + unreviewed + " unreviewed";
  $("export").disabled = rows.length === 0;
  $("export-csv").disabled = rows.length === 0;
  $("mark-reviewed").disabled = !rows.some((alert) => !reviewed.has(alertKey(alert)));
  for (const header of document.querySelectorAll("th[data-sort]")) {
    if (header.dataset.sort === sort.key) header.setAttribute("aria-sort", sort.dir < 0 ? "descending" : "ascending");
    else header.removeAttribute("aria-sort");
  }
  $("new-banner").hidden = newAlerts.size === 0;
  $("new-banner-text").textContent = newAlerts.size + (newAlerts.size === 1 ? " new alert" : " new alerts");
}
function renderInsights() {
  const base = matchingAlerts({ignoreTime: true});
  const end = new Date();
  end.setMinutes(0, 0, 0);
  const endMs = end.getTime() + HOUR;
  const start = endMs - 24 * HOUR;
  const buckets = Array.from({length: 24}, () => ({total: 0, critical: 0, high: 0, medium: 0, low: 0}));
  for (const alert of base) {
    const index = Math.floor((timeValue(alert).getTime() - start) / HOUR);
    if (index < 0 || index > 23) continue;
    const severity = severityRank[alert.severity] ? alert.severity : "low";
    buckets[index][severity] += 1;
    buckets[index].total += 1;
  }
  const peak = Math.max(1, ...buckets.map((bucket) => bucket.total));
  const chart = $("timeline");
  const parts = [];
  for (let i = 0; i <= 2; i++) parts.push(svg("line", {x1: 0, x2: 240, y1: 4 + i * 28, y2: 4 + i * 28, class: "grid-line"}));
  buckets.forEach((bucket, index) => {
    const bucketStart = start + index * HOUR;
    const group = svg("g", {class: "bucket" + (hourFilter === bucketStart ? " selected" : ""), tabindex: 0, role: "button"});
    const label = hourLabel(bucketStart) + "–" + hourLabel(bucketStart + HOUR) + ": " + bucket.total + " alerts" +
      (bucket.total ? " (" + severityOrder.filter((s) => bucket[s]).map((s) => bucket[s] + " " + s).join(", ") + ")" : "");
    group.setAttribute("aria-label", label);
    const title = svg("title");
    title.textContent = label;
    group.append(title, svg("rect", {x: index * 10, y: 0, width: 10, height: 64, class: "hit"}));
    let y = 60;
    for (const severity of ["low", "medium", "high", "critical"]) {
      if (!bucket[severity]) continue;
      const height = Math.max(1.5, (bucket[severity] / peak) * 56);
      y -= height;
      group.append(svg("rect", {x: index * 10 + 1.5, y, width: 7, height, class: "bar " + severity}));
    }
    if (!bucket.total) group.append(svg("rect", {x: index * 10 + 1.5, y: 59, width: 7, height: 1, class: "bar empty"}));
    const choose = () => setAlertFilter({hour: hourFilter === bucketStart ? null : bucketStart, range: ""});
    group.addEventListener("click", choose);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(); }
    });
    parts.push(group);
  });
  chart.replaceChildren(...parts);
  const axis = buckets.map((_, index) => node("span", index % 4 === 0 ? hourLabel(start + index * HOUR) : ""));
  axis.push(node("span", "now", "now"));
  $("timeline-axis").replaceChildren(...axis);
  const busiest = buckets.reduce((best, bucket, index) => bucket.total > buckets[best].total ? index : best, 0);
  const last = buckets[23].total;
  $("timeline-summary").textContent = base.length ? last + " this hour · peak " + buckets[busiest].total + " at " + hourLabel(start + busiest * HOUR) :
    "No alerts match the current filters";

  // Breakdowns follow every active filter, including the selected hour.
  const rows = matchingAlerts();
  const counts = Object.fromEntries(severityOrder.map((severity) => [severity, rows.filter((alert) => alert.severity === severity).length]));
  const bar = $("severity-bar");
  bar.replaceChildren(...severityOrder.filter((severity) => counts[severity]).map((severity) => {
    const segment = node("span", null, "segment " + severity);
    segment.style.flexGrow = String(counts[severity]);
    segment.title = counts[severity] + " " + severity;
    return segment;
  }));
  bar.classList.toggle("is-empty", rows.length === 0);
  $("severity-total").textContent = rows.length + " shown";
  $("severity-legend").replaceChildren(...severityOrder.map((severity) => {
    const item = node("li");
    const button = node("button", null, "legend-item" + ($("severity").value === severity ? " selected" : ""));
    button.append(node("span", null, "swatch " + severity), node("span", severity), node("strong", counts[severity]));
    button.addEventListener("click", () => setAlertFilter({severity: $("severity").value === severity ? "" : severity}));
    item.append(button);
    return item;
  }));
  rankList($("top-rules"), tally(rows, (alert) => text(alert.rule_id, "")).map(([id, count]) => {
    const sample = rows.find((alert) => alert.rule_id === id);
    return {label: text(sample && sample.rule_name, id), detail: id, count, action: () => setAlertFilter({search: id})};
  }), rows.length, "No detections in view");
  rankList($("top-entities"), tally(rows, (alert) => { const item = evidence(alert); return item ? item.kind + "\u0000" + item.value : ""; }).map(([key, count]) => {
    const [kind, value] = key.split("\u0000");
    return {label: value, detail: kind, count, action: () => setAlertFilter({search: value})};
  }), rows.length, "No evidence fields in view");
}
function tally(rows, keyOf) {
  const counts = new Map();
  for (const row of rows) {
    const key = keyOf(row);
    if (key) counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
}
function rankList(container, items, total, emptyText) {
  if (!items.length) {
    container.replaceChildren(node("li", emptyText, "rank-empty"));
    return;
  }
  container.replaceChildren(...items.map((item) => {
    const li = node("li");
    const button = node("button", null, "rank-item");
    button.title = "Filter alerts by " + item.label;
    const labels = node("span", null, "rank-labels");
    labels.append(node("span", item.label, "rank-label"), node("span", item.detail, "rank-detail"));
    const meter = node("span", null, "meter");
    const fill = node("span", null, "meter-fill");
    fill.style.width = Math.max(4, Math.round((item.count / Math.max(1, total)) * 100)) + "%";
    meter.append(fill);
    button.append(labels, node("strong", item.count), meter);
    button.addEventListener("click", item.action);
    li.append(button);
    return li;
  }));
}

/* ---------- Rules ---------- */
function defaultLabel(file) {
  return {"ssh.yaml": "SSH default", "processes.yaml": "Process default", "file-watch.yaml": "File default",
    "starter.yaml": "Synthetic examples"}[file] || "Bundled rules";
}
function renderRules() {
  const search = $("rule-search").value.trim().toLowerCase();
  const severity = $("rule-severity").value;
  const state = $("rule-state").value;
  const firing = new Map();
  for (const alert of data ? data.alerts : []) firing.set(alert.rule_id, (firing.get(alert.rule_id) || 0) + 1);
  const fragment = document.createDocumentFragment();
  let count = 0;
  let total = 0;
  const files = data && data.rules ? data.rules.files : [];
  for (const file of files) {
    for (const rule of file.rules || []) {
      total += 1;
      const hits = firing.get(rule.id) || 0;
      if (severity && rule.severity !== severity) continue;
      if (state === "enabled" && !rule.enabled) continue;
      if (state === "disabled" && rule.enabled) continue;
      if (state === "firing" && !hits) continue;
      if (search && !JSON.stringify(rule).toLowerCase().includes(search) && !file.file.toLowerCase().includes(search)) continue;
      count += 1;
      const card = node("article", null, "rule-card" + (rule.enabled ? "" : " disabled") + (hits ? " firing" : ""));
      const top = node("div", null, "card-top");
      top.append(node("code", rule.id), badge(rule.severity));
      card.append(top, node("h3", rule.name), node("p", rule.description || "Review matching events against local policy."));
      const tags = node("div", null, "rule-tags");
      if (rule.threshold) {
        const threshold = rule.threshold;
        tags.append(node("span", "≥ " + threshold.count + " in " + threshold.window_seconds + "s · by " + threshold.group_by.join(", "), "pill"));
      }
      if (Array.isArray(rule.response) && rule.response.length) {
        for (const response of rule.response) tags.append(node("span", "⚡ " + text(response.action, "response") + " · " + text(response.mode, "dry_run"), "pill response"));
      }
      if (!rule.enabled) tags.append(node("span", "Disabled", "pill muted"));
      if (tags.childNodes.length) card.append(tags);
      const bottom = node("div", null, "card-bottom");
      bottom.append(node("span", defaultLabel(file.file) + " · " + file.file));
      const actions = node("span", null, "card-actions");
      if (hits) {
        const alerts = node("button", hits + (hits === 1 ? " alert" : " alerts") + " · 24h →", "text-button hot");
        alerts.addEventListener("click", () => pivot({search: rule.id}));
        actions.append(alerts);
      }
      const button = node("button", "View YAML ↗", "text-button");
      button.addEventListener("click", () => detail("BUNDLED RULE SOURCE", file.file, file.yaml, {
        fields: [["Rule", rule.id], ["Severity", badge(rule.severity)], ["State", rule.enabled ? "Enabled" : "Disabled"],
          ["Alerts in window", String(hits)]],
        actions: hits ? [["Show " + hits + " matching alerts", () => pivot({search: rule.id})]] : []
      }));
      actions.append(button);
      bottom.append(actions);
      card.append(bottom);
      fragment.append(card);
    }
  }
  $("rule-grid").replaceChildren(fragment);
  $("rules-empty").hidden = count > 0;
  $("rule-count").textContent = count + " of " + total + " rules shown · " + firing.size + " firing in the last 24 hours";
}

/* ---------- Collectors ---------- */
function renderServices() {
  const fragment = document.createDocumentFragment();
  const services = data ? data.services : [];
  const unavailable = !data || data.loading || sourceUnavailable("services");
  const problems = [];
  for (const [id, name] of Object.entries(names)) {
    const service = services.find((row) => row.Id === id) || {};
    const state = service.ActiveState || "unknown";
    if (!unavailable && state !== "active") problems.push(name + " is " + state);
    const restarts = Number(service.NRestarts || 0);
    if (!unavailable && restarts > 0) problems.push(name + " restarted " + restarts + "×");
    const card = node("article", null, "service-card" + (state === "active" ? "" : " down"));
    const top = node("div", null, "card-top");
    top.append(node("code", id), badge(state));
    card.append(top, node("h3", name + (name === "Dashboard" ? " server" : name === "Responses" ? " worker" : " collector")),
      node("p", descriptions[id]));
    const since = service.ActiveEnterTimestamp ? new Date(service.ActiveEnterTimestamp) : null;
    const uptime = since && Number.isFinite(since.getTime()) && state === "active" ? "up " + ago(since).replace(" ago", "") : "";
    const dl = node("dl");
    for (const [label, value, warn] of [
      ["Substate", service.SubState], ["Main PID", service.MainPID],
      ["Restarts", service.NRestarts, restarts > 0], ["Last exit status", service.ExecMainStatus, service.ExecMainStatus && service.ExecMainStatus !== "0"],
      ["Unit load state", service.LoadState, service.LoadState && service.LoadState !== "loaded"],
      ["Active since", service.ActiveEnterTimestamp ? service.ActiveEnterTimestamp + (uptime ? " · " + uptime : "") : undefined]
    ]) {
      const pair = node("div");
      pair.append(node("dt", label), node("dd", text(value), warn ? "warn" : ""));
      dl.append(pair);
    }
    const details = node("details");
    details.append(node("summary", "Inspect launch configuration"));
    details.append(node("pre", "Unit: " + text(service.FragmentPath) + "\n\n" + text(service.ExecStart, "No launch information available.")));
    const footer = node("div", null, "card-bottom");
    const logs = node("button", "View diagnostics →", "text-button");
    logs.addEventListener("click", () => {
      setView("logs");
      $("log-unit").value = id in names && id !== "chompedr-dashboard.service" ? id : "";
      renderLogs();
    });
    footer.append(node("span", uptime || "—"), logs);
    card.append(dl, details);
    if (id !== "chompedr-dashboard.service") card.append(footer);
    fragment.append(card);
  }
  $("service-grid").replaceChildren(fragment);
  const summary = $("service-summary");
  summary.className = "health" + (unavailable ? " unknown" : problems.length ? " warn" : " ok");
  summary.replaceChildren(node("strong", unavailable ? "Service status unavailable" :
    problems.length ? problems.length + (problems.length === 1 ? " item needs" : " items need") + " attention" : "All Chomp services are active"),
  node("span", unavailable ? "Waiting for systemd data; cached values may be shown." : problems.length ? problems.join(" · ") : "No restarts recorded since the units started."));
  $("collector-flag").hidden = unavailable || !services.some((row) => COLLECTOR_UNITS.includes(row.Id) && row.ActiveState !== "active");
}

/* ---------- Diagnostics ---------- */
function isAlertRecord(row) {
  return typeof row.MESSAGE === "string" && /^\{.*"rule_id"\s*:/.test(row.MESSAGE);
}
function renderLogs() {
  const search = $("log-search").value.trim().toLowerCase();
  const unit = $("log-unit").value;
  const problemsOnly = $("log-problems").checked;
  const hideAlerts = $("log-hide-alerts").checked;
  const fragment = document.createDocumentFragment();
  const all = data ? data.logs : [];
  const rows = all.filter((row) =>
    (!unit || row._SYSTEMD_UNIT === unit) &&
    (!problemsOnly || PROBLEM.test(text(row.MESSAGE, ""))) &&
    (!hideAlerts || !isAlertRecord(row)) &&
    (!search || JSON.stringify(row).toLowerCase().includes(search)));
  let problems = 0;
  for (const row of rows) {
    const problem = PROBLEM.test(text(row.MESSAGE, ""));
    if (problem) problems += 1;
    const entry = node("div", null, "log-row" + (problem ? " problem" : "") + (isAlertRecord(row) ? " alert-record" : ""));
    const meta = node("div", null, "log-meta");
    const when = node("span", formatTime(row.__REALTIME_TIMESTAMP));
    when.title = fullTime(new Date(Number(row.__REALTIME_TIMESTAMP) / 1000));
    meta.append(when, node("span", names[row._SYSTEMD_UNIT] || text(row._SYSTEMD_UNIT), "unit-tag"));
    if (problem) meta.append(node("span", "problem", "problem-tag"));
    if (isAlertRecord(row)) meta.append(node("span", "alert", "alert-tag"));
    entry.append(meta, node("pre", text(row.MESSAGE, "[Non-text journal record]")));
    fragment.append(entry);
  }
  if (!rows.length) {
    fragment.append(node("p", sourceUnavailable("logs") ? "Diagnostic feed unavailable; review the error above." :
      "No journal records match this view.", "empty"));
  }
  $("log-list").replaceChildren(fragment);
  $("log-count").textContent = rows.length + " of " + all.length + " records shown · " + problems + " problem lines";
}

/* ---------- Responses ---------- */
async function decideResponse(request, decision) {
  if (deciding) return;
  const token = $("management-token").value.trim();
  if (!token) {
    $("response-message").textContent = "Enter the administrator management token to approve or reject requests.";
    $("management-token").closest("details").open = true;
    $("management-token").focus();
    return;
  }
  const action = request.response && request.response.action;
  if (!window.confirm((decision === "approve" ? "Approve execution of " : decision === "reject" ? "Reject " : "") +
      (decision === "pause" ? "Pause preservation of " : decision === "resume" ? "Capture a new baseline and resume preservation of " : text(action) + " for ") + JSON.stringify(request.target) + "?")) return;
  deciding = true;
  renderResponses();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("/api/responses/" + encodeURIComponent(request.id) + "/" + decision,
      {method: "POST", headers: {Authorization: "Bearer " + token}, signal: controller.signal});
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    $("response-message").textContent = decision === "pause" ? "Preservation paused. You can now make legitimate changes." : decision === "resume" ? "Resume requested. Current contents will become the new baseline at activation." : decision === "approve" ?
      "Approved and queued. The worker will verify the target again before execution." : "Request rejected.";
    toast($("response-message").textContent);
    // The background snapshot can lag a successful decision; prevent repeat clicks immediately.
    request.status = result.status;
    renderResponses();
    setTimeout(() => refresh(true), 1200);
  } catch (error) {
    $("response-message").textContent = "Decision could not be confirmed: " + error.message +
      ". Refresh the request status before trying again.";
  } finally {
    clearTimeout(timeout);
    deciding = false;
    renderResponses();
  }
}
function targetText(target) {
  if (target && typeof target === "object" && !Array.isArray(target)) {
    return Object.entries(target).map(([key, value]) => key + ": " + (typeof value === "object" ? JSON.stringify(value) : value)).join(" · ");
  }
  return JSON.stringify(target);
}
function openRequest(request) {
  const created = new Date(request.created * 1000);
  const response = request.response || {};
  detail("RESPONSE REQUEST", text(response.action, "Response request"), request, {
    fields: [["Status", statusBadge(request.status)], ["Mode", text(response.mode, "dry_run")], ["Rule", text(request.rule_id)],
      ["Created", fullTime(created) + " (" + ago(created) + ")"], ["Target", targetText(request.target)],
      ["Result", text(request.detail, "")], ["Request ID", text(request.id)]],
    actions: [["Alerts for this rule", () => pivot({search: text(request.rule_id, "")})]]
  });
}
function renderResponses() {
  const responses = data && data.responses;
  const available = data && data.sources.responses && data.sources.responses.ok;
  const search = $("response-search").value.trim().toLowerCase();
  const status = $("response-status").value;
  const requests = responses ? responses.requests : [];
  const rows = requests.filter((request) => (!status || request.status === status) &&
    (!search || JSON.stringify(request).toLowerCase().includes(search)));
  $("pending-count").textContent = available ? responses.pending_count : "—";
  $("pending-count").classList.toggle("alert", Boolean(available && responses.pending_count));
  const counts = tallyAll(requests, (request) => request.status);
  const chips = [["", "All", requests.length], ...Object.keys(statusLabels).filter((key) => counts.get(key))
    .map((key) => [key, statusLabels[key], counts.get(key)])];
  $("response-chips").replaceChildren(...chips.map(([key, label, count]) => {
    const chip = node("button", null, "chip status" + (status === key ? " selected" : "") + (key === "pending" || key === "failed" ? " " + key : ""));
    chip.append(node("span", label), node("strong", count));
    chip.setAttribute("aria-pressed", String(status === key));
    chip.addEventListener("click", () => { $("response-status").value = key; renderResponses(); });
    return chip;
  }));
  const fragment = document.createDocumentFragment();
  for (const request of rows) {
    const row = node("tr", null, request.status === "pending" ? "needs-decision" : "");
    const created = new Date(request.created * 1000);
    const when = node("td", formatTime(created), "time");
    when.title = fullTime(created);
    when.append(node("span", ago(created), "secondary"));
    const action = node("td", text(request.rule_id));
    const inspect = node("button", text(request.response && request.response.action), "rule-button");
    inspect.addEventListener("click", () => openRequest(request));
    action.append(node("br"), inspect);
    const target = node("td", targetText(request.target), "response-target");
    target.title = request.detail || "";
    const state = node("td");
    state.append(statusBadge(request.status), node("span", request.response && request.response.mode || "dry_run", "secondary"));
    const controls = node("td");
    const preserve = request.response && request.response.action === "preserve_file";
    const decisions = request.status === "pending" ? ["approve", "reject"] : preserve && request.status === "active" ? ["pause"] : preserve && request.status === "paused" ? ["resume"] : [];
    if (decisions.length) {
      for (const decision of decisions) {
        const button = node("button", ({approve: "Approve", reject: "Reject", pause: "Pause", resume: "Resume"})[decision],
          "button" + (decision === "approve" ? " approve" : decision === "reject" ? " reject" : ""));
        button.disabled = !available || deciding;
        button.addEventListener("click", () => decideResponse(request, decision));
        controls.append(button);
      }
    } else controls.append(node("span", request.detail, "secondary"));
    row.append(when, action, target, state, controls);
    fragment.append(row);
  }
  $("response-table").replaceChildren(fragment);
  $("response-empty").hidden = rows.length > 0;
  $("response-empty").textContent = !available ? "Response service unavailable. Cached requests may be stale; decisions are disabled." :
    "No response requests match this view. Rules without response declarations do not create requests.";
  $("response-count").textContent = rows.length + " of " + requests.length + " retained requests shown";
  renderAudit();
}
function renderAudit() {
  const responses = data && data.responses;
  const search = $("audit-search").value.trim().toLowerCase();
  const audit = document.createDocumentFragment();
  const entries = (responses ? responses.audit : []).filter((entry) => !search || JSON.stringify(entry).toLowerCase().includes(search));
  for (const entry of entries) {
    const line = node("div", null, "log-row");
    const meta = node("div", null, "log-meta");
    const at = new Date(entry.at * 1000);
    meta.append(node("span", fullTime(at)), node("span", ago(at)));
    const link = node("button", text(entry.id).slice(0, 16) + "… · " + text(entry.status), "text-button");
    link.addEventListener("click", () => detail("RESPONSE AUDIT", entry.id, entry));
    line.append(meta, link, node("pre", entry.detail));
    audit.append(line);
  }
  if (!entries.length) audit.append(node("p", "No audit entries match this view.", "empty"));
  $("response-audit").replaceChildren(audit);
}
function tallyAll(rows, keyOf) {
  const counts = new Map();
  for (const row of rows) counts.set(keyOf(row), (counts.get(keyOf(row)) || 0) + 1);
  return counts;
}

/* ---------- Global state ---------- */
function connection(state, label) {
  $("connection-dot").className = "dot" + (state ? " " + state : "");
  $("connection-label").textContent = label;
}
function updateTitle() {
  document.title = (newAlerts.size ? "(" + newAlerts.size + ") " : "") + "Chomp EDR · Operations";
}
function trackNewAlerts() {
  if (!data || data.loading || sourceUnavailable("alerts") && !data.alerts.length) return;
  const keys = data.alerts.map(alertKey);
  if (knownAlerts === null) {
    knownAlerts = new Set(keys);
    return;
  }
  const fresh = data.alerts.filter((alert) => !knownAlerts.has(alertKey(alert)));
  for (const alert of fresh) {
    knownAlerts.add(alertKey(alert));
    newAlerts.add(alertKey(alert));
  }
  const present = new Set(keys);
  for (const key of newAlerts) if (!present.has(key)) newAlerts.delete(key);
  updateTitle();
  if (fresh.length) notifyAlerts(fresh);
}
function notifyAlerts(fresh) {
  if (!notify || !("Notification" in window) || Notification.permission !== "granted") return;
  const urgent = fresh.filter((alert) => alert.severity === "high" || alert.severity === "critical");
  for (const alert of urgent.slice(0, 3)) {
    const item = evidence(alert);
    const note = new Notification("Chomp EDR · " + text(alert.severity, "alert") + " alert", {
      body: text(alert.rule_name, text(alert.rule_id)) + (item ? "\n" + item.kind + ": " + item.value : ""),
      tag: alertKey(alert)
    });
    note.addEventListener("click", () => { window.focus(); setView("alerts"); openAlert(alert); });
  }
  if (urgent.length > 3) new Notification("Chomp EDR", {body: (urgent.length - 3) + " more high or critical alerts arrived."});
}
function renderNotifyButton() {
  const button = $("notify-toggle");
  const supported = "Notification" in window;
  button.setAttribute("aria-pressed", String(notify && supported));
  button.classList.toggle("on", notify && supported);
  button.title = !supported ? "Desktop notifications are not supported in this browser" :
    notify ? "Desktop notifications on for new high and critical alerts (click to turn off)" :
      "Turn on desktop notifications for new high and critical alerts";
}
function renderSummaryMetrics() {
  const unreviewed = data.alerts.filter((alert) => !reviewed.has(alertKey(alert))).length;
  $("metric-alerts-sub").textContent = data.alerts.length ? unreviewed + " unreviewed · last 24 hours" : "Retained alerts · last 24 hours";
  const critical = data.alerts.filter((alert) => alert.severity === "critical").length;
  $("metric-high-sub").textContent = critical ? critical + " critical · prioritize investigation" : "Prioritize investigation";
}
function render() {
  if (!data) return;
  trackNewAlerts();
  $("sidebar-host").textContent = data.host;
  $("footer-host").textContent = data.host;
  $("nav-count").textContent = data.alerts.length;
  $("metric-alerts").textContent = (data.loading || (sourceUnavailable("alerts") && !data.alerts.length)) ? "—" : data.alerts.length;
  $("metric-high").textContent = sourceUnavailable("alerts") && !data.alerts.length ? "—" :
    data.alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const responsesOk = data.sources.responses && data.sources.responses.ok;
  $("metric-pending").textContent = responsesOk && data.responses ? data.responses.pending_count : "—";
  const collectors = data.services.filter((row) => COLLECTOR_UNITS.includes(row.Id) && row.ActiveState === "active").length;
  $("metric-collectors").textContent = (data.loading || sourceUnavailable("services")) ? "—" : collectors + " / 3";
  $("metric-collectors").classList.toggle("degraded", !data.loading && !sourceUnavailable("services") && collectors < 3);
  const ruleCount = data.rules ? data.rules.files.reduce((sum, file) => sum + file.rules.length, 0) : "—";
  $("metric-rules").textContent = ruleCount;
  if (data.rules) {
    const enabled = data.rules.files.reduce((sum, file) => sum + file.rules.filter((rule) => rule.enabled).length, 0);
    $("metric-rules-sub").textContent = enabled + " enabled · from the installed executable";
  }
  renderSummaryMetrics();
  $("version").textContent = "Chomp EDR " + (data.rules ? text(data.rules.version, "") : "");
  const errors = data.errors || [];
  $("errors").hidden = errors.length === 0;
  $("errors").replaceChildren(...errors.map((error) => node("p", error.source + ": " + error.message)));
  if (data.loading) connection("warn", "Collecting first snapshot");
  else if (paused) connection("warn", "Refresh paused");
  else if (errors.length) connection("warn", "Some data unavailable");
  else if (data.updated_at && Date.now() - new Date(data.updated_at).getTime() > 30000) connection("warn", "Snapshot delayed");
  else connection("", "Connected · refresh every 5s");
  const times = Object.entries(data.sources || {}).map(([source, status]) =>
    source + ": " + (status.updated_at ? new Date(status.updated_at).toLocaleString() : "not available") +
    (status.ok ? "" : " (cached / unavailable)"));
  $("updated").textContent = data.updated_at ? "Snapshot " + new Date(data.updated_at).toLocaleTimeString() + " · browser local time" :
    "Waiting for first snapshot";
  $("updated").title = times.join("\n");
  tickAgo();
  const drawers = [
    ["alerts", renderAlertView, [data.alerts, newAlerts.size]],
    ["rules", renderRules, [data.rules, data.alerts.length, data.alerts[0] && alertKey(data.alerts[0])]],
    ["services", renderServices, [data.services]],
    ["logs", renderLogs, [data.logs]],
    ["responses", renderResponses, [data.responses]]
  ];
  for (const [key, draw, parts] of drawers) {
    const source = key === "services" ? "services" : key;
    const signature = JSON.stringify([parts, data.sources[source] && data.sources[source].ok, data.loading]);
    if (signatures[key] !== signature) { draw(); signatures[key] = signature; }
  }
}
function tickAgo() {
  $("updated-ago").textContent = data && data.updated_at ? "· " + ago(new Date(data.updated_at)) : "";
}
async function refresh(force = false) {
  if (loading || (paused && !force)) return;
  loading = true;
  $("refresh").disabled = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("/api/snapshot", {cache: "no-store", signal: controller.signal});
    if (!response.ok) throw new Error("HTTP " + response.status);
    data = await response.json();
    lastSuccess = Date.now();
    render();
  } catch (error) {
    connection("error", "Disconnected");
    $("errors").hidden = false;
    $("errors").replaceChildren(node("p", "Dashboard connection lost. " +
      (lastSuccess ? "Showing the last browser snapshot; values may be stale. " : "") + text(error.message)));
  } finally {
    clearTimeout(timeout);
    loading = false;
    $("refresh").disabled = false;
  }
}

/* ---------- Navigation ---------- */
function setView(view, updateHash = true) {
  if (!views[view]) view = "alerts";
  activeView = view;
  for (const item of document.querySelectorAll("[data-view]")) {
    const selected = item.dataset.view === view;
    item.classList.toggle("selected", selected);
    if (selected) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  for (const section of document.querySelectorAll(".view")) section.hidden = section.id !== "view-" + view;
  const [title, description, crumb] = views[view];
  $("page-title").textContent = title;
  $("page-description").textContent = description;
  $("breadcrumb").textContent = crumb;
  if (updateHash && location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
}
for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => setView(button.dataset.view));
}
window.addEventListener("hashchange", () => setView(location.hash.slice(1), false));
for (const metric of document.querySelectorAll("[data-jump]")) {
  metric.addEventListener("click", () => {
    setView(metric.dataset.jump);
    if (metric.dataset.preset === "all") clearAlertFilters();
    else if (metric.dataset.preset === "high") setAlertFilter({severity: "high+"});
    else if (metric.dataset.preset === "pending") { $("response-status").value = "pending"; renderResponses(); }
  });
}

/* ---------- Event wiring ---------- */
for (const id of ["alert-search", "severity", "collector", "range", "hide-reviewed"]) $(id).addEventListener("input", renderAlertView);
for (const header of document.querySelectorAll("th[data-sort]")) {
  header.querySelector("button").addEventListener("click", () => {
    const key = header.dataset.sort;
    sort.dir = sort.key === key ? -sort.dir : (key === "detection" || key === "evidence" || key === "source" ? 1 : -1);
    sort.key = key;
    renderAlerts();
  });
}
$("mark-reviewed").addEventListener("click", () => {
  const rows = matchingAlerts().filter((alert) => !reviewed.has(alertKey(alert)));
  if (rows.length > 25 && !window.confirm("Mark " + rows.length + " shown alerts as reviewed in this browser?")) return;
  for (const alert of rows) { reviewed.add(alertKey(alert)); newAlerts.delete(alertKey(alert)); }
  saveReviewed();
  updateTitle();
  renderAlertView();
  renderSummaryMetrics();
  toast(rows.length + " alerts marked reviewed.");
});
$("dismiss-new").addEventListener("click", () => { newAlerts.clear(); updateTitle(); renderAlerts(); });
$("show-new").addEventListener("click", () => { sort.key = "time"; sort.dir = -1; clearAlertFilters(); });
$("rule-search").addEventListener("input", renderRules);
for (const id of ["rule-severity", "rule-state"]) $(id).addEventListener("input", renderRules);
for (const id of ["log-search", "log-unit", "log-problems", "log-hide-alerts"]) $(id).addEventListener("input", renderLogs);
for (const id of ["response-search", "response-status"]) $(id).addEventListener("input", renderResponses);
$("audit-search").addEventListener("input", renderAudit);
$("management-token").addEventListener("input", () => {
  const set = $("management-token").value.trim().length > 0;
  $("token-state").textContent = set ? "Token entered" : "No token";
  $("token-state").classList.toggle("set", set);
});
$("clear-token").addEventListener("click", () => {
  $("management-token").value = "";
  $("management-token").dispatchEvent(new Event("input"));
  $("response-message").textContent = "Management token cleared.";
});
$("refresh").addEventListener("click", () => refresh(true));
function togglePause() {
  paused = !paused;
  $("pause").textContent = paused ? "Resume refresh" : "Pause refresh";
  render();
  if (!paused) refresh(true);
}
$("pause").addEventListener("click", togglePause);
$("close-detail").addEventListener("click", closeDetail);
$("copy-detail").addEventListener("click", () => copyText(detailCopy));
for (const id of ["detail", "shortcuts"]) {
  $(id).addEventListener("click", (event) => {
    if (event.target === $(id)) {
      const rect = $(id).getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $(id).close();
    }
  });
}
$("open-shortcuts").addEventListener("click", () => $("shortcuts").showModal());
$("close-shortcuts").addEventListener("click", () => $("shortcuts").close());
$("notify-toggle").addEventListener("click", async () => {
  if (!("Notification" in window)) { toast("This browser does not support desktop notifications."); return; }
  if (!notify && Notification.permission !== "granted") {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") { toast("Notification permission was not granted."); return; }
  }
  notify = !notify;
  storageSet(STORAGE.notify, notify);
  renderNotifyButton();
  toast(notify ? "Desktop notifications on for new high and critical alerts." : "Desktop notifications off.");
});
function csvCell(value) {
  let cell = text(value, "");
  // Neutralize spreadsheet formula injection from attacker-controlled event fields.
  if (/^[=+\-@\t\r]/.test(cell)) cell = "'" + cell;
  return "\"" + cell.replace(/"/g, "\"\"") + "\"";
}
$("export-csv").addEventListener("click", () => {
  const header = ["time", "severity", "rule_id", "rule_name", "host", "evidence_type", "evidence", "collector", "reviewed"];
  const lines = sortedAlerts(matchingAlerts()).map((alert) => {
    const item = evidence(alert);
    const date = timeValue(alert);
    return [Number.isFinite(date.getTime()) ? date.toISOString() : "", alert.severity, alert.rule_id, alert.rule_name,
      alert.event && alert.event.host, item && item.kind, item && item.value, names[alert.collector_unit] || alert.collector_unit,
      reviewed.has(alertKey(alert)) ? "yes" : "no"].map(csvCell).join(",");
  });
  download("chomp-alerts-" + new Date().toISOString().slice(0, 10) + ".csv", [header.join(","), ...lines].join("\r\n"), "text/csv");
});
$("export").addEventListener("click", () => {
  download("chomp-alerts-" + new Date().toISOString().slice(0, 10) + ".json", JSON.stringify(sortedAlerts(matchingAlerts()), null, 2), "application/json");
});
document.addEventListener("keydown", (event) => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  const typing = event.target.closest && event.target.closest("input, select, textarea");
  if (typing) {
    if (event.key === "Escape" && event.target.blur) event.target.blur();
    return;
  }
  if ($("detail").open || $("shortcuts").open) return;
  if (/^[1-5]$/.test(event.key)) setView(viewOrder[Number(event.key) - 1]);
  else if (event.key === "/") {
    const input = searchFor[activeView] && $(searchFor[activeView]);
    if (input) { event.preventDefault(); input.focus(); input.select(); }
  } else if (event.key === "r") refresh(true);
  else if (event.key === "p") togglePause();
  else if (event.key === "x") { setView("alerts"); clearAlertFilters(); }
  else if (event.key === "h") { setView("alerts"); setAlertFilter({severity: "high+"}); }
  else if (event.key === "?") $("shortcuts").showModal();
  else return;
  event.preventDefault();
});

setView(location.hash.slice(1) || "alerts", false);
renderNotifyButton();
renderAlertView();
refresh();
setInterval(() => refresh(), 5000);
setInterval(tickAgo, 1000);
// Relative times and the hourly timeline drift even when the snapshot does not change.
setInterval(() => { if (data) { renderAlertView(); renderServices(); } }, 60000);
