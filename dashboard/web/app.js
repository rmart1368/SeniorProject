"use strict";
const $ = (id) => document.getElementById(id);
const names = {
  "chompedr-ssh.service": "SSH",
  "chompedr-processes.service": "Processes",
  "chompedr-files.service": "Files",
  "chompedr-dashboard.service": "Dashboard"
};
const descriptions = {
  "chompedr-ssh.service": "Authentication events and grouped failure detection.",
  "chompedr-processes.service": "Periodic /proc snapshots and executable location review.",
  "chompedr-files.service": "Metadata changes on selected files and directories.",
  "chompedr-dashboard.service": "Local web interface and read-only journal access."
};
const views = {
  alerts: ["Alert activity", "Investigate detections from your competition endpoint.", "Alerts"],
  rules: ["Detection rules", "Inspect bundled detections and their source definitions.", "Detection rules"],
  collectors: ["Endpoint collectors", "Inspect service state, restarts, and launch configuration.", "Collectors"],
  logs: ["Collector diagnostics", "Review the signals behind collection and detection.", "Diagnostics"]
};
let data = null;
let paused = false;
let loading = false;
let lastSuccess = 0;
let activeView = "alerts";
const signatures = {};

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
function text(value, fallback = "—") {
  return typeof value === "string" || typeof value === "number" ? String(value) : fallback;
}
function badge(value) {
  const safe = ["critical", "high", "medium", "low", "active", "inactive", "failed"].includes(value) ? value : "unknown";
  return node("span", text(value, "unknown"), "badge " + safe);
}
function detail(label, title, content) {
  $("detail-label").textContent = label;
  $("detail-title").textContent = text(title, "Details");
  $("detail-content").textContent = typeof content === "string" ? content : JSON.stringify(content, null, 2);
  $("detail").showModal();
}
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
function sourceUnavailable(source) {
  return data && data.sources[source] && !data.sources[source].ok;
}
function matchingAlerts() {
  const search = $("alert-search").value.toLowerCase().trim();
  const severity = $("severity").value;
  const collector = $("collector").value;
  return (data ? data.alerts : []).filter((alert) =>
    (!severity || alert.severity === severity) &&
    (!collector || alert.collector_unit === collector) &&
    (!search || JSON.stringify(alert).toLowerCase().includes(search)));
}
function showEmpty(title, message) {
  const container = $("alert-empty");
  container.querySelector("h3").textContent = title;
  container.querySelector("p").textContent = message;
}
function renderAlerts() {
  const rows = matchingAlerts();
  const fragment = document.createDocumentFragment();
  for (const alert of rows) {
    const event = alert.event || {};
    const row = node("tr");
    const date = timeValue(alert);
    const when = node("td", formatTime(date), "time");
    when.title = fullTime(date);
    when.append(node("span", Number.isFinite(date.getTime()) ? date.toLocaleDateString() : "", "secondary"));
    const severity = node("td");
    severity.append(badge(alert.severity));
    const detection = node("td");
    const button = node("button", text(alert.rule_name, text(alert.rule_id)), "rule-button");
    button.addEventListener("click", () => detail("EVENT DETAIL", alert.rule_name, alert));
    detection.append(button, node("span", text(alert.rule_id), "secondary"));
    const evidence = node("td", text(event.host, data ? data.host : "—"));
    const evidenceText = text(event.source && event.source.ip,
      text(event.file && event.file.path, text(event.process && event.process.executable, "View full event")));
    const secondary = node("span", evidenceText, "secondary");
    secondary.title = evidenceText;
    evidence.append(secondary);
    row.append(when, severity, detection, evidence,
      node("td", names[alert.collector_unit] || text(alert.collector_unit), "source"));
    fragment.append(row);
  }
  $("alert-table").replaceChildren(fragment);
  $("alert-empty").hidden = rows.length > 0;
  if (!rows.length) {
    if (!data || data.loading) showEmpty("Waiting for endpoint data", "The first snapshot is being collected.");
    else if (sourceUnavailable("alerts")) showEmpty("Alert feed unavailable", "Review the source error above. An empty feed does not establish that the endpoint is quiet.");
    else if (data.alerts.length) showEmpty("No matching detections", "Try another search or clear the filters.");
    else showEmpty("No alerts in the retained window", "Generate a harmless file or process test to verify collection. No alerts alone does not prove complete coverage.");
  }
  $("alert-count").textContent = rows.length + " of " + (data ? data.alerts.length : 0) + " alerts shown";
  $("export").disabled = rows.length === 0;
}
function defaultLabel(file) {
  return {"ssh.yaml": "SSH default", "processes.yaml": "Process default", "file-watch.yaml": "File default",
    "starter.yaml": "Synthetic examples"}[file] || "Bundled rules";
}
function renderRules() {
  const search = $("rule-search").value.trim().toLowerCase();
  const fragment = document.createDocumentFragment();
  let count = 0;
  const files = data && data.rules ? data.rules.files : [];
  for (const file of files) {
    for (const rule of file.rules || []) {
      if (search && !JSON.stringify(rule).toLowerCase().includes(search) && !file.file.toLowerCase().includes(search)) continue;
      count += 1;
      const card = node("article", null, "rule-card");
      const top = node("div", null, "card-top");
      top.append(node("code", rule.id), badge(rule.severity));
      card.append(top, node("h3", rule.name), node("p", rule.description || "Review matching events against local policy."));
      if (rule.threshold) {
        const threshold = rule.threshold;
        card.append(node("p", threshold.count + " matches / " + threshold.window_seconds + " seconds · grouped by " +
          threshold.group_by.join(", "), "subtle"));
      }
      const bottom = node("div", null, "card-bottom");
      bottom.append(node("span", defaultLabel(file.file) + " · " + (rule.enabled ? "enabled" : "disabled")));
      const button = node("button", "View YAML ↗", "text-button");
      button.addEventListener("click", () => detail("BUNDLED RULE SOURCE", file.file, file.yaml));
      bottom.append(button);
      card.append(bottom);
      fragment.append(card);
    }
  }
  $("rule-grid").replaceChildren(fragment);
  $("rules-empty").hidden = count > 0;
}
function renderServices() {
  const fragment = document.createDocumentFragment();
  for (const [id, name] of Object.entries(names)) {
    const service = (data ? data.services : []).find((row) => row.Id === id) || {};
    const card = node("article", null, "service-card");
    const top = node("div", null, "card-top");
    top.append(node("code", id), badge(service.ActiveState || "unknown"));
    card.append(top, node("h3", name + (name === "Dashboard" ? " server" : " collector")),
      node("p", descriptions[id]));
    const dl = node("dl");
    for (const [label, value] of [
      ["Substate", service.SubState], ["Main PID", service.MainPID],
      ["Restarts", service.NRestarts], ["Last exit status", service.ExecMainStatus],
      ["Unit load state", service.LoadState], ["Active since", service.ActiveEnterTimestamp]
    ]) {
      const pair = node("div");
      pair.append(node("dt", label), node("dd", text(value)));
      dl.append(pair);
    }
    const details = node("details");
    details.append(node("summary", "Inspect launch configuration"));
    details.append(node("pre", "Unit: " + text(service.FragmentPath) + "\n\n" + text(service.ExecStart, "No launch information available.")));
    card.append(dl, details);
    fragment.append(card);
  }
  $("service-grid").replaceChildren(fragment);
}
function renderLogs() {
  const search = $("log-search").value.trim().toLowerCase();
  const fragment = document.createDocumentFragment();
  const rows = (data ? data.logs : []).filter((row) =>
    !search || JSON.stringify(row).toLowerCase().includes(search));
  for (const row of rows) {
    const entry = node("div", null, "log-row");
    const meta = node("div", null, "log-meta");
    meta.append(node("span", formatTime(row.__REALTIME_TIMESTAMP)),
      node("span", names[row._SYSTEMD_UNIT] || text(row._SYSTEMD_UNIT)));
    entry.append(meta, node("pre", text(row.MESSAGE, "[Non-text journal record]")));
    fragment.append(entry);
  }
  if (!rows.length) {
    fragment.append(node("p", sourceUnavailable("logs") ? "Diagnostic feed unavailable; review the error above." :
      "No journal records match this view.", "empty"));
  }
  $("log-list").replaceChildren(fragment);
}
function connection(state, label) {
  $("connection-dot").className = "dot" + (state ? " " + state : "");
  $("connection-label").textContent = label;
}
function render() {
  if (!data) return;
  $("sidebar-host").textContent = data.host;
  $("footer-host").textContent = data.host;
  $("nav-count").textContent = data.alerts.length;
  $("metric-alerts").textContent = (data.loading || (sourceUnavailable("alerts") && !data.alerts.length)) ? "—" : data.alerts.length;
  $("metric-high").textContent = sourceUnavailable("alerts") && !data.alerts.length ? "—" :
    data.alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const collectors = data.services.filter((row) => row.Id !== "chompedr-dashboard.service" && row.ActiveState === "active").length;
  $("metric-collectors").textContent = (data.loading || sourceUnavailable("services")) ? "—" : collectors + " / 3";
  const ruleCount = data.rules ? data.rules.files.reduce((sum, file) => sum + file.rules.length, 0) : "—";
  $("metric-rules").textContent = ruleCount;
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
  for (const [key, draw] of [["alerts", renderAlerts], ["rules", renderRules], ["services", renderServices], ["logs", renderLogs]]) {
    const signature = JSON.stringify([data[key], data.sources[key] && data.sources[key].ok, data.loading]);
    if (signatures[key] !== signature) { draw(); signatures[key] = signature; }
  }
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
for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => {
    activeView = button.dataset.view;
    for (const item of document.querySelectorAll("[data-view]")) {
      item.classList.toggle("selected", item === button);
      if (item === button) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    }
    for (const section of document.querySelectorAll(".view")) section.hidden = section.id !== "view-" + activeView;
    const [title, description, crumb] = views[activeView];
    $("page-title").textContent = title;
    $("page-description").textContent = description;
    $("breadcrumb").textContent = crumb;
  });
}
for (const id of ["alert-search", "severity", "collector"]) $(id).addEventListener("input", renderAlerts);
$("rule-search").addEventListener("input", renderRules);
$("log-search").addEventListener("input", renderLogs);
$("refresh").addEventListener("click", () => refresh(true));
$("pause").addEventListener("click", () => {
  paused = !paused;
  $("pause").textContent = paused ? "Resume refresh" : "Pause refresh";
  render();
  if (!paused) refresh(true);
});
$("close-detail").addEventListener("click", () => $("detail").close());
$("detail").addEventListener("click", (event) => {
  if (event.target === $("detail")) {
    const rect = $("detail").getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $("detail").close();
  }
});
$("export").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(matchingAlerts(), null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = node("a");
  link.href = url;
  link.download = "chomp-alerts-" + new Date().toISOString().slice(0, 10) + ".json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
refresh();
setInterval(() => refresh(), 5000);
