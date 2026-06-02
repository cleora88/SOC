const state = {
  alerts: [],
  selectedId: null,
  simulatorRunning: false,
};

const sampleAlert = {
  source: "qradar",
  rule_name: "Multiple failed VPN login attempts",
  event_type: "failed_login",
  severity: 8,
  source_ip: "196.92.10.44",
  destination_ip: "10.20.3.12",
  username: "admin",
  hostname: "bank-vpn-gateway-01",
  destination_port: 443,
  protocol: "https",
  asset_criticality: "critical",
  log_message: "Multiple failed login attempts detected for admin user from same source IP",
  raw_event: {
    vendor: "demo",
    connector: "manual",
  },
};

const els = {
  rows: document.querySelector("#alertRows"),
  total: document.querySelector("#totalCount"),
  critical: document.querySelector("#criticalCount"),
  high: document.querySelector("#highCount"),
  low: document.querySelector("#lowCount"),
  burst: document.querySelector("#burstBtn"),
  incident: document.querySelector("#incidentBtn"),
  sim: document.querySelector("#simBtn"),
  clear: document.querySelector("#clearBtn"),
  send: document.querySelector("#sendAlertBtn"),
  applyFilters: document.querySelector("#applyFiltersBtn"),
  search: document.querySelector("#searchInput"),
  priorityFilter: document.querySelector("#priorityFilter"),
  statusFilter: document.querySelector("#statusFilter"),
  manual: document.querySelector("#manualAlert"),
  mitreList: document.querySelector("#mitreList"),
  incidentList: document.querySelector("#incidentList"),
  modelName: document.querySelector("#modelName"),
  modelRole: document.querySelector("#modelRole"),
  emptyDetail: document.querySelector("#emptyDetail"),
  detailContent: document.querySelector("#detailContent"),
  detailPriority: document.querySelector("#detailPriority"),
  detailCategory: document.querySelector("#detailCategory"),
  detailConfidence: document.querySelector("#detailConfidence"),
  detailSourceIp: document.querySelector("#detailSourceIp"),
  detailUser: document.querySelector("#detailUser"),
  detailRule: document.querySelector("#detailRule"),
  detailModel: document.querySelector("#detailModel"),
  detailExplanation: document.querySelector("#detailExplanation"),
  detailAction: document.querySelector("#detailAction"),
  statusSelect: document.querySelector("#statusSelect"),
  saveStatus: document.querySelector("#saveStatusBtn"),
  reportLink: document.querySelector("#reportLink"),
  noteInput: document.querySelector("#noteInput"),
  addNote: document.querySelector("#addNoteBtn"),
};

function formatCategory(value) {
  return (value || "other").replaceAll("_", " ");
}

function priorityPill(priority) {
  const label = priority || "low";
  return `<span class="pill ${label}">${label}</span>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderAlerts() {
  els.rows.innerHTML = state.alerts
    .map(
      (alert) => `
        <tr data-id="${alert.id}">
          <td>${priorityPill(alert.priority)}</td>
          <td>${escapeHtml((alert.status || "new").replaceAll("_", " "))}</td>
          <td class="category">${escapeHtml(formatCategory(alert.category))}</td>
          <td>${escapeHtml(alert.source)}</td>
          <td>${escapeHtml(alert.rule_name || alert.event_type)}</td>
          <td>${escapeHtml(alert.hostname || alert.destination_ip || "-")}</td>
          <td>${escapeHtml(alert.risk_score)}</td>
          <td>${escapeHtml(alert.mitre_attack)}</td>
        </tr>
      `,
    )
    .join("");
}

function renderStats(stats) {
  els.total.textContent = stats.total ?? state.alerts.length;
  els.critical.textContent = stats.critical ?? 0;
  els.high.textContent = stats.high ?? 0;
  els.low.textContent = stats.low ?? 0;
}

function selectAlert(id) {
  const alert = state.alerts.find((item) => item.id === id);
  if (!alert) return;
  state.selectedId = id;
  els.emptyDetail.classList.add("hidden");
  els.detailContent.classList.remove("hidden");
  els.detailPriority.innerHTML = priorityPill(alert.priority);
  els.detailCategory.textContent = formatCategory(alert.category);
  els.detailConfidence.textContent = `${Math.round((alert.confidence || 0) * 100)}%`;
  els.detailSourceIp.textContent = alert.source_ip || "-";
  els.detailUser.textContent = alert.username || "-";
  els.detailRule.textContent = alert.rule_name || "-";
  els.detailModel.textContent = alert.model_used || "-";
  els.detailExplanation.textContent = alert.explanation || "-";
  els.detailAction.textContent = alert.recommended_action || "-";
  els.statusSelect.value = alert.status || "new";
  els.reportLink.href = `/api/alerts/${alert.id}/report`;
}

function currentQuery() {
  const params = new URLSearchParams({ limit: "100" });
  if (els.search.value.trim()) params.set("q", els.search.value.trim());
  if (els.priorityFilter.value) params.set("priority", els.priorityFilter.value);
  if (els.statusFilter.value) params.set("status", els.statusFilter.value);
  return params.toString();
}

function renderMitre(items) {
  els.mitreList.innerHTML = items.length
    ? items
        .map(
          (item) => `
            <div class="list-row">
              <strong>${escapeHtml(item.technique)} - ${escapeHtml(item.name)}</strong>
              <span>${escapeHtml(item.tactic)} · ${escapeHtml(item.count)} alerts</span>
            </div>
          `,
        )
        .join("")
    : `<div class="empty-state">No MITRE data yet.</div>`;
}

function renderIncidents(items) {
  els.incidentList.innerHTML = items.length
    ? items
        .map(
          (item) => `
            <div class="list-row">
              <strong>${escapeHtml(item.id)} · ${escapeHtml(item.source_ip)}</strong>
              <span>${escapeHtml(item.summary)} Highest risk: ${escapeHtml(item.highest_risk)}</span>
            </div>
          `,
        )
        .join("")
    : `<div class="empty-state">No correlated incidents yet.</div>`;
}

async function loadIntel() {
  const [mitreResponse, incidentResponse] = await Promise.all([fetch("/api/mitre"), fetch("/api/incidents")]);
  renderMitre((await mitreResponse.json()).techniques || []);
  renderIncidents((await incidentResponse.json()).incidents || []);
}

async function loadInitialData() {
  const [alertsResponse, statsResponse, modelResponse] = await Promise.all([
    fetch(`/api/alerts?${currentQuery()}`),
    fetch("/api/stats"),
    fetch("/api/model"),
  ]);
  const alertsData = await alertsResponse.json();
  const stats = await statsResponse.json();
  const model = await modelResponse.json();
  state.alerts = alertsData.alerts || [];
  renderAlerts();
  renderStats(stats);
  els.modelName.textContent = model.classifier;
  els.modelRole.textContent = `${model.active_model || ""} · ${model.role}`;
  await loadIntel();
}

function connectEvents() {
  const source = new EventSource("/api/events");
  source.onmessage = (message) => {
    const event = JSON.parse(message.data);
    if (event.type === "classified_alert") {
      state.alerts = [event.data, ...state.alerts.filter((alert) => alert.id !== event.data.id)].slice(0, 100);
      renderAlerts();
      if (!state.selectedId) selectAlert(event.data.id);
      loadIntel();
    }
    if (event.type === "updated_alert") {
      state.alerts = state.alerts.map((alert) => (alert.id === event.data.id ? event.data : alert));
      renderAlerts();
      if (state.selectedId === event.data.id) selectAlert(event.data.id);
    }
    if (event.type === "stats" || event.type === "heartbeat") {
      renderStats(event.data);
    }
  };
}

async function postJson(url, body = undefined) {
  const response = await fetch(url, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

els.rows.addEventListener("click", (event) => {
  const row = event.target.closest("tr");
  if (row) selectAlert(row.dataset.id);
});

els.burst.addEventListener("click", async () => {
  await postJson("/api/demo/burst?count=8");
});

els.incident.addEventListener("click", async () => {
  await postJson("/api/demo/incident");
});

els.applyFilters.addEventListener("click", loadInitialData);

els.sim.addEventListener("click", async () => {
  if (state.simulatorRunning) {
    await postJson("/api/simulator/stop");
    state.simulatorRunning = false;
    els.sim.textContent = "Start Simulator";
  } else {
    await postJson("/api/simulator/start");
    state.simulatorRunning = true;
    els.sim.textContent = "Stop Simulator";
  }
});

els.clear.addEventListener("click", async () => {
  await fetch("/api/alerts", { method: "DELETE" });
  state.alerts = [];
  state.selectedId = null;
  els.detailContent.classList.add("hidden");
  els.emptyDetail.classList.remove("hidden");
  renderAlerts();
  renderStats({ total: 0, critical: 0, high: 0, low: 0 });
  await loadIntel();
});

els.send.addEventListener("click", async () => {
  const payload = JSON.parse(els.manual.value);
  await postJson("/api/alerts", payload);
});

els.saveStatus.addEventListener("click", async () => {
  if (!state.selectedId) return;
  const updated = await fetch(`/api/alerts/${state.selectedId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: els.statusSelect.value }),
  }).then((response) => response.json());
  state.alerts = state.alerts.map((alert) => (alert.id === updated.id ? updated : alert));
  renderAlerts();
  selectAlert(updated.id);
});

els.addNote.addEventListener("click", async () => {
  if (!state.selectedId || !els.noteInput.value.trim()) return;
  await postJson(`/api/alerts/${state.selectedId}/notes`, { note: els.noteInput.value.trim() });
  els.noteInput.value = "";
});

els.manual.value = JSON.stringify(sampleAlert, null, 2);
loadInitialData().then(connectEvents).catch((error) => {
  console.error(error);
  els.modelName.textContent = "Unable to load app state";
});
