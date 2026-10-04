const API = "/api";
const state = {
  alerts: [],
  primaryAlertId: null,
  ceoUpn: "m.webb@northgateholdings.com",
  fpUpn: "p.anand@northgateholdings.com",
};

// ---------------------------------------------------------------- utils
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function statusPillClass(status) {
  if (/new/i.test(status)) return "pill-new";
  if (/investigat/i.test(status)) return "pill-investigating";
  if (/contain/i.test(status)) return "pill-contained";
  return "pill-closed";
}

async function api(path, opts) {
  const res = await fetch(API + path, opts);
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || "Request failed");
  return body;
}

// ---------------------------------------------------------------- clock
function tickClock() {
  $("#clock").textContent = new Date().toLocaleString(undefined, {
    weekday: "short", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}
setInterval(tickClock, 1000);
tickClock();

// ---------------------------------------------------------------- queue view
async function loadQueue() {
  state.alerts = await api("/alerts");
  const rows = $("#alertRows");
  rows.innerHTML = "";
  for (const a of state.alerts) {
    const tr = document.createElement("tr");
    tr.className = `sev-${a.severity}` + (a.primary ? "" : " disabled");
    tr.innerHTML = `
      <td><span class="sev-bar"></span></td>
      <td>
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.description}</div>
      </td>
      <td>${a.userDisplayName}</td>
      <td class="time-cell">${fmtTime(a.createdTime)}</td>
      <td><span class="pill ${statusPillClass(a.status)}">${a.status}</span></td>
    `;
    if (a.primary) {
      state.primaryAlertId = a.id;
      tr.addEventListener("click", () => openCase(a.id));
    }
    rows.appendChild(tr);
  }
}

// ---------------------------------------------------------------- navigation
function showView(id) {
  $$(".view").forEach(v => v.hidden = true);
  $(id).hidden = false;
}

$("#btnHome").addEventListener("click", () => { showView("#view-queue"); loadQueue(); });
$("#btnBack").addEventListener("click", () => { showView("#view-queue"); loadQueue(); });

let caseLoaded = false;
async function openCase(alertId) {
  showView("#view-case");
  goToStep("triage");
  if (!caseLoaded) {
    await Promise.all([
      loadTriage(alertId),
      loadBaselineAndCompare(),
      loadHunt(alertId),
      loadPersistence(alertId),
      loadReportTab(alertId),
    ]);
    caseLoaded = true;
  }
  refreshCaseStatus(alertId);
}

$$(".step").forEach(btn => btn.addEventListener("click", () => goToStep(btn.dataset.step)));
$$("[data-goto]").forEach(btn => btn.addEventListener("click", () => goToStep(btn.dataset.goto)));

function goToStep(step) {
  $$(".panel").forEach(p => p.hidden = true);
  $(`#panel-${step}`).hidden = false;
  $$(".step").forEach(b => b.classList.toggle("active", b.dataset.step === step));
}

async function refreshCaseStatus(alertId) {
  const a = await api(`/alerts/${alertId}`);
  $("#caseStatusPill").textContent = a.status;
}

// ---------------------------------------------------------------- STEP 1: triage
async function loadTriage(alertId) {
  const a = await api(`/alerts/${alertId}`);
  $("#triageAlertCard").innerHTML = `
    <h4>${a.title}</h4>
    <div class="meta">Severity ${a.severity} &middot; ${a.user} &middot; ${fmtTime(a.createdTime)}</div>
    <p style="margin-top:8px">${a.description}</p>
  `;

  const logs = await api(`/signin-logs?user=${encodeURIComponent(state.ceoUpn)}&resultType=0&limit=5`);
  const breach = logs.find(l => l.IPAddress !== "198.51.100.10") || logs[0];
  const kv = $("#triageSignin");
  kv.innerHTML = "";
  const rows = [
    ["Time", fmtTime(breach.TimeGenerated)],
    ["User", breach.UserPrincipalName],
    ["IP address", breach.IPAddress],
    ["Location", `${breach.City}, ${breach.Country}`],
    ["App / protocol", breach.AppDisplayName],
    ["Conditional Access", breach.ConditionalAccessStatus],
    ["Risk level", breach.RiskLevel],
  ];
  for (const [k, v] of rows) {
    const flag = (k === "Conditional Access" && v === "notApplied") || (k === "Risk level" && v === "high");
    kv.innerHTML += `<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-val ${flag ? "flag" : ""}">${v}</span></div>`;
  }
  state.breachSigninId = breach.Id;
}

// ---------------------------------------------------------------- STEP 2: baseline & compare
function renderBaselineCard(b) {
  const topLoc = b.locations[0];
  const topDev = b.devices[0];
  return `
    <div class="kv">
      <div class="kv-row"><span class="kv-key">Sign-ins analyzed</span><span class="kv-val">${b.signInCount}</span></div>
      <div class="kv-row"><span class="kv-key">Typical hours</span><span class="kv-val">${b.typicalHourRange[0]}:00–${b.typicalHourRange[1]}:00</span></div>
      <div class="kv-row"><span class="kv-key">Usual location</span><span class="kv-val">${topLoc.City}, ${topLoc.Country}</span></div>
      <div class="kv-row"><span class="kv-key">Usual device</span><span class="kv-val">${topDev.DeviceOS} / ${topDev.Browser}</span></div>
      <div class="kv-row"><span class="kv-key">Known IPs</span><span class="kv-val">${b.ipAddresses.map(i => i.IPAddress).join(", ")}</span></div>
    </div>
  `;
}

function renderCompare(c) {
  const flagRows = Object.entries(c.flags).map(([k, v]) => {
    const label = k.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase());
    return `<div class="kv-row"><span class="kv-key">${label}</span><span class="kv-val ${v ? "flag" : ""}">${v ? "Yes" : "No"}</span></div>`;
  }).join("");
  const verdictColor = c.verdict.startsWith("Likely") ? "var(--red)" : c.verdict.startsWith("Needs") ? "var(--amber)" : "var(--green)";
  return `
    <div class="kv">${flagRows}</div>
    <div style="margin-top:10px;font-family:var(--mono);font-weight:600;color:${verdictColor}">
      Verdict: ${c.verdict}
    </div>
  `;
}

async function loadBaselineAndCompare() {
  const [ceoBaseline, ceoCompare] = await Promise.all([
    api(`/users/${encodeURIComponent(state.ceoUpn)}/baseline`),
    api(`/compare?user=${encodeURIComponent(state.ceoUpn)}&signInId=${state.breachSigninId}`),
  ]);
  $("#baselineCeo").innerHTML = renderBaselineCard(ceoBaseline);
  $("#compareCeo").innerHTML = renderCompare(ceoCompare);

  // false positive: Priya's Dubai sign-in
  const fpLogs = await api(`/signin-logs?user=${encodeURIComponent(state.fpUpn)}&limit=50`);
  const dubai = fpLogs.find(l => l.City === "Dubai");
  const fpCompare = await api(`/compare?user=${encodeURIComponent(state.fpUpn)}&signInId=${dubai.Id}`);
  $("#compareFp").innerHTML = `
    <div class="kv-row" style="border:none;padding-top:0"><span class="kv-key">Sign-in</span>
      <span class="kv-val">${dubai.City}, ${dubai.Country} at ${fmtTime(dubai.TimeGenerated)}</span></div>
    ${renderCompare(fpCompare)}
  `;
}

// ---------------------------------------------------------------- STEP 3: hunt (KQL)
const EXAMPLE_QUERIES = {
  spray: `SigninLogs
| where ResultType == 50126
| summarize count() by IPAddress, bin(TimeGenerated, 1h)
| where count_ > 20
| order by count_ desc`,
  ceo: `SigninLogs
| where UserPrincipalName == "${"m.webb@northgateholdings.com"}"
| order by TimeGenerated desc
| take 20`,
  breach: `SigninLogs
| where ResultType == 0
| where IPAddress == "154.72.184.23"`,
  audit: `AuditLogs
| where IPAddress == "154.72.184.23"
| order by TimeGenerated`,
};

$$(".chip").forEach(chip => chip.addEventListener("click", () => {
  $("#kqlInput").value = EXAMPLE_QUERIES[chip.dataset.q];
}));

function renderKqlResults(result) {
  const box = $("#kqlResults");
  if (!result.rows.length) {
    box.innerHTML = `<p class="muted small">No rows returned.</p>`;
    return;
  }
  const cols = result.columns;
  let html = `<table><thead><tr>${cols.map(c => `<th>${c}</th>`).join("")}</tr></thead><tbody>`;
  for (const row of result.rows.slice(0, 200)) {
    html += `<tr>${cols.map(c => `<td>${row[c]}</td>`).join("")}</tr>`;
  }
  html += `</tbody></table>`;
  box.innerHTML = html;
}

async function runKql() {
  const query = $("#kqlInput").value;
  $("#kqlStatus").textContent = "Running…";
  try {
    const result = await api("/kql", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });
    $("#kqlStatus").textContent = `${result.row_count} row(s)`;
    renderKqlResults(result);
  } catch (e) {
    $("#kqlStatus").textContent = "";
    $("#kqlResults").innerHTML = `<div class="kql-error">${e.message}</div>`;
  }
}
$("#btnRunKql").addEventListener("click", runKql);

async function loadHunt(alertId) {
  await runKql();
  const timeline = await api(`/incident/${alertId}/timeline`);
  const box = $("#huntTimeline");
  box.innerHTML = timeline.map(e => `
    <div class="timeline-item">
      <div class="timeline-time">${fmtTime(e.time)}</div>
      <div class="timeline-phase">${e.phase.toUpperCase()}</div>
      <div class="timeline-title">${e.title}</div>
      <div class="timeline-detail">${e.detail}</div>
    </div>
  `).join("");
}

// ---------------------------------------------------------------- STEP 4: persistence & containment
const CONTAINMENT_LABELS = {
  revoked_sessions: "Revoke all active sessions & refresh tokens",
  removed_mfa_method: "Remove attacker-registered MFA method",
  removed_inbox_rule: "Delete hidden inbox rule",
  removed_forwarding: "Remove external mail forwarding",
  revoked_oauth_consent: "Revoke unverified OAuth app consent",
  blocked_ip: "Block attacker IP at tenant firewall",
  forced_password_reset: "Force password reset for all 24 targeted accounts",
};

async function loadPersistence(alertId) {
  const audit = await api(`/audit-logs?user=${encodeURIComponent(state.ceoUpn)}`);
  const attackerAudit = audit.filter(a => a.IPAddress === "154.72.184.23");
  $("#persistenceAudit").innerHTML = attackerAudit.map(a => `
    <div class="audit-item">
      <div class="audit-op">${a.OperationName}</div>
      <div class="audit-detail">${a.AdditionalDetails}</div>
      <div class="audit-time">${fmtTime(a.TimeGenerated)} &middot; from ${a.IPAddress}</div>
    </div>
  `).join("");

  await renderContainment(alertId);
}

async function renderContainment(alertId) {
  const c = await api(`/incident/${alertId}/containment`);
  const box = $("#containmentList");
  box.innerHTML = Object.entries(CONTAINMENT_LABELS).map(([key, label]) => {
    const done = c.containment[key];
    return `
      <div class="containment-item ${done ? "done" : ""}">
        <span class="containment-label">${label}</span>
        <button class="containment-btn ${done ? "done" : ""}" data-action="${key}" ${done ? "disabled" : ""}>
          ${done ? "✓ Done" : "Take action"}
        </button>
      </div>
    `;
  }).join("");
  $$(".containment-btn", box).forEach(btn => {
    if (btn.disabled) return;
    btn.addEventListener("click", async () => {
      await api(`/incident/${alertId}/containment`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: btn.dataset.action }),
      });
      await renderContainment(alertId);
      await refreshCaseStatus(alertId);
    });
  });
}

// ---------------------------------------------------------------- STEP 5: report
async function loadReportTab(alertId) {
  const mitre = await api("/mitre");
  $("#mitreList").innerHTML = mitre.map(m => `
    <div class="mitre-item">
      <span class="mitre-id">${m.id}</span><span class="mitre-name">${m.name}</span>
      <span class="mitre-tactic">${m.tactic}</span>
      <div class="mitre-evidence">${m.evidence}</div>
    </div>
  `).join("");

  await renderNotes(alertId);
  await renderReport(alertId);

  $("#btnAddNote").addEventListener("click", async () => {
    const input = $("#noteInput");
    if (!input.value.trim()) return;
    await api(`/incident/${alertId}/notes`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: input.value.trim() }),
    });
    input.value = "";
    await renderNotes(alertId);
    await renderReport(alertId);
  });

  $("#btnDownloadReport").addEventListener("click", async () => {
    const { markdown } = await api(`/incident/${alertId}/report`);
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "incident-report.md";
    a.click();
    URL.revokeObjectURL(url);
  });
}

async function renderNotes(alertId) {
  const notes = await api(`/incident/${alertId}/notes`);
  $("#notesList").innerHTML = notes.length
    ? notes.map(n => `<div class="note-item"><span class="note-time">${fmtTime(n.time)}</span>${n.text}</div>`).join("")
    : `<p class="muted small">No notes yet.</p>`;
}

async function renderReport(alertId) {
  const { markdown } = await api(`/incident/${alertId}/report`);
  $("#reportPreview").textContent = markdown;
}

// ---------------------------------------------------------------- boot
loadQueue();
