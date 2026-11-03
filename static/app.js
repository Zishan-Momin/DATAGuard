const state = { token: localStorage.getItem("dataguard_token"), user: null, page: "overview", authMode: "login", connections: [], analyses: [], findings: [], repairs: [], report: null };
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
const dateText = (value) => value ? new Date(value.replace(" ", "T") + (value.includes("Z") ? "" : "Z")).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(`/api${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && !path.startsWith("/auth/")) signOut();
  if (!response.ok) throw new Error(data.detail || "The request could not be completed.");
  return data;
}
function toast(message, error = false) {
  const el = $("#toast"); el.textContent = message; el.classList.toggle("error", error); el.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { el.hidden = true; }, 4200);
}
function setAuth(mode) {
  state.authMode = mode;
  $("#auth-submit").textContent = mode === "login" ? "Sign in" : "Create account";
  $("#auth-switch-text").textContent = mode === "login" ? "New to Dataguard?" : "Already have an account?";
  $("#auth-toggle").textContent = mode === "login" ? "Create account" : "Sign in";
  $("#admin-setup-field").hidden = mode === "login";
  $("#auth-note").textContent = mode === "login"
    ? "For a new local installation, the first registered account becomes administrator."
    : "On hosted deployments, enter the administrator setup token provided by the deployer.";
  $("#auth-message").hidden = true;
}
function signOut() {
  state.token = null; state.user = null; localStorage.removeItem("dataguard_token");
  $("#workspace").hidden = true; $("#auth-view").hidden = false;
}
async function enterApp() {
  const response = await api("/auth/me"); state.user = response.user;
  $("#user-email").textContent = state.user.email; $("#user-role").textContent = state.user.role;
  $("#user-avatar").textContent = state.user.email[0].toUpperCase();
  $("#auth-view").hidden = true; $("#workspace").hidden = false;
  await refreshData(); renderPage();
}
async function refreshData() {
  const [connections, analyses, findings, repairs, report] = await Promise.all([
    api("/connections"), api("/analyses"), api("/findings"), api("/repairs"), api("/reports")
  ]);
  Object.assign(state, { connections, analyses, findings, repairs, report });
  $("#findings-nav-count").textContent = findings.filter(item => item.status === "detected" && item.repair_status !== "resolved").length;
}
function badge(status) {
  const key = String(status || "").toLowerCase();
  return `<span class="badge ${escapeHtml(key)}">${escapeHtml(status || "unknown")}</span>`;
}
function heading(title, description, actions = "") {
  return `<div class="page-heading"><div><h1>${title}</h1><p>${description}</p></div><div class="heading-actions">${actions}</div></div>`;
}
function metric(title, value, note, icon, good = false) {
  return `<article class="metric-card"><div class="metric-top">${title}<span class="metric-icon">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-foot ${good ? "good" : ""}">${note}</div></article>`;
}
function empty(title, note, icon = "◇") {
  return `<div class="empty-state"><div class="empty-icon">${icon}</div><strong>${title}</strong><p>${note}</p></div>`;
}
function barRows(counts, colors = {}) {
  const entries = Object.entries(counts || {});
  const max = Math.max(1, ...entries.map(([, count]) => Number(count)));
  if (!entries.length) return empty("No data to chart yet", "Run a database analysis to populate this chart.", "▤");
  return `<div class="chart-rows">${entries.map(([name, count]) => `<div class="chart-row"><span>${escapeHtml(name)}</span><div class="bar-track"><div class="bar-fill ${colors[name] || ""}" style="width:${Math.max(3, count / max * 100)}%"></div></div><b>${count}</b></div>`).join("")}</div>`;
}
function activityRows() {
  const rows = state.analyses.slice(0, 5);
  if (!rows.length) return empty("No analysis activity", "Connect a database and run your first scan.", "↗");
  return `<div class="activity-list">${rows.map(item => `<div class="activity-item"><span class="activity-mark">⌕</span><div><strong>Analysis completed</strong><small>${escapeHtml(item.connection_name)} · ${item.tables_analyzed} tables · health ${item.health_score}</small></div><time>${escapeHtml(dateText(item.created_at))}</time></div>`).join("")}</div>`;
}
function overviewPage() {
  const detected = state.findings.filter(item => item.status === "detected" && item.repair_status !== "resolved");
  const critical = detected.filter(item => item.severity === "Critical").length;
  const pending = state.repairs.filter(item => item.status === "pending").length;
  const resolved = state.repairs.filter(item => item.status === "executed" && item.verified).length;
  const latest = state.analyses[0];
  const categories = {}; const severities = {};
  detected.forEach(item => { categories[item.category] = (categories[item.category] || 0) + 1; severities[item.severity] = (severities[item.severity] || 0) + 1; });
  return `${heading("Database overview", "A clear view of your connected data health.", `<button class="button secondary" data-go="connections">＋ Add database</button><button class="button primary" data-go="connections">Run analysis</button>`)}
    <div class="metric-grid">
      ${metric("Connected databases", state.connections.filter(item => item.connected).length, `${state.connections.length} configured`, "⌘")}
      ${metric("Tables analyzed", latest?.tables_analyzed ?? 0, latest ? `Latest: ${escapeHtml(latest.connection_name)}` : "Run your first analysis", "▦")}
      ${metric("Detected problems", detected.length, `${state.findings.filter(item => item.status === "potential").length} optimization opportunities`, "⌕")}
      ${metric("Critical problems", critical, critical ? "Requires immediate review" : "No critical findings", "!", critical === 0)}
    </div>
    <div class="metric-grid">
      ${metric("Pending approvals", pending, "Administrator review needed", "◷")}
      ${metric("Resolved repairs", resolved, "Executed and verified", "✓", true)}
      ${metric("Database health", latest ? `${latest.health_score}<small style="font:500 12px var(--font)"> / 100</small>` : "—", latest ? "Latest analysis score" : "Not yet analyzed", "◉")}
      ${metric("Latest scan", latest ? escapeHtml(dateText(latest.created_at)) : "—", latest ? `${latest.summary.detected} detected · ${latest.summary.potential} potential` : "No recent activity", "↗")}
    </div>
    <div class="content-grid">
      <section class="panel"><div class="panel-heading"><div><h3>Recent analysis activity</h3><p>Your latest database health checks</p></div><button class="panel-link" data-go="activity">View activity →</button></div>${activityRows()}</section>
      <section class="panel"><div class="panel-heading"><div><h3>Problem categories</h3><p>Detected findings only</p></div></div>${barRows(categories, { "Data quality": "amber", "Integrity": "red" })}</section>
    </div>
    <div class="section-row"><section class="panel"><div class="panel-heading"><div><h3>Severity distribution</h3><p>Open detected findings</p></div></div>${barRows(severities, { High: "red", Critical: "red", Medium: "amber", Low: "blue" })}</section>
    <section class="panel"><div class="panel-heading"><div><h3>Repair status</h3><p>Approval and execution history</p></div><button class="panel-link" data-go="approvals">Review →</button></div>${barRows(Object.fromEntries(state.report.repairs.map(item => [item.status, item.count])), { failed: "red", pending: "blue", executed: "" })}</section></div>`;
}
function connectionsPage() {
  const rows = state.connections.length ? `<div class="connection-list">${state.connections.map(item => `<div class="connection-row"><span class="db-icon">${item.backend === "SQLite" ? "▣" : "◈"}</span><div class="connection-info"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.backend)} · ${item.connected ? "Ready for analysis" : "Reconnect after server restart"}</small></div>${badge(item.connected ? "connected" : "offline")} ${item.connected ? `<button class="button small primary" data-analyze="${escapeHtml(item.id)}">Analyze</button>` : ""}</div>`).join("")}</div>` : empty("No databases connected", "Add a sample database or connect a database you own.", "⌘");
  return `${heading("Database connections", "Connect and analyze databases using read-only diagnostics.")}
    <div class="split-panel"><section class="panel"><div class="panel-heading"><div><h3>Connect a database</h3><p>Credentials are kept in server memory and never saved to the app database.</p></div></div>
      <form id="connection-form"><div class="form-grid">
        <div class="field"><label>Connection name</label><input name="name" required maxlength="80" placeholder="Production reporting"></div>
        <div class="field"><label>Database engine</label><select name="backend"><option>SQLite</option><option>PostgreSQL</option><option>MySQL</option></select></div>
        <div class="field full"><label>Database path or SQLAlchemy URL</label><input name="connection_url" required placeholder="C:\\data\\analytics.db"></div>
        <div class="field-hint full">SQLite: local file path. PostgreSQL: postgresql+psycopg://… · MySQL: mysql+pymysql://… Keep database permissions read-only for analysis.</div>
      </div><div class="heading-actions"><button class="button secondary" name="action" value="test">Test connection</button><button class="button primary" name="action" value="add">Save connection</button></div></form>
    </section><section class="panel"><div class="panel-heading"><div><h3>Explore a sample database</h3><p>Seeded with realistic data-quality and integrity issues.</p></div><span class="db-icon">▣</span></div>
      <div class="details-grid"><div class="detail-item"><small>DEMO FINDINGS</small><strong>Duplicate rows · NULL values · Orphan records</strong></div><div class="detail-item"><small>SAFE OPTIMIZATION</small><strong>Missing foreign-key index</strong></div></div>
      <div class="notice-box">The sample is local and reproducible. Analysis does not modify the target database. Only an administrator-approved index creation can be executed.</div>
      <button class="button primary" id="add-sample" style="margin-top:14px">＋ Add sample database</button>
    </section></div>
    <section class="panel" style="margin-top:14px"><div class="panel-heading"><div><h3>Your databases</h3><p>Active connections for this session</p></div></div>${rows}</section>`;
}
function explorerPage() {
  const active = state.connections.filter(item => item.connected);
  if (!active.length) return `${heading("Database explorer", "Inspect tables, columns, indexes, and relationships.", `<button class="button secondary" data-go="connections">Connect database</button>`)}<section class="panel">${empty("No active database connection", "Connect a database during this server session to explore its schema.", "▦")}</section>`;
  return `${heading("Database explorer", "Inspect database structure without changing target data.", `<select class="button secondary" id="schema-database">${active.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("")}</select>`)}
    <div id="schema-results"><section class="panel"><div class="loading">Loading schema…</div></section></div>`;
}
async function loadExplorer(connectionId) {
  const target = $("#schema-results");
  if (!target) return;
  target.innerHTML = `<section class="panel"><div class="loading">Loading schema metadata…</div></section>`;
  try {
    const result = await api(`/connections/${connectionId}/schema`);
    if (state.page !== "explorer" || !$("#schema-results")) return;
    target.innerHTML = result.tables.length
      ? `<div class="panel-heading"><div><h3>${result.tables.length} tables · ${escapeHtml(result.database)}</h3><p>Schema metadata only; records are not modified.</p></div></div><div class="split-panel">${result.tables.map(table => `<section class="panel"><div class="panel-heading"><div><h3>${escapeHtml(table.name)}</h3><p>${table.columns.length} columns · ${table.indexes.length} indexes</p></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Column</th><th>Type</th><th>Null</th><th>Key</th></tr></thead><tbody>${table.columns.map(column => `<tr><td class="primary-cell">${escapeHtml(column.name)}</td><td>${escapeHtml(column.type)}</td><td>${column.nullable ? "Yes" : "No"}</td><td>${column.primary_key ? "Primary" : "—"}</td></tr>`).join("")}</tbody></table></div>${table.foreign_keys.length ? `<p class="sub-cell">Foreign keys: ${table.foreign_keys.map(key => `${escapeHtml((key.constrained_columns || []).join(", "))} → ${escapeHtml(key.referred_table || "")}`).join(" · ")}</p>` : ""}${table.indexes.length ? `<p class="sub-cell">Indexes: ${table.indexes.map(index => escapeHtml(index.name)).join(", ")}</p>` : ""}</section>`).join("")}</div>`
      : `<section class="panel">${empty("No tables found", "This database has no tables in the current schema.", "▦")}</section>`;
  } catch (error) {
    if (state.page === "explorer" && $("#schema-results")) target.innerHTML = `<section class="panel"><div class="notice-box">${escapeHtml(error.message)}</div></section>`;
  }
}
function findingsPage() {
  const rows = state.findings;
  const table = rows.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Type</th><th>Repair</th></tr></thead><tbody>${rows.map(item => `<tr><td class="primary-cell">${escapeHtml(item.name)}<br><span class="sub-cell">${escapeHtml(item.description)}</span></td><td>${escapeHtml(item.category)}</td><td>${badge(item.severity)}</td><td>${badge(item.status)}</td><td>${item.repair_kind === "create_index" && item.repair_status === "not_proposed" ? `<button class="button small secondary" data-propose="${escapeHtml(item.id)}">Propose repair</button>` : badge(item.repair_status === "not_proposed" ? "advisory" : item.repair_status)}</td></tr>`).join("")}</tbody></table></div>` : empty("No findings yet", "Connect a database and run an analysis to see actual results.", "⌕");
  return `${heading("Detected findings", "Rule-based findings are separated from optimization opportunities.", `<button class="button secondary" data-go="connections">Choose database</button>`)}<section class="panel">${table}</section>`;
}
function approvalsPage() {
  const pending = state.repairs.filter(item => item.status === "pending");
  const others = state.repairs.filter(item => item.status !== "pending");
  const canApprove = state.user.role === "admin";
  const cards = pending.length ? pending.map(item => `<article class="proposal-card"><div class="proposal-top"><strong>${escapeHtml(item.finding_name)}</strong>${badge(item.status)}</div><p>${escapeHtml(item.description)}<br><br><b>Recommendation:</b> ${escapeHtml(item.recommendation)}<br><b>Risk:</b> ${escapeHtml(item.risk)}</p><div class="sql-box">${escapeHtml(item.sql_preview)}</div>${canApprove ? `<div class="repair-actions"><button class="button small danger" data-decision="rejected" data-id="${escapeHtml(item.id)}">Reject</button><button class="button small primary" data-decision="approved" data-id="${escapeHtml(item.id)}">Approve</button></div>` : `<p>Only an administrator can approve or reject this repair.</p>`}</article>`).join("") : empty("No pending approvals", "Safe repair proposals submitted by users will appear here.", "◷");
  const history = others.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Repair</th><th>Database</th><th>Status</th><th>Verification</th><th>Action</th></tr></thead><tbody>${others.map(item => `<tr><td class="primary-cell">${escapeHtml(item.finding_name)}<br><span class="sub-cell">${escapeHtml(dateText(item.created_at))}</span></td><td>${escapeHtml(item.connection_name)}</td><td>${badge(item.status)}</td><td>${item.verified ? badge("verified") : "—"}</td><td>${item.status === "approved" && canApprove ? `<button class="button small primary" data-execute="${escapeHtml(item.id)}">Execute approved repair</button>` : item.error_detail ? `<span class="sub-cell">${escapeHtml(item.error_detail)}</span>` : "—"}</td></tr>`).join("")}</tbody></table></div>` : empty("No repair history", "Reviewed repair proposals will appear here.", "↗");
  return `${heading("Administrator approvals", canApprove ? "Review each proposal before a controlled repair can run." : "Review repair proposals. Decisions and execution are restricted to administrators.")}<section class="panel"><div class="panel-heading"><div><h3>Awaiting decision</h3><p>${pending.length} proposal${pending.length === 1 ? "" : "s"} pending</p></div></div>${cards}</section><section class="panel" style="margin-top:14px"><div class="panel-heading"><div><h3>Reviewed repairs</h3><p>Execution is available only for approved operations.</p></div></div>${history}</section>`;
}
function activityPage() {
  const rows = state.analyses.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Analysis</th><th>Database</th><th>Tables</th><th>Health</th><th>Findings</th></tr></thead><tbody>${state.analyses.map(item => `<tr><td>${escapeHtml(dateText(item.created_at))}</td><td class="primary-cell">${escapeHtml(item.connection_name)}</td><td>${item.tables_analyzed}</td><td>${item.health_score}/100</td><td>${item.summary.detected} detected · ${item.summary.potential} potential</td></tr>`).join("")}</tbody></table></div>` : empty("No activity to show", "Your analysis and repair history will appear here.", "↗");
  return `${heading("Analysis activity", "A record of completed database health checks.")}<section class="panel">${rows}</section><section class="panel" style="margin-top:14px"><div class="panel-heading"><div><h3>Audit trail</h3><p>Administrator actions and execution outcomes</p></div></div>${auditTable()}</section>`;
}
function auditTable() {
  return api("/audit").then(rows => rows.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>${rows.map(item => `<tr><td>${escapeHtml(dateText(item.created_at))}</td><td>${escapeHtml(item.actor_email)}</td><td>${badge(item.action)}</td><td>${escapeHtml(item.detail)}</td></tr>`).join("")}</tbody></table></div>` : empty("Audit log is empty", "Approval, rejection, and execution events are recorded here.", "▤")).catch(error => `<div class="notice-box">${escapeHtml(error.message)}</div>`);
}
function reportsPage() {
  const report = state.report;
  const findingCounts = {}; report.findings.forEach(item => { const key = `${item.status} · ${item.severity}`; findingCounts[key] = item.count; });
  return `${heading("Health reports", "An exportable snapshot of diagnostics, approvals, and repair outcomes.", `<button class="button secondary" id="download-report">↓ Download JSON</button>`)}
    <div class="metric-grid">${metric("Total analyses", report.totals.analyses, "All completed scans", "⌕")}${metric("Tables analyzed", report.totals.tables_analyzed, "Across analysis history", "▦")}${metric("Average health", `${Math.round(report.totals.average_health)} / 100`, "Mean analysis score", "◉")}${metric("Repair outcomes", state.repairs.filter(item => item.status === "executed").length, "Executed repairs", "✓", true)}</div>
    <div class="content-grid"><section class="panel"><div class="panel-heading"><div><h3>Findings by type and severity</h3><p>Historical count by analysis result</p></div></div>${barRows(findingCounts, { "detected · High": "red", "detected · Medium": "amber", "potential · Medium": "blue" })}</section><section class="panel"><div class="panel-heading"><div><h3>Repair history</h3><p>Approval and execution status</p></div></div>${barRows(Object.fromEntries(report.repairs.map(item => [item.status, item.count])), { failed: "red", pending: "blue" })}</section></div>`;
}
const pages = { overview: overviewPage, connections: connectionsPage, explorer: explorerPage, findings: findingsPage, approvals: approvalsPage, activity: activityPage, reports: reportsPage };
async function renderPage() {
  $("#page-title").textContent = ({ overview: "Overview", connections: "Databases", explorer: "Explorer", findings: "Findings", approvals: "Approvals", activity: "Activity", reports: "Reports" })[state.page];
  document.querySelectorAll(".nav-link").forEach(button => button.classList.toggle("active", button.dataset.page === state.page));
  $("#page-content").innerHTML = pages[state.page]();
  if (state.page === "explorer") {
    const selector = $("#schema-database");
    if (selector) await loadExplorer(selector.value);
  }
  if (state.page === "activity") {
    const audit = await auditTable(); const panel = $("#page-content .panel:last-child"); if (panel) panel.innerHTML = `<div class="panel-heading"><div><h3>Audit trail</h3><p>Administrator actions and execution outcomes</p></div></div>${audit}`;
  }
}
$("#auth-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = new FormData(event.currentTarget);
  try {
    const body = { email: form.get("email"), password: form.get("password") };
    if (state.authMode === "register") body.admin_setup_token = form.get("admin_setup_token");
    const result = await api(`/auth/${state.authMode === "login" ? "login" : "register"}`, { method: "POST", body: JSON.stringify(body) });
    state.token = result.token; localStorage.setItem("dataguard_token", result.token); await enterApp();
  } catch (error) { $("#auth-message").textContent = error.message; $("#auth-message").hidden = false; }
});
$("#auth-toggle").addEventListener("click", () => setAuth(state.authMode === "login" ? "register" : "login"));
$("#signout").addEventListener("click", signOut);
$("#refresh").addEventListener("click", async () => { try { await refreshData(); renderPage(); toast("Workspace data refreshed."); } catch (error) { toast(error.message, true); } });
$("#navigation").addEventListener("click", event => { const button = event.target.closest("[data-page]"); if (button) { state.page = button.dataset.page; renderPage(); } });
$("#page-content").addEventListener("click", async event => {
  const target = event.target.closest("button"); if (!target) return;
  try {
    if (target.dataset.go) { state.page = target.dataset.go; renderPage(); return; }
    if (target.dataset.analyze) {
      target.disabled = true; target.textContent = "Analyzing…";
      const result = await api(`/analysis/${target.dataset.analyze}`, { method: "POST" });
      await refreshData(); state.page = "findings"; renderPage();
      toast(`Analysis complete: ${result.summary.detected} detected, ${result.summary.potential} potential.`);
    }
    if (target.dataset.propose) {
      await api(`/findings/${target.dataset.propose}/propose`, { method: "POST" });
      await refreshData(); renderPage(); toast("Repair submitted for administrator approval.");
    }
    if (target.dataset.decision) {
      await api(`/repairs/${target.dataset.id}/decision`, { method: "POST", body: JSON.stringify({ decision: target.dataset.decision }) });
      await refreshData(); renderPage(); toast(`Repair ${target.dataset.decision}.`);
    }
    if (target.dataset.execute) {
      await api(`/repairs/${target.dataset.execute}/execute`, { method: "POST" });
      await refreshData(); renderPage(); toast("Repair executed and verified.");
    }
    if (target.id === "add-sample") {
      target.disabled = true; await api("/connections/sample", { method: "POST" }); await refreshData(); renderPage(); toast("Sample database connected.");
    }
    if (target.id === "download-report") {
      const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" });
      const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "dataguard-health-report.json"; link.click(); URL.revokeObjectURL(link.href);
    }
  } catch (error) { toast(error.message, true); }
});
$("#page-content").addEventListener("submit", async event => {
  if (event.target.id !== "connection-form") return;
  event.preventDefault(); const form = new FormData(event.target);
  const body = { name: form.get("name"), backend: form.get("backend"), connection_url: form.get("connection_url") };
  const submitter = event.submitter?.value;
  try {
    const result = await api(submitter === "test" ? "/connections/test" : "/connections", { method: "POST", body: JSON.stringify(body) });
    if (submitter !== "test") await refreshData();
    renderPage(); toast(result.message || "Database connection saved.");
  } catch (error) { toast(error.message, true); }
});
$("#page-content").addEventListener("change", event => {
  if (event.target.id === "schema-database") loadExplorer(event.target.value);
});
if (state.token) enterApp().catch(() => signOut());
