const invoke = window.__TAURI__?.core?.invoke;

const typeLabels = {
  web_server: "Web Server",
  database: "Database",
  development: "Development",
  system: "System",
  other: "Other",
};

const state = {
  entries: [],
  filtered: [],
  favorites: new Set(),
  view: "all",
  processType: null,
  tableMode: "simple",
  expanded: new Set(),
  pendingKill: null,
  refreshToken: 0,
  renderToken: 0,
};

const ROW_RENDER_BATCH = 80;
const GROUP_RENDER_BATCH = 20;

const els = {
  rows: document.getElementById("rows"),
  groupView: document.getElementById("groupView"),
  tableView: document.getElementById("tableView"),
  query: document.getElementById("query"),
  protocol: document.getElementById("protocol"),
  ipVersion: document.getElementById("ipVersion"),
  tcpState: document.getElementById("state"),
  showDetails: document.getElementById("showDetails"),
  tableMode: document.getElementById("tableMode"),
  refresh: document.getElementById("refresh"),
  notice: document.getElementById("notice"),
  countAll: document.getElementById("countAll"),
  countListen: document.getElementById("countListen"),
  countGroups: document.getElementById("countGroups"),
  countFavorites: document.getElementById("countFavorites"),
  viewLabel: document.getElementById("viewLabel"),
  viewTitle: document.getElementById("viewTitle"),
  modal: document.getElementById("modal"),
  modalText: document.getElementById("modalText"),
  modalFacts: document.getElementById("modalFacts"),
  cancelKill: document.getElementById("cancelKill"),
  confirmKill: document.getElementById("confirmKill"),
  navItems: Array.from(document.querySelectorAll(".nav-item")),
};

async function initialize() {
  if (!invoke) {
    showNotice("Tauri API 未加载。请通过 portKill.exe 启动此界面。");
    return;
  }

  els.tableMode.value = state.tableMode;
  renderPortTableHeader();

  try {
    const favorites = await invoke("load_favorites");
    state.favorites = new Set(favorites.map(Number));
  } catch (err) {
    showNotice(String(err));
  }
  await refreshPorts();
}

function currentFilter() {
  return {
    protocol: els.protocol.value,
    ip_version: els.ipVersion.value,
    state: els.tcpState.value,
    query: els.query.value,
    listeners_only: !els.showDetails.checked,
    port: null,
  };
}

async function refreshPorts() {
  const token = ++state.refreshToken;
  els.refresh.disabled = true;
  try {
    state.entries = await invoke("get_ports");
    if (token !== state.refreshToken) return;
    applyClientFilter();
    if (!els.notice.textContent.includes("收藏")) showNotice("");
    enrichProcessDetails(token);
  } catch (err) {
    showNotice(String(err));
  } finally {
    els.refresh.disabled = false;
  }
}

async function enrichProcessDetails(token) {
  const requests = uniqueProcessRequests(state.entries);
  if (requests.length === 0) return;

  try {
    const details = await invoke("get_process_details", { requests });
    if (token !== state.refreshToken) return;

    const detailMap = new Map(details.map((item) => [Number(item.pid), item]));
    state.entries = state.entries.map((entry) => {
      const detail = detailMap.get(Number(entry.pid));
      if (!detail) return entry;
      return {
        ...entry,
        user: detail.user || entry.user || "",
        command: detail.command || entry.command || "",
        process_type: mergeProcessType(entry.process_type, detail.process_type),
      };
    });
    applyClientFilter();
  } catch (err) {
    console.warn("Process details enrichment failed", err);
  }
}

function mergeProcessType(current, incoming) {
  if (!incoming || incoming === "other") return current || "other";
  return incoming;
}

function uniqueProcessRequests(entries) {
  const map = new Map();
  for (const entry of entries) {
    const pid = Number(entry.pid);
    if (!map.has(pid)) {
      map.set(pid, {
        pid,
        process: entry.process || "",
        path: entry.path || "",
      });
    }
  }
  return Array.from(map.values());
}

function applyClientFilter() {
  const filter = currentFilter();
  const query = filter.query.trim().toLowerCase();
  const protocol = filter.protocol.toLowerCase();
  const ipVersion = filter.ip_version.toLowerCase();
  const tcpState = filter.state.toUpperCase();

  state.filtered = state.entries.filter((entry) => {
    if (protocol !== "all" && entry.protocol.toLowerCase() !== protocol) return false;
    if (ipVersion !== "all" && entryIpVersion(entry) !== ipVersion) return false;
    if (tcpState && entry.state.toUpperCase() !== tcpState) return false;
    if (filter.listeners_only && entry.protocol !== "UDP" && entry.state !== "LISTENING") {
      return false;
    }
    if (state.view === "favorites" && !state.favorites.has(entry.local_port)) return false;
    if (state.processType && entry.process_type !== state.processType) return false;
    if (!query) return true;
    return [
      entry.local_addr,
      entry.local_port,
      entry.remote_addr,
      entry.remote_port,
      entry.state,
      entry.pid,
      entry.process,
      entry.path,
      entry.user,
      entry.command,
      entry.process_type,
      processTypeLabel(entry.process_type),
    ]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });

  renderSummary();
  renderCurrentView();
}

function renderSummary() {
  const listening = state.entries.filter(
    (entry) => entry.protocol === "UDP" || entry.state === "LISTENING",
  ).length;
  els.countAll.textContent = state.filtered.length;
  els.countListen.textContent = listening;
  els.countGroups.textContent = groupEntries(state.filtered).length;
  els.countFavorites.textContent = state.favorites.size;
}

function renderCurrentView() {
  const token = ++state.renderToken;
  syncNav();
  updateTitle();
  if (state.view === "grouped") {
    els.tableView.hidden = true;
    els.groupView.hidden = false;
    renderGroups(token);
  } else {
    els.groupView.hidden = true;
    els.tableView.hidden = false;
    renderRows(token);
  }
}

async function renderRows(token) {
  if (state.filtered.length === 0) {
    renderPortTableHeader();
    els.rows.innerHTML = `<tr><td colspan="${state.tableMode === "simple" ? 3 : 14}" class="empty">没有匹配的端口记录</td></tr>`;
    return;
  }

  renderPortTableHeader();
  els.rows.replaceChildren();
  for (let index = 0; index < state.filtered.length; index += ROW_RENDER_BATCH) {
    if (token !== state.renderToken) return;

    const fragment = document.createDocumentFragment();
    for (const entry of state.filtered.slice(index, index + ROW_RENDER_BATCH)) {
      fragment.appendChild(state.tableMode === "simple" ? createSimplePortRow(entry) : createPortRow(entry));
    }
    els.rows.appendChild(fragment);
    await nextFrame();
  }
}

function renderPortTableHeader() {
  const thead = els.tableView.querySelector("thead");
  if (state.tableMode === "simple") {
    els.tableView.classList.add("simple-mode");
    thead.innerHTML = `
      <tr>
        <th>端口</th>
        <th>进程</th>
        <th>操作</th>
      </tr>
    `;
    return;
  }

  els.tableView.classList.remove("simple-mode");
  thead.innerHTML = `
    <tr>
      <th>收藏</th>
      <th>类型</th>
      <th>协议</th>
      <th>本地地址</th>
      <th>端口</th>
      <th>远程地址</th>
      <th>远程端口</th>
      <th>状态</th>
      <th>PID</th>
      <th>用户</th>
      <th>进程</th>
      <th>Command</th>
      <th>路径</th>
      <th>操作</th>
    </tr>
  `;
}

function createSimplePortRow(entry) {
  const tr = document.createElement("tr");
  const canKill = Boolean(entry.can_terminate);
  const actionTitle = canKill ? "结束进程" : entry.deny_reason || "不可结束";
  const favorite = state.favorites.has(entry.local_port);
  const details = entryDetailsTitle(entry);
  const endpoint = `${entry.local_addr}:${entry.local_port}`;

  tr.className = "simple-row";
  tr.title = details;
  tr.innerHTML = `
    <td class="simple-port" title="${escapeAttr(details)}">
      <div class="simple-cell">
        <button class="favorite-action ${favorite ? "active" : ""}" type="button" title="${favorite ? "移除收藏" : "添加收藏"}">${favorite ? "★" : "☆"}</button>
        <span class="badge ${entry.protocol === "UDP" ? "udp" : ""}">${escapeHtml(entry.protocol)}</span>
        <strong>${escapeHtml(String(entry.local_port))}</strong>
        <span>${escapeHtml(endpoint)}</span>
      </div>
    </td>
    <td class="simple-process" title="${escapeAttr(details)}">
      <div class="simple-cell">
        <strong>${escapeHtml(entry.process)}</strong>
        <span>PID ${entry.pid}</span>
        <span class="type-badge type-${escapeAttr(entry.process_type || "other")}">${escapeHtml(processTypeLabel(entry.process_type))}</span>
      </div>
    </td>
    <td><button class="row-action" type="button" ${canKill ? "" : "disabled"} title="${escapeAttr(actionTitle)}">结束进程</button></td>
  `;

  tr.querySelector(".favorite-action").addEventListener("click", () => toggleFavorite(entry.local_port));
  const button = tr.querySelector(".row-action");
  if (canKill) button.addEventListener("click", () => openKillModal(entry));
  return tr;
}

function createPortRow(entry, compact = false) {
  const tr = document.createElement("tr");
  const canKill = Boolean(entry.can_terminate);
  const actionTitle = canKill ? "结束进程" : entry.deny_reason || "不可结束";
  const favorite = state.favorites.has(entry.local_port);

  tr.innerHTML = `
    <td><button class="favorite-action ${favorite ? "active" : ""}" type="button" title="${favorite ? "移除收藏" : "添加收藏"}">${favorite ? "★" : "☆"}</button></td>
    <td><span class="type-badge type-${escapeAttr(entry.process_type || "other")}">${escapeHtml(processTypeLabel(entry.process_type))}</span></td>
    <td><span class="badge ${entry.protocol === "UDP" ? "udp" : ""}">${escapeHtml(entry.protocol)}</span></td>
    <td>${escapeHtml(entry.local_addr)}</td>
    <td>${entry.local_port}</td>
    <td>${escapeHtml(entry.remote_addr)}</td>
    <td>${entry.remote_port}</td>
    <td class="${stateClass(entry.state)}">${escapeHtml(entry.state)}</td>
    <td>${entry.pid}</td>
    <td class="clip" title="${escapeAttr(entry.user)}">${escapeHtml(entry.user || "-")}</td>
    <td>${escapeHtml(entry.process)}</td>
    <td class="command" title="${escapeAttr(entry.command)}">${escapeHtml(entry.command || "-")}</td>
    <td class="path" title="${escapeAttr(entry.path)}">${escapeHtml(entry.path || "-")}</td>
    <td><button class="row-action" type="button" ${canKill ? "" : "disabled"} title="${escapeAttr(actionTitle)}">结束进程</button></td>
  `;

  if (compact) tr.classList.add("compact-row");
  tr.querySelector(".favorite-action").addEventListener("click", () => toggleFavorite(entry.local_port));
  const button = tr.querySelector(".row-action");
  if (canKill) button.addEventListener("click", () => openKillModal(entry));
  return tr;
}

function entryDetailsTitle(entry) {
  return [
    `协议: ${entry.protocol}`,
    `本地: ${entry.local_addr}:${entry.local_port}`,
    `远程: ${entry.remote_addr}:${entry.remote_port}`,
    `状态: ${entry.state}`,
    `PID: ${entry.pid}`,
    `进程: ${entry.process}`,
    `类型: ${processTypeLabel(entry.process_type)}`,
    `用户: ${entry.user || "-"}`,
    `Command: ${entry.command || "-"}`,
    `路径: ${entry.path || "-"}`,
    `操作: ${entry.can_terminate ? "可结束" : entry.deny_reason || "不可结束"}`,
  ].join("\n");
}

async function renderGroups(token = ++state.renderToken) {
  const groups = groupEntries(state.filtered);
  if (groups.length === 0) {
    els.groupView.innerHTML = '<div class="empty group-empty">没有匹配的程序组</div>';
    return;
  }

  const table = document.createElement("table");
  table.className = "group-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>展开</th>
        <th>类型</th>
        <th>进程</th>
        <th>PID / 端口</th>
        <th>端口数</th>
        <th>用户</th>
        <th>Command / 路径</th>
        <th>端口</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;
  const tbody = table.querySelector("tbody");
  els.groupView.replaceChildren(table);

  for (let index = 0; index < groups.length; index += GROUP_RENDER_BATCH) {
    if (token !== state.renderToken) return;

    const fragment = document.createDocumentFragment();
    for (const group of groups.slice(index, index + GROUP_RENDER_BATCH)) {
      for (const row of createProcessGroupRows(group)) {
        fragment.appendChild(row);
      }
    }
    tbody.appendChild(fragment);
    await nextFrame();
  }
}

function createProcessGroupRows(group) {
  const groupKey = `process:${group.key}`;
  const expanded = state.expanded.has(groupKey);
  const portsText = group.ports.map((entry) => entry.local_port).join(", ");
  const rows = [];
  const tr = document.createElement("tr");
  tr.className = "process-name-row";
  tr.innerHTML = `
    <td><button class="group-toggle process-toggle" type="button" aria-expanded="${expanded}" title="${expanded ? "收起进程" : "展开进程"}">${expanded ? "▼" : "▶"}</button></td>
    <td><span class="type-badge type-${escapeAttr(group.process_type || "other")}">${escapeHtml(processTypeLabel(group.process_type))}</span></td>
    <td class="group-process" title="${escapeAttr(group.process)}">${escapeHtml(group.process)}</td>
    <td>${group.pidGroups.length} PID</td>
    <td>${group.ports.length}</td>
    <td class="clip" title="${escapeAttr(group.users.join(", "))}">${escapeHtml(group.users.join(", ") || "-")}</td>
    <td class="command" title="${escapeAttr(group.paths.join(" | "))}">${escapeHtml(group.paths.join(" | ") || "-")}</td>
    <td class="path" title="${escapeAttr(portsText)}">${escapeHtml(portsText)}</td>
    <td><button class="row-action" type="button" disabled title="请展开后按 PID 结束进程">结束进程</button></td>
  `;

  tr.querySelector(".group-toggle").addEventListener("click", () => {
    if (state.expanded.has(groupKey)) state.expanded.delete(groupKey);
    else state.expanded.add(groupKey);
    renderGroups();
  });
  rows.push(tr);

  if (expanded) {
    for (const pidGroup of group.pidGroups) {
      rows.push(createPidGroupRow(group, pidGroup));
      if (state.expanded.has(pidGroup.key)) {
        for (const entry of pidGroup.ports) {
          rows.push(createGroupPortRow(entry));
        }
      }
    }
  }

  return rows;
}

function createPidGroupRow(group, pidGroup) {
  const expanded = state.expanded.has(pidGroup.key);
  const portsText = pidGroup.ports.map((entry) => entry.local_port).join(", ");
  const canKill = pidGroup.ports.some((entry) => entry.can_terminate);
  const tr = document.createElement("tr");
  tr.className = "process-pid-row";
  tr.innerHTML = `
    <td><button class="group-toggle pid-toggle" type="button" aria-expanded="${expanded}" title="${expanded ? "收起端口" : "展开端口"}">${expanded ? "−" : "+"}</button></td>
    <td><span class="type-badge type-${escapeAttr(pidGroup.process_type || group.process_type || "other")}">${escapeHtml(processTypeLabel(pidGroup.process_type || group.process_type))}</span></td>
    <td class="group-pid-indent" title="${escapeAttr(pidGroup.process)}">${escapeHtml(pidGroup.process)}</td>
    <td>PID ${pidGroup.pid}</td>
    <td>${pidGroup.ports.length}</td>
    <td class="clip" title="${escapeAttr(pidGroup.user)}">${escapeHtml(pidGroup.user || "-")}</td>
    <td class="command" title="${escapeAttr(pidGroup.command || pidGroup.path)}">${escapeHtml(pidGroup.command || pidGroup.path || "-")}</td>
    <td class="path" title="${escapeAttr(portsText)}">${escapeHtml(portsText)}</td>
    <td><button class="row-action group-kill" type="button" ${canKill ? "" : "disabled"}>结束进程</button></td>
  `;

  tr.querySelector(".group-toggle").addEventListener("click", () => {
    if (state.expanded.has(pidGroup.key)) state.expanded.delete(pidGroup.key);
    else state.expanded.add(pidGroup.key);
    renderGroups();
  });
  const killButton = tr.querySelector(".group-kill");
  if (canKill) {
    const entry = pidGroup.ports.find((item) => item.can_terminate);
    killButton.addEventListener("click", () => openKillModal(entry));
  }
  return tr;
}

function createGroupPortRow(entry) {
  const tr = document.createElement("tr");
  tr.className = "group-port-row";
  const canKill = Boolean(entry.can_terminate);
  const favorite = state.favorites.has(entry.local_port);
  const remote = entry.remote_addr === "-" ? "-" : `${entry.remote_addr}:${entry.remote_port}`;
  tr.innerHTML = `
    <td><button class="favorite-action ${favorite ? "active" : ""}" type="button" title="${favorite ? "移除收藏" : "添加收藏"}">${favorite ? "★" : "☆"}</button></td>
    <td><span class="badge ${entry.protocol === "UDP" ? "udp" : ""}">${escapeHtml(entry.protocol)}</span></td>
    <td class="group-port-indent" title="${escapeAttr(entry.local_addr)}">${escapeHtml(entry.local_addr)}</td>
    <td>${entry.local_port}</td>
    <td class="${stateClass(entry.state)}">${escapeHtml(entry.state)}</td>
    <td>${entry.pid}</td>
    <td class="command" title="${escapeAttr(remote)}">${escapeHtml(remote)}</td>
    <td class="path" title="${escapeAttr(entry.path)}">${escapeHtml(entry.path || "-")}</td>
    <td><button class="row-action" type="button" ${canKill ? "" : "disabled"} title="${escapeAttr(canKill ? "结束进程" : entry.deny_reason || "不可结束")}">结束进程</button></td>
  `;
  tr.querySelector(".favorite-action").addEventListener("click", () => toggleFavorite(entry.local_port));
  const button = tr.querySelector(".row-action");
  if (canKill) button.addEventListener("click", () => openKillModal(entry));
  return tr;
}

function groupEntries(entries) {
  const map = new Map();
  for (const entry of entries) {
    const process = entry.process || `PID ${entry.pid}`;
    const key = process.toLowerCase();
    if (!map.has(key)) {
      map.set(key, {
        key,
        process,
        process_type: entry.process_type || "other",
        pidMap: new Map(),
        ports: [],
      });
    }
    const group = map.get(key);
    group.ports.push(entry);
    group.process_type = mergeProcessType(group.process_type, entry.process_type);

    const pidKey = `pid:${key}:${entry.pid}`;
    if (!group.pidMap.has(pidKey)) {
      group.pidMap.set(pidKey, {
        key: pidKey,
        pid: entry.pid,
        process,
        path: entry.path,
        user: entry.user,
        command: entry.command,
        process_type: entry.process_type || "other",
        ports: [],
      });
    }
    const pidGroup = group.pidMap.get(pidKey);
    pidGroup.ports.push(entry);
    pidGroup.path ||= entry.path;
    pidGroup.user ||= entry.user;
    pidGroup.command ||= entry.command;
    pidGroup.process_type = mergeProcessType(pidGroup.process_type, entry.process_type);
  }
  return Array.from(map.values())
    .map((group) => ({
      ...group,
      ports: sortPorts(group.ports),
      pidGroups: Array.from(group.pidMap.values())
        .map((pidGroup) => ({
          ...pidGroup,
          ports: sortPorts(pidGroup.ports),
        }))
        .sort((a, b) => a.pid - b.pid),
      users: uniqueValues(group.ports.map((entry) => entry.user).filter(Boolean)),
      paths: uniqueValues(group.ports.map((entry) => entry.path).filter(Boolean)),
    }))
    .sort((a, b) => a.process.localeCompare(b.process));
}

function nextFrame() {
  return new Promise((resolve) => requestAnimationFrame(resolve));
}

function sortPorts(ports) {
  return [...ports].sort((a, b) => a.local_port - b.local_port || a.protocol.localeCompare(b.protocol));
}

function uniqueValues(values) {
  return Array.from(new Set(values));
}

async function toggleFavorite(port) {
  if (state.favorites.has(port)) state.favorites.delete(port);
  else state.favorites.add(port);
  try {
    await invoke("save_favorites", { favorites: Array.from(state.favorites) });
    applyClientFilter();
  } catch (err) {
    showNotice(String(err));
  }
}

function setView(view, processType = null) {
  state.view = view;
  state.processType = processType;
  applyClientFilter();
}

function syncNav() {
  for (const item of els.navItems) {
    const active =
      (item.dataset.view && item.dataset.view === state.view && !state.processType) ||
      (item.dataset.type && item.dataset.type === state.processType);
    item.classList.toggle("active", Boolean(active));
  }
}

function updateTitle() {
  const title = state.processType
    ? processTypeLabel(state.processType)
    : state.view === "favorites"
      ? "Favorites"
      : state.view === "grouped"
        ? "Grouped by Process"
        : "All Ports";
  els.viewLabel.textContent = state.processType ? "Process Types" : "Categories";
  els.viewTitle.textContent = title;
}

function stateClass(value) {
  if (value === "LISTENING") return "state-listen";
  if (value === "ESTABLISHED") return "state-established";
  return "";
}

function entryIpVersion(entry) {
  return String(entry.local_addr).includes(":") ? "ipv6" : "ipv4";
}

function processTypeLabel(value) {
  return typeLabels[value] || "Other";
}

function openKillModal(entry) {
  state.pendingKill = entry;
  els.modalText.textContent = "端口不是独立进程。这里会结束占用该端口的进程，请确认它不是系统或重要服务。";
  els.modalFacts.innerHTML = `
    <dt>协议</dt><dd>${escapeHtml(entry.protocol)}</dd>
    <dt>本地端口</dt><dd>${escapeHtml(entry.local_addr)}:${entry.local_port}</dd>
    <dt>PID</dt><dd>${entry.pid}</dd>
    <dt>进程</dt><dd>${escapeHtml(entry.process)}</dd>
    <dt>类型</dt><dd>${escapeHtml(processTypeLabel(entry.process_type))}</dd>
    <dt>用户</dt><dd>${escapeHtml(entry.user || "-")}</dd>
    <dt>Command</dt><dd>${escapeHtml(entry.command || "-")}</dd>
    <dt>路径</dt><dd>${escapeHtml(entry.path || "-")}</dd>
  `;
  els.modal.hidden = false;
  els.cancelKill.focus();
}

function closeKillModal() {
  state.pendingKill = null;
  els.modal.hidden = true;
}

async function confirmKill() {
  if (!state.pendingKill) return;
  const pid = state.pendingKill.pid;
  els.confirmKill.disabled = true;
  try {
    await invoke("terminate_process", { pid });
    closeKillModal();
    await refreshPorts();
    showNotice(`已结束 PID ${pid}。`);
  } catch (err) {
    showNotice(String(err));
  } finally {
    els.confirmKill.disabled = false;
  }
}

function showNotice(message) {
  els.notice.textContent = message;
  els.notice.hidden = !message;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

for (const item of els.navItems) {
  item.addEventListener("click", () => {
    if (item.dataset.type) setView("type", item.dataset.type);
    else setView(item.dataset.view);
  });
}

for (const el of [els.query, els.protocol, els.ipVersion, els.tcpState, els.showDetails]) {
  el.addEventListener("input", applyClientFilter);
  el.addEventListener("change", applyClientFilter);
}

els.tableMode.addEventListener("change", () => {
  state.tableMode = els.tableMode.value === "complex" ? "complex" : "simple";
  renderCurrentView();
});
els.refresh.addEventListener("click", refreshPorts);
els.cancelKill.addEventListener("click", closeKillModal);
els.confirmKill.addEventListener("click", confirmKill);
els.modal.addEventListener("click", (event) => {
  if (event.target === els.modal) closeKillModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.modal.hidden) closeKillModal();
});

initialize();
