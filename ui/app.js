const invoke = window.__TAURI__?.core?.invoke;

const state = {
  entries: [],
  filtered: [],
  pendingKill: null,
};

const els = {
  rows: document.getElementById("rows"),
  query: document.getElementById("query"),
  protocol: document.getElementById("protocol"),
  ipVersion: document.getElementById("ipVersion"),
  tcpState: document.getElementById("state"),
  showDetails: document.getElementById("showDetails"),
  refresh: document.getElementById("refresh"),
  notice: document.getElementById("notice"),
  countAll: document.getElementById("countAll"),
  countListen: document.getElementById("countListen"),
  countTcp: document.getElementById("countTcp"),
  countUdp: document.getElementById("countUdp"),
  modal: document.getElementById("modal"),
  modalText: document.getElementById("modalText"),
  modalFacts: document.getElementById("modalFacts"),
  cancelKill: document.getElementById("cancelKill"),
  confirmKill: document.getElementById("confirmKill"),
};

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
  if (!invoke) {
    showNotice("Tauri API 未加载。请通过 portKill.exe 启动此界面。");
    return;
  }

  els.refresh.disabled = true;
  try {
    state.entries = await invoke("get_ports");
    applyClientFilter();
    showNotice("");
  } catch (err) {
    showNotice(String(err));
  } finally {
    els.refresh.disabled = false;
  }
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
    ]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });

  renderSummary();
  renderRows();
}

function renderSummary() {
  const listening = state.entries.filter(
    (entry) => entry.protocol === "UDP" || entry.state === "LISTENING",
  ).length;
  els.countAll.textContent = state.filtered.length;
  els.countListen.textContent = listening;
  els.countTcp.textContent = state.entries.filter((entry) => entry.protocol === "TCP").length;
  els.countUdp.textContent = state.entries.filter((entry) => entry.protocol === "UDP").length;
}

function renderRows() {
  if (state.filtered.length === 0) {
    els.rows.innerHTML = '<tr><td colspan="10" class="empty">没有匹配的端口记录</td></tr>';
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const entry of state.filtered) {
    const tr = document.createElement("tr");
    const canKill = Boolean(entry.can_terminate);
    const actionTitle = canKill ? "结束进程" : entry.deny_reason || "不可结束";

    tr.innerHTML = `
      <td><span class="badge ${entry.protocol === "UDP" ? "udp" : ""}">${escapeHtml(entry.protocol)}</span></td>
      <td>${escapeHtml(entry.local_addr)}</td>
      <td>${entry.local_port}</td>
      <td>${escapeHtml(entry.remote_addr)}</td>
      <td>${entry.remote_port}</td>
      <td class="${stateClass(entry.state)}">${escapeHtml(entry.state)}</td>
      <td>${entry.pid}</td>
      <td>${escapeHtml(entry.process)}</td>
      <td class="path" title="${escapeAttr(entry.path)}">${escapeHtml(entry.path || "-")}</td>
      <td><button class="row-action" type="button" ${canKill ? "" : "disabled"} title="${escapeAttr(actionTitle)}">结束进程</button></td>
    `;

    const button = tr.querySelector("button");
    if (canKill) {
      button.addEventListener("click", () => openKillModal(entry));
    }
    fragment.appendChild(tr);
  }
  els.rows.replaceChildren(fragment);
}

function stateClass(value) {
  if (value === "LISTENING") return "state-listen";
  if (value === "ESTABLISHED") return "state-established";
  return "";
}

function entryIpVersion(entry) {
  return String(entry.local_addr).includes(":") ? "ipv6" : "ipv4";
}

function openKillModal(entry) {
  state.pendingKill = entry;
  els.modalText.textContent = "端口不是独立进程。这里会结束占用该端口的进程，请确认它不是系统或重要服务。";
  els.modalFacts.innerHTML = `
    <dt>协议</dt><dd>${escapeHtml(entry.protocol)}</dd>
    <dt>本地端口</dt><dd>${entry.local_addr}:${entry.local_port}</dd>
    <dt>PID</dt><dd>${entry.pid}</dd>
    <dt>进程</dt><dd>${escapeHtml(entry.process)}</dd>
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
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

for (const el of [els.query, els.protocol, els.ipVersion, els.tcpState, els.showDetails]) {
  el.addEventListener("input", applyClientFilter);
  el.addEventListener("change", applyClientFilter);
}

els.refresh.addEventListener("click", refreshPorts);
els.cancelKill.addEventListener("click", closeKillModal);
els.confirmKill.addEventListener("click", confirmKill);
els.modal.addEventListener("click", (event) => {
  if (event.target === els.modal) closeKillModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.modal.hidden) closeKillModal();
});

refreshPorts();
