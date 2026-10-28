const token = new URLSearchParams(location.search).get("token") || "";

const state = {
  status: null,
  scan: null,
  conversations: [],
  filteredConversations: [],
  activeConversation: null,
  page: 1,
  pageSize: 80,
  hasMore: false,
  messages: new Map(),
  searchMessages: new Map(),
  editing: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBytes(bytes) {
  let value = Number(bytes || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index ? 2 : 0)} ${units[index]}`;
}

function truncate(value, length = 240) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

let toastTimer;
function toast(message, kind = "success", timeout = 4200) {
  const element = $("#toast");
  clearTimeout(toastTimer);
  element.textContent = message;
  element.className = `toast ${kind}`;
  toastTimer = setTimeout(() => element.classList.add("hidden"), timeout);
}

async function api(path, options = {}) {
  const settings = {
    method: options.method || "GET",
    headers: { "X-App-Token": token },
  };
  if (options.body !== undefined) {
    settings.headers["Content-Type"] = "application/json";
    settings.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, settings);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`本地服务返回了无效响应（HTTP ${response.status}）`);
  }
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || `请求失败（HTTP ${response.status}）`);
  }
  return payload.data;
}

function setBusy(button, busy, busyText = "处理中…") {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function showError(error) {
  console.error(error);
  toast(error.message || String(error), "error", 7000);
}

function showSnapshotSummary(snapshot) {
  const box = $("#snapshotSummary");
  if (!snapshot?.loaded) {
    box.innerHTML = "尚未打开快照。";
    return;
  }
  box.innerHTML = `
    <strong>已打开：</strong>${escapeHtml(snapshot.root)}<br>
    <strong>源目录（只读来源）：</strong>${escapeHtml(snapshot.source_root)}<br>
    <strong>创建时间：</strong>${escapeHtml(snapshot.created_at || "未知")}<br>
    <strong>原始层：</strong>${formatBytes(snapshot.raw_bytes)} · <strong>编辑层初始数据：</strong>${formatBytes(snapshot.working_bytes)}
  `;
}

function renderStatus() {
  const snapshot = state.status?.snapshot;
  const unlocked = Boolean(snapshot?.unlocked);
  $("#unlockCard").classList.toggle("hidden", !snapshot?.loaded || unlocked);
  $("#setupView").classList.toggle("hidden", unlocked);
  $("#editorView").classList.toggle("hidden", !unlocked);
  $("#lockButton").classList.toggle("hidden", !unlocked);
  const badge = $("#lockBadge");
  if (unlocked) {
    badge.textContent = "编辑层已解锁";
    badge.className = "badge";
  } else if (snapshot?.loaded) {
    badge.textContent = "快照已打开 · 密钥已锁定";
    badge.className = "badge muted";
  } else {
    badge.textContent = "未打开副本";
    badge.className = "badge muted";
  }
  showSnapshotSummary(snapshot);
}

async function refreshStatus() {
  state.status = await api("/api/status");
  if (!$("#sourcePath").value) $("#sourcePath").value = state.status.default_source;
  if (!$("#snapshotPath").value) $("#snapshotPath").value = state.status.suggested_snapshot;
  if (!$("#existingPath").value && state.status.snapshot?.loaded) {
    $("#existingPath").value = state.status.snapshot.root;
  }
  renderStatus();
  if (state.status.snapshot?.unlocked && !state.conversations.length) {
    await loadConversations();
  }
}

async function scanSource() {
  const button = $("#scanButton");
  const box = $("#scanResult");
  setBusy(button, true, "检查中…");
  try {
    const data = await api("/api/source/scan", {
      method: "POST",
      body: { source: $("#sourcePath").value.trim() },
    });
    state.scan = data;
    const running = data.weixin_running?.length;
    box.className = `result-box ${running ? "warning" : "success"}`;
    box.innerHTML = `
      <strong>识别成功：</strong>${escapeHtml(data.source)}<br>
      <strong>数据库相关文件：</strong>${data.file_count} 个，${escapeHtml(data.total_human)}<br>
      <strong>聊天分片：</strong>${data.message_databases.length} 个<br>
      <span>${escapeHtml(data.message_databases.join("、"))}</span><br>
      <strong>微信进程：</strong>${running ? `仍在运行（${escapeHtml(data.weixin_running.join("、"))}），创建快照前必须正常退出` : "未检测到，可以创建一致性快照"}
    `;
    box.classList.remove("hidden");
  } catch (error) {
    box.className = "result-box error";
    box.textContent = error.message;
    box.classList.remove("hidden");
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function createSnapshot() {
  const button = $("#snapshotButton");
  const jobBox = $("#jobBox");
  setBusy(button, true, "创建中…");
  try {
    const job = await api("/api/snapshot/create", {
      method: "POST",
      body: {
        source: $("#sourcePath").value.trim(),
        target: $("#snapshotPath").value.trim(),
      },
    });
    jobBox.classList.remove("hidden");
    await watchJob(job.id);
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function watchJob(id) {
  while (true) {
    const job = await api(`/api/jobs/${encodeURIComponent(id)}`);
    const total = Number(job.total_bytes || 0);
    const copied = Number(job.copied_bytes || 0);
    const percent = total ? Math.min(100, Math.round((copied / total) * 100)) : 0;
    $("#jobMessage").textContent = job.message || job.phase;
    $("#jobPercent").textContent = `${percent}%`;
    $("#jobProgress").style.width = `${percent}%`;
    $("#jobDetail").textContent = total ? `${formatBytes(copied)} / ${formatBytes(total)}` : "正在扫描文件";
    if (job.status === "completed") {
      toast("双层副本已创建并完成哈希校验。", "success", 6000);
      $("#existingPath").value = job.snapshot_root;
      await refreshStatus();
      $("#keyInput").focus();
      return;
    }
    if (job.status === "failed") {
      throw new Error(job.error || "创建快照失败");
    }
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

async function openSnapshot() {
  const button = $("#openSnapshotButton");
  setBusy(button, true, "打开中…");
  try {
    await api("/api/snapshot/open", {
      method: "POST",
      body: { path: $("#existingPath").value.trim() },
    });
    state.conversations = [];
    await refreshStatus();
    $("#keyInput").focus();
    toast("快照已打开，请输入密钥解锁编辑层。", "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function unlockSnapshot() {
  const button = $("#unlockButton");
  const key = $("#keyInput").value.trim();
  setBusy(button, true, "验证中…");
  try {
    await api("/api/snapshot/unlock", { method: "POST", body: { key } });
    $("#keyInput").value = "";
    await refreshStatus();
    await loadConversations(true);
    toast("密钥验证成功。现在浏览和修改的都是编辑层副本。", "success", 6000);
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function lockSnapshot() {
  await api("/api/snapshot/lock", { method: "POST", body: {} });
  state.conversations = [];
  state.activeConversation = null;
  state.messages.clear();
  await refreshStatus();
  toast("密钥已从程序状态中清除。", "success");
}

async function loadConversations(refresh = false) {
  const data = await api(`/api/conversations${refresh ? "?refresh=1" : ""}`);
  state.conversations = data.items;
  applyConversationFilter();
  rebuildSearchScope();
}

function applyConversationFilter() {
  const query = $("#conversationFilter").value.trim().toLocaleLowerCase();
  state.filteredConversations = state.conversations.filter((item) => {
    const haystack = `${item.display_name} ${item.username} ${item.database}`.toLocaleLowerCase();
    return haystack.includes(query);
  });
  $("#conversationStats").textContent = `显示 ${state.filteredConversations.length} / ${state.conversations.length} 个会话；记录可能分布在多个分片。`;
  const activeId = state.activeConversation?.id;
  $("#conversationList").innerHTML = state.filteredConversations.length
    ? state.filteredConversations.map((item) => `
      <button class="conversation-item ${item.id === activeId ? "active" : ""}" data-id="${escapeHtml(item.id)}" type="button">
        <strong>${item.is_group ? "群 · " : ""}${escapeHtml(item.display_name)}</strong>
        <small>${escapeHtml(item.username || item.table)} · ${escapeHtml(item.database)}</small>
      </button>
    `).join("")
    : '<div class="empty">没有匹配的会话。</div>';
}

function rebuildSearchScope() {
  const selected = $("#searchScope").value;
  $("#searchScope").innerHTML = '<option value="">全部会话</option>' + state.conversations.map((item) => `
    <option value="${escapeHtml(item.id)}">${escapeHtml(item.display_name)} · ${escapeHtml(item.database)}</option>
  `).join("");
  if ([...$("#searchScope").options].some((option) => option.value === selected)) {
    $("#searchScope").value = selected;
  }
}

async function selectConversation(id, page = 1) {
  const conversation = state.conversations.find((item) => item.id === id);
  if (!conversation) return;
  state.activeConversation = conversation;
  state.page = page;
  applyConversationFilter();
  $("#activeConversation").textContent = conversation.display_name;
  $("#activeUsername").textContent = conversation.username || "未映射会话";
  $("#activeDatabase").textContent = `${conversation.db_rel} · ${conversation.table}`;
  $("#messageRows").innerHTML = '<tr><td colspan="6" class="empty">正在读取并解压消息…</td></tr>';
  try {
    const query = new URLSearchParams({
      db_rel: conversation.db_rel,
      table: conversation.table,
      page: String(page),
      page_size: String(state.pageSize),
    });
    const data = await api(`/api/messages?${query}`);
    state.hasMore = data.has_more;
    renderMessages(data);
  } catch (error) {
    $("#messageRows").innerHTML = `<tr><td colspan="6" class="empty">${escapeHtml(error.message)}</td></tr>`;
    showError(error);
  }
}

function messageKey(item) {
  return `${item.db_rel}|${item.table}|${item.local_id}`;
}

function renderMessages(data) {
  state.messages.clear();
  for (const item of data.items) state.messages.set(messageKey(item), item);
  $("#pageLabel").textContent = `第 ${data.page} 页`;
  $("#prevPage").disabled = data.page <= 1;
  $("#nextPage").disabled = !data.has_more;
  $("#messageMeta").textContent = `共 ${data.total ?? "未知"} 条 · 本页 ${data.items.length} 条 · 每页 ${data.page_size} 条`;
  $("#messageRows").innerHTML = data.items.length ? data.items.map((item) => `
    <tr>
      <td>${escapeHtml(item.display_time)}<br><span class="mono">${escapeHtml(item.create_time)}</span></td>
      <td>${escapeHtml(item.sender_username || `ID ${item.real_sender_id}`)}<br><span class="mono">sender_id=${escapeHtml(item.real_sender_id)}</span></td>
      <td><span class="pill">${escapeHtml(item.type_label)}</span><br><span class="mono">${escapeHtml(item.content_storage)}</span></td>
      <td><div class="content-cell">${escapeHtml(item.message_content || item.source || "[空内容]")}</div></td>
      <td><span class="mono">local_id=${escapeHtml(item.local_id)}<br>${escapeHtml(item.db_rel.split("/").pop())}</span></td>
      <td><button class="button small secondary edit-message" data-key="${escapeHtml(messageKey(item))}" type="button">编辑</button></td>
    </tr>
  `).join("") : '<tr><td colspan="6" class="empty">这一页没有记录。</td></tr>';
}

function fieldValue(value) {
  return value === null || value === undefined ? "" : String(value);
}

function openEditor(item) {
  state.editing = item;
  $("#editLocator").textContent = `${item.db_rel} · ${item.table} · local_id=${item.local_id}`;
  $("#editContent").value = item.message_content ?? "";
  $("#editContent").disabled = !item.content_editable;
  $("#contentStorage").textContent = `当前存储：${item.content_storage}${item.content_editable ? "；保存时保持压缩/文本类型" : "；该二进制内容不可直接编辑"}`;
  $("#editSource").value = item.source ?? "";
  $("#editSource").disabled = !item.source_editable;
  $("#sourceStorage").textContent = `当前存储：${item.source_storage}${item.source_editable ? "；保存时保持压缩/文本类型" : "；该二进制内容不可直接编辑"}`;
  $("#editCreateTime").value = fieldValue(item.create_time);
  $("#editLocalType").value = fieldValue(item.local_type);
  $("#editSenderId").value = fieldValue(item.real_sender_id);
  $("#editStatus").value = fieldValue(item.status);
  $("#editSortSeq").value = fieldValue(item.sort_seq);
  $("#editOriginSource").value = fieldValue(item.origin_source);
  $("#editDialog").showModal();
}

function collectChanges(item) {
  const candidates = {
    message_content: $("#editContent").value,
    source: $("#editSource").value,
    create_time: $("#editCreateTime").value,
    local_type: $("#editLocalType").value,
    real_sender_id: $("#editSenderId").value,
    status: $("#editStatus").value,
    sort_seq: $("#editSortSeq").value,
    origin_source: $("#editOriginSource").value,
  };
  const changes = {};
  for (const [key, value] of Object.entries(candidates)) {
    if ((key === "message_content" && !item.content_editable) || (key === "source" && !item.source_editable)) continue;
    if (String(item[key] ?? "") !== String(value)) changes[key] = value;
  }
  return changes;
}

async function saveEdit(event) {
  event.preventDefault();
  const item = state.editing;
  if (!item) return;
  const fields = collectChanges(item);
  if (!Object.keys(fields).length) {
    toast("没有检测到字段变化。", "error");
    return;
  }
  const button = $("#saveEdit");
  setBusy(button, true, "保存中…");
  try {
    await api("/api/message/update", {
      method: "POST",
      body: { db_rel: item.db_rel, table: item.table, local_id: item.local_id, fields },
    });
    $("#editDialog").close();
    toast("修改已写入编辑层，并已记录加密审计。", "success", 6000);
    await refreshCurrentContext();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

function confirmAction(title, text, buttonText = "确认") {
  const dialog = $("#confirmDialog");
  $("#confirmTitle").textContent = title;
  $("#confirmText").textContent = text;
  $("#confirmAccept").textContent = buttonText;
  return new Promise((resolve) => {
    const accept = () => finish(true);
    const cancel = () => finish(false);
    const finish = (value) => {
      $("#confirmAccept").removeEventListener("click", accept);
      $("#confirmCancel").removeEventListener("click", cancel);
      dialog.close();
      resolve(value);
    };
    $("#confirmAccept").addEventListener("click", accept);
    $("#confirmCancel").addEventListener("click", cancel);
    dialog.showModal();
  });
}

async function deleteEditingMessage() {
  const item = state.editing;
  if (!item) return;
  const accepted = await confirmAction(
    "删除副本记录？",
    `将从 working_encrypted 中删除 local_id=${item.local_id}。原微信目录和只读原始层不受影响，并可通过加密审计撤销。`,
    "删除副本记录",
  );
  if (!accepted) return;
  const button = $("#deleteMessage");
  setBusy(button, true, "删除中…");
  try {
    await api("/api/message/delete", {
      method: "POST",
      body: { db_rel: item.db_rel, table: item.table, local_id: item.local_id },
    });
    $("#editDialog").close();
    toast("记录已从编辑层删除，可在“修改与撤销”中恢复。", "success", 6000);
    await refreshCurrentContext();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function refreshCurrentContext() {
  if (state.activeConversation) await selectConversation(state.activeConversation.id, state.page);
  await loadAudit();
}

async function runSearch() {
  const button = $("#searchButton");
  const keyword = $("#searchKeyword").value.trim();
  if (!keyword) {
    toast("请输入搜索关键词。", "error");
    return;
  }
  setBusy(button, true, "扫描并解压中…");
  $("#searchMeta").textContent = "正在扫描消息；数据量大时可能需要一些时间。";
  $("#searchResults").innerHTML = "";
  try {
    const data = await api("/api/search", {
      method: "POST",
      body: {
        keyword,
        conversation_id: $("#searchScope").value || null,
        scan_limit: Number($("#scanLimit").value),
        limit: 200,
      },
    });
    state.searchMessages.clear();
    for (const item of data.items) state.searchMessages.set(messageKey(item), item);
    $("#searchMeta").textContent = `扫描 ${data.scanned} 条，找到 ${data.items.length} 条${data.truncated ? "；已达到结果或扫描上限" : ""}。`;
    $("#searchResults").innerHTML = data.items.length ? data.items.map((item) => `
      <article class="search-card">
        <header><strong>${escapeHtml(item.conversation_name || item.username)}</strong><span>${escapeHtml(item.display_time)}</span></header>
        <p>${escapeHtml(truncate(item.message_content || item.source || "[空内容]", 800))}</p>
        <footer><span class="mono">${escapeHtml(item.db_rel.split("/").pop())} · local_id=${escapeHtml(item.local_id)}</span><button class="button small secondary edit-search" data-key="${escapeHtml(messageKey(item))}" type="button">编辑</button></footer>
      </article>
    `).join("") : '<div class="empty">未找到匹配记录。可选择具体会话或提高扫描上限。</div>';
  } catch (error) {
    $("#searchMeta").textContent = error.message;
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function loadAudit() {
  try {
    const data = await api("/api/audit?limit=150");
    const items = data.items;
    $("#auditList").innerHTML = items.length ? items.map((item, index) => `
      <article class="audit-item ${item.undone ? "undone" : ""} ${item.status === "failed" ? "failed" : ""}">
        <header><strong>#${item.id} · ${item.action === "delete" ? "删除" : "修改"}${item.undone ? " · 已撤销" : ""}</strong><span>${escapeHtml(item.changed_at)}</span></header>
        <p><strong>修改前：</strong>${escapeHtml(item.before_preview || "[空]")}<br><strong>修改后：</strong>${escapeHtml(item.after_preview || (item.action === "delete" ? "[已删除]" : "[空]"))}</p>
        <footer><span class="mono">${escapeHtml(item.db_rel)} · ${escapeHtml(item.table)} · local_id=${escapeHtml(item.local_id)} · ${escapeHtml(item.status)}</span>${index === 0 && item.status === "applied" && !item.undone ? `<button class="button small secondary undo-audit" data-id="${item.id}" type="button">撤销此操作</button>` : ""}</footer>
      </article>
    `).join("") : '<div class="empty">还没有修改记录。</div>';
  } catch (error) {
    $("#auditList").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

async function undoAudit(id) {
  const accepted = await confirmAction("撤销最近修改？", "将把该记录恢复到操作前状态。只能按时间倒序撤销。", "确认撤销");
  if (!accepted) return;
  try {
    await api("/api/audit/undo", { method: "POST", body: { audit_id: Number(id) } });
    toast("最近一次修改已撤销。", "success");
    await refreshCurrentContext();
  } catch (error) {
    showError(error);
  }
}

async function verifyRaw() {
  const button = $("#verifyRaw");
  setBusy(button, true, "哈希计算中…");
  $("#verifyRawResult").textContent = "正在逐文件读取只读原始层并计算 SHA-256…";
  try {
    const data = await api("/api/verify/raw", { method: "POST", body: {} });
    $("#verifyRawResult").textContent = data.ok
      ? `通过：${data.checked} 个文件全部与创建快照时一致。`
      : `未通过：\n${data.failures.map((item) => `${item.file}: ${item.error}`).join("\n")}`;
  } catch (error) {
    $("#verifyRawResult").textContent = error.message;
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

async function verifyDatabases() {
  const button = $("#verifyDb");
  setBusy(button, true, "检查中…");
  $("#verifyDbResult").textContent = "正在逐个检查聊天分片…";
  try {
    const data = await api("/api/verify/databases", { method: "POST", body: {} });
    $("#verifyDbResult").textContent = data.items.map((item) => `${item.ok ? "✓" : "✗"} ${item.database}: ${item.result}`).join("\n");
  } catch (error) {
    $("#verifyDbResult").textContent = error.message;
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

function switchTab(name) {
  $$(".tab").forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  $$(".tab-page").forEach((page) => page.classList.remove("active"));
  $(`#${name}Tab`).classList.add("active");
  if (name === "audit") loadAudit();
}

async function shutdown() {
  const accepted = await confirmAction("退出本地工具？", "密钥会从程序状态中清除，浏览器页面随后失去连接。", "退出");
  if (!accepted) return;
  try {
    await api("/api/shutdown", { method: "POST", body: {} });
    document.body.innerHTML = '<main><section class="panel setup-card"><h1>工具已退出</h1><p>密钥已从程序状态中清除，可以关闭此页面。</p></section></main>';
  } catch (error) {
    showError(error);
  }
}

function wireEvents() {
  $("#scanButton").addEventListener("click", scanSource);
  $("#snapshotButton").addEventListener("click", createSnapshot);
  $("#openSnapshotButton").addEventListener("click", openSnapshot);
  $("#unlockButton").addEventListener("click", unlockSnapshot);
  $("#keyInput").addEventListener("keydown", (event) => { if (event.key === "Enter") unlockSnapshot(); });
  $("#toggleKeyButton").addEventListener("click", () => {
    const input = $("#keyInput");
    input.type = input.type === "password" ? "text" : "password";
    $("#toggleKeyButton").textContent = input.type === "password" ? "显示" : "隐藏";
  });
  $("#lockButton").addEventListener("click", lockSnapshot);
  $("#shutdownButton").addEventListener("click", shutdown);
  $("#refreshConversations").addEventListener("click", async () => {
    try { await loadConversations(true); toast("会话列表已刷新。", "success"); } catch (error) { showError(error); }
  });
  $("#conversationFilter").addEventListener("input", applyConversationFilter);
  $("#conversationList").addEventListener("click", (event) => {
    const button = event.target.closest(".conversation-item");
    if (button) selectConversation(button.dataset.id, 1);
  });
  $("#prevPage").addEventListener("click", () => {
    if (state.activeConversation && state.page > 1) selectConversation(state.activeConversation.id, state.page - 1);
  });
  $("#nextPage").addEventListener("click", () => {
    if (state.activeConversation && state.hasMore) selectConversation(state.activeConversation.id, state.page + 1);
  });
  $("#messageRows").addEventListener("click", (event) => {
    const button = event.target.closest(".edit-message");
    if (button) openEditor(state.messages.get(button.dataset.key));
  });
  $("#editForm").addEventListener("submit", saveEdit);
  $("#closeEdit").addEventListener("click", () => $("#editDialog").close());
  $("#cancelEdit").addEventListener("click", () => $("#editDialog").close());
  $("#deleteMessage").addEventListener("click", deleteEditingMessage);
  $$(".tab").forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.tab)));
  $("#searchButton").addEventListener("click", runSearch);
  $("#searchKeyword").addEventListener("keydown", (event) => { if (event.key === "Enter") runSearch(); });
  $("#searchResults").addEventListener("click", (event) => {
    const button = event.target.closest(".edit-search");
    if (button) openEditor(state.searchMessages.get(button.dataset.key));
  });
  $("#refreshAudit").addEventListener("click", loadAudit);
  $("#auditList").addEventListener("click", (event) => {
    const button = event.target.closest(".undo-audit");
    if (button) undoAudit(button.dataset.id);
  });
  $("#verifyRaw").addEventListener("click", verifyRaw);
  $("#verifyDb").addEventListener("click", verifyDatabases);
}

async function init() {
  wireEvents();
  if (!token) {
    document.body.innerHTML = '<main><section class="panel setup-card"><h1>无效启动方式</h1><p>请双击程序启动，不要手工打开 HTML 文件。</p></section></main>';
    return;
  }
  try {
    await refreshStatus();
  } catch (error) {
    showError(error);
  }
}

init();

// Keep attribution separate from application actions and data requests.
(() => {
  const dialog = document.getElementById('authorDialog');
  const signature = document.getElementById('authorSignature');
  if (!dialog || !signature) return;
  signature.addEventListener('click', () => dialog.showModal());
  dialog.showModal();
})();
