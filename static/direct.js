const token = new URLSearchParams(location.search).get("token") || "";
const state = {
  status: null,
  conversations: [],
  filtered: [],
  active: null,
  page: 1,
  pageSize: 80,
  hasMore: false,
  messages: new Map(),
  searchMessages: new Map(),
  editing: null,
  insertOptions: null,
  extractedKeyring: false,
  extractedSource: "",
  captureSource: "",
  captureTimer: null,
  lastCaptureStatus: "idle",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function truncate(value, length = 600) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

let toastTimer;
function toast(message, kind = "success", timeout = 4500) {
  const node = $("#toast");
  clearTimeout(toastTimer);
  node.textContent = message;
  node.className = `toast ${kind}`;
  toastTimer = setTimeout(() => node.classList.add("hidden"), timeout);
}

function showError(error) {
  console.error(error);
  toast(error.message || String(error), "error", 7500);
}

async function api(path, options = {}) {
  const request = { method: options.method || "GET", headers: { "X-App-Token": token } };
  if (options.body !== undefined) {
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, request);
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload?.ok) throw new Error(payload?.error || `请求失败（HTTP ${response.status}）`);
  return payload.data;
}

function setBusy(button, busy, text = "处理中…") {
  if (busy) {
    button.dataset.oldText = button.textContent;
    button.textContent = text;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.oldText || button.textContent;
    button.disabled = false;
  }
}

const activeCaptureStatuses = new Set([
  "waiting_for_weixin", "scanning", "waiting_for_login", "finalizing",
]);

function setCaptureUi(active) {
  const button = $("#extractKeyButton");
  button.disabled = active;
  button.textContent = active ? "正在等待登录并提取…" : "开始等待登录并提取";
  $("#cancelExtractButton").classList.toggle("hidden", !active);
}

function stopCapturePolling() {
  if (state.captureTimer !== null) clearTimeout(state.captureTimer);
  state.captureTimer = null;
}

function scheduleCapturePoll() {
  stopCapturePolling();
  state.captureTimer = setTimeout(pollCaptureStatus, 1500);
}

function captureProgressHtml(capture) {
  const attempts = Number(capture.attempts || 0);
  const processCount = Number(capture.process_count || 0);
  const progress = capture.required_database_count
    ? `<br><strong>逐库验真：</strong>${escapeHtml(capture.validated_database_count || 0)}/${escapeHtml(capture.required_database_count)}`
    : "";
  return `<strong>${escapeHtml(capture.message || "正在等待微信登录流程…")}</strong><br>
    <strong>扫描轮次：</strong>${attempts}${processCount ? `；检测到 ${processCount} 个微信进程` : ""}${progress}<br>
    <strong>正确顺序：</strong>保持微信在未登录界面启动捕获，看到“现在可以登录”后再完成登录。`;
}

function applyCaptureStatus(capture) {
  if (!capture) return;
  const previous = state.lastCaptureStatus;
  const status = capture.status || "idle";
  const active = activeCaptureStatuses.has(status);
  const box = $("#scanResult");
  setCaptureUi(active);

  if (status === "complete") {
    stopCapturePolling();
    const data = capture.result || {};
    const source = state.captureSource || $("#sourcePath").value.trim()
      || state.status?.extracted_source_root || "";
    state.extractedKeyring = true;
    state.extractedSource = source;
    const input = $("#keyInput");
    input.value = "";
    input.placeholder = `已在内存中准备 ${data.key_count || 0} 个数据库 raw key`;
    input.type = "password";
    $("#toggleKeyButton").textContent = "显示";
    $("#keyExportPanel").classList.remove("hidden");
    box.className = "result-box success";
    box.innerHTML = `<strong>数据库密钥环已捕获并逐库只读验真。</strong><br>
      <strong>来源进程：</strong>${escapeHtml(data.process || "当前微信进程")}<br>
      <strong>结果：</strong>${escapeHtml(data.validated_database_count || 0)}/${escapeHtml(data.required_database_count || 0)} 个编辑必需数据库全部通过；内存中保存 ${escapeHtml(data.key_count || 0)} 个 salt 绑定 raw key<br>
      <strong>密钥环指纹：</strong>${escapeHtml(data.fingerprint || "")}（仅用于核对，不是密钥）<br>
      <strong>扫描：</strong>${escapeHtml(data.accumulated_scanned_human || data.scanned_human || "未知")}，共 ${escapeHtml(data.attempts || capture.attempts || 1)} 轮<br>
      <strong>下一步：</strong>现在请完全退出微信和托盘进程，再点击“直接打开源数据库”。你也可以主动生成并复制 WCKEY1 密钥包。`;
    box.classList.remove("hidden");
    if (previous !== "complete") {
      toast("密钥环已在当前会话内准备好。请完全退出微信后再打开源数据库。", "success", 10000);
    }
  } else if (["error", "timed_out", "cancelled"].includes(status)) {
    stopCapturePolling();
    box.className = status === "cancelled" ? "result-box warning" : "result-box error";
    box.textContent = capture.message || "密钥捕获未完成。";
    box.classList.remove("hidden");
    if (previous !== status && status !== "cancelled") {
      toast(capture.message || "密钥捕获未完成。", "error", 9000);
    }
  } else if (active) {
    box.className = "result-box warning";
    box.innerHTML = captureProgressHtml(capture);
    box.classList.remove("hidden");
    scheduleCapturePoll();
  }
  state.lastCaptureStatus = status;
}

async function pollCaptureStatus() {
  try {
    const capture = await api("/api/key/capture/status");
    applyCaptureStatus(capture);
  } catch (error) {
    stopCapturePolling();
    setCaptureUi(false);
    showError(error);
  }
}

async function copySecretText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch (_error) {
    const output = $("#keyBundleOutput");
    output.classList.remove("hidden");
    output.focus();
    output.select();
    return document.execCommand("copy");
  }
}

function clearCredentialFields(clearPath = false) {
  if (clearPath) $("#sourcePath").value = "";
  const input = $("#keyInput");
  input.value = "";
  input.placeholder = "";
  input.type = "password";
  $("#toggleKeyButton").textContent = "显示";
  $("#keyBundleOutput").value = "";
  $("#keyBundleOutput").classList.add("hidden");
  $("#copyKeyButton").classList.add("hidden");
  $("#keyExportPanel").classList.add("hidden");
}

function renderStatus() {
  const unlocked = Boolean(state.status?.unlocked);
  $("#setupView").classList.toggle("hidden", unlocked);
  $("#editorView").classList.toggle("hidden", !unlocked);
  $("#lockButton").classList.toggle("hidden", !unlocked);
  const badge = $("#statusBadge");
  if (unlocked) {
    badge.textContent = "正在直接编辑源库";
    badge.className = "badge";
  } else {
    badge.textContent = state.status?.opened ? "源库已关闭 · 需重新输入密钥" : "尚未打开源库";
    badge.className = "badge muted";
  }
}

async function refreshStatus() {
  state.status = await api("/api/direct/status");
  if (state.status.extracted_keyring_ready && state.status.extracted_source_root) {
    state.extractedKeyring = true;
    state.extractedSource = state.status.extracted_source_root;
    $("#keyInput").placeholder = `已在内存中准备 ${state.status.extracted_key_count} 个数据库 raw key`;
    $("#keyExportPanel").classList.remove("hidden");
  }
  applyCaptureStatus(state.status.capture);
  renderStatus();
  if (state.status.unlocked && !state.conversations.length) await loadConversations();
}

async function scanSource() {
  const button = $("#scanButton");
  const box = $("#scanResult");
  setBusy(button, true, "检查中…");
  try {
    const data = await api("/api/source/scan", {
      method: "POST", body: { source: $("#sourcePath").value.trim() },
    });
    const running = data.weixin_running?.length;
    box.className = `result-box ${running ? "warning" : "success"}`;
    box.innerHTML = `<strong>账号目录：</strong>${escapeHtml(data.source)}<br>
      <strong>数据库相关文件：</strong>${data.file_count} 个，${escapeHtml(data.total_human)}<br>
      <strong>聊天主分片：</strong>${data.message_databases.length} 个<br>
      <strong>微信进程：</strong>${running ? `仍在运行（${escapeHtml(data.weixin_running.join("、"))}），不能直接写入` : "未检测到，可以直接打开"}`;
    box.classList.remove("hidden");
  } catch (error) {
    box.className = "result-box error";
    box.textContent = error.message;
    box.classList.remove("hidden");
    showError(error);
  } finally { setBusy(button, false); }
}

async function extractDatabaseKey() {
  const source = $("#sourcePath").value.trim();
  if (!source) { toast("请先手动填写微信账号目录。", "error"); return; }
  const accepted = await confirmAction(
    "微信现在停在未登录界面吗？",
    "请先完全退出已登录微信，再重新打开并停在二维码或登录确认界面。确认后工具开始等待；看到“现在可以登录微信”的提示后，再完成登录。工具只读进程内存和数据库，不会修改、结束或重启微信。",
    "开始等待，然后我再登录",
  );
  if (!accepted) return;
  const box = $("#scanResult");
  try {
    stopCapturePolling();
    state.captureSource = source;
    state.lastCaptureStatus = "idle";
    state.extractedKeyring = false;
    state.extractedSource = "";
    clearCredentialFields(false);
    box.className = "result-box warning";
    box.textContent = "正在启动只读等待，请暂时保持微信在未登录界面…";
    box.classList.remove("hidden");
    const capture = await api("/api/key/capture/start", {
      method: "POST", body: { source, timeout_seconds: 180 },
    });
    applyCaptureStatus(capture);
  } catch (error) {
    setCaptureUi(false);
    box.className = "result-box error";
    box.textContent = error.message;
    box.classList.remove("hidden");
    showError(error);
  }
}

async function cancelDatabaseKeyCapture() {
  try {
    const capture = await api("/api/key/capture/cancel", { method: "POST", body: {} });
    applyCaptureStatus(capture);
    toast("已取消密钥捕获。", "success");
  } catch (error) { showError(error); }
}

async function exportKeyBundle() {
  const button = $("#exportKeyButton");
  setBusy(button, true, "正在生成…");
  try {
    const data = await api("/api/key/export", { method: "POST", body: {} });
    const output = $("#keyBundleOutput");
    output.value = data.bundle;
    output.classList.remove("hidden");
    $("#copyKeyButton").classList.remove("hidden");
    const copied = await copySecretText(data.bundle);
    toast(copied ? "WCKEY1 密钥包已复制到剪贴板，请安全保管。" : "密钥包已显示，请手动复制。", copied ? "success" : "error", 8000);
  } catch (error) { showError(error); }
  finally { setBusy(button, false); }
}

async function copyExportedKeyBundle() {
  const value = $("#keyBundleOutput").value;
  if (!value) return;
  const copied = await copySecretText(value);
  toast(copied ? "密钥包已再次复制。" : "自动复制失败，请手动选择复制。", copied ? "success" : "error");
}

function confirmAction(title, text, acceptText = "确认") {
  const dialog = $("#confirmDialog");
  $("#confirmTitle").textContent = title;
  $("#confirmText").textContent = text;
  $("#confirmAccept").textContent = acceptText;
  return new Promise((resolve) => {
    const finish = (result) => {
      $("#confirmAccept").removeEventListener("click", accept);
      $("#confirmCancel").removeEventListener("click", cancel);
      dialog.removeEventListener("cancel", dismiss);
      dialog.close();
      resolve(result);
    };
    const accept = () => finish(true);
    const cancel = () => finish(false);
    const dismiss = (event) => { event.preventDefault(); finish(false); };
    $("#confirmAccept").addEventListener("click", accept);
    $("#confirmCancel").addEventListener("click", cancel);
    dialog.addEventListener("cancel", dismiss);
    dialog.showModal();
  });
}

async function openDirect() {
  const source = $("#sourcePath").value.trim();
  const key = $("#keyInput").value.trim();
  if (!source) { toast("请先手动填写微信账号目录。", "error"); return; }
  const useExtractedKeys = !key && state.extractedKeyring && state.extractedSource === source;
  const keyMode = key.startsWith("WCKEY1:")
    ? "粘贴的 WCKEY1 密钥包（将先逐库只读验真）"
    : (useExtractedKeys ? "本次捕获的内存密钥环" : "手动账号密钥");
  const accepted = await confirmAction(
    "直接打开微信源数据库？",
    `之后的保存将直接写入：${source}\n\n密钥方式：${keyMode}\n不会创建副本、备份或撤销记录。请确认微信已经完全退出。`,
    "确认直接打开",
  );
  if (!accepted) return;
  const button = $("#openDirectButton");
  setBusy(button, true, "验证源库中…");
  try {
    await api("/api/direct/open", {
      method: "POST",
      body: { source, key, use_extracted_keys: useExtractedKeys },
    });
    $("#keyInput").value = "";
    state.conversations = [];
    await refreshStatus();
    await loadConversations(true);
    toast("源数据库已直接打开。后续保存会写入原文件。", "success", 6500);
  } catch (error) { showError(error); }
  finally { setBusy(button, false); }
}

async function closeDatabase() {
  await api("/api/direct/lock", { method: "POST", body: {} });
  stopCapturePolling();
  state.extractedKeyring = false;
  state.extractedSource = "";
  state.captureSource = "";
  state.conversations = [];
  state.active = null;
  state.insertOptions = null;
  state.messages.clear();
  clearCredentialFields(true);
  await refreshStatus();
  toast("数据库已关闭；账号目录、密钥和捕获状态均已清空。", "success");
}

async function loadConversations(refresh = false) {
  const data = await api(`/api/conversations${refresh ? "?refresh=1" : ""}`);
  state.conversations = data.items;
  filterConversations();
  rebuildScope();
}

function filterConversations() {
  const query = $("#conversationFilter").value.trim().toLocaleLowerCase();
  state.filtered = state.conversations.filter((item) =>
    `${item.display_name} ${item.username} ${item.database}`.toLocaleLowerCase().includes(query));
  $("#conversationStats").textContent = `显示 ${state.filtered.length} / ${state.conversations.length} 个会话；这些会话来自多个源分片。`;
  $("#conversationList").innerHTML = state.filtered.length ? state.filtered.map((item) => `
    <button class="conversation-item ${state.active?.id === item.id ? "active" : ""}" data-id="${escapeHtml(item.id)}" type="button">
      <strong>${item.is_group ? "群 · " : ""}${escapeHtml(item.display_name)}</strong>
      <small>${escapeHtml(item.username || item.table)} · ${escapeHtml(item.database)}</small>
    </button>`).join("") : '<div class="empty">没有匹配会话。</div>';
}

function rebuildScope() {
  const current = $("#searchScope").value;
  $("#searchScope").innerHTML = '<option value="">全部会话</option>' + state.conversations.map((item) =>
    `<option value="${escapeHtml(item.id)}">${escapeHtml(item.display_name)} · ${escapeHtml(item.database)}</option>`).join("");
  if ([...$("#searchScope").options].some((item) => item.value === current)) $("#searchScope").value = current;
}

async function selectConversation(id, page = 1) {
  const conversation = state.conversations.find((item) => item.id === id);
  if (!conversation) return;
  state.active = conversation;
  state.insertOptions = null;
  state.page = page;
  filterConversations();
  $("#activeConversation").textContent = conversation.display_name;
  $("#activeUsername").textContent = conversation.username || "未映射会话";
  $("#activeDatabase").textContent = `${conversation.db_rel} · ${conversation.table}`;
  $("#addMessage").disabled = false;
  $("#messageRows").innerHTML = '<tr><td colspan="6" class="empty">正在读取源数据库…</td></tr>';
  try {
    const query = new URLSearchParams({ db_rel: conversation.db_rel, table: conversation.table,
      page: String(page), page_size: String(state.pageSize) });
    renderMessages(await api(`/api/messages?${query}`));
  } catch (error) {
    $("#messageRows").innerHTML = `<tr><td colspan="6" class="empty">${escapeHtml(error.message)}</td></tr>`;
    showError(error);
  }
}

function messageKey(item) { return `${item.db_rel}|${item.table}|${item.local_id}`; }

function renderMessages(data) {
  state.messages.clear();
  data.items.forEach((item) => state.messages.set(messageKey(item), item));
  state.hasMore = data.has_more;
  $("#pageLabel").textContent = `第 ${data.page} 页`;
  $("#prevPage").disabled = data.page <= 1;
  $("#nextPage").disabled = !data.has_more;
  $("#messageMeta").textContent = `源表共 ${data.total ?? "未知"} 条 · 本页 ${data.items.length} 条`;
  $("#messageRows").innerHTML = data.items.length ? data.items.map((item) => `<tr>
    <td>${escapeHtml(item.display_time)}<br><span class="mono">${escapeHtml(item.create_time)}</span></td>
    <td>${escapeHtml(item.sender_username || `ID ${item.real_sender_id}`)}<br><span class="mono">sender_id=${escapeHtml(item.real_sender_id)}</span></td>
    <td><span class="pill">${escapeHtml(item.type_label)}</span>${item.is_local_inserted ? ` <span class="pill local-pill">本地新增 · ${item.local_insert_direction === "other" ? "对方" : "我"}</span>` : ""}<br><span class="mono">${escapeHtml(item.content_storage)}</span></td>
    <td><div class="content-cell">${escapeHtml(item.display_content || item.source || "[空内容]")}</div></td>
    <td><span class="mono">local_id=${escapeHtml(item.local_id)}<br>${escapeHtml(item.db_rel.split("/").pop())}</span></td>
    <td><button class="button small destructive edit-message" data-key="${escapeHtml(messageKey(item))}" type="button">直接编辑</button></td>
  </tr>`).join("") : '<tr><td colspan="6" class="empty">这一页没有记录。</td></tr>';
}

function valueOf(value) { return value === null || value === undefined ? "" : String(value); }

function localDateTimeValue(date = new Date()) {
  const shifted = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return shifted.toISOString().slice(0, 19);
}

function updateInsertDirectionUi() {
  const other = $("#insertDirection").value === "other";
  $("#insertSenderLabel").classList.toggle("hidden", !other);
  if (other) {
    const isGroup = Boolean(state.insertOptions?.is_group);
    $("#insertSenderHelp").textContent = isGroup
      ? "群聊只能选择这个会话中已有接收文本记录、且能安全映射内部编号的成员。"
      : "私聊对方身份固定为当前会话联系人。";
    $("#insertDirectionHelp").textContent = isGroup
      ? "正文会自动加入群成员内部前缀，并写入“当前群聊 → 本人”的左侧气泡路由。"
      : "将使用当前联系人身份，并写入“当前联系人 → 本人”的左侧气泡路由。";
  } else {
    $("#insertDirectionHelp").textContent =
      "将使用已确认的本人身份，并写入“本人 → 当前会话”的右侧气泡路由。";
  }
}

async function openInsertDialog() {
  if (!state.active) { toast("请先从左侧选择一个会话。", "error"); return; }
  const button = $("#addMessage");
  setBusy(button, true, "读取身份…");
  try {
    state.insertOptions = await api("/api/message/insert/options", { method: "POST", body: {
      db_rel: state.active.db_rel, table: state.active.table,
    }});
    const senders = state.insertOptions.other_senders || [];
    $("#insertSender").innerHTML = senders.length
      ? senders.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.display_name || item.username)} · ${escapeHtml(item.username)}</option>`).join("")
      : '<option value="">没有可安全使用的对方身份</option>';
    $("#insertSender").disabled = !senders.length;
    $("#insertDirection").value = "self";
    updateInsertDirectionUi();
    $("#insertTarget").textContent = `${state.active.display_name} · ${state.active.db_rel} · ${state.active.table}`;
    $("#insertContent").value = "";
    $("#insertTime").value = localDateTimeValue();
    $("#insertDialog").showModal();
    $("#insertContent").focus();
  } catch (error) { showError(error); }
  finally { setBusy(button, false); }
}

async function insertTextMessage(event) {
  event.preventDefault();
  const conversation = state.active;
  if (!conversation) return;
  const content = $("#insertContent").value;
  if (!content.trim()) { toast("新增聊天正文不能为空。", "error"); return; }
  const selectedTime = new Date($("#insertTime").value);
  const timestamp = Math.floor(selectedTime.getTime() / 1000);
  if (!Number.isFinite(timestamp)) { toast("请选择有效的消息时间。", "error"); return; }
  const senderMode = $("#insertDirection").value;
  const senderId = senderMode === "other" ? $("#insertSender").value : null;
  if (senderMode === "other" && !senderId) {
    toast("当前会话没有可安全使用的对方身份。", "error");
    return;
  }
  const senderDescription = senderMode === "self"
    ? "我发送（右侧气泡）"
    : `对方发送（左侧气泡） · ${$("#insertSender").selectedOptions[0]?.textContent || "当前联系人"}`;
  const accepted = await confirmAction(
    "永久新增一条本地聊天记录？",
    `会话：${conversation.display_name}\n发送方：${senderDescription}\n时间：${selectedTime.toLocaleString()}\n\n工具会写入对应的发送者、状态、群聊前缀和收发路由，但不调用任何微信发送接口。没有备份或撤销，首次请用不重要的会话验证。`,
    "确认新增",
  );
  if (!accepted) return;
  const button = $("#saveInsert");
  setBusy(button, true, "写入并 checkpoint…");
  try {
    const result = await api("/api/message/insert", { method: "POST", body: {
      db_rel: conversation.db_rel,
      table: conversation.table,
      visible_content: content,
      create_time: timestamp,
      sender_mode: senderMode,
      sender_id: senderId,
    }});
    $("#insertDialog").close();
    const preview = result.display_sync?.session_preview_updated
      ? "；已成为最后一条并同步会话预览"
      : "；按所选时间插入历史位置，会话预览保持不变";
    const side = result.sender_mode === "other" ? "对方发送（左侧）" : "我发送（右侧）";
    toast(`${side}的本地文本已直接新增到源库${preview}。重新启动微信后查看。`, "success", 9000);
    await selectConversation(conversation.id, 1);
  } catch (error) { showError(error); }
  finally { setBusy(button, false); }
}

function openEditor(item) {
  if (!item) return;
  state.editing = item;
  $("#editLocator").textContent = `${item.db_rel} · ${item.table} · local_id=${item.local_id}`;
  $("#editContent").value = item.display_content ?? "";
  $("#editContent").disabled = !item.display_content_editable;
  $("#contentStorage").textContent = item.display_content_editable
    ? `源字段存储：${item.content_storage}；保存时保持原存储类型${item.content_has_group_prefix ? "，并保留群聊发送者内部前缀" : ""}`
    : "只有文本消息可以安全修改聊天窗口显示正文；其他消息类型请勿改正文结构。";
  $("#editSource").value = item.source ?? "";
  $("#editSource").disabled = !item.source_editable;
  $("#sourceStorage").textContent = `源字段存储：${item.source_storage}${item.source_editable ? "；保存时保持原存储类型" : "；该二进制内容不可直接编辑"}`;
  $("#editCreateTime").value = valueOf(item.create_time);
  $("#editLocalType").value = valueOf(item.local_type);
  $("#editSenderId").value = valueOf(item.real_sender_id);
  $("#editStatus").value = valueOf(item.status);
  $("#editSortSeq").value = valueOf(item.sort_seq);
  $("#editOriginSource").value = valueOf(item.origin_source);
  $("#editDialog").showModal();
}

function collectChanges(item) {
  const values = {
    display_content: $("#editContent").value, source: $("#editSource").value,
    create_time: $("#editCreateTime").value, local_type: $("#editLocalType").value,
    real_sender_id: $("#editSenderId").value, status: $("#editStatus").value,
    sort_seq: $("#editSortSeq").value, origin_source: $("#editOriginSource").value,
  };
  const changes = {};
  for (const [key, value] of Object.entries(values)) {
    if ((key === "display_content" && !item.display_content_editable) || (key === "source" && !item.source_editable)) continue;
    if (String(item[key] ?? "") !== String(value)) changes[key] = value;
  }
  return changes;
}

async function saveEdit(event) {
  event.preventDefault();
  const item = state.editing;
  if (!item) return;
  const fields = collectChanges(item);
  if (!Object.keys(fields).length) { toast("没有检测到字段变化。", "error"); return; }
  const accepted = await confirmAction(
    "永久保存到微信源库？",
    `将直接更新 ${item.db_rel} 中 local_id=${item.local_id}。没有自动备份，也不能在本工具中撤销。`,
    "永久保存",
  );
  if (!accepted) return;
  const button = $("#saveEdit");
  setBusy(button, true, "提交并 checkpoint…");
  try {
    const result = await api("/api/message/update", { method: "POST", body: {
      db_rel: item.db_rel, table: item.table, local_id: item.local_id, fields,
    }});
    $("#editDialog").close();
    const preview = result.display_sync?.session_preview_updated
      ? "；该消息是会话最后一条，左侧会话预览也已同步"
      : "；聊天气泡将在微信重新启动后读取新内容";
    toast(`已经直接写入源数据库并完成 WAL checkpoint${preview}。`, "success", 8000);
    if (state.active) await selectConversation(state.active.id, state.page);
  } catch (error) { showError(error); }
  finally { setBusy(button, false); }
}

async function runSearch() {
  const keyword = $("#searchKeyword").value.trim();
  if (!keyword) { toast("请输入搜索关键词。", "error"); return; }
  const button = $("#searchButton");
  setBusy(button, true, "扫描源库中…");
  $("#searchMeta").textContent = "正在扫描和解压源库记录…";
  try {
    const data = await api("/api/search", { method: "POST", body: {
      keyword, conversation_id: $("#searchScope").value || null,
      scan_limit: Number($("#scanLimit").value), limit: 200,
    }});
    state.searchMessages.clear();
    data.items.forEach((item) => state.searchMessages.set(messageKey(item), item));
    $("#searchMeta").textContent = `扫描 ${data.scanned} 条，找到 ${data.items.length} 条${data.truncated ? "；已达到上限" : ""}。`;
    $("#searchResults").innerHTML = data.items.length ? data.items.map((item) => `
      <article class="search-card"><header><strong>${escapeHtml(item.conversation_name || item.username)}</strong><span>${escapeHtml(item.display_time)}</span></header>
      <p>${escapeHtml(truncate(item.display_content || item.source || "[空内容]"))}</p>
      <footer><span class="mono">${escapeHtml(item.db_rel.split("/").pop())} · local_id=${escapeHtml(item.local_id)}</span><button class="button small destructive edit-search" data-key="${escapeHtml(messageKey(item))}" type="button">直接编辑</button></footer></article>`).join("") : '<div class="empty">未找到匹配记录。</div>';
  } catch (error) { $("#searchMeta").textContent = error.message; showError(error); }
  finally { setBusy(button, false); }
}

async function verifyDatabases() {
  const button = $("#verifyDb");
  setBusy(button, true, "检查中…");
  $("#verifyDbResult").textContent = "正在逐个检查源聊天分片…";
  try {
    const data = await api("/api/verify/databases", { method: "POST", body: {} });
    $("#verifyDbResult").textContent = data.items.map((item) => `${item.ok ? "✓" : "✗"} ${item.database}: ${item.result}`).join("\n");
  } catch (error) { $("#verifyDbResult").textContent = error.message; showError(error); }
  finally { setBusy(button, false); }
}

async function repairInsertRoutes() {
  const accepted = await confirmAction(
    "修复旧版新增记录的气泡方向？",
    "只会处理带 codex-wechat-local-insert-v1 本地标记、普通文本类型且 packed_info_data 为空的记录。旧版新增记录会按“我发送”补上本人 → 当前会话的右侧气泡路由；正常微信记录不会匹配。操作会直接写入源库且不可撤销。",
    "确认修复",
  );
  if (!accepted) return;
  const button = $("#repairInsertRoutes");
  setBusy(button, true, "扫描并修复…");
  $("#repairInsertResult").textContent = "正在扫描工具旧版新增记录…";
  try {
    const data = await api("/api/message/insert/repair-routes", { method: "POST", body: {} });
    const databases = data.databases?.length
      ? `\n涉及数据库：${data.databases.join("、")}`
      : "";
    $("#repairInsertResult").textContent = data.row_count
      ? `已修复 ${data.row_count} 条记录，分布在 ${data.table_count} 个会话表、${data.database_count} 个数据库。${databases}`
      : "没有发现需要修复的旧版新增记录。现有正常记录没有改动。";
    toast(
      data.row_count
        ? `已补齐 ${data.row_count} 条旧版新增记录的右侧气泡路由。重新启动微信后查看。`
        : "没有发现需要修复的旧版新增记录。",
      "success",
      9000,
    );
    if (state.active) await selectConversation(state.active.id, state.page);
  } catch (error) {
    $("#repairInsertResult").textContent = error.message || String(error);
    showError(error);
  } finally {
    setBusy(button, false);
  }
}

function switchTab(name) {
  $$(".tab").forEach((item) => item.classList.toggle("active", item.dataset.tab === name));
  $$(".tab-page").forEach((item) => item.classList.remove("active"));
  $(`#${name}Tab`).classList.add("active");
}

async function shutdown() {
  const accepted = await confirmAction("退出直接编辑器？", "数据库连接和内存中的密钥会被关闭。", "退出");
  if (!accepted) return;
  await api("/api/shutdown", { method: "POST", body: {} });
  stopCapturePolling();
  clearCredentialFields(true);
  document.body.innerHTML = '<main><section class="panel setup-card"><h1>工具已退出</h1><p>数据库连接和密钥已关闭，可以关闭此页面。</p></section></main>';
}

function wireEvents() {
  $("#scanButton").addEventListener("click", scanSource);
  $("#extractKeyButton").addEventListener("click", extractDatabaseKey);
  $("#cancelExtractButton").addEventListener("click", cancelDatabaseKeyCapture);
  $("#exportKeyButton").addEventListener("click", exportKeyBundle);
  $("#copyKeyButton").addEventListener("click", copyExportedKeyBundle);
  $("#openDirectButton").addEventListener("click", openDirect);
  $("#lockButton").addEventListener("click", closeDatabase);
  $("#shutdownButton").addEventListener("click", shutdown);
  $("#toggleKeyButton").addEventListener("click", () => {
    const input = $("#keyInput"); input.type = input.type === "password" ? "text" : "password";
    $("#toggleKeyButton").textContent = input.type === "password" ? "显示" : "隐藏";
  });
  $("#keyInput").addEventListener("keydown", (event) => { if (event.key === "Enter") openDirect(); });
  $("#sourcePath").addEventListener("input", () => {
    if ($("#sourcePath").value.trim() !== state.extractedSource) {
      state.extractedKeyring = false;
      $("#keyInput").placeholder = "";
      $("#keyExportPanel").classList.add("hidden");
      $("#keyBundleOutput").value = "";
    }
  });
  $("#refreshConversations").addEventListener("click", async () => {
    try { await loadConversations(true); toast("已重新读取源会话。", "success"); } catch (error) { showError(error); }
  });
  $("#conversationFilter").addEventListener("input", filterConversations);
  $("#conversationList").addEventListener("click", (event) => {
    const button = event.target.closest(".conversation-item"); if (button) selectConversation(button.dataset.id, 1);
  });
  $("#prevPage").addEventListener("click", () => { if (state.active && state.page > 1) selectConversation(state.active.id, state.page - 1); });
  $("#nextPage").addEventListener("click", () => { if (state.active && state.hasMore) selectConversation(state.active.id, state.page + 1); });
  $("#messageRows").addEventListener("click", (event) => {
    const button = event.target.closest(".edit-message"); if (button) openEditor(state.messages.get(button.dataset.key));
  });
  $("#editForm").addEventListener("submit", saveEdit);
  $("#addMessage").addEventListener("click", openInsertDialog);
  $("#insertForm").addEventListener("submit", insertTextMessage);
  $("#insertDirection").addEventListener("change", updateInsertDirectionUi);
  $("#closeInsert").addEventListener("click", () => $("#insertDialog").close());
  $("#cancelInsert").addEventListener("click", () => $("#insertDialog").close());
  $("#closeEdit").addEventListener("click", () => $("#editDialog").close());
  $("#cancelEdit").addEventListener("click", () => $("#editDialog").close());
  $$(".tab").forEach((item) => item.addEventListener("click", () => switchTab(item.dataset.tab)));
  $("#searchButton").addEventListener("click", runSearch);
  $("#searchKeyword").addEventListener("keydown", (event) => { if (event.key === "Enter") runSearch(); });
  $("#searchResults").addEventListener("click", (event) => {
    const button = event.target.closest(".edit-search"); if (button) openEditor(state.searchMessages.get(button.dataset.key));
  });
  $("#verifyDb").addEventListener("click", verifyDatabases);
  $("#repairInsertRoutes").addEventListener("click", repairInsertRoutes);
  $("#startupGuide").addEventListener("cancel", (event) => event.preventDefault());
}

async function init() {
  if (!token) {
    document.body.innerHTML = '<main><section class="panel setup-card"><h1>无效启动方式</h1><p>请运行 direct_app.py 或双击程序启动。</p></section></main>';
    return;
  }
  wireEvents();
  clearCredentialFields(true);
  try { await refreshStatus(); } catch (error) {
    showError(error);
  }
  $("#startupGuide").showModal();
}

init();
