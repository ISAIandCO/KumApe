(function initInvestigationDb(global) {
  "use strict";

  const DB_NAME = "kumape-investigations";
  const DB_VERSION = 1;
  const uid = (prefix) => `${prefix}_${global.crypto?.randomUUID?.() || `${Date.now()}_${Math.random().toString(36).slice(2)}`}`;
  const done = (request) => new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const transactionDone = (transaction) => new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error || new Error("Транзакция отменена"));
  });

  function open() {
    if (!global.indexedDB) return Promise.reject(new Error("IndexedDB недоступна"));
    const request = global.indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      const investigations = db.createObjectStore("investigations", { keyPath: "id" });
      investigations.createIndex("byUpdatedAt", "updatedAt");
      investigations.createIndex("byStatus", "status");
      const items = db.createObjectStore("items", { keyPath: "id" });
      items.createIndex("byInvestigation", "investigationId");
      items.createIndex("byInvestigationTime", ["investigationId", "timestamp"]);
      items.createIndex("byEntity", "entityKeys", { multiEntry: true });
    };
    return done(request);
  }

  function eventValue(event, fields) {
    const entries = new Map(Object.entries(event || {}).map(([key, value]) => [key.toLowerCase(), value]));
    for (const field of fields) {
      const value = entries.get(field.toLowerCase());
      if (value !== undefined && value !== null && value !== "") return String(value);
    }
    return null;
  }

  function describeEvent(event) {
    const code = eventValue(event, ["DeviceEventClassID", "EventID", "Name"]);
    const process = eventValue(event, ["DeviceProcessName", "DestinationProcessName", "SourceProcessName", "ProcessName"]);
    const user = eventValue(event, ["SourceUserName", "DestinationUserName", "UserName"]);
    const host = eventValue(event, ["DeviceHostName", "SourceHostName", "DestinationHostName"]);
    const rule = eventValue(event, ["CorrelationRuleName", "CorrelationRuleTitle", "RuleName"]);
    if (rule) return `Корреляция: ${rule}`;
    if (["4688", "1", "EXECVE"].includes(code) && process) return `Запущен процесс ${process}${user ? ` (${user})` : ""}`;
    if (["4624", "USER_LOGIN"].includes(code) && user) return `Вход пользователя ${user}${host ? ` на ${host}` : ""}`;
    if (["4625", "USER_AUTH"].includes(code) && user) return `Неуспешный вход ${user}${host ? ` на ${host}` : ""}`;
    return [code && `Событие ${code}`, process, user, host].filter(Boolean).join(" · ") || "Событие KUMA";
  }

  function entityKeys(event) {
    const definitions = {
      host: ["DeviceHostName", "SourceHostName", "DestinationHostName"],
      account: ["SourceUserName", "DestinationUserName", "UserName"],
      process: ["DeviceProcessName", "DestinationProcessName", "SourceProcessName"],
      ip: ["SourceAddress", "DestinationAddress", "DeviceAddress"],
      hash: ["FileHash", "OldFileHash", "Hash"],
    };
    const keys = [];
    for (const [kind, fields] of Object.entries(definitions)) {
      for (const field of fields) {
        const value = eventValue(event, [field]);
        if (value) keys.push(`${kind}:${value.toLowerCase()}`);
      }
    }
    return [...new Set(keys)];
  }

  async function listInvestigations() {
    const db = await open();
    const values = await done(db.transaction("investigations").objectStore("investigations").getAll());
    db.close();
    return values.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  async function getInvestigation(id) {
    const db = await open();
    const investigation = await done(db.transaction("investigations").objectStore("investigations").get(id));
    db.close();
    return investigation || null;
  }

  async function createInvestigation(title = "Новое расследование") {
    const now = new Date().toISOString();
    const investigation = { id: uid("inv"), title: String(title).trim().slice(0, 160) || "Новое расследование", status: "open", tags: [], notes: "", createdAt: now, updatedAt: now };
    const db = await open();
    await done(db.transaction("investigations", "readwrite").objectStore("investigations").add(investigation));
    db.close();
    return investigation;
  }

  async function updateInvestigation(id, changes) {
    const current = await getInvestigation(id);
    if (!current) throw new Error("Расследование не найдено");
    const next = {
      ...current,
      ...(changes.title !== undefined ? { title: String(changes.title).trim().slice(0, 160) || current.title } : {}),
      ...(changes.status !== undefined ? { status: changes.status === "closed" ? "closed" : "open" } : {}),
      ...(changes.notes !== undefined ? { notes: String(changes.notes).slice(0, 100000) } : {}),
      ...(changes.tags !== undefined ? { tags: [...new Set(changes.tags.map((tag) => String(tag).trim()).filter(Boolean))].slice(0, 30) } : {}),
      updatedAt: new Date().toISOString(),
    };
    const db = await open();
    await done(db.transaction("investigations", "readwrite").objectStore("investigations").put(next));
    db.close();
    return next;
  }

  async function addEvent(investigationId, event, source = {}) {
    if (!event || typeof event !== "object") throw new Error("Событие не найдено");
    const investigation = await getInvestigation(investigationId);
    if (!investigation) throw new Error("Расследование не найдено");
    const eventId = eventValue(event, ["ID", "EventID", "EventId", "event.id"]);
    const timestamp = global.KumApeAdapter?.eventTimestamp(event) || Date.now();
    const item = {
      id: eventId ? `event_${investigationId}_${eventId}` : uid("item"),
      investigationId,
      type: "event",
      timestamp: new Date(timestamp).toISOString(),
      label: describeEvent(event),
      source: { uiOrigin: source.uiOrigin || null, eventId, url: source.url || null },
      entityKeys: entityKeys(event),
      payload: event,
    };
    const db = await open();
    const tx = db.transaction(["items", "investigations"], "readwrite");
    tx.objectStore("items").put(item);
    tx.objectStore("investigations").put({ ...investigation, updatedAt: new Date().toISOString() });
    await transactionDone(tx);
    db.close();
    return item;
  }

  async function listItems(investigationId) {
    const db = await open();
    const items = await done(db.transaction("items").objectStore("items").index("byInvestigation").getAll(investigationId));
    db.close();
    return items.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  async function deleteInvestigation(id) {
    const db = await open();
    const tx = db.transaction(["items", "investigations"], "readwrite");
    const index = tx.objectStore("items").index("byInvestigation");
    const keys = await done(index.getAllKeys(id));
    for (const key of keys) tx.objectStore("items").delete(key);
    tx.objectStore("investigations").delete(id);
    await transactionDone(tx);
    db.close();
  }

  function toMarkdown(investigation, items) {
    const lines = [`# ${investigation.title}`, "", `Статус: ${investigation.status === "closed" ? "закрыто" : "открыто"}`, `Обновлено: ${investigation.updatedAt}`];
    if (investigation.tags.length) lines.push(`Теги: ${investigation.tags.join(", ")}`);
    if (investigation.notes) lines.push("", "## Заметки", "", investigation.notes);
    lines.push("", "## События", "");
    for (const item of items) lines.push(`- ${item.timestamp} — ${item.label}`);
    return `${lines.join("\n")}\n`;
  }

  global.KumApeInvestigations = Object.freeze({ addEvent, createInvestigation, deleteInvestigation, describeEvent, entityKeys, getInvestigation, listInvestigations, listItems, open, toMarkdown, updateInvestigation });
})(globalThis);
