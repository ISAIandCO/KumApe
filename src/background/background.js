"use strict";

const adapterApi = globalThis.KumApeAdapter;
const processApi = globalThis.KumApeProcess;
const DEFAULT_CONFIG = Object.freeze({
  uiOrigin: "",
  apiOrigin: "",
  clusterId: "",
  fieldProfiles: adapterApi.BUILTIN_FIELD_PROFILES,
  processMappings: processApi.BUILTIN_PROCESS_MAPPINGS,
  usefulFilters: globalThis.KumApeFilters.BUILTIN_FILTERS,
  ai: { enabled: false, endpoint: "http://127.0.0.1:8080/v1", model: "local-model", privacyMode: "strict" },
});
const processGraphs = new Map();
const processGraphTabs = new Map();
const processOperations = new Map();
const REQUEST_TTL_MS = 5 * 60_000;
const ALLOWED_REQUESTS = Object.freeze([
  { method: "GET", base: "ui", pattern: /^\/api\/whoami$/ },
  { method: "GET", base: "api", pattern: /^\/api\/v3\/users\/whoami$/ },
  { method: "GET", base: "api", pattern: /^\/api\/v3\/events\/clusters(?:\?[^#]*)?$/ },
  { method: "GET", base: "api", pattern: /^\/api\/v3\/settings\/extendedFields\/export$/ },
  { method: "GET", base: "api", pattern: /^\/api\/v3\/resources\/correlationRule\/[^/?#]+$/ },
  { method: "POST", base: "api", pattern: /^\/api\/v3\/events$/ },
]);

// One-time migration keeps keys entered before the persistent-storage update.
const keyMigration = (async () => {
  const [local, session] = await Promise.all([
    browser.storage.local.get(["apiToken", "iocApiKeys", "fieldProfiles", "processMappings", "usefulFilters"]),
    browser.storage.session.get(["apiToken", "iocApiKeys"]),
  ]);
  const moved = {};
  for (const key of ["apiToken", "iocApiKeys"]) {
    if (local[key] === undefined && session[key] !== undefined) moved[key] = session[key];
  }
  if (local.processMappings === undefined) {
    const legacy = processApi.mappingsFromLegacyProfiles(local.fieldProfiles);
    moved.processMappings = legacy.length ? legacy : processApi.BUILTIN_PROCESS_MAPPINGS;
    if (legacy.length) moved.fieldProfiles = local.fieldProfiles.map(({ processGraph, ...profile }) => profile);
  }
  if (local.processMappings) {
    moved.processMappings = local.processMappings.map(mapping => {
      const migrated = mapping.eventIdValue === "4688" && mapping.pid === "DestinationProcessID" && mapping.parentPid === "SourceProcessID" && !mapping.fallbackPid
        ? { ...mapping, pid: "DeviceCustomString5", parentPid: "DeviceCustomString3", fallbackPid: "DestinationProcessID", fallbackParentPid: "SourceProcessID" }
        : mapping;
      const builtin = processApi.BUILTIN_PROCESS_MAPPINGS.find(candidate => candidate.eventIdField === migrated.eventIdField && candidate.eventIdValue === migrated.eventIdValue && (candidate.eventIdValue === "1" || candidate.name === migrated.name));
      const categoriesMissing = Array.isArray(migrated.eventCategories) ? !migrated.eventCategories.length : !String(migrated.eventCategories || "").trim();
      return categoriesMissing && builtin?.eventCategories ? { ...migrated, eventCategories: builtin.eventCategories } : migrated;
    });
  }
  if (local.usefulFilters) moved.usefulFilters = globalThis.KumApeFilters.migrateBuiltinFilters(local.usefulFilters);
  if (Object.keys(moved).length) await browser.storage.local.set(moved);
  await browser.storage.session.remove(["apiToken", "iocApiKeys"]);
})();

async function loadConfig() {
  await keyMigration;
  const stored = await browser.storage.local.get({ ...DEFAULT_CONFIG, apiToken: "" });
  const { apiToken, ...config } = stored;
  return { ...config, token: apiToken || "" };
}

function permissionPattern(origin) {
  const url = new URL(adapterApi.normalizeOrigin(origin));
  return `${url.protocol}//${url.hostname}/*`;
}

function responseMessage(body, contentType) {
  if (!body) return "";
  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(body);
      const detail = parsed?.message ?? parsed?.error?.message ?? parsed?.error ?? parsed?.details;
      if (typeof detail === "string") return detail.replace(/\s+/g, " ").slice(0, 300);
    } catch {
      // Fall back to a safe plain-text excerpt.
    }
  }
  return /[<>]/.test(body) ? "" : body.replace(/\s+/g, " ").slice(0, 300);
}

async function readJson(response, path, method = "GET") {
  const text = await response.text();
  if (!response.ok) {
    const detail = responseMessage(text, response.headers.get("content-type") || "");
    const hint = response.status === 403 && method === "POST" && path === "/api/v3/events"
      ? " Для поиска событий требуется право POST /api/v3/events: одних GET-прав недостаточно. Это SQL-поиск, данные он не изменяет. Если POST уже разрешён, проверьте доступ пользователя к выбранному кластеру и тенанту."
      : "";
    throw new Error(`${method} ${path}: HTTP ${response.status}${detail ? ` — ${detail}` : ""}${hint}`);
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${path}: KUMA вернула ответ не в формате JSON`);
  }
}

async function kumaRequest({ origin, path, method = "GET", token, body }) {
  const normalizedOrigin = adapterApi.normalizeOrigin(origin);
  const config = await loadConfig();
  const origins = {
    ui: config.uiOrigin ? adapterApi.normalizeOrigin(config.uiOrigin) : null,
    api: config.apiOrigin ? adapterApi.normalizeOrigin(config.apiOrigin) : null,
  };
  const rule = ALLOWED_REQUESTS.find((candidate) => (
    origins[candidate.base] === normalizedOrigin
    && candidate.method === method
    && candidate.pattern.test(path)
  ));
  if (!rule) throw new Error("Запрос заблокирован read-only политикой KumApe");
  const granted = await browser.permissions.contains({ origins: [permissionPattern(normalizedOrigin)] });
  if (!granted) throw new Error(`Нет разрешения Firefox для ${normalizedOrigin}. Пересохраните настройки.`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json; charset=utf-8";
  try {
    const response = await fetch(new URL(path, normalizedOrigin), {
      method,
      credentials: rule.base === "ui" ? "include" : "omit",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    return await readJson(response, path, method);
  } catch (error) {
    if (error?.name === "AbortError") throw new Error(`${path}: превышено время ожидания`);
    if (error instanceof TypeError || /NetworkError|Failed to fetch/i.test(error?.message || "")) {
      throw new Error(`${path}: Firefox не смог подключиться к ${normalizedOrigin}. Проверьте доступность порта 7223, протокол HTTPS и доверие сертификату API`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function adapter() {
  const config = await loadConfig();
  if (!config.uiOrigin || !config.apiOrigin) throw new Error("Сначала укажите адрес KUMA в настройках");
  return new adapterApi.KumaAdapter(config, kumaRequest);
}

function requestId() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function safeRelatedAction(message) {
  const config = await loadConfig();
  const action = adapterApi.buildRelatedActions(message.event, config.fieldProfiles).find((candidate) => (
    candidate.kind === message.action?.kind && candidate.value === message.action?.value
  ));
  if (!action) throw new Error("Параметры related search не соответствуют текущему событию");
  return action;
}

async function safeFilter(message) {
  const config = await loadConfig();
  const filter = globalThis.KumApeFilters.findUsefulFilter(message.filterId, message.event, config.fieldProfiles, config.processMappings, config.usefulFilters);
  if (!filter) throw new Error("Фильтр неприменим к текущему событию");
  return filter;
}

async function openKumaSearchTab(message, action) {
  const config = await loadConfig();
  if (!config.uiOrigin) throw new Error("Сначала укажите адрес KUMA в настройках");
  const query = adapterApi.buildEventsQuery(action.where, message.limit);
  const tab = await browser.tabs.create({ url: adapterApi.threatHuntingUrl(config.uiOrigin, query, action.period || message.rangeSeconds) });
  if (!Number.isInteger(tab?.id)) throw new Error("Firefox не вернул идентификатор вкладки KUMA");
  return { tabId: tab.id };
}

async function openProcessGraph(message) {
  const config = await loadConfig();
  processApi.graphSearchAction(message.event, config.processMappings);
  const id = requestId();
  await browser.storage.session.set({ [`processRequest:${id}`]: {
    event: message.event,
    rangeSeconds: Math.max(60, Number(message.rangeSeconds) || adapterApi.DEFAULT_RANGE_SECONDS || 900),
    limit: Math.max(1, Math.min(1000, Number(message.limit) || 1000)),
    expiresAt: Date.now() + REQUEST_TTL_MS,
  } });
  const graphTab = await browser.tabs.create({ url: browser.runtime.getURL(`process-graph/graph.html?id=${encodeURIComponent(id)}&layout=${["force", "timeline", "step"].includes(message.layout) ? message.layout : "force"}`) });
  if (graphTab?.id) processGraphTabs.set(graphTab.id, id);
  return { id };
}

async function runProcessGraph(message) {
  const previous = processGraphs.get(message.id) || await globalThis.KumApeGraphStore?.get(message.id);
  const request = previous?.request || await storedRequest("processRequest", message.id);
  const config = await loadConfig();
  if (previous && previous.result.origin !== config.uiOrigin) throw new Error("Адрес KUMA изменён. Откройте новый граф.");
  const operation = requestId(); processOperations.set(message.id, operation);
  const expanding = message.type === "process:expand";
  const mode = expanding ? previous?.result.queryMetadata.mode : message.mode === "step" ? "step" : "broad";
  if (expanding && !previous) throw new Error("Сначала загрузите граф");
  const selected = expanding ? previous.result.graph.nodes.find(n => n.id === message.nodeId) : null;
  if (expanding && !selected) throw new Error("Узел отсутствует на текущем графе");
  const queryLimit = message.nodeLimit === 10000 ? 10000 : request.limit;
  const anchor = selected?.event || request.event;
  let range = expanding ? Math.max(60, Math.min(86400, Number(message.rangeSeconds) || 900)) : request.rangeSeconds;
  let searchEvent = anchor;
  const direction = message.direction || "both";
  const interval = expanding && ["previous", "next"].includes(direction);
  if (interval) {
    const period = previous.result.period;
    const edge = Date.parse(direction === "previous" ? period.from : period.to);
    searchEvent = { ...anchor, Timestamp: new Date(edge + (direction === "previous" ? -1 : 1) * range * 1000).toISOString() };
  }
  const action = !interval && (expanding || mode === "step")
    ? processApi.relatedAction(anchor, config.processMappings, direction)
    : processApi.graphSearchAction(anchor, config.processMappings);
  try {
    const fetched = await (await adapter()).searchRelated(action, searchEvent, range, queryLimit, 10000);
    if (processOperations.get(message.id) !== operation) throw new Error("Загрузка отменена");
    let candidate = processApi.buildGraph(fetched.events, anchor, config.processMappings);
    if (!interval && (mode === "step" || expanding) && direction !== "siblings") candidate = processApi.connectedGraph(candidate, candidate.sourceNodeId, direction);
    const events = [...(expanding ? previous.result.graph.nodes.map(n => n.event) : []), ...candidate.nodes.map(n => n.event)];
    const graph = processApi.buildGraph(events, request.event, config.processMappings);
    const period = expanding ? {
      from: new Date(Math.min(Date.parse(previous.result.period.from), Date.parse(fetched.period.from))).toISOString(),
      to: new Date(Math.max(Date.parse(previous.result.period.to), Date.parse(fetched.period.to))).toISOString(),
    } : fetched.period;
    graph.truncated = fetched.events.length >= queryLimit;
    const result = { graph, sourceNodeId: graph.sourceNodeId, sourceEvent: request.event, origin: config.uiOrigin, query: fetched.query, period,
      queryMetadata: { mode, partial: true, timeFrom: period.from, timeTo: period.to, limitReached: graph.truncated, maxNodes: queryLimit } };
    const snapshot = { request: { ...request, limit: queryLimit }, result };
    await globalThis.KumApeGraphStore?.set(message.id, snapshot);
    processGraphs.set(message.id, snapshot);
    return result;
  } finally { if (processOperations.get(message.id) === operation) processOperations.delete(message.id); }
}

async function storedRequest(prefix, id) {
  if (!/^[a-z0-9_-]{8,100}$/i.test(String(id || ""))) throw new Error("Некорректный идентификатор запроса");
  const key = `${prefix}:${id}`;
  const value = (await browser.storage.session.get(key))[key];
  if (!value) throw new Error("Запрос не найден. Откройте результаты заново из KumApe.");
  if (value.expiresAt < Date.now()) {
    await browser.storage.session.remove(key);
    throw new Error("Запрос устарел. Откройте результаты заново из KumApe.");
  }
  return value;
}

function aiEndpoint(config) {
  const url = new URL(config.ai?.endpoint || "");
  if (!/^https?:$/.test(url.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error("Локальный AI endpoint должен использовать localhost, 127.0.0.1 или [::1]");
  }
  return url;
}

async function runAi(message) {
  const config = await loadConfig();
  if (!config.ai?.enabled) throw new Error("Локальный AI выключен в настройках");
  const endpoint = aiEndpoint(config);
  if (!await browser.permissions.contains({ origins: [permissionPattern(endpoint.origin)] })) throw new Error("Нет разрешения Firefox для локального AI endpoint");
  const request = await storedRequest("aiRequest", message.id);
  if (request.bytes > 200_000) throw new Error("Контекст AI превышает лимит 200 КБ. Используйте Strict или Redacted режим.");
  const messages = Array.isArray(message.messages) ? message.messages.slice(-20).map((item) => ({
    role: item?.role === "assistant" ? "assistant" : "user",
    content: String(item?.content || "").slice(0, 20000),
  })).filter((item) => item.content) : [];
  if (!messages.length) throw new Error("Введите вопрос");
  const base = endpoint.href.endsWith("/") ? endpoint.href : `${endpoint.href}/`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);
  let response;
  try {
    response = await fetch(new URL("chat/completions", base), {
      method: "POST", credentials: "omit", signal: controller.signal,
      headers: { Accept: "application/json", "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        model: config.ai.model || "local-model", stream: false,
        messages: [
          { role: "system", content: "Ты SOC-аналитик. Анализируй только приложенное событие KUMA. Не выдумывай отсутствующие факты. Отвечай по-русски, кратко и структурированно." },
          { role: "user", content: `Контекст события KUMA:\n${JSON.stringify(request.payload)}` },
          ...messages,
        ],
      }),
    });
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("Локальный AI: превышено время ожидания 120 секунд");
    throw error;
  } finally { clearTimeout(timeout); }
  if (!response.ok) throw new Error(`Локальный AI: HTTP ${response.status}`);
  const result = await response.json();
  const content = result?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || !content.trim()) throw new Error("Локальный AI вернул пустой ответ");
  return content;
}

browser.tabs.onRemoved?.addListener(async tabId => {
  const id = processGraphTabs.get(tabId);
  if (!id) return;
  processGraphTabs.delete(tabId); processGraphs.delete(id); processOperations.delete(id);
  await browser.storage.session.remove(`processRequest:${id}`);
  await globalThis.KumApeGraphStore?.remove(id);
});

browser.runtime.onMessage.addListener(async (message, sender) => {
  try {
    if (!message || typeof message.type !== "string") return undefined;
    if (sender?.tab && !sender.url?.startsWith(browser.runtime.getURL(""))) {
      const config = await loadConfig();
      if (!sender.url || new URL(sender.url).origin !== config.uiOrigin
        || !["ioc:lookup", "ioc:open", "ioc:options"].includes(message.type)) {
        throw new Error("Сообщение разрешено только из карточки настроенной KUMA");
      }
      if (!await browser.permissions.contains({ origins: [permissionPattern(config.uiOrigin)] })) {
        throw new Error("Доступ к KUMA отозван");
      }
    }
    switch (message.type) {
      case "ioc:lookup":
        await keyMigration;
        return { ok: true, result: await globalThis.KumApeLookup.lookup(message.provider, message.ioc) };
      case "ioc:open": {
        const ioc = globalThis.KumApeIoc.validateIoc(message.ioc);
        const link = adapterApi.iocLinks(ioc).find((item) => item.provider === message.provider);
        if (!link) throw new Error("Неизвестный IOC-провайдер");
        await browser.tabs.create({ url: link.url });
        return { ok: true };
      }
      case "ioc:options":
        await browser.runtime.openOptionsPage();
        return { ok: true };

      case "config:get": {
        const config = await loadConfig();
        return { ok: true, config: { ...config, token: undefined, tokenPresent: Boolean(config.token) } };
      }
      case "session:test":
        return { ok: true, user: await (await adapter()).getCurrentUser() };
      case "api:test":
        return { ok: true, user: await (await adapter()).getApiCurrentUser() };
      case "clusters:list":
        return { ok: true, clusters: await (await adapter()).getClusters() };
      case "extended-fields:list":
        return { ok: true, fields: await (await adapter()).getExtendedFields() };
      case "related:actions":
        {
          const config = await loadConfig();
          return { ok: true, actions: adapterApi.buildRelatedActions(message.event, config.fieldProfiles) };
        }
      case "related:search":
        {
          const safeAction = await safeRelatedAction(message);
          return {
            ok: true,
            result: await (await adapter()).searchRelated(safeAction, message.event, message.rangeSeconds, message.limit),
          };
        }
      case "related:query": {
        const action = await safeRelatedAction(message);
        return { ok: true, query: adapterApi.buildEventsQuery(action.where, message.limit) };
      }
      case "related:open-tab":
        return { ok: true, result: await openKumaSearchTab(message, await safeRelatedAction(message)) };
      case "filters:list": {
        const config = await loadConfig();
        const filters = globalThis.KumApeFilters.buildUsefulFilters(message.event, config.fieldProfiles, config.processMappings, config.usefulFilters);
        return { ok: true, filters: filters.map(({ where, ...filter }) => ({ ...filter, ...(where ? { preview: where } : {}) })) };
      }
      case "filters:query": {
        const filter = await safeFilter(message);
        return { ok: true, query: adapterApi.buildEventsQuery(filter.where, message.limit) };
      }
      case "filters:search": {
        const filter = await safeFilter(message);
        return { ok: true, result: await (await adapter()).searchRelated(filter, message.event, filter.rangeSeconds, message.limit) };
      }
      case "filters:open-tab": {
        const filter = await safeFilter(message);
        return { ok: true, result: await openKumaSearchTab({ ...message, rangeSeconds: filter.rangeSeconds }, filter) };
      }
      case "process:open-graph":
        return { ok: true, result: await openProcessGraph(message) };
      case "process:request:run":
      case "process:expand":
        return { ok: true, result: await runProcessGraph(message) };
      case "process:cancel":
        processOperations.delete(message.id);
        return { ok: true };
      case "process:event:open": {
        const config = await loadConfig();
        const mapping = processApi.mappingForEvent(message.event, config.processMappings);
        if (!mapping) throw new Error("Для узла не найдено сопоставление полей графа");
        const mappedEventId = mapping.eventRecordId && adapterApi.valuesForAliases(message.event, [mapping.eventRecordId])[0];
        const eventIdField = mappedEventId ? mapping.eventRecordId : "ID";
        const eventId = mappedEventId || adapterApi.valuesForAliases(message.event, ["ID"])[0];
        if (!eventId) throw new Error("Для узла не найден ID события KUMA");
        const timestamp = Math.floor(adapterApi.eventTimestamp(message.event));
        const from = Math.floor(timestamp / 60_000) * 60_000;
        return { ok: true, result: await openKumaSearchTab(message, { where: adapterApi.equalityWhere([eventIdField], eventId), period: { from, to: from + 59_999 } }) };
      }
      case "workspace:open":
        await browser.tabs.create({ url: browser.runtime.getURL(message.id ? `workspace/workspace.html?id=${encodeURIComponent(message.id)}` : "workspace/workspace.html") });
        return { ok: true };
      case "ai:open": {
        const config = await loadConfig();
        if (!config.ai?.enabled) throw new Error("Включите локальный AI в настройках KumApe");
        aiEndpoint(config);
        const sessionKey = Number.isInteger(message.sourceTabId) ? `aiSession:${config.uiOrigin}:${message.sourceTabId}` : null;
        let existing = null;
        if (sessionKey) {
          const sourceTab = await browser.tabs.get(message.sourceTabId);
          if (new URL(sourceTab.url).origin !== config.uiOrigin) throw new Error("Исходная вкладка не принадлежит настроенной KUMA");
          existing = (await browser.storage.session.get(sessionKey))[sessionKey];
        }
        let old = null;
        if (existing) { try { old = await storedRequest("aiRequest", existing.id); } catch { existing = null; } }
        const previous = old ? (old.payload.Events || [old.payload]) : [];
        const current = Array.isArray(message.event?.Events) ? message.event.Events : [message.event];
        const combined = [...previous, ...current].map(event => globalThis.KumApeAiPrivacy.prepareEvent(event, config.ai.privacyMode || "strict"));
        const unique = [...new Map(combined.map(event => [JSON.stringify(event),event])).values()].slice(-100);
        const preview = globalThis.KumApeAiPrivacy.preview(unique.length === 1 ? unique[0] : {Events:unique}, config.ai.privacyMode || "strict");
        if (preview.bytes > 200000) throw new Error("Контекст AI превышает 200 КБ; выберите более строгий режим");
        const id = existing?.id || requestId();
        await browser.storage.session.set({ [`aiRequest:${id}`]: { payload: preview.payload, fields: preview.fields, bytes: preview.bytes, mode: preview.mode, expiresAt: Date.now() + 24 * 60 * 60_000 } });
        if (existing?.tabId) {
          try {
            const tab = await browser.tabs.get(existing.tabId);
            if (tab.url === browser.runtime.getURL(`ai/assistant.html?id=${encodeURIComponent(id)}`)) {
              await browser.tabs.update(tab.id,{active:true}); return {ok:true};
            }
          } catch { /* Reopen a closed chat using its prepared context. */ }
        }
        const tab = await browser.tabs.create({ url: browser.runtime.getURL(`ai/assistant.html?id=${encodeURIComponent(id)}`) });
        if (sessionKey) await browser.storage.session.set({[sessionKey]:{id,tabId:tab.id}});
        return { ok: true };
      }
      case "ai:request:get": {
        const request = await storedRequest("aiRequest", message.id);
        const config = await loadConfig();
        return { ok: true, preview: { fields: request.fields, bytes: request.bytes, mode: request.mode, endpoint: config.ai?.endpoint, model: config.ai?.model } };
      }
      case "ai:chat":
        return { ok: true, content: await runAi(message) };
      case "ioc:list": {
        const iocs = adapterApi.iocsFromEvent(message.event);
        return { ok: true, iocs: iocs.map((ioc) => ({ ...ioc, links: adapterApi.iocLinks(ioc) })) };
      }
      case "rule:get": {
        const id = message.id || adapterApi.correlationRuleId(message.event);
        if (!id) throw new Error("В событии не найден идентификатор правила корреляции");
        return { ok: true, id, rule: await (await adapter()).getCorrelationRule(id) };
      }
      case "tabs:open": {
        const url = new URL(message.url);
        if (!/^https?:$/.test(url.protocol)) throw new Error("Разрешены только HTTP(S)-ссылки");
        await browser.tabs.create({ url: url.href });
        return { ok: true };
      }
      default:
        return undefined;
    }
  } catch (error) {
    return { ok: false, error: error?.message || String(error) };
  }
});
