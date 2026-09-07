"use strict";

const adapterApi = globalThis.KumApeAdapter;
const DEFAULT_CONFIG = Object.freeze({
  uiOrigin: "",
  apiOrigin: "",
  clusterId: "",
  fieldProfiles: adapterApi.BUILTIN_FIELD_PROFILES,
});
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
    browser.storage.local.get(["apiToken", "iocApiKeys"]),
    browser.storage.session.get(["apiToken", "iocApiKeys"]),
  ]);
  const moved = {};
  for (const key of ["apiToken", "iocApiKeys"]) {
    if (local[key] === undefined && session[key] !== undefined) moved[key] = session[key];
  }
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
          const config = await loadConfig();
          const safeAction = adapterApi.buildRelatedActions(message.event, config.fieldProfiles).find((action) => (
            action.kind === message.action?.kind && action.value === message.action?.value
          ));
          if (!safeAction) throw new Error("Параметры related search не соответствуют текущему событию");
          return {
            ok: true,
            result: await (await adapter()).searchRelated(safeAction, message.event, message.rangeSeconds, message.limit),
          };
        }
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
