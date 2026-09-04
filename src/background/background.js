"use strict";

const adapterApi = globalThis.KumApeAdapter;
const DEFAULT_CONFIG = Object.freeze({ uiOrigin: "", apiOrigin: "", clusterId: "" });
const ALLOWED_REQUESTS = Object.freeze([
  { method: "GET", base: "ui", pattern: /^\/api\/whoami$/ },
  { method: "GET", base: "ui", pattern: /^\/api\/private\/resources\/correlationRule\/[^/?#]+$/ },
  { method: "GET", base: "api", pattern: /^\/api\/v3\/events\/clusters(?:\?[^#]*)?$/ },
  { method: "POST", base: "api", pattern: /^\/api\/v3\/events$/ },
]);

async function loadConfig() {
  const [stored, session] = await Promise.all([
    browser.storage.local.get(DEFAULT_CONFIG),
    browser.storage.session.get({ apiToken: "" }),
  ]);
  return { ...stored, token: session.apiToken || "" };
}

function permissionPattern(origin) {
  return `${adapterApi.normalizeOrigin(origin)}/*`;
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

async function readJson(response, path) {
  const text = await response.text();
  if (!response.ok) {
    const detail = responseMessage(text, response.headers.get("content-type") || "");
    throw new Error(`${path}: HTTP ${response.status}${detail ? ` — ${detail}` : ""}`);
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
      credentials: "include",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    return await readJson(response, path);
  } catch (error) {
    if (error?.name === "AbortError") throw new Error(`${path}: превышено время ожидания`);
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

browser.runtime.onMessage.addListener(async (message) => {
  try {
    if (!message || typeof message.type !== "string") return undefined;
    switch (message.type) {
      case "config:get": {
        const config = await loadConfig();
        return { ok: true, config: { ...config, token: undefined, tokenPresent: Boolean(config.token) } };
      }
      case "session:test":
        return { ok: true, user: await (await adapter()).getCurrentUser() };
      case "clusters:list":
        return { ok: true, clusters: await (await adapter()).getClusters() };
      case "related:actions":
        return { ok: true, actions: adapterApi.buildRelatedActions(message.event) };
      case "related:search":
        {
          const safeAction = adapterApi.buildRelatedActions(message.event).find((action) => (
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
