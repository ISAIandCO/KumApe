"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { tab: null, config: null, context: null, relatedActions: [] };

function setStatus(text, error = false) {
  $("#status").textContent = text;
  $("#status").style.color = error ? "#d34b4b" : "";
}

async function send(message) {
  const response = await browser.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Операция не выполнена");
  return response;
}

function tabOrigin() {
  try { return new URL(state.tab.url).origin; } catch { return null; }
}

function defaultApiOrigin(uiOrigin) {
  const url = new URL(uiOrigin);
  url.port = "7223";
  return url.origin;
}

async function requestOrigins(origins) {
  const patterns = [...new Set(origins.map((origin) => `${origin}/*`))];
  return browser.permissions.request({ origins: patterns });
}

async function useCurrentOrigin() {
  const uiOrigin = tabOrigin();
  if (!uiOrigin || !/^https?:\/\//.test(uiOrigin)) throw new Error("Текущую вкладку нельзя использовать как KUMA");
  const apiOrigin = defaultApiOrigin(uiOrigin);
  if (!await requestOrigins([uiOrigin, apiOrigin])) throw new Error("Firefox не выдал доступ к указанному узлу");
  await browser.storage.local.set({ uiOrigin, apiOrigin, clusterId: "" });
  await initialize();
}

async function extractContext() {
  let target = { tabId: state.tab.id, allFrames: true };
  try {
    await browser.scripting.executeScript({ target, files: ["content/content.js"] });
  } catch {
    target = { tabId: state.tab.id };
    await browser.scripting.executeScript({ target, files: ["content/content.js"] });
  }
  const results = await browser.scripting.executeScript({ target, func: () => globalThis.KumApePage?.extractPageContext?.() ?? null });
  return results.map((item) => item.result).filter(Boolean).sort((a, b) => b.score - a.score)[0] || null;
}

function activatePanel(id) {
  for (const button of document.querySelectorAll("nav button")) button.classList.toggle("active", button.dataset.panel === id);
  for (const panel of document.querySelectorAll(".panel")) panel.classList.toggle("active", panel.id === id);
}

function addCard(container, title, value) {
  const card = document.createElement("article");
  card.className = "card";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const body = document.createElement("p");
  body.textContent = value;
  const actions = document.createElement("div");
  actions.className = "actions";
  card.append(heading, body, actions);
  container.append(card);
  return actions;
}

function button(label, handler) {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = label;
  element.addEventListener("click", async () => {
    element.disabled = true;
    try { await handler(); } catch (error) { setStatus(error.message, true); }
    finally { element.disabled = false; }
  });
  return element;
}

async function renderRelated() {
  const container = $("#related-actions");
  container.replaceChildren();
  state.relatedActions = [];
  if (!state.context?.event) {
    container.textContent = "Нужны структурированные поля текущего события.";
    return;
  }
  const response = await send({ type: "related:actions", event: state.context.event });
  state.relatedActions = response.actions;
  if (!response.actions.length) {
    container.textContent = "В событии не найдены поддерживаемые поля связи.";
    return;
  }
  for (const action of response.actions) {
    const actions = addCard(container, action.title, action.value);
    actions.append(
      button("Найти через API", async () => {
        setStatus(`Ищу события по ${action.value}…`);
        const result = await send({
          type: "related:search",
          action,
          event: state.context.event,
          rangeSeconds: Number($("#range").value),
          limit: 250,
        });
        $("#related-result").hidden = false;
        $("#related-result").textContent = JSON.stringify({
          query: result.result.query,
          period: result.result.period,
          clusterId: result.result.clusterId,
          count: result.result.events.length,
          events: result.result.events,
        }, null, 2);
        setStatus(`Найдено событий: ${result.result.events.length}`);
      }),
      button("Копировать SQL", async () => {
        const query = `SELECT * FROM \`events\` WHERE ${action.where} ORDER BY Timestamp DESC LIMIT 250`;
        await navigator.clipboard.writeText(query);
        setStatus("SQL скопирован");
      }),
    );
  }
}

async function renderIocs() {
  const container = $("#ioc-list");
  container.replaceChildren();
  if (!state.context?.event) {
    container.textContent = "Нужны структурированные поля текущего события.";
    return;
  }
  const response = await send({ type: "ioc:list", event: state.context.event });
  if (!response.iocs.length) {
    container.textContent = "IOC в поддерживаемых полях не найдены.";
    return;
  }
  for (const ioc of response.iocs) {
    const actions = addCard(container, `${ioc.type.toUpperCase()} · ${ioc.field}`, ioc.value);
    actions.append(button("Копировать", () => navigator.clipboard.writeText(ioc.value)));
    for (const link of ioc.links) {
      actions.append(button(link.provider, () => send({ type: "tabs:open", url: link.url })));
    }
  }
}

function ruleId(event) {
  if (!event || typeof event !== "object") return null;
  const fields = ["CorrelationRuleID", "CorrelationRuleId", "RuleID", "RuleId", "correlationRuleID"];
  const entries = new Map(Object.entries(event).map(([key, value]) => [key.toLowerCase(), value]));
  for (const field of fields) {
    const value = entries.get(field.toLowerCase());
    if (value !== undefined && value !== null && value !== "") return String(value);
  }
  return null;
}

async function renderContext() {
  const context = state.context;
  const output = context?.event ? JSON.stringify(context.event, null, 2) : context?.raw;
  $("#event-json").textContent = output || "Событие не найдено. Откройте карточку события или область Raw.";
  $("#event-source").textContent = context?.source ? `Источник: ${context.source}` : "";
  $("#copy-json").disabled = !output;
  await Promise.all([renderRelated(), renderIocs()]);
  const id = ruleId(context?.event);
  $("#rule-id").textContent = id ? `ID: ${id}` : "ID правила в событии не найден.";
  $("#load-rule").disabled = !id;
  $("#rule-result").textContent = id ? "Нажмите «Загрузить read-only»." : "В текущем событии идентификатор правила не найден.";
}

async function refreshContext() {
  setStatus("Читаю открытую карточку KUMA…");
  try {
    state.context = await extractContext();
    await renderContext();
    if (state.context?.event) setStatus(`Событие получено (${Object.keys(state.context.event).length} полей)`);
    else if (state.context?.raw) setStatus("Получен Raw-текст; структурированный JSON не найден");
    else setStatus("Откройте карточку события или область Raw", true);
  } catch (error) {
    state.context = null;
    await renderContext();
    setStatus(`Не удалось прочитать вкладку: ${error.message}`, true);
  }
}

async function initialize() {
  state.tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  const response = await send({ type: "config:get" });
  state.config = response.config;
  const currentOrigin = tabOrigin();
  const configured = Boolean(state.config.uiOrigin);
  const matching = configured && currentOrigin === state.config.uiOrigin;
  $("#setup").hidden = matching;
  $("#tabs").hidden = !matching;
  $("#main").hidden = !matching;
  if (!matching) {
    $("#setup-text").textContent = configured
      ? `Настроен ${state.config.uiOrigin}, а открыта ${currentOrigin || "служебная вкладка Firefox"}.`
      : `Можно использовать ${currentOrigin || "текущую вкладку"} как веб-интерфейс KUMA.`;
    $("#use-current").hidden = !currentOrigin || !/^https?:\/\//.test(currentOrigin);
    setStatus(configured ? "Открыта не настроенная KUMA" : "Первичная настройка");
    return;
  }
  await refreshContext();
}

$("#tabs").addEventListener("click", (event) => {
  const panel = event.target.closest("button")?.dataset.panel;
  if (panel) activatePanel(panel);
});
$("#open-options").addEventListener("click", () => browser.runtime.openOptionsPage());
$("#setup-options").addEventListener("click", () => browser.runtime.openOptionsPage());
$("#use-current").addEventListener("click", () => useCurrentOrigin().catch((error) => setStatus(error.message, true)));
$("#refresh").addEventListener("click", refreshContext);
$("#copy-json").addEventListener("click", async () => {
  const text = state.context?.event ? JSON.stringify(state.context.event, null, 2) : state.context?.raw;
  if (text) await navigator.clipboard.writeText(text);
  setStatus("Событие скопировано");
});
$("#copy-link").addEventListener("click", async () => {
  await navigator.clipboard.writeText(state.tab.url);
  setStatus("Ссылка скопирована");
});
$("#load-rule").addEventListener("click", async () => {
  try {
    setStatus("Загружаю правило…");
    const response = await send({ type: "rule:get", event: state.context.event });
    $("#rule-result").textContent = JSON.stringify(response.rule, null, 2);
    setStatus("Правило загружено");
  } catch (error) { setStatus(error.message, true); }
});

initialize().catch((error) => setStatus(error.message, true));
