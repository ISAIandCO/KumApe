"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { tab: null, config: null, context: null, relatedActions: [], filters: [] };

$("#version").textContent = browser.runtime.getManifest().version;

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
  const patterns = [...new Set(origins.map((origin) => { const url = new URL(origin); return `${url.protocol}//${url.hostname}/*`; }))];
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
  let results;
  try {
    results = await browser.scripting.executeScript({ target, files: ["/content/content.js"] });
  } catch {
    target = { tabId: state.tab.id };
    results = await browser.scripting.executeScript({ target, files: ["/content/content.js"] });
  }
  const context = results
    .map((item) => item.result)
    .filter(Boolean)
    .sort((a, b) => b.score - a.score)[0] || null;
  if (!context) {
    const error = results.find((item) => item.error)?.error;
    throw new Error(error?.message || (error && String(error)) || "Скрипт чтения карточки не вернул результат. Перезагрузите расширение и вкладку KUMA.");
  }
  return context;
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
        renderResults(result.result);
        setStatus(`Найдено событий: ${result.result.events.length}`);
      }),
      button("Копировать SQL", async () => {
        const response = await send({ type: "related:query", action, event: state.context.event, limit: 250 });
        await navigator.clipboard.writeText(response.query);
        setStatus("SQL скопирован");
      }),
      button("Открыть в новой вкладке", async () => {
        await send({ type: "related:open-tab", action, event: state.context.event, rangeSeconds: Number($("#range").value), limit: 250 });
        setStatus("Фильтр передан в новую вкладку KUMA");
      }),
    );
  }
}

async function renderFilters() {
  const select = $("#useful-filter"); select.replaceChildren(); state.filters = [];
  if (!state.context?.event) {
    select.disabled = true;
    $("#filter-description").textContent = "Нужны структурированные поля текущего события.";
    previewFilter();
    return;
  }
  const response = await send({ type: "filters:list", event: state.context.event });
  state.filters = response.filters.sort((a, b) => Number(b.applicable) - Number(a.applicable) || a.title.localeCompare(b.title, "ru"));
  for (const filter of state.filters) {
    const missing = filter.missing?.length ? ` — нет полей: ${filter.missing.join(", ")}` : "";
    const option = new Option(`${filter.title}${missing}`, filter.id);
    option.disabled = !filter.applicable;
    select.add(option);
  }
  select.disabled = !state.filters.length;
  previewFilter();
}

function selectedFilter() { return state.filters.find((filter) => filter.id === $("#useful-filter").value) || null; }

function previewFilter() {
  const filter = selectedFilter();
  const graph = filter?.type === "processGraph";
  $("#filter-description").textContent = filter ? `${filter.description} Диапазон: ±${filter.timeRange}.` : "Нет доступных фильтров.";
  $("#filter-preview").textContent = filter?.applicable ? filter.preview : (filter?.reason || "Фильтр недоступен.");
  $("#run-filter").hidden = graph;
  $("#open-filter-graph").hidden = !graph;
  for (const control of [$("#run-filter"), $("#open-filter-graph"), $("#copy-filter-sql"), $("#open-filter")]) control.disabled = !filter?.applicable;
}

async function withSelectedFilter(handler) {
  const filter = selectedFilter();
  if (!filter?.applicable) throw new Error("Выбранный фильтр неприменим к событию");
  return handler(filter);
}

async function renderInvestigations() {
  if (!globalThis.KumApeInvestigations || !globalThis.indexedDB) { $("#add-investigation").disabled = !state.context?.event; return; }
  const select = $("#investigation-select"); const previous = select.value; select.replaceChildren(new Option("Новое расследование…", ""));
  for (const investigation of await globalThis.KumApeInvestigations.listInvestigations()) if (investigation.status === "open") select.add(new Option(investigation.title, investigation.id));
  if ([...select.options].some((option) => option.value === previous)) select.value = previous;
  $("#add-investigation").disabled = !state.context?.event;
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
  $("#open-ai").disabled = !context?.event;
  await Promise.all([renderRelated(), renderFilters(), renderIocs(), renderInvestigations()]);
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
    else setStatus(`Поля не найдены (проверено DOM-контекстов: ${state.context?.rootsChecked || 0})`, true);
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
  const { mountChat } = await import("../shared/chat-view.js");
  const { relatedAiContext } = await import("../shared/ai-context.js");
  await mountChat($("#popup-chat"), `aiTabHistory:${state.config.uiOrigin}:${state.tab.id}`, () => ({event:state.context.event}), () => relatedAiContext(state.context.event));
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
$("#add-investigation").addEventListener("click", async () => {
  try {
    let id = $("#investigation-select").value;
    if (!id) { const title = prompt("Название нового расследования", globalThis.KumApeInvestigations.describeEvent(state.context.event)); if (title === null) return; id = (await globalThis.KumApeInvestigations.createInvestigation(title)).id; }
    await globalThis.KumApeInvestigations.addEvent(id, state.context.event, { uiOrigin: state.config.uiOrigin, url: state.tab.url });
    await renderInvestigations(); $("#investigation-select").value = id; setStatus("Событие добавлено в расследование");
  } catch (error) { setStatus(error.message, true); }
});
$("#open-workspace").addEventListener("click", () => send({ type: "workspace:open", id: $("#investigation-select").value }).catch((error) => setStatus(error.message, true)));
$("#open-ai").addEventListener("click", () => send({ type: "ai:open", event: state.context?.event, sourceTabId: state.tab?.id }).catch((error) => setStatus(error.message, true)));
$("#load-rule").addEventListener("click", async () => {
  try {
    setStatus("Загружаю правило…");
    const response = await send({ type: "rule:get", event: state.context.event });
    $("#rule-result").textContent = JSON.stringify(response.rule, null, 2);
    setStatus("Правило загружено");
  } catch (error) { setStatus(error.message, true); }
});
$("#useful-filter").addEventListener("change", previewFilter);
$("#run-filter").addEventListener("click", () => withSelectedFilter(async (filter) => {
  setStatus(`Применяю фильтр «${filter.title}»…`);
  const response = await send({ type: "filters:search", filterId: filter.id, event: state.context.event, limit: 250 });
  activatePanel("related"); renderResults(response.result); setStatus(`Найдено событий: ${response.result.events.length}`);
}).catch((error) => setStatus(error.message, true)));
$("#open-filter-graph").addEventListener("click", () => withSelectedFilter(async (filter) => {
  await send({ type: "process:open-graph", event: state.context.event, rangeSeconds: filter.rangeSeconds, limit: 1000 });
  setStatus("Граф процессов открыт");
}).catch((error) => setStatus(error.message, true)));
$("#copy-filter-sql").addEventListener("click", () => withSelectedFilter(async (filter) => {
  const response = await send({ type: "filters:query", filterId: filter.id, event: state.context.event, limit: filter.type === "processGraph" ? 1000 : 250 });
  await navigator.clipboard.writeText(response.query); setStatus("SQL скопирован");
}).catch((error) => setStatus(error.message, true)));
$("#open-filter").addEventListener("click", () => withSelectedFilter(async (filter) => {
  await send({ type: "filters:open-tab", filterId: filter.id, event: state.context.event, limit: filter.type === "processGraph" ? 1000 : 250 });
  setStatus("Фильтр передан в новую вкладку KUMA");
}).catch((error) => setStatus(error.message, true)));

initialize().catch((error) => setStatus(error.message, true));

$("#process").addEventListener("click", event => {
  const layout=event.target.closest("[data-graph]")?.dataset.graph;
  if (layout) send({type:"process:open-graph",event:state.context?.event,rangeSeconds:layout === "step" ? 3600 : Number($("#range").value),layout}).catch(error => setStatus(error.message,true));
});
$("#download-json").addEventListener("click", () => {
  if (!state.context?.event) return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(state.context.event,null,2)],{type:"application/json"}));
  const link=document.createElement("a");link.href=url;link.download="kuma-event.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});

function renderResults(result) {
  const root=$("#related-result"); root.hidden=false; root.replaceChildren();
  for(const event of [...result.events].sort((a,b)=>globalThis.KumApeAdapter.eventTimestamp(a)-globalThis.KumApeAdapter.eventTimestamp(b))) {
    const actions=addCard(root,globalThis.KumApeInvestigations.describeEvent(event),new Date(globalThis.KumApeAdapter.eventTimestamp(event)).toLocaleString("ru-RU"));
    actions.append(button("JSON",()=>navigator.clipboard.writeText(JSON.stringify(event,null,2))),button("В расследование",async()=>{
      let id=$("#investigation-select").value;
      if(!id){const title=prompt("Название расследования","Новое расследование");if(title===null)return;id=(await globalThis.KumApeInvestigations.createInvestigation(title)).id;}
      await globalThis.KumApeInvestigations.addEvent(id,event);await renderInvestigations();$("#investigation-select").value=id;setStatus("Событие добавлено");
    }));
  }
  if(!result.events.length) root.textContent="События не найдены";
}
