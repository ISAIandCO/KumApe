"use strict";

const $ = (selector) => document.querySelector(selector);
const api = globalThis.KumApeAdapter;
const processApi = globalThis.KumApeProcess;
const PROCESS_FIELDS = [
  ["eventIdField", "Поле Event ID", true], ["eventIdValue", "Значение Event ID", true],
  ["eventCategories", "DeviceEventCategory (через запятую)", false],
  ["host", "Узел / host", true], ["pid", "PID процесса", true], ["parentPid", "PID родителя", true],
  ["fallbackPid", "Резервное поле PID", false], ["fallbackParentPid", "Резервное поле PID родителя", false],
  ["processGuid", "GUID процесса", false], ["parentGuid", "GUID родителя", false],
  ["image", "Образ / путь", false], ["commandLine", "Командная строка", false],
  ["user", "Пользователь", false], ["eventRecordId", "ID события KUMA", false],
];

function mappingCard(mapping = {}) {
  const card = document.createElement("article"); card.className = "mapping-card";
  const head = document.createElement("div"); head.className = "mapping-head";
  const nameLabel = document.createElement("label"); nameLabel.textContent = "Название";
  const name = document.createElement("input"); name.dataset.key = "name"; name.value = mapping.name || ""; name.placeholder = "Например, Windows Security 4688"; nameLabel.append(name);
  const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Удалить"; remove.addEventListener("click", () => card.remove());
  head.append(nameLabel, remove);
  const grid = document.createElement("div"); grid.className = "mapping-grid";
  for (const [key, title, required] of PROCESS_FIELDS) {
    const label = document.createElement("label"); label.textContent = title;
    const input = document.createElement("input"); input.dataset.key = key; input.value = Array.isArray(mapping[key]) ? mapping[key].join(", ") : mapping[key] || ""; input.required = required;
    input.placeholder = key === "eventIdValue" ? "4688" : ({ eventIdField: "DeviceEventClassID", eventCategories: "Microsoft-Windows-Security-Auditing", pid: "DeviceCustomString5", parentPid: "DeviceCustomString3" }[key] || "Необязательно");
    label.append(input); grid.append(label);
  }
  card.append(head, grid); return card;
}

function renderProcessMappings(mappings) {
  const root = $("#process-mappings"); root.replaceChildren();
  for (const mapping of mappings) root.append(mappingCard(mapping));
}

function collectProcessMappings() {
  return [...document.querySelectorAll(".mapping-card")].map((card) => Object.fromEntries([...card.querySelectorAll("[data-key]")].map((input) => [input.dataset.key, input.value.trim()])));
}

function show(value, error = false) {
  $("#result").textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  $("#result").style.color = error ? "#d34b4b" : "";
}

async function send(message) {
  const response = await browser.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Операция не выполнена");
  return response;
}

function renderClusters(clusters, selected = "") {
  const select = $("#cluster-id");
  select.replaceChildren(new Option("Определять автоматически, если он один", ""));
  for (const cluster of clusters) select.add(new Option(cluster.name || cluster.id, cluster.id));
  select.value = selected;
}

async function load() {
  const { config } = await send({ type: "config:get" });
  $("#ui-origin").value = config.uiOrigin || "";
  $("#api-origin").value = config.apiOrigin || "";
  $("#field-profiles").value = JSON.stringify(config.fieldProfiles || api.BUILTIN_FIELD_PROFILES, null, 2);
  renderProcessMappings(config.processMappings || processApi.BUILTIN_PROCESS_MAPPINGS);
  $("#useful-filters").value = JSON.stringify(config.usefulFilters || globalThis.KumApeFilters.BUILTIN_FILTERS, null, 2);
  $("#ai-enabled").checked = Boolean(config.ai?.enabled);
  $("#ai-endpoint").value = config.ai?.endpoint || "http://127.0.0.1:8080/v1";
  $("#ai-model").value = config.ai?.model || "local-model";
  $("#ai-privacy").value = config.ai?.privacyMode || "strict";
  renderClusters([], config.clusterId || "");
  if (config.clusterId) {
    $("#cluster-id").add(new Option(config.clusterId, config.clusterId));
    $("#cluster-id").value = config.clusterId;
  }
  await renderIocSettings();
  $("#api-token").placeholder = config.tokenPresent ? "Токен сохранён" : "Не сохранён";
}

async function save() {
  const uiOrigin = api.normalizeOrigin($("#ui-origin").value);
  const apiOrigin = api.normalizeOrigin($("#api-origin").value);
  let parsedProfiles;
  try {
    parsedProfiles = JSON.parse($("#field-profiles").value);
  } catch (error) {
    throw new Error(`Профили полей: некорректный JSON (${error.message})`);
  }
  const fieldProfiles = api.normalizeFieldProfiles(parsedProfiles);
  const processMappings = processApi.normalizeMappings(collectProcessMappings());
  let parsedFilters;
  try {
    parsedFilters = JSON.parse($("#useful-filters").value);
  } catch (error) {
    throw new Error(`Полезные фильтры: некорректный JSON (${error.message})`);
  }
  const usefulFilters = globalThis.KumApeFilters.normalizeFilterTemplates(parsedFilters);
  const ai = { enabled: $("#ai-enabled").checked, endpoint: $("#ai-endpoint").value.trim(), model: $("#ai-model").value.trim() || "local-model", privacyMode: $("#ai-privacy").value };
  const origins = [uiOrigin, apiOrigin];
  if (ai.enabled) {
    const endpoint = new URL(ai.endpoint);
    if (!/^https?:$/.test(endpoint.protocol) || !api.isLocalNetworkHost(endpoint.hostname)) throw new Error("AI endpoint должен находиться на этом компьютере или в локальной сети");
    origins.push(endpoint.origin);
  }
  const granted = await browser.permissions.request({ origins: [...new Set(origins.map((origin) => { const url = new URL(origin); return `${url.protocol}//${url.hostname}/*`; }))] });
  if (!granted) throw new Error("Firefox не выдал доступ к указанным адресам");
  await browser.storage.local.set({ uiOrigin, apiOrigin, clusterId: $("#cluster-id").value, fieldProfiles, processMappings, usefulFilters, ai });
  $("#field-profiles").value = JSON.stringify(fieldProfiles, null, 2);
  $("#useful-filters").value = JSON.stringify(usefulFilters, null, 2);
  const token = $("#api-token").value.trim();
  if (token) {
    await browser.storage.local.set({ apiToken: token });
    $("#api-token").value = "";
    $("#api-token").placeholder = "Токен сохранён";
  }
  show("Настройки сохранены.");
}

$("#settings").addEventListener("submit", (event) => {
  event.preventDefault();
  save().catch((error) => show(error.message, true));
});
$("#save-ai").addEventListener("click", () => save().catch((error) => show(error.message, true)));
$("#clear-token").addEventListener("click", async () => {
  await browser.storage.session.remove("apiToken");
  await browser.storage.local.remove("apiToken");
  $("#api-token").value = "";
  $("#api-token").placeholder = "Не сохранён";
  show("API-токен удалён.");
});
$("#test-session").addEventListener("click", async () => {
  try { show((await send({ type: "session:test" })).user); } catch (error) { show(error.message, true); }
});
$("#test-api").addEventListener("click", async () => {
  try { show((await send({ type: "api:test" })).user); } catch (error) { show(error.message, true); }
});
$("#open-api").addEventListener("click", async () => {
  try {
    const origin = api.normalizeOrigin($("#api-origin").value);
    await browser.tabs.create({ url: new URL("/api/v3/events/clusters", origin).href });
    show("API-адрес открыт. Подтвердите доверие сертификату, если Firefox покажет предупреждение; HTTP 401 без токена ожидаем.");
  } catch (error) { show(error.message, true); }
});
$("#load-clusters").addEventListener("click", async () => {
  try {
    const selected = $("#cluster-id").value;
    const response = await send({ type: "clusters:list" });
    renderClusters(response.clusters, selected);
    show(response.clusters);
  } catch (error) { show(error.message, true); }
});
$("#load-extended-fields").addEventListener("click", async () => {
  try { show((await send({ type: "extended-fields:list" })).fields); } catch (error) { show(error.message, true); }
});
$("#restore-profiles").addEventListener("click", () => {
  $("#field-profiles").value = JSON.stringify(api.BUILTIN_FIELD_PROFILES, null, 2);
  show(`Подставлено профилей: ${api.BUILTIN_FIELD_PROFILES.length}. Нажмите «Сохранить», чтобы применить.`);
});
$("#clear-profiles").addEventListener("click", () => {
  $("#field-profiles").value = "[]";
  show("Профили очищены. После сохранения останется общий набор нормализованных полей.");
});
$("#add-process-mapping").addEventListener("click", () => $("#process-mappings").append(mappingCard({ eventIdField: "DeviceEventClassID" })));
$("#restore-process-mappings").addEventListener("click", () => {
  renderProcessMappings(processApi.BUILTIN_PROCESS_MAPPINGS);
  show(`Подставлено настроек графа: ${processApi.BUILTIN_PROCESS_MAPPINGS.length}. Нажмите «Сохранить», чтобы применить.`);
});
$("#restore-useful-filters").addEventListener("click", () => {
  $("#useful-filters").value = JSON.stringify(globalThis.KumApeFilters.BUILTIN_FILTERS, null, 2);
  show(`Подставлено фильтров: ${globalThis.KumApeFilters.BUILTIN_FILTERS.length}. Нажмите «Сохранить», чтобы применить.`);
});
$("#ui-origin").addEventListener("change", () => {
  if ($("#api-origin").value) return;
  try {
    const url = new URL(api.normalizeOrigin($("#ui-origin").value));
    url.port = "7223";
    $("#api-origin").value = url.origin;
  } catch { /* Validation is shown on save. */ }
});

load().catch((error) => show(error.message, true));

async function renderIocSettings() {
  const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
  const container = $("#ioc-providers");
  container.replaceChildren();
  for (const [id, provider] of Object.entries(globalThis.KumApeIoc.PROVIDERS)) {
    const label = document.createElement("label");
    label.textContent = `${provider.name}: API-ключ`;
    const input = document.createElement("input");
    input.type = "password";
    input.autocomplete = "off";
    const savedKeyLabel = (key) => key ? `Сохранён ключ …${String(key).trim().slice(-4)}` : "Не сохранён";
    input.placeholder = savedKeyLabel(iocApiKeys[id]);
    label.append(input);
    const actions = document.createElement("div");
    actions.className = "actions";
    for (const [text, action] of [
      ["Сохранить и проверить", async () => {
        if (!await browser.permissions.request({ origins: [`${provider.origin}/*`], data_collection: ["websiteContent", "authenticationInfo"] })) throw new Error("Firefox не выдал доступ");
        const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
        if (input.value.trim()) iocApiKeys[id] = input.value.trim();
        if (!iocApiKeys[id]) throw new Error("Введите API-ключ");
        await browser.storage.local.set({ iocApiKeys });
        input.value = ""; input.placeholder = savedKeyLabel(iocApiKeys[id]);
        try {
          await send({ type: "ioc:lookup", provider: id, ioc: { type: "ip", value: "8.8.8.8" } });
        } catch (error) {
          throw new Error(`Ключ сохранён, но проверка не пройдена: ${error.message}`);
        }
        return `${provider.name}: ключ сохранён и принят API`;
      }],
      ["Удалить ключ", async () => {
        const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
        delete iocApiKeys[id];
        await browser.storage.local.set({ iocApiKeys });
        input.value = ""; input.placeholder = "Не сохранён";
        return `${provider.name}: ключ удалён`;
      }],
    ]) {
      const button = document.createElement("button");
      button.type = "button"; button.textContent = text;
      button.addEventListener("click", async () => {
        button.disabled = true;
        try { $("#ioc-status").textContent = await action(); }
        catch (error) { $("#ioc-status").textContent = error.message; }
        finally { button.disabled = false; }
      });
      actions.append(button);
    }
    container.append(label, actions);
  }
}
