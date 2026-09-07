"use strict";

const $ = (selector) => document.querySelector(selector);
const api = globalThis.KumApeAdapter;

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
  const granted = await browser.permissions.request({ origins: [...new Set([uiOrigin, apiOrigin].map((origin) => { const url = new URL(origin); return `${url.protocol}//${url.hostname}/*`; }))] });
  if (!granted) throw new Error("Firefox не выдал доступ к указанным адресам");
  await browser.storage.local.set({ uiOrigin, apiOrigin, clusterId: $("#cluster-id").value, fieldProfiles });
  $("#field-profiles").value = JSON.stringify(fieldProfiles, null, 2);
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
    input.placeholder = iocApiKeys[id] ? "Ключ сохранён" : "Не сохранён";
    label.append(input);
    const actions = document.createElement("div");
    actions.className = "actions";
    for (const [text, action] of [
      ["Сохранить и выдать доступ", async () => {
        if (!await browser.permissions.request({ origins: [`${provider.origin}/*`], data_collection: ["websiteContent", "authenticationInfo"] })) throw new Error("Firefox не выдал доступ");
        const { iocApiKeys = {} } = await browser.storage.local.get("iocApiKeys");
        if (input.value.trim()) iocApiKeys[id] = input.value.trim();
        if (!iocApiKeys[id]) throw new Error("Введите API-ключ");
        await browser.storage.local.set({ iocApiKeys });
        input.value = ""; input.placeholder = "Ключ сохранён";
        return `${provider.name}: ключ сохранён`;
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
