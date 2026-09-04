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
  $("#api-token").placeholder = config.tokenPresent ? "Токен уже загружен в текущей сессии" : "Не сохранён в этой сессии Firefox";
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
  const granted = await browser.permissions.request({ origins: [...new Set([`${uiOrigin}/*`, `${apiOrigin}/*`])] });
  if (!granted) throw new Error("Firefox не выдал доступ к указанным адресам");
  await browser.storage.local.set({ uiOrigin, apiOrigin, clusterId: $("#cluster-id").value, fieldProfiles });
  $("#field-profiles").value = JSON.stringify(fieldProfiles, null, 2);
  const token = $("#api-token").value.trim();
  if (token) {
    await browser.storage.session.set({ apiToken: token });
    $("#api-token").value = "";
    $("#api-token").placeholder = "Токен уже загружен в текущей сессии";
  }
  show("Настройки сохранены.");
}

$("#settings").addEventListener("submit", (event) => {
  event.preventDefault();
  save().catch((error) => show(error.message, true));
});
$("#clear-token").addEventListener("click", async () => {
  await browser.storage.session.remove("apiToken");
  $("#api-token").value = "";
  $("#api-token").placeholder = "Не сохранён в этой сессии Firefox";
  show("API-токен удалён из сессии Firefox.");
});
$("#test-session").addEventListener("click", async () => {
  try { show((await send({ type: "session:test" })).user); } catch (error) { show(error.message, true); }
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
