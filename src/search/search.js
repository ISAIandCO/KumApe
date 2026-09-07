"use strict";

const $ = (selector) => document.querySelector(selector);
const id = new URL(location.href).searchParams.get("id");
let query = "";

async function send(message) {
  const response = await browser.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Операция не выполнена");
  return response;
}

function value(event, names) {
  const entries = new Map(Object.entries(event || {}).map(([key, item]) => [key.toLowerCase(), item]));
  for (const name of names) {
    const item = entries.get(name.toLowerCase());
    if (item !== undefined && item !== null && item !== "") return String(item);
  }
  return "—";
}

function render(events) {
  const root = $("#results"); root.replaceChildren();
  if (!events.length) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = "События не найдены."; root.append(empty); return; }
  const wrap = document.createElement("div"); wrap.className = "table-wrap";
  const table = document.createElement("table");
  const head = document.createElement("thead"); const row = document.createElement("tr");
  for (const title of ["Время", "Узел", "Класс", "Пользователь", "Процесс", "Сообщение", "JSON"]) { const cell = document.createElement("th"); cell.textContent = title; row.append(cell); }
  head.append(row); table.append(head);
  const body = document.createElement("tbody");
  for (const event of events) {
    const tr = document.createElement("tr");
    const columns = [
      value(event, ["Timestamp", "EventTime", "DeviceReceiptTime"]), value(event, ["DeviceHostName", "SourceHostName"]),
      value(event, ["DeviceEventClassID", "Name"]), value(event, ["SourceUserName", "DestinationUserName"]),
      value(event, ["DeviceProcessName", "DestinationProcessName", "SourceProcessName"]), value(event, ["Message"]),
    ];
    for (const text of columns) { const td = document.createElement("td"); td.textContent = text; tr.append(td); }
    const td = document.createElement("td"); const details = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "Показать"; const pre = document.createElement("pre"); pre.textContent = JSON.stringify(event, null, 2); details.append(summary, pre); td.append(details); tr.append(td); body.append(tr);
  }
  table.append(body); wrap.append(table); root.append(wrap);
}

async function run() {
  if (!id) throw new Error("Идентификатор поиска отсутствует");
  $("#status").textContent = "Запрашиваю события через KUMA API…";
  const { result } = await send({ type: "search:request:run", id });
  query = result.query; $("#sql").textContent = query; $("#copy-sql").disabled = false;
  render(result.events || []);
  $("#status").textContent = `Найдено: ${(result.events || []).length} · ${result.period.from} — ${result.period.to}`;
}

$("#copy-sql").addEventListener("click", async () => { await navigator.clipboard.writeText(query); $("#status").textContent = "SQL скопирован"; });
$("#rerun").addEventListener("click", () => run().catch((error) => { $("#status").textContent = error.message; }));
run().catch((error) => { $("#status").textContent = error.message; });
