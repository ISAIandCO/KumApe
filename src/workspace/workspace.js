"use strict";

const db = globalThis.KumApeInvestigations;
const $ = (selector) => document.querySelector(selector);
let currentId = new URL(location.href).searchParams.get("id");

function status(text) { $("#status").textContent = text; }
function download(name, type, content) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function renderList() {
  const investigations = await db.listInvestigations(); const list = $("#list"); list.replaceChildren();
  if (!investigations.length) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "Расследований пока нет."; list.append(p); return investigations; }
  for (const investigation of investigations) {
    const button = document.createElement("button"); button.className = `investigation${investigation.id === currentId ? " active" : ""}`;
    button.textContent = `${investigation.status === "closed" ? "✓" : "●"} ${investigation.title}`;
    button.addEventListener("click", () => { currentId = investigation.id; history.replaceState(null, "", `?id=${encodeURIComponent(currentId)}`); render().catch((error) => status(error.message)); });
    list.append(button);
  }
  return investigations;
}

async function renderDetail() {
  const root = $("#detail"); root.replaceChildren();
  if (!currentId) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "Выберите или создайте расследование."; root.append(p); return; }
  const [investigation, items] = await Promise.all([db.getInvestigation(currentId), db.listItems(currentId)]);
  if (!investigation) { currentId = null; return renderDetail(); }
  const title = document.createElement("input"); title.type = "text"; title.value = investigation.title; title.setAttribute("aria-label", "Название расследования");
  const state = document.createElement("select"); for (const [value, text] of [["open", "Открыто"], ["closed", "Закрыто"]]) state.add(new Option(text, value)); state.value = investigation.status;
  const tags = document.createElement("input"); tags.type = "text"; tags.value = investigation.tags.join(", "); tags.placeholder = "теги через запятую";
  const save = document.createElement("button"); save.textContent = "Сохранить"; save.addEventListener("click", async () => { await db.updateInvestigation(currentId, { title: title.value, status: state.value, tags: tags.value.split(","), notes: notes.value }); status("Расследование сохранено"); await render(); });
  const remove = document.createElement("button"); remove.className = "danger"; remove.textContent = "Удалить"; remove.addEventListener("click", async () => { if (!confirm(`Удалить «${investigation.title}» вместе с событиями?`)) return; await db.deleteInvestigation(currentId); currentId = null; history.replaceState(null, "", location.pathname); await render(); });
  const heading = document.createElement("div"); heading.className = "form-row"; heading.append(title, state, tags, save, remove); root.append(heading);
  const notesTitle = document.createElement("h2"); notesTitle.textContent = "Заметки"; const notes = document.createElement("textarea"); notes.value = investigation.notes || ""; root.append(notesTitle, notes);
  const tools = document.createElement("div"); tools.className = "toolbar";
  const json = document.createElement("button"); json.textContent = "Экспорт JSON"; json.addEventListener("click", () => download(`${investigation.title}.json`, "application/json", `${JSON.stringify({ investigation, items }, null, 2)}\n`));
  const markdown = document.createElement("button"); markdown.textContent = "Экспорт Markdown"; markdown.addEventListener("click", () => download(`${investigation.title}.md`, "text/markdown", db.toMarkdown(investigation, items)));
  tools.append(json, markdown); root.append(tools);
  const h2 = document.createElement("h2"); h2.textContent = `События (${items.length})`; root.append(h2);
  const timeline = document.createElement("div"); timeline.className = "timeline";
  for (const item of items) { const card = document.createElement("article"); const h3 = document.createElement("h3"); h3.textContent = item.label; const time = document.createElement("time"); time.textContent = item.timestamp; const entities = document.createElement("p"); entities.className = "entities"; entities.textContent = item.entityKeys.join(" · "); const details = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "JSON события"; const pre = document.createElement("pre"); pre.textContent = JSON.stringify(item.payload, null, 2); details.append(summary, pre); card.append(h3, time, entities, details); timeline.append(card); }
  if (!items.length) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "Добавьте событие из popup KumApe."; timeline.append(p); }
  root.append(timeline);
}

async function render() { await renderList(); await renderDetail(); }
$("#create").addEventListener("click", async () => { const title = prompt("Название расследования", "Новое расследование"); if (title === null) return; const investigation = await db.createInvestigation(title); currentId = investigation.id; history.replaceState(null, "", `?id=${encodeURIComponent(currentId)}`); await render(); });
render().catch((error) => status(error.message));
