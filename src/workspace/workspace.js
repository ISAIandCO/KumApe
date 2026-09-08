import { mountChat } from "../shared/chat-view.js";
import { compareEvents, eventDiffToMarkdown } from "../shared/event-compare.js";
import { InvestigationCanvas } from "./investigation-canvas.js";
import { createEntityGraph } from "./entity-model.js";
"use strict";

const db = globalThis.KumApeInvestigations;
const $ = (selector) => document.querySelector(selector);
let graphView = null;
let currentId = new URL(location.href).searchParams.get("id");

function status(text) { $("#status").textContent = text; }
function download(name, type, content) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function renderList() {
  const investigations = await db.listInvestigations(); const list = $("#list"); list.replaceChildren();
  const needle = $("#workspace-search").value.trim().toLowerCase();
  const ordering = $("#workspace-sort").value;
  investigations.sort((a,b) => ordering === "title" ? a.title.localeCompare(b.title, "ru") : ordering === "created" ? b.createdAt.localeCompare(a.createdAt) : b.updatedAt.localeCompare(a.updatedAt));
  if (!investigations.length) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "Расследований пока нет."; list.append(p); return investigations; }
  for (const investigation of investigations) {
    if (needle && !`${investigation.title} ${investigation.tags.join(" ")} ${investigation.notes}`.toLowerCase().includes(needle)) continue;
    const button = document.createElement("button"); button.className = `investigation${investigation.id === currentId ? " active" : ""}`;
    button.textContent = `${investigation.status === "closed" ? "✓" : "●"} ${investigation.title}`;
    button.addEventListener("click", () => { currentId = investigation.id; history.replaceState(null, "", `?id=${encodeURIComponent(currentId)}`); render().catch((error) => status(error.message)); });
    list.append(button);
  }
  return investigations;
}

async function renderDetail() {
  if (graphView) { graphView.resizeObserver.disconnect(); graphView.alpha = 0; graphView = null; }
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
  const aiSelected = new Set();
  const ai = document.createElement("button"); ai.textContent = "Обсудить с локальным AI"; ai.disabled = !items.length;
  ai.addEventListener("click", () => aiPanel.scrollIntoView({behavior:"smooth"}));
  tools.append(json, markdown, ai); root.append(tools);
  const graphTitle = document.createElement("h2"); graphTitle.textContent = "Граф связей";
  const graphTools = document.createElement("div"); graphTools.className = "toolbar";
  const fit = document.createElement("button"); fit.textContent = "Вписать";
  let selectedEntities = [];
  const mode = document.createElement("select"); mode.add(new Option("Совпадают все (AND)","all")); mode.add(new Option("Совпадает любое (OR)","any"));
  const range = document.createElement("select"); for (const [seconds,label] of [[900,"±15 минут"],[3600,"±1 час"],[86400,"±24 часа"],[604800,"±7 дней"]]) range.add(new Option(label,seconds)); range.value="3600";
  const selectedLabels = document.createElement("p"); const searchResults = document.createElement("div");

  const searchKuma = document.createElement("button"); searchKuma.textContent = "Найти связанные события в KUMA"; searchKuma.disabled = true;
  searchKuma.addEventListener("click", async () => {
    try {
      if (!selectedEntities.length) return;
      const targetId = currentId;
      const result = await browser.runtime.sendMessage({type:"workspace:search",investigationId:targetId,entities:selectedEntities,mode:mode.value,rangeSeconds:Number(range.value)});
      if (!result?.ok) throw new Error(result?.error || "Не удалось найти события");
      searchResults.replaceChildren();
      for (const event of result.result.events) {
        const row = document.createElement("article"); const label=document.createElement("span"); label.textContent=db.describeEvent(event);
        const add=document.createElement("button"); add.textContent="Добавить в расследование";
        add.addEventListener("click",async()=>{await db.addEvent(targetId,event);add.disabled=true;add.textContent="Добавлено";}); row.append(label,add); searchResults.append(row);
      }
      const refresh=document.createElement("button");refresh.textContent="Обновить граф и список";refresh.addEventListener("click",()=>render().catch(error=>status(error.message)));searchResults.append(refresh);
      status(`Найдено: ${result.result.events.length}. Выберите события для добавления`);
    } catch(error) {status(error.message);}
  });
  const search = document.createElement("input"); search.placeholder = "Фильтр событий: текст"; search.type = "search";
  const force = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "Силы графа"; force.append(summary);
  const wrapper = document.createElement("div"); wrapper.className = "entity-graph";
  const canvas = document.createElement("canvas"); canvas.setAttribute("aria-label", "Граф событий и сущностей");
  const tooltip = document.createElement("div"); tooltip.className = "entity-tooltip"; tooltip.hidden = true;
  wrapper.append(canvas, tooltip); graphTools.append(fit, search, searchKuma, force); root.append(graphTitle, graphTools, wrapper, selectedLabels, searchResults); graphTools.append(mode,range);
  graphView = new InvestigationCanvas(canvas, tooltip, {
    onEventOpen: node => document.getElementById(`item-${node.itemId}`)?.scrollIntoView({block:"center",behavior:"smooth"}),
    onSelectionChange: nodes => { selectedEntities = nodes; searchKuma.disabled = !nodes.length; selectedLabels.textContent = nodes.map(node=>`${node.entityType}: ${node.label}`).join(" · "); },
  });
  function renderGraph() { const words = search.value.toLowerCase().split(/\s+/).filter(Boolean); graphView.setGraph(createEntityGraph(items.filter(item => words.every(word => JSON.stringify(item.payload).toLowerCase().includes(word))))); }
  for (const [key,label,min,max,step] of [["attraction","Притяжение",0,1,.05],["repulsion","Отталкивание",0,30,.25],["linkStrength","Сила связи",0,2,.05],["linkDistance","Расстояние",40,500,1]]) {
    const row=document.createElement("label");row.textContent=label;
    const slider=document.createElement("input");slider.type="range";slider.min=min;slider.max=max;slider.step=step;slider.value=graphView.forceSettings[key];
    slider.addEventListener("input",()=>{graphView.updateForceSetting(key, Number(slider.value));graphView.persistForceSettings();});row.append(slider);force.append(row);
  }
  fit.addEventListener("click",()=>graphView.fit()); search.addEventListener("input",renderGraph); renderGraph();
  const comparePanel = document.createElement("details"); const compareTitle = document.createElement("summary"); compareTitle.textContent = "Сравнить события";
  const first = document.createElement("select"), second = document.createElement("select"), third = document.createElement("select"), compareButton = document.createElement("button"), compareResult = document.createElement("div");
  third.add(new Option("Без третьего события","")); third.setAttribute("aria-label","Третье событие");
  first.setAttribute("aria-label","Первое событие"); second.setAttribute("aria-label","Второе событие");
  for(const item of items) {third.add(new Option(`${item.timestamp} — ${item.label}`,item.id));first.add(new Option(`${item.timestamp} — ${item.label}`,item.id));second.add(new Option(`${item.timestamp} — ${item.label}`,item.id));}
  if(items.length>1) second.selectedIndex=1; compareButton.textContent="Показать различия";compareButton.disabled=items.length<2;
  compareButton.addEventListener("click",()=>{
    compareResult.replaceChildren(); const diff=compareEvents([first.value,second.value,...(third.value?[third.value]:[])].map(id=>items.find(item=>item.id===id).payload));
    const table=document.createElement("table"); const head=document.createElement("tr");for(const value of ["Поле","Первое событие","Второе событие",...(third.value?["Третье событие"]:[])]){const th=document.createElement("th");th.textContent=value;head.append(th);}table.append(head);
    for(const row of diff.rows.filter(r=>r.status!=="same")){const tr=document.createElement("tr");for(const value of [row.field,...row.values]){const td=document.createElement("td");td.textContent=value===undefined?"—":typeof value==="object"?JSON.stringify(value):String(value);tr.append(td);}table.append(tr);}
    const exportJson=document.createElement("button");exportJson.textContent="Экспорт diff JSON";exportJson.addEventListener("click",()=>download("event-diff.json","application/json",JSON.stringify(diff,null,2)));
    const exportMd=document.createElement("button");exportMd.textContent="Экспорт diff Markdown";exportMd.addEventListener("click",()=>download("event-diff.md","text/markdown",eventDiffToMarkdown(diff)));
    compareResult.append(exportJson,exportMd,table);
  });
  comparePanel.append(compareTitle,first,second,third,compareButton,compareResult);root.append(comparePanel);
  const h2 = document.createElement("h2"); h2.textContent = `События (${items.length})`; root.append(h2);
  const timeline = document.createElement("div"); timeline.className = "timeline";
  for (const item of items) { const card = document.createElement("article"); card.id = `item-${item.id}`; const h3 = document.createElement("h3"); h3.textContent = item.label; const time = document.createElement("time"); time.textContent = item.timestamp; const entities = document.createElement("p"); entities.className = "entities"; entities.textContent = item.entityKeys.join(" · "); const details = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "JSON события"; const pre = document.createElement("pre"); pre.textContent = JSON.stringify(item.payload, null, 2); details.append(summary, pre); const selectAi = document.createElement("label"); const checkbox = document.createElement("input"); checkbox.type = "checkbox";
    checkbox.addEventListener("change", () => checkbox.checked ? aiSelected.add(item.id) : aiSelected.delete(item.id)); selectAi.append(checkbox, document.createTextNode(" В AI"));
    card.append(h3, time, entities, selectAi, details); timeline.append(card); }
  if (!items.length) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "Добавьте событие из popup KumApe."; timeline.append(p); }
  root.append(timeline);
  const ordering = document.createElement("select"); ordering.setAttribute("aria-label", "Порядок событий");
  for (const [value,label] of [["asc","Сначала ранние"],["desc","Сначала поздние"]]) ordering.add(new Option(label,value));
  root.insertBefore(ordering,timeline);
  ordering.addEventListener("change", () => { for (const item of [...items].sort((a,b) => ordering.value === "asc" ? a.timestamp.localeCompare(b.timestamp) : b.timestamp.localeCompare(a.timestamp))) timeline.append(document.getElementById(`item-${item.id}`)); });
  for (const item of items) {
    const card = document.getElementById(`item-${item.id}`);
    const remove = document.createElement("button"); remove.textContent = "Удалить объект";
    remove.addEventListener("click", async () => { await db.removeItem(currentId,item.id); await render(); });
    const open = document.createElement("button"); open.textContent = "Открыть в KUMA"; open.disabled = !item.source?.eventId;
    open.addEventListener("click", async () => {
      const result = await browser.runtime.sendMessage({type:"event:open",event:item.payload});
      if (!result?.ok) status(result?.error || "Не удалось открыть событие");
    });
    card.append(open,remove);
  }
  const aiNotes = document.createElement("label"); const notesCheck = document.createElement("input"); notesCheck.type="checkbox"; aiNotes.append(notesCheck,document.createTextNode(" Добавить заметки аналитика в AI")); root.append(aiNotes);
  const aiPanel = document.createElement("section"); root.append(aiPanel);
  const investigationId = currentId;
  await mountChat(aiPanel, `investigationAi:${investigationId}`, () => ({ event: { Events: [...items.filter(item => !aiSelected.size || aiSelected.has(item.id)).map(item => item.payload), ...(notesCheck.checked ? [{Message:notes.value}] : [])] } }), async () => ({event:{Events:(await db.listItems(investigationId)).map(item=>item.payload)}}));
}

async function render() { await renderList(); await renderDetail(); }
$("#create").addEventListener("click", async () => { const title = prompt("Название расследования", "Новое расследование"); if (title === null) return; const investigation = await db.createInvestigation(title); currentId = investigation.id; history.replaceState(null, "", `?id=${encodeURIComponent(currentId)}`); await render(); });
render().catch((error) => status(error.message));
$("#workspace-search").addEventListener("input", () => renderList().catch(error => status(error.message)));
$("#workspace-sort").addEventListener("change", () => renderList().catch(error => status(error.message)));
