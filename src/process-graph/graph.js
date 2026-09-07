"use strict";

const $ = (selector) => document.querySelector(selector);
const requestId = new URL(location.href).searchParams.get("id");
const canvas = $("#graph"); const context = canvas.getContext("2d");
const state = { graph: { nodes: [], edges: [], sourceNodeId: null }, scale: 1, x: 0, y: 0, hovered: null, selected: null, pinned: null, dragging: null, panning: null, visible: new Set(), query: "", layout: "force", running: 0 };

async function send(message) { const response = await browser.runtime.sendMessage(message); if (!response?.ok) throw new Error(response?.error || "Операция не выполнена"); return response; }
const label = (node) => node.image?.split(/[\\/]/).pop() || `PID ${node.pid}`;
const searchable = (node) => `${node.image} ${node.commandLine} ${node.user} ${node.pid} ${node.parentPid} ${node.host}`.toLowerCase();

function resize() { const rect = canvas.getBoundingClientRect(); const ratio = devicePixelRatio || 1; canvas.width = Math.max(1, Math.round(rect.width * ratio)); canvas.height = Math.max(1, Math.round(rect.height * ratio)); draw(); }
function world(clientX, clientY) { const rect = canvas.getBoundingClientRect(); return { x: (clientX - rect.left - state.x) / state.scale, y: (clientY - rect.top - state.y) / state.scale }; }
function screen(node) { return { x: node.x * state.scale + state.x, y: node.y * state.scale + state.y }; }

function adjacency(direction) {
  const map = new Map(state.graph.nodes.map((node) => [node.id, []]));
  for (const edge of state.graph.edges) {
    if (direction !== "ancestors") map.get(edge.source)?.push(edge.target);
    if (direction !== "descendants") map.get(edge.target)?.push(edge.source);
  }
  return map;
}

function refreshVisible() {
  if ($("#scope").value === "all") state.visible = new Set(state.graph.nodes.map((node) => node.id));
  else {
    const map = adjacency($("#scope").value); const seen = new Set(); const queue = [state.graph.sourceNodeId];
    while (queue.length) { const id = queue.shift(); if (!id || seen.has(id)) continue; seen.add(id); queue.push(...(map.get(id) || [])); }
    state.visible = seen;
  }
  draw();
}

function seedLayout() {
  const nodes = state.graph.nodes; const byId = new Map(nodes.map((node) => [node.id, node]));
  const depth = new Map(); const children = new Map(nodes.map((node) => [node.id, []])); const parents = new Map(nodes.map((node) => [node.id, []]));
  for (const edge of state.graph.edges) { children.get(edge.source)?.push(edge.target); parents.get(edge.target)?.push(edge.source); }
  const queue = [[state.graph.sourceNodeId, 0]];
  while (queue.length) { const [id, value] = queue.shift(); if (!id || depth.has(id)) continue; depth.set(id, value); for (const next of children.get(id) || []) queue.push([next, value + 1]); for (const next of parents.get(id) || []) queue.push([next, value - 1]); }
  let orphan = 0; for (const node of nodes) if (!depth.has(node.id)) depth.set(node.id, 3 + orphan++ % 4);
  const lanes = new Map();
  for (const node of nodes) { const d = depth.get(node.id); const lane = lanes.get(d) || 0; lanes.set(d, lane + 1); node.x = d * 190; node.y = (lane - 2) * 90; node.vx = 0; node.vy = 0; node.r = Math.min(18, 7 + Math.sqrt((children.get(node.id)?.length || 0) + (parents.get(node.id)?.length || 0)) * 2); }
  fit(); startSimulation();
}

function forceStep() {
  const nodes = state.graph.nodes.filter((node) => state.visible.has(node.id)); const byId = new Map(nodes.map((node) => [node.id, node]));
  for (const node of nodes) { node.vx *= .86; node.vy *= .86; node.vx += -node.x * .0004; node.vy += -node.y * .0004; }
  for (const edge of state.graph.edges) {
    const a = byId.get(edge.source); const b = byId.get(edge.target); if (!a || !b) continue;
    const dx = b.x - a.x; const dy = b.y - a.y; const distance = Math.max(1, Math.hypot(dx, dy)); const force = (distance - 150) * .0018;
    a.vx += dx / distance * force; a.vy += dy / distance * force; b.vx -= dx / distance * force; b.vy -= dy / distance * force;
  }
  const cellSize = 120; const grid = new Map();
  for (const node of nodes) { const key = `${Math.floor(node.x / cellSize)},${Math.floor(node.y / cellSize)}`; if (!grid.has(key)) grid.set(key, []); grid.get(key).push(node); }
  for (const node of nodes) {
    const cx = Math.floor(node.x / cellSize); const cy = Math.floor(node.y / cellSize);
    for (let gx = cx - 1; gx <= cx + 1; gx++) for (let gy = cy - 1; gy <= cy + 1; gy++) for (const other of grid.get(`${gx},${gy}`) || []) {
      if (other.id <= node.id) continue; let dx = other.x - node.x; let dy = other.y - node.y; const d2 = Math.max(25, dx * dx + dy * dy); const force = 420 / d2;
      if (!dx && !dy) dx = 1; const distance = Math.sqrt(d2); node.vx -= dx / distance * force; node.vy -= dy / distance * force; other.vx += dx / distance * force; other.vy += dy / distance * force;
    }
  }
  for (const node of nodes) if (state.dragging?.id !== node.id) { node.x += node.vx; node.y += node.vy; }
}

function timelineLayout() {
  const nodes = state.graph.nodes.filter((node) => state.visible.has(node.id)); if (!nodes.length) return;
  const min = Math.min(...nodes.map((node) => node.timestamp)); const max = Math.max(...nodes.map((node) => node.timestamp));
  const rows = new Map(); for (const node of nodes.sort((a,b) => a.timestamp-b.timestamp)) { const row = rows.get(node.pid) ?? rows.size; rows.set(node.pid, row); node.x = ((node.timestamp - min) / Math.max(1, max - min)) * 1000; node.y = row * 55; }
}

function startSimulation() { state.running = 180; requestAnimationFrame(tick); }
function tick() { if (state.layout === "force" && state.running-- > 0) { forceStep(); draw(); requestAnimationFrame(tick); } }

function arrow(a, b) {
  const dx = b.x - a.x; const dy = b.y - a.y; const distance = Math.max(1, Math.hypot(dx,dy)); const ux = dx / distance; const uy = dy / distance; const endX = b.x - ux * (b.r + 3); const endY = b.y - uy * (b.r + 3);
  context.beginPath(); context.moveTo(a.x + ux * a.r, a.y + uy * a.r); context.lineTo(endX,endY); context.stroke();
  context.beginPath(); context.moveTo(endX,endY); context.lineTo(endX-ux*9-uy*4,endY-uy*9+ux*4); context.lineTo(endX-ux*9+uy*4,endY-uy*9-ux*4); context.closePath(); context.fill();
}

function draw() {
  const ratio = devicePixelRatio || 1; context.setTransform(ratio,0,0,ratio,0,0); context.clearRect(0,0,canvas.width/ratio,canvas.height/ratio); context.save(); context.translate(state.x,state.y); context.scale(state.scale,state.scale);
  const byId = new Map(state.graph.nodes.map((node) => [node.id,node])); context.strokeStyle = "#587080"; context.fillStyle = "#587080"; context.lineWidth = 1.2 / state.scale;
  for (const edge of state.graph.edges) { if (!state.visible.has(edge.source) || !state.visible.has(edge.target)) continue; arrow(byId.get(edge.source),byId.get(edge.target)); }
  for (const node of state.graph.nodes) {
    if (!state.visible.has(node.id)) continue; const match = state.query && searchable(node).includes(state.query); const selected = state.selected?.id === node.id;
    context.beginPath(); context.arc(node.x,node.y,node.r,0,Math.PI*2); context.fillStyle = node.source ? "#ffb74d" : match ? "#ed6fc4" : "#38b8d3"; context.fill();
    if (selected || state.hovered?.id === node.id) { context.strokeStyle = "#fff"; context.lineWidth = 2 / state.scale; context.stroke(); }
    if (state.scale > .45) { context.fillStyle = "#dce8ef"; context.font = `${Math.max(9,11/state.scale)}px system-ui`; context.textAlign = "center"; context.fillText(label(node).slice(0,30),node.x,node.y+node.r+14/state.scale); }
  }
  context.restore();
}

function hit(clientX,clientY) { const point = world(clientX,clientY); let best = null; let distance = Infinity; for (const node of state.graph.nodes) { if (!state.visible.has(node.id)) continue; const current = Math.hypot(node.x-point.x,node.y-point.y); if (current <= node.r+6/state.scale && current < distance) { best=node; distance=current; } } return best; }
function tooltip(node, clientX, clientY) { const root=$("#tooltip"); if (!node) { root.hidden=true; return; } root.textContent=`${label(node)}\nPID ${node.pid}${node.parentPid ? ` ← ${node.parentPid}` : ""}\n${node.user || ""}\n${node.commandLine || ""}`; root.hidden=false; const rect=canvas.getBoundingClientRect(); root.style.left=`${Math.min(rect.width-root.offsetWidth-8,clientX-rect.left+12)}px`; root.style.top=`${Math.min(rect.height-root.offsetHeight-8,clientY-rect.top+12)}px`; }
function details(node) { state.selected=node; const root=$("#details"); root.replaceChildren(); if (!node) return; const title=document.createElement("strong"); title.textContent=label(node); const dl=document.createElement("dl"); for (const [key,value] of [["Время",new Date(node.timestamp).toLocaleString()],["Узел",node.host],["PID",node.pid],["Parent PID",node.parentPid],["Пользователь",node.user],["Команда",node.commandLine],["Источник",node.mappingName]]) { const dt=document.createElement("dt");dt.textContent=key;const dd=document.createElement("dd");dd.textContent=value||"—";dl.append(dt,dd); } const open=document.createElement("button");open.textContent="Открыть событие в KUMA";open.disabled=!node.eventRecordId;open.addEventListener("click",()=>openEvent(node));root.append(title,dl,open);draw(); }
async function openEvent(node) { try { await send({type:"process:event:open",event:node.event,rangeSeconds:300}); } catch(error) { $("#status").textContent=error.message; } }

function fit() { const nodes=state.graph.nodes.filter((node)=>state.visible.has(node.id)); if(!nodes.length)return; const rect=canvas.getBoundingClientRect(); const minX=Math.min(...nodes.map(n=>n.x-30)),maxX=Math.max(...nodes.map(n=>n.x+30)),minY=Math.min(...nodes.map(n=>n.y-30)),maxY=Math.max(...nodes.map(n=>n.y+30)); state.scale=Math.max(.08,Math.min(2,Math.min((rect.width-80)/Math.max(1,maxX-minX),(rect.height-80)/Math.max(1,maxY-minY)))); state.x=rect.width/2-(minX+maxX)/2*state.scale; state.y=rect.height/2-(minY+maxY)/2*state.scale;draw(); }
function zoom(factor, clientX=canvas.getBoundingClientRect().width/2, clientY=canvas.getBoundingClientRect().height/2) { const before={x:(clientX-state.x)/state.scale,y:(clientY-state.y)/state.scale};state.scale=Math.max(.08,Math.min(5,state.scale*factor));state.x=clientX-before.x*state.scale;state.y=clientY-before.y*state.scale;draw(); }

canvas.addEventListener("wheel",(event)=>{event.preventDefault();const rect=canvas.getBoundingClientRect();zoom(event.deltaY<0?1.12:.89,event.clientX-rect.left,event.clientY-rect.top);},{passive:false});
canvas.addEventListener("pointerdown",(event)=>{const node=hit(event.clientX,event.clientY);canvas.setPointerCapture(event.pointerId);if(node){state.dragging=node;node.vx=0;node.vy=0;details(node);}else state.panning={clientX:event.clientX,clientY:event.clientY,x:state.x,y:state.y};canvas.classList.add("dragging");});
canvas.addEventListener("pointermove",(event)=>{if(state.dragging){const point=world(event.clientX,event.clientY);state.dragging.x=point.x;state.dragging.y=point.y;draw();return;}if(state.panning){state.x=state.panning.x+event.clientX-state.panning.clientX;state.y=state.panning.y+event.clientY-state.panning.clientY;draw();return;}state.hovered=hit(event.clientX,event.clientY);if(!state.pinned)tooltip(state.hovered,event.clientX,event.clientY);draw();});
canvas.addEventListener("pointerup",()=>{state.dragging=null;state.panning=null;canvas.classList.remove("dragging");startSimulation();});
canvas.addEventListener("dblclick",(event)=>{const node=hit(event.clientX,event.clientY);if(node)openEvent(node);});
canvas.addEventListener("contextmenu",(event)=>{event.preventDefault();state.pinned=hit(event.clientX,event.clientY);tooltip(state.pinned,event.clientX,event.clientY);});
window.addEventListener("keydown",(event)=>{if(event.key==="Escape"){state.pinned=null;tooltip(null);}});window.addEventListener("resize",resize);
$("#fit").addEventListener("click",fit);$("#zoom-in").addEventListener("click",()=>zoom(1.2));$("#zoom-out").addEventListener("click",()=>zoom(.8));
$("#scope").addEventListener("change",()=>{refreshVisible();fit();});$("#search").addEventListener("input",(event)=>{state.query=event.target.value.trim().toLowerCase();draw();});
$("#layout").addEventListener("change",(event)=>{state.layout=event.target.value;if(state.layout==="timeline")timelineLayout();else startSimulation();fit();});

async function run(){if(!requestId)throw new Error("Идентификатор графа отсутствует");const {result}=await send({type:"process:request:run",id:requestId});state.graph=result.graph;state.visible=new Set(result.graph.nodes.map(node=>node.id));$("#sql").textContent=result.query;$("#status").textContent=`${result.graph.nodes.length} процессов · ${result.graph.edges.length} связей · ${result.period.from} — ${result.period.to}`;seedLayout();details(state.graph.nodes.find(node=>node.id===state.graph.sourceNodeId)||null);resize();}
run().catch((error)=>{$("#status").textContent=error.message;});
