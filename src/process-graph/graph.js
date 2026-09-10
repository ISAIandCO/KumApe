import { mountProcessGraph } from "@isaiandco/ape-share-core/ui/process-graph";
import { buildProcessGraphView } from "./view-model.js";

const id = new URLSearchParams(location.search).get("id");
const key = "kumape.processGraph.forceSettings.v1";
async function request(message) {
  const result = await browser.runtime.sendMessage(message);
  if (!result?.ok) throw new Error(result?.error ?? "KUMA не вернула данные");
  return result;
}
const expand = async (input, scope = "range") => (await request({ type: "process:expand", id,
  nodeId: input.node?.id ?? input.response.sourceNodeId, direction: input.direction,
  rangeSeconds: input.stepSeconds, nodeLimit: input.nodeLimit, scope, resumeLimit: input.resumeLimit })).result;
const view = mountProcessGraph(document, {
  search: location.search,
  buildView: buildProcessGraphView,
  isAvailable: () => Boolean(id),
  loadForceSettings: () => JSON.parse(localStorage.getItem(key) ?? "{}"),
  saveForceSettings: value => localStorage.setItem(key, JSON.stringify(value)),
  load: async ({ mode, nodeLimit }) => (await request({ type: "process:request:run", id, mode, nodeLimit })).result,
  expand,
  expandNode: input => expand(input, "node"),
  loadSnapshot: async () => (await request({ type: "process:snapshot:get", id })).snapshot,
  cancel: () => request({ type: "process:cancel", id }),
  reconnect: async state => { const { config } = await request({ type: "config:get" }); if (config.uiOrigin !== state.origin) throw new Error("Адрес KUMA изменён. Откройте новый граф из события."); },
  async pin(node) {
    const db = globalThis.KumApeInvestigations;
    const choices = await db.listInvestigations();
    const title = prompt("Название расследования (существующее или новое)", choices[0]?.title || "Расследование процессов");
    if (title === null) return null;
    const investigation = choices.find(item => item.title === title) || await db.createInvestigation(title);
    await db.addEvent(investigation.id, node.event);
    return investigation.title;
  },
  open: node => request({ type: "process:event:open", event: node.event, rangeSeconds: 900 }),
  openWorkspace: () => request({ type: "workspace:open" }),
});
window.addEventListener("pagehide", () => view.destroy(), { once: true });
