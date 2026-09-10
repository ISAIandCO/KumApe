import { downloadText as download } from "@isaiandco/ape-share-core/ui/download";
import { mountWorkspace } from "@isaiandco/ape-share-core/ui/workspace";
import { workspaceToJson, workspaceToMarkdown } from "@isaiandco/ape-share-core/investigation/model";
import { previewWorkspaceAi, requestWorkspaceAi } from "../shared/workspace-ai.js";
import { createEntityGraph } from "./entity-model.js";

const db = globalThis.KumApeInvestigations;
const api = globalThis.KumApeAdapter;
const FORCE_KEY = "kumape.processGraph.forceSettings.v1";
let config;
let workspaces = [];
async function request(message) {
  const result = await browser.runtime.sendMessage(message);
  if (!result?.ok) throw new Error(result?.error || "Операция не выполнена");
  return result;
}
const downloadText = (text, options) => download(text, options, { download({ url, filename }) {
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click();
} });
const view = mountWorkspace(document, {
  filenamePrefix: "kumape", downloadText, workspaceToJson, workspaceToMarkdown, requestAiCompletion: requestWorkspaceAi,
  loadForceSettings() { try { return JSON.parse(localStorage.getItem(FORCE_KEY) || "null"); } catch { return null; } },
  saveForceSettings(settings) { try { localStorage.setItem(FORCE_KEY, JSON.stringify(settings)); } catch { /* optional preference */ } },
  async request(message) {
    switch (message.type) {
      case "settings:get": config = (await request({ type: "config:get" })).config; return { settings: { features: { aiAssistant: config.ai?.enabled }, ai: config.ai } };
      case "workspace:list": {
        workspaces = await db.listWorkspaces();
        for (const workspace of workspaces) workspace.siemOrigin ||= config.uiOrigin;
        return { workspaces };
      }
      case "workspace:create": return { workspace: await db.createInvestigation(message.workspace.title) };
      case "workspace:update": return { workspace: await db.updateInvestigation(message.id, message.patch) };
      case "workspace:delete": await db.deleteInvestigation(message.id); return {};
      case "workspace:item:remove": await db.removeWorkspaceItem(message.id, message.index); return {};
      case "workspace:item:add": await db.addEvent(message.workspaceId, message.item.snapshot, { uiOrigin: config.uiOrigin }); return {};
      case "workspace:chat:get": return { chat: await db.getWorkspaceAiChat(message.id) };
      case "workspace:chat:save": return { chat: await db.saveWorkspaceAiChat(message.id, message.chat) };
      case "ai:preview": return previewWorkspaceAi(message);
      default: throw new Error(`Неизвестная операция: ${message.type}`);
    }
  },
  buildInvestigationGraph: (items, options) => createEntityGraph(items.map(item => ({ id: item.value, label: item.label, timestamp: api.eventTimestamp(item.snapshot), entityKeys: db.entityKeys(item.snapshot) })), options),
  describeInvestigationEvent: event => ({ title: db.describeEvent(event), description: api.valuesForAliases(event, ["Message"])[0] || "" }),
  eventTime: event => api.eventTimestamp(event),
  eventIdentity: event => String(api.valuesForAliases(event, ["ID"])[0] ?? JSON.stringify(event)),
  eventItem: event => ({ type: "event", snapshot: event }),
  canSearch: workspace => Boolean(workspace?.items.length && config.uiOrigin),
  canOpenEvent: (_workspace, item) => Boolean(item?.sourceEventUuid),
  openEvent: (_workspace, item) => request({ type: "event:open", event: item.snapshot }),
  async searchEntities(workspace, selected, { mode, rangeSeconds }) {
    return (await request({ type: "workspace:search", investigationId: workspace.id, entities: selected, mode, rangeSeconds })).result;
  },
 });
window.addEventListener("pagehide", () => view.destroy(), { once: true });
