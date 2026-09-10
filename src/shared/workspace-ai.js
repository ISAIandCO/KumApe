import { prepareAiRequest } from "@isaiandco/ape-share-core/ai/payload";
import { chatEndpoint } from "@isaiandco/ape-share-core/ai/transport";
import { requestPreparedAi } from "./ai-request.js";
import "./ai-privacy.js";

async function prepare(message) {
  const { ai = {} } = await browser.storage.local.get("ai");
  if (!ai.enabled) throw new Error("AI выключен в настройках");
  const conversation = message.conversation.map(entry => ({ ...entry,
    attachments: (entry.attachments ?? []).map(attachment => attachment.type === "event"
      ? { ...attachment, snapshot: globalThis.KumApeAiPrivacy.prepareEvent(attachment.snapshot, ai.privacyMode || "strict") }
      : attachment),
  }));
  const preview = await prepareAiRequest(null, { model: ai.model || "local-model", mode: "denylist", denyFields: [], maxBytes: 2 * 1024 * 1024 }, {
    conversation, contextType: "workspace", allowSiemTools: message.allowSiemTools,
  });
  return { preview, endpoint: chatEndpoint(ai.endpoint, { expandBase: true }).href };
}
export const previewWorkspaceAi = prepare;
export async function requestWorkspaceAi(message) {
  if (!message.confirmed) throw new Error("Подтвердите отправку payload");
  const { preview, endpoint } = await prepare(message);
  if (preview.hash !== message.previewHash) throw new Error("Контекст или настройки изменились. Сформируйте payload заново");
  return requestPreparedAi({ body: preview.serialized, endpoint }, { allowTools: message.allowSiemTools, contextType: "workspace" });
}
