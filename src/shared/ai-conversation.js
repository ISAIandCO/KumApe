import { prepareAiRequest } from "@isaiandco/ape-share-core/ai/payload";
import { localAiEndpoint } from "./ai-endpoint.js";
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
  for (const entry of conversation) for (const item of entry.attachments ?? []) {
    if (new TextEncoder().encode(JSON.stringify(item)).byteLength > 2 * 1024 * 1024) throw new Error("Контекст AI превышает лимит 2 МБ");
  }
  const preview = await prepareAiRequest(null, { model: ai.model || "local-model", mode: "denylist", denyFields: [], maxBytes: 2 * 1024 * 1024 }, {
    conversation, contextType: message.contextType ?? "workspace", allowSiemTools: message.allowSiemTools,
  });
  return { preview, endpoint: localAiEndpoint(ai.endpoint).href };
}
export const previewLocalAi = prepare;
export async function requestLocalAi(message) {
  if (!message.confirmed) throw new Error("Подтвердите отправку payload");
  const { preview, endpoint } = await prepare(message);
  if (endpoint !== message.previewEndpoint) throw new Error("Адрес AI изменился. Сформируйте payload заново");
  if (preview.hash !== message.previewHash) throw new Error("Контекст или настройки изменились. Сформируйте payload заново");
  return requestPreparedAi({ body: preview.serialized, endpoint }, { allowTools: message.allowSiemTools, contextType: message.contextType ?? "workspace" });
}
