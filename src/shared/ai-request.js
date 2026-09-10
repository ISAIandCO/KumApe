import { normalizeAiResponse } from "@isaiandco/ape-share-core/ai/payload";
import { requestChatCompletion } from "@isaiandco/ape-share-core/ai/transport";

import { localAiEndpoint } from "./ai-endpoint.js";

function endpointPattern(url) {
  return `${url.protocol}//${url.hostname}/*`;
}

// Keep slow inference in the visible chat page; MV3 background message channels may be unloaded.
export async function requestPreparedAi(preview, { allowTools = false, contextType, browserApi = browser, requestImpl = requestChatCompletion } = {}) {
  if (!preview || typeof preview.body !== "string" || typeof preview.endpoint !== "string") throw new Error("Сначала сформируйте и проверьте payload");
  const { ai = {}, aiApiKey = "" } = await browserApi.storage.local.get({ ai: {}, aiApiKey: "" });
  const endpoint = localAiEndpoint(ai.endpoint);
  if (endpoint.href !== preview.endpoint) throw new Error("Настройки AI изменились. Сформируйте payload заново");
  if (!await browserApi.permissions.contains({ origins: [endpointPattern(endpoint)] })) throw new Error("Нет разрешения Firefox для локального AI endpoint");
  const reply = await requestImpl(endpoint, preview.body, { apiKey: String(aiApiKey).trim() });
  return normalizeAiResponse(reply, { contextType: contextType ?? "context", allowSiemTools: allowTools });
}
