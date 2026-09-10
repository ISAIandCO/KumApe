import { normalizeAiToolCalls } from "@isaiandco/ape-share-core/ai/payload";
import { chatEndpoint, requestChatCompletion } from "@isaiandco/ape-share-core/ai/transport";

function endpointPattern(url) {
  return `${url.protocol}//${url.hostname}/*`;
}

// Keep slow inference in the visible chat page; MV3 background message channels may be unloaded.
export async function requestPreparedAi(preview, { allowTools = false, contextType, browserApi = browser, requestImpl = requestChatCompletion } = {}) {
  if (!preview || typeof preview.body !== "string" || typeof preview.endpoint !== "string") throw new Error("Сначала сформируйте и проверьте payload");
  const { ai = {}, aiApiKey = "" } = await browserApi.storage.local.get({ ai: {}, aiApiKey: "" });
  const endpoint = chatEndpoint(ai.endpoint || "", { expandBase: true });
  if (endpoint.href !== preview.endpoint) throw new Error("Настройки AI изменились. Сформируйте payload заново");
  if (!await browserApi.permissions.contains({ origins: [endpointPattern(endpoint)] })) throw new Error("Нет разрешения Firefox для локального AI endpoint");
  const reply = await requestImpl(endpoint, preview.body, { apiKey: String(aiApiKey).trim() });
  const content = typeof reply?.content === "string" ? reply.content : "";
  const toolCalls = allowTools ? contextType === "workspace" ? normalizeAiToolCalls(reply, contextType) : (reply?.tool_calls || [])
    .filter((call) => call?.function?.name === "get_additional_context")
    .slice(0, 4)
    .map((call) => ({ name: call.function.name, arguments: String(call.function.arguments || "{}").slice(0, 4000) })) : [];
  if (!content.trim() && !toolCalls.length) throw new Error("Локальный AI вернул пустой ответ");
  return { content, toolCalls };
}
