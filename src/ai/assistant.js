import { mountChat } from "../shared/chat-view.js";
import { relatedAiContext } from "../shared/ai-context.js";
const id = new URL(location.href).searchParams.get("id");
async function initialize() {
  const response = await browser.runtime.sendMessage({ type: "ai:request:get", id });
  if (!response?.ok) throw new Error(response?.error || "Контекст отсутствует");
  const { preview } = response;
  for (const [field, value] of Object.entries({endpoint: preview.endpoint, privacy: preview.mode, bytes: preview.bytes})) document.getElementById(field).textContent = value;
  document.getElementById("fields").replaceChildren(...preview.fields.map(field => { const li = document.createElement("li"); li.textContent = field; return li; }));
  const dispose = await mountChat(document.querySelector("main > section"), preview.historyKey || `aiHistory:${id}`, () => ({ id }), async () => {
    const latest=await browser.runtime.sendMessage({type:"ai:request:get",id});
    if (!latest?.ok) throw new Error(latest?.error || "Контекст отсутствует");
    const payload=latest.preview.payload;
    return relatedAiContext(payload.Events?.at(-1) || payload);
  });
  window.addEventListener("pagehide", dispose, { once: true });
  document.getElementById("status").textContent = "Диалог события";
}
initialize().catch(error => document.getElementById("status").textContent = error.message);
