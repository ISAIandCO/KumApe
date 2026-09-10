import { createAiConversation } from "@isaiandco/ape-share-core/ai/conversation";
import { addAiAttachment, normalizeAiChat } from "@isaiandco/ape-share-core/ai/chat";
import { renderChatMessages } from "@isaiandco/ape-share-core/ui/chat-messages";
import { previewLocalAi, requestLocalAi } from "./ai-conversation.js";

export async function mountChat(root, key, context, additionalContext) {
  const document = root.ownerDocument;
  const make = (tag, text) => { const node = document.createElement(tag); if (text) node.textContent = text; return node; };
  const stored = (await browser.storage.local.get(key))[key] ?? {};
  const previousContexts = [];
  const messages = (stored.messages ?? []).map(message => {
    if (message.role !== "user" || !message.context) return message;
    previousContexts.push(message.context);
    return { ...message, attachments: [{ type: "event", value: "event-context", label: "Контекст событий", snapshot: globalThis.KumApeAiPrivacy.mergeContexts(previousContexts, "full").payload }] };
  });
  let chat = normalizeAiChat({ ...stored, messages });
  const listeners = [];
  let destroyed = false;
  function listen(target, event, handler) { target.addEventListener(event, handler); listeners.push(() => target.removeEventListener(event, handler)); }
  async function contextAttachments(getContext) {
    const input = await getContext();
    const event = input.event ?? (await browser.runtime.sendMessage({ type: "ai:request:get", id: input.id })).preview?.payload;
    if (!event) throw new Error("Контекст события недоступен");
    const previous = [...chat.messages, { attachments: chat.pendingAttachments }].flatMap(message => (message.attachments ?? []).filter(item => item.type === "event").map(item => item.snapshot));
    const merged = globalThis.KumApeAiPrivacy.mergeContexts([...previous, event], "full");
    const events = Array.isArray(merged.payload.Events) ? merged.payload.Events : [merged.payload];
    return [{ type: "event", value: "event-context", label: `${events.length} событий`, snapshot: merged.payload }];
  }
  root.replaceChildren(); root.classList.add("ai-chat");
  const history = make("div"); history.className = "chat-messages"; history.setAttribute("aria-live", "polite");
  const prompt = make("textarea"); prompt.placeholder = "Что нужно проверить?"; prompt.setAttribute("aria-label", "Сообщение AI");
  const previewButton = make("button", "Сформировать точный payload"), submit = make("button", "Отправить проверенный payload"), clear = make("button", "Очистить диалог");
  const output = make("pre"), details = make("details"), status = make("p"), requests = make("div"), pending = make("div");
  status.setAttribute("role", "status"); details.append(make("summary", "Точный payload"), output);
  const allow = make("input"); allow.type = "checkbox";
  const allowLabel = make("label"); allowLabel.append(allow, document.createTextNode(" Разрешить AI запрашивать дополнительный контекст с подтверждением"));
  const actions = make("div"); actions.className = "toolbar"; actions.append(previewButton, submit, clear);
  root.append(make("h2", "SEC AI Assistant"), history, pending, prompt, allowLabel, requests, actions, status, details);
  const save = value => browser.storage.local.set({ [key]: value ?? chat });
  const controller = createAiConversation({
    read: () => chat, write: value => { chat = value; render(); }, scope: () => key,
    async request() {
      const attachments = chat.pendingAttachments.length ? chat.pendingAttachments : await contextAttachments(context);
      return { contextType: "context", conversation: [...chat.messages, { role: "user", content: chat.draft.trim() || "Проанализируй приложенные данные", attachments }], allowSiemTools: chat.allowSiemTools };
    },
    preview: previewLocalAi, complete: requestLocalAi, persist: save,
    changed() {
      if (destroyed) return;
      for (const node of [previewButton, prompt, allow, clear, ...requests.querySelectorAll("button")]) node.disabled = controller.busy;
      submit.disabled = controller.busy || !controller.reviewed;
    },
  });
  const report = error => { if (!destroyed) status.textContent = error.message; };
  function render() {
    renderChatMessages(history, chat.messages, { messageClass: "message" });
    prompt.value = chat.draft; allow.checked = chat.allowSiemTools;
    pending.textContent = chat.pendingAttachments.map(item => item.label).join(" · ");
    requests.replaceChildren();
    for (const call of chat.pendingToolCalls) {
      const approve = make("button", "Подготовить дополнительный контекст");
      approve.disabled = controller.busy;
      approve.addEventListener("click", async () => {
        if (controller.busy) return;
        controller.invalidate();
        try {
          const attachments = await contextAttachments(additionalContext ?? context);
          if (destroyed) return;
          for (const item of attachments) chat = addAiAttachment(chat, item);
          chat.pendingToolCalls = []; chat.draft = "Учти дополнительный контекст и продолжи анализ";
          controller.invalidate(); await save(); render();
          status.textContent = "Контекст подготовлен. Проверьте payload перед отправкой";
        } catch (error) { report(error); }
      });
      requests.append(make("p", `AI запросил контекст: ${call.arguments.reason ?? call.name}`), approve);
    }
    history.scrollTop = history.scrollHeight;
  }
  listen(prompt, "input", () => { chat.draft = prompt.value; controller.invalidate(); save().catch(report); });
  listen(allow, "change", () => { chat.allowSiemTools = allow.checked; controller.invalidate(); save().catch(report); });
  listen(previewButton, "click", async () => {
    try { const result = await controller.preview(); if (result) { output.textContent = result.preview.serialized; status.textContent = result.endpoint; } }
    catch (error) { report(error); }
  });
  listen(submit, "click", async () => {
    try { status.textContent = "Модель отвечает…"; await controller.send({ confirmed: true }); if (!destroyed) status.textContent = "Ответ получен"; }
    catch (error) { report(error); }
  });
  listen(clear, "click", async () => {
    chat = normalizeAiChat({ allowSiemTools: chat.allowSiemTools }); controller.invalidate(); output.textContent = ""; await save(); render();
  });
  render(); controller.invalidate();
  return () => { destroyed = true; controller.destroy(); for (const remove of listeners) remove(); };
}
