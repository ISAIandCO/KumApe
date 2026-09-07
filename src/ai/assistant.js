import { renderMarkdown } from "../shared/markdown.js";
"use strict";

const $ = (selector) => document.querySelector(selector);
const id = new URL(location.href).searchParams.get("id");
const historyKey = `aiHistory:${id}`;
const messages = JSON.parse(sessionStorage.getItem(historyKey) || "[]");
const saveHistory = () => sessionStorage.setItem(historyKey, JSON.stringify(messages.slice(-40)));

async function send(message) {
  const response = await browser.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Операция не выполнена");
  return response;
}
function add(role, content) {
  const node = document.createElement("div"); node.className = `message ${role}`;
  const title = document.createElement("strong"); title.textContent = role === "user" ? "Вы" : "KumApe AI";
  const text = document.createElement("div"); text.className = "markdown-body"; if (role === "assistant") renderMarkdown(text, content); else text.textContent = content; node.append(title, text); $("#chat").append(node); node.scrollIntoView({ block: "end" });
}
async function initialize() {
  if (!id) throw new Error("Контекст AI отсутствует");
  const { preview } = await send({ type: "ai:request:get", id });
  $("#endpoint").textContent = `${preview.endpoint} · ${preview.model}`; $("#privacy").textContent = preview.mode.toUpperCase(); $("#bytes").textContent = `${preview.bytes.toLocaleString("ru-RU")} байт`;
  $("#fields").replaceChildren();
  for (const field of preview.fields) { const item = document.createElement("li"); item.textContent = field; $("#fields").append(item); }
  $("#status").textContent = "Контекст подготовлен; отправка произойдёт только после нажатия кнопки";
}
$("#form").addEventListener("submit", async (event) => {
  event.preventDefault(); const prompt = $("#prompt").value.trim(); if (!prompt) return;
  const submit = event.submitter || $("#form button"); submit.disabled = true; $("#prompt").value = ""; add("user", prompt); messages.push({ role: "user", content: prompt }); saveHistory();
  try { $("#status").textContent = "Локальная модель отвечает…"; const response = await send({ type: "ai:chat", id, messages }); messages.push({ role: "assistant", content: response.content }); add("assistant", response.content); saveHistory(); $("#status").textContent = "Ответ получен локально"; }
  catch (error) { $("#status").textContent = error.message; }
  finally { submit.disabled = false; }
});
$("#clear").addEventListener("click", () => { messages.length = 0; saveHistory(); $("#chat").replaceChildren(); $("#status").textContent = "Диалог очищен; контекст события сохранён"; });
for (const message of messages) add(message.role, message.content);
window.addEventListener("focus", () => initialize().catch(error => {$("#status").textContent=error.message;}));
initialize().catch((error) => { $("#status").textContent = error.message; });
