import { renderMarkdown } from './markdown.js';

// Shared by event and investigation chats, following ApePatrol's persistent chat flow.
export async function mountChat(root, key, context, additionalContext) {
  let stored = (await browser.storage.local.get(key))[key];
  if (!stored) {
    try { stored = {messages:JSON.parse(sessionStorage.getItem(key) || "[]")}; } catch { stored = {}; }
  }
  const messages = Array.isArray(stored.messages) ? stored.messages.slice(-40) : [];
  const make = (tag, text) => { const node = document.createElement(tag); if (text) node.textContent = text; return node; };
  root.replaceChildren();
  root.classList.add('ai-chat');
  const title = make('h2', 'SEC AI Assistant');
  const history = make('div'); history.className = 'chat-messages'; history.setAttribute('aria-live', 'polite');
  const prompt = make('textarea'); prompt.placeholder = 'Что нужно проверить?'; prompt.value = stored.draft || ''; prompt.setAttribute('aria-label', 'Сообщение AI');
  const previewButton = make('button', 'Сформировать точный payload');
  const submit = make('button', 'Отправить проверенный payload'); submit.disabled = true;
  const clear = make('button', 'Очистить диалог');
  const details = make('details'); details.append(make('summary', 'Точный payload'));
  const output = make('pre'); details.append(output);
  const status = make('p'); status.setAttribute('role', 'status');
  const actions = make('div'); actions.className = 'toolbar'; actions.append(previewButton, submit, clear);
  const allow = make('input'); allow.type='checkbox';
  const allowLabel = make('label'); allowLabel.append(allow,document.createTextNode(' Разрешить AI запрашивать дополнительный контекст с подтверждением'));
  const requests = make('div');
  root.append(title, history, prompt, allowLabel, requests, actions, status, details);
  let extra = null;
  let prepared = null;
  const save = () => {
    while (messages.length > 40 || (messages.length > 2 && new TextEncoder().encode(JSON.stringify(messages)).byteLength > 2 * 1024 * 1024)) messages.shift();
    return browser.storage.local.set({ [key]: { messages, draft: prompt.value.slice(0,20000) } });
  };
  const request = async (message) => { const result = await browser.runtime.sendMessage(message); if (!result?.ok) throw new Error(result?.error || 'Ошибка AI'); return result; };
  function render() {
    history.replaceChildren();
    for (const message of messages) {
      const card = make('article'); card.className = `message ${message.role}`; card.append(make('strong', message.role === 'user' ? 'Вы' : 'SEC AI Assistant'));
      const content = make('div'); content.className = 'markdown-body';
      if (message.role === 'assistant') renderMarkdown(content, message.content); else content.textContent = message.content;
      card.append(content); history.append(card);
    }
    history.scrollTop = history.scrollHeight;
  }
  prompt.addEventListener('input', () => { prepared = null; submit.disabled = true; save().catch(error => status.textContent = error.message); });
  previewButton.addEventListener('click', async () => {
    submit.disabled = true; previewButton.disabled = true; prompt.disabled = true; allow.disabled = true; clear.disabled = true;
    try {
      if (!prompt.value.trim()) throw new Error('Введите вопрос');
      prepared = { ...(extra || await context()), allowTools:allow.checked, messages: [...messages, { role: 'user', content: prompt.value.trim() }] };
      const result = await request({ ...prepared, type: 'ai:preview' });
      prepared.preview = result.preview;
      output.textContent = JSON.stringify(JSON.parse(result.preview.body), null, 2);
      status.textContent = result.preview.endpoint; submit.disabled = false;
    } catch (error) { prepared = null; status.textContent = error.message; }
    finally { previewButton.disabled = false; prompt.disabled = false; allow.disabled = false; clear.disabled = false; }
  });
  submit.addEventListener('click', async () => {
    if (!prepared) return;
    submit.disabled = true; previewButton.disabled = true; prompt.disabled = true; clear.disabled = true; allow.disabled = true;
    try {
      status.textContent = 'Модель отвечает…';
      const response = await request({ ...prepared, type: 'ai:chat' });
      messages.push({ ...prepared.messages.at(-1), context: prepared.preview.context }, { role: 'assistant', content: response.content });
      requests.replaceChildren();
      for (const call of response.toolCalls || []) {
        const text=make('p',`AI запросил дополнительный контекст: ${call.arguments}`);
        const approve=make('button','Подготовить дополнительный контекст');
        approve.addEventListener('click',async()=>{
          try { extra=await (additionalContext || context)(); prompt.value='Учти дополнительный контекст и продолжи анализ'; submit.disabled=true; prepared=null; status.textContent='Контекст подготовлен. Сформируйте и проверьте payload перед отправкой'; approve.disabled=true; }
          catch(error) {status.textContent=error.message;}
        });
        requests.append(text,approve);
      }
      prompt.value = ''; await save(); render(); prepared = null; extra = null; status.textContent = 'Ответ получен';
    } catch (error) { status.textContent = error.message; }
    finally { previewButton.disabled = false; prompt.disabled = false; clear.disabled = false; allow.disabled = false; }
  });
  allow.addEventListener('change',()=>{prepared=null;submit.disabled=true;});
  clear.addEventListener('click', async () => { messages.length = 0; prepared = null; extra = null; prompt.value = ''; requests.replaceChildren(); output.textContent = ''; status.textContent = ''; submit.disabled = true; await save(); render(); });
  render();
}
