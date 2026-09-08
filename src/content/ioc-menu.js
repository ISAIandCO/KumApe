(function (global) {
  "use strict";
  if (global.KumApeIocMenu) { global.KumApeIocMenu.start().catch(() => {}); return; }
  const selector = '[kuma-section="event-field"][kuma-id]';
  const buttons = new Map();
  const eventButtons = new Map();
  const observers = new Map();
  let running = false;
  let generation = 0;
  let timer;
  let opened;
  let eventOpened;

  function fieldIoc(node) {
    const field = node.getAttribute("kuma-id") || "";
    const value = node.getAttribute("kuma-data") || node.querySelector(":scope > span:nth-of-type(2)")?.textContent?.trim() || "";
    return global.KumApeAdapter.iocsFromEvent({ [field]: value })[0] || null;
  }
  function fieldLabel(node) {
    return node.querySelector(":scope > span:nth-of-type(1)") || null;
  }
  function close() {
    if (!opened) return;
    opened.anchor.setAttribute("aria-expanded", "false");
    opened.abort.abort();
    opened.host.remove();
    opened = null;
  }
  function closeEvent() {
    if (!eventOpened) return;
    eventOpened.anchor.setAttribute("aria-expanded", "false");
    eventOpened.abort.abort();
    eventOpened.host.remove();
    eventOpened = null;
  }
  async function send(message) {
    const response = await browser.runtime.sendMessage(message);
    if (!response?.ok) throw new Error(response?.error || "Операция не выполнена");
    return response;
  }
  function open(anchor, node) {
    if (opened?.anchor === anchor) { close(); return; }
    close(); closeEvent();
    const ioc = fieldIoc(node);
    if (!ioc) return;
    const host = document.createElement("span");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `:host { all: initial; } section { position: fixed; inset: auto; margin: 0; width: 330px; max-width: calc(100vw - 16px); max-height: min(480px, calc(100vh - 16px)); overflow: auto; box-sizing: border-box; padding: 12px; border: 1px solid #7a929d; border-radius: 9px; background: #18252e; color: #f1f5f8; font: 13px/1.45 system-ui; box-shadow: 0 8px 28px #0005; } strong, p { display: block; margin: 0 0 8px; overflow-wrap: anywhere; } button { display: block; width: 100%; padding: 7px 9px; margin: 5px 0; text-align: left; background: #263c49; color: #fff; border: 1px solid #57727e; border-radius: 5px; font: inherit; cursor: pointer; } button:hover, button:focus-visible { outline: 2px solid #00b8cf; } button:disabled { opacity: .6; } pre { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; margin: 8px 0 0; }`;
    const menu = document.createElement("section");
    menu.setAttribute("popover", "manual");
    menu.setAttribute("role", "dialog");
    menu.setAttribute("aria-label", "Проверка IOC — KumApe");
    const title = document.createElement("strong");
    title.textContent = `${ioc.field}: ${ioc.value}`;
    menu.append(title);
    const status = document.createElement("pre");
    status.setAttribute("role", "status");
    const add = (text, action) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = text;
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        if (!event.isTrusted) return;
        button.disabled = true;
        try { await action(); } catch (error) { status.textContent = error.message; }
        finally { button.disabled = false; reposition(); }
      });
      menu.append(button);
    };
    add("Копировать IOC", async () => { await navigator.clipboard.writeText(ioc.value); status.textContent = "Скопировано"; });
    for (const [id, provider] of Object.entries(global.KumApeIoc.PROVIDERS)) {
      if (!provider.types.includes(ioc.type)) continue;
      add(`Проверить: ${provider.name} API`, async () => {
        status.textContent = `Запрос к ${provider.name}…`;
        const { result } = await send({ type: "ioc:lookup", provider: id, ioc });
        status.textContent = `${result.provider}\n${result.summary}${result.details ? `\n${JSON.stringify(result.details, null, 2)}` : ""}`;
      });
    }
    for (const link of global.KumApeAdapter.iocLinks(ioc)) {
      add(`Открыть отчёт: ${link.provider}`, () => send({ type: "ioc:open", ioc, provider: link.provider }));
    }
    add("Настройки ключей…", () => send({ type: "ioc:options" }));
    add("Закрыть", () => { close(); anchor.focus(); });
    menu.append(status);
    root.append(style, menu);
    document.documentElement.append(host);
    const abort = new AbortController();
    opened = { host, anchor, node, value: ioc.value, abort };
    anchor.setAttribute("aria-expanded", "true");
    function reposition() {
      if (opened?.host !== host) return;
      if (!anchor.isConnected || fieldIoc(node)?.value !== ioc.value) { close(); return; }
      const box = anchor.getBoundingClientRect();
      if (box.bottom <= 0 || box.top >= innerHeight) { close(); return; }
      menu.style.left = `${Math.max(8, Math.min(box.left, innerWidth - menu.offsetWidth - 8))}px`;
      menu.style.top = `${Math.max(8, Math.min(box.bottom + 4, innerHeight - menu.offsetHeight - 8))}px`;
    }
    menu.addEventListener("toggle", () => {
      if (!menu.matches(":popover-open") && opened?.host === host) close();
    });
    // Capture scroll from the card and its ancestors, including open shadow roots.
    const targets = new Set([window, ...observers.keys()]);
    for (const target of targets) target.addEventListener("scroll", reposition, { capture: true, passive: true, signal: abort.signal });
    window.addEventListener("resize", reposition, { signal: abort.signal });
    document.addEventListener("pointerdown", (event) => {
      const path = event.composedPath();
      if (!path.includes(host) && !path.includes(buttons.get(node))) close();
    }, { capture: true, signal: abort.signal });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { event.preventDefault(); close(); anchor.focus(); }
    }, { signal: abort.signal });
    menu.showPopover();
    reposition();
    menu.querySelector("button").focus();
  }
  function eventContext() {
    const context = global.KumApePage?.extractPageContext(document, location.href);
    return context?.event && Object.keys(context.event).length ? context : null;
  }
  function openEvent(anchor) {
    if (eventOpened?.anchor === anchor) { closeEvent(); return; }
    close(); closeEvent();
    if (!eventContext()) return;
    const host = document.createElement("span");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `:host { all: initial; } section { position: fixed; z-index: 2147483647; inset: auto; margin: 0; display: grid; min-width: 230px; max-width: min(360px, calc(100vw - 12px)); max-height: calc(100vh - 12px); overflow: auto; box-sizing: border-box; padding: 7px; border: 1px solid #64748b; border-radius: 7px; background: #fff; color: #111827; box-shadow: 0 8px 24px #0004; font: 13px/1.35 system-ui, sans-serif; } button { padding: 6px 8px; border: 0; background: transparent; color: inherit; text-align: left; font: inherit; cursor: pointer; } button:hover, button:focus-visible { background: #e8f1fb; outline: none; } button:disabled { opacity: .5; } span { min-width: 80px; padding: 5px 8px; color: #166534; overflow-wrap: anywhere; }`;
    const menu = document.createElement("section");
    menu.setAttribute("popover", "manual");
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Действия KumApe с событием");
    const status = document.createElement("span"); status.setAttribute("role", "status");
    const add = (label, action) => {
      const button = document.createElement("button"); button.type = "button"; button.textContent = label; button.setAttribute("role", "menuitem");
      button.addEventListener("click", async (event) => {
        event.preventDefault(); event.stopPropagation();
        if (!event.isTrusted) return;
        button.disabled = true;
        try {
          const context = eventContext();
          if (!context) throw new Error("Событие не найдено");
          status.textContent = await action(context) || "Готово";
        } catch (error) { status.textContent = `Ошибка: ${error.message}`; }
        finally { button.disabled = false; reposition(); }
      });
      menu.append(button);
    };
    add("📌 В расследование", async (context) => {
      const response = await send({ type: "investigation:event:add", event: context.event });
      return `Добавлено в «${response.investigation.title}»`;
    });
    add("Копировать JSON", async (context) => { await navigator.clipboard.writeText(JSON.stringify(context.event, null, 2)); return "JSON скопирован"; });
    add("Копировать ссылку", async () => { await navigator.clipboard.writeText(location.href); return "Ссылка скопирована"; });
    add("Скачать JSON", async (context) => {
      const id = global.KumApeAdapter.valuesForAliases(context.event, ["ID"])[0] || "event";
      const url = URL.createObjectURL(new Blob([JSON.stringify(context.event, null, 2)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `kuma-event-${id.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 120)}.json`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return "Загрузка начата";
    });
    menu.append(status); root.append(style, menu); document.documentElement.append(host);
    const abort = new AbortController(); eventOpened = { host, anchor, abort };
    anchor.setAttribute("aria-expanded", "true");
    function reposition() {
      if (eventOpened?.host !== host) return;
      if (!anchor.isConnected) { closeEvent(); return; }
      const box = anchor.getBoundingClientRect();
      if (box.bottom <= 0 || box.top >= innerHeight) { closeEvent(); return; }
      menu.style.left = `${Math.max(6, Math.min(box.left, innerWidth - menu.offsetWidth - 6))}px`;
      menu.style.top = `${Math.max(6, Math.min(box.bottom + 4, innerHeight - menu.offsetHeight - 6))}px`;
    }
    for (const target of new Set([window, ...observers.keys()])) target.addEventListener("scroll", reposition, { capture: true, passive: true, signal: abort.signal });
    window.addEventListener("resize", reposition, { signal: abort.signal });
    document.addEventListener("pointerdown", (event) => { if (!event.composedPath().includes(host)) closeEvent(); }, { capture: true, signal: abort.signal });
    document.addEventListener("keydown", (event) => { if (event.key === "Escape") { event.preventDefault(); closeEvent(); anchor.focus(); } }, { signal: abort.signal });
    menu.showPopover(); reposition(); menu.querySelector("button").focus();
  }
  function mountEventButton(node) {
    const host = document.createElement("span"); const shadow = host.attachShadow({ mode: "closed" });
    const button = document.createElement("button"); button.type = "button"; button.textContent = "🐵 Действия"; button.title = "Действия KumApe с событием";
    button.setAttribute("aria-haspopup", "menu"); button.setAttribute("aria-expanded", "false");
    button.style.cssText = "margin-inline-start:7px;padding:3px 7px;border:1px solid #94a3b8;border-radius:5px;background:#fff;color:#111827;cursor:pointer;white-space:nowrap;font:12px/1.3 system-ui,sans-serif;vertical-align:middle";
    button.addEventListener("click", (event) => { event.preventDefault(); event.stopPropagation(); if (event.isTrusted) openEvent(button); });
    shadow.append(button); node.append(host); eventButtons.set(node, host);
  }
  function isEventTitle(node) {
    const exact = (value) => value?.replace(/\s+/g, " ").trim().toLowerCase() === "информация о событии";
    if (!exact(node.textContent) || [...(node.children || [])].some((child) => exact(child.textContent))) return false;
    for (let parent = node.parentElement, depth = 0; parent && depth < 8; parent = parent.parentElement, depth++) {
      if (parent.getAttribute?.("kuma-section") === "event-field" || parent === document.body || parent === document.documentElement) return false;
      if ((parent.querySelectorAll?.(selector).length || 0) >= 3) return true;
    }
    return false;
  }
  function scan() {
    if (!running) return;
    for (const [node, host] of buttons) {
      if (!node.isConnected || !host.isConnected || !fieldIoc(node)) { host.remove(); buttons.delete(node); }
    }
    for (const [node, host] of eventButtons) {
      if (!node.isConnected || !host.isConnected) { host.remove(); eventButtons.delete(node); }
    }
    if (opened && (!opened.node.isConnected || fieldIoc(opened.node)?.value !== opened.value)) close();
    const roots = [document];
    for (let index = 0; index < roots.length; index++) {
      const root = roots[index];
      for (const node of root.querySelectorAll("*")) {
        if (node.shadowRoot) roots.push(node.shadowRoot);
        if (!eventButtons.has(node) && isEventTitle(node)) mountEventButton(node);
      }
      if (!observers.has(root)) {
        const observer = new MutationObserver(schedule);
        observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["kuma-id", "kuma-data"] });
        observers.set(root, observer);
      }
      for (const node of root.querySelectorAll(selector)) {
        if (buttons.has(node) || !fieldIoc(node)) continue;
        const host = document.createElement("span");
        const shadow = host.attachShadow({ mode: "closed" });
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = "🐵";
        button.title = "KumApe: проверить IOC";
        button.setAttribute("aria-label", `KumApe: проверить IOC в поле ${node.getAttribute("kuma-id") || ""}`);
        button.setAttribute("aria-haspopup", "dialog");
        button.setAttribute("aria-expanded", "false");
        button.style.cssText = "margin-inline-start:4px;margin-inline-end:0;padding:1px 4px;border:0;background:transparent;color:inherit;cursor:pointer;font-size:14px;vertical-align:baseline";
        button.addEventListener("click", (event) => {
          event.preventDefault(); event.stopPropagation();
          if (event.isTrusted) open(button, node);
        });
        shadow.append(button);
        (fieldLabel(node) || node).append(host);
        buttons.set(node, host);
      }
    }
    for (const [root, observer] of observers) {
      if (root !== document && !root.host.isConnected) { observer.disconnect(); observers.delete(root); }
    }
  }
  function schedule() { if (!timer) timer = setTimeout(() => { timer = null; scan(); }, 120); }
  async function start() {
    if (running) return;
    const current = ++generation;
    const { uiOrigin } = await browser.storage.local.get("uiOrigin");
    // Firefox match patterns cannot restrict ports. Enforce the exact origin here.
    if (current !== generation || location.origin !== uiOrigin) return;
    running = true; scan();
  }
  function stop() {
    generation++; running = false; clearTimeout(timer); timer = null; close(); closeEvent();
    for (const observer of observers.values()) observer.disconnect();
    observers.clear();
    for (const host of buttons.values()) host.remove();
    buttons.clear();
    for (const host of eventButtons.values()) host.remove();
    eventButtons.clear();
  }
  browser.runtime.onMessage.addListener((message) => { if (message?.type === "ioc:menu:stop") stop(); });
  global.KumApeIocMenu = Object.freeze({ start, stop });
  start().catch(() => {});
})(globalThis);
