import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
const sources = ["shared/kuma-adapter.js", "shared/ioc-providers.js", "content/ioc-menu.js"].map(path => buildSync({ entryPoints: [fileURLToPath(new URL(`../src/${path}`, import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text);

function fixture(origin = "https://kuma.test:7220") {
  const observers = [];
  const messages = [];
  const clipboard = [];
  const elements = [];
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.listeners = {}; this.isConnected = true; this.offsetWidth = 330; this.offsetHeight = 400; elements.push(this); }
    append(...nodes) { for (const node of nodes) { node.parent = this; node.parentElement = this; this.children.push(node); } }
    prepend(...nodes) { for (const node of [...nodes].reverse()) { node.parent = this; node.parentElement = this; this.children.unshift(node); } }
    attachShadow() { this.closedRoot = new Element("shadow"); return this.closedRoot; }
    setAttribute(key, value) { this.attrs[key] = value; }
    getAttribute(key) { return this.attrs[key] ?? null; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    async emit(type, extra = {}) { for (const fn of this.listeners[type] || []) await fn({ isTrusted: true, preventDefault() {}, stopPropagation() {}, ...extra }); }
    querySelector(selector) {
      if (selector === "button") return this.children.find((node) => node.tag === "button") || null;
      if (selector === ":scope > span:nth-of-type(1)") return this.children.filter((node) => node.tag === "span")[0] || null;
      if (selector === ":scope > span:nth-of-type(2)") return this.children.filter((node) => node.tag === "span")[1] || null;
      return null;
    }
    querySelectorAll(selector) {
      const descendants = [];
      const visit = (parent) => { for (const child of parent.children) { descendants.push(child); visit(child); } };
      visit(this);
      if (selector === "*") return descendants.filter((node) => node.isConnected);
      if (selector === '[kuma-section="event-field"][kuma-id]') return descendants.filter((node) => node.isConnected && node.attrs["kuma-section"] === "event-field" && node.attrs["kuma-id"]);
      return [];
    }
    getBoundingClientRect() { return { left: 50, top: 40, bottom: 60 }; }
    remove() { this.isConnected = false; if (this.parent) this.parent.children = this.parent.children.filter((node) => node !== this); }
    showPopover() { this.visible = true; }
    matches() { return this.visible; }
    focus() {}
  }
  const document = new Element("document");
  document.documentElement = new Element("html");
  document.append(document.documentElement);
  document.createElement = (tag) => new Element(tag);
  const field = new Element("div");
  field.setAttribute("kuma-section", "event-field"); field.setAttribute("kuma-id", "SourceAddress"); field.setAttribute("kuma-data", "8.8.8.8");
  const label = new Element("span"); label.textContent = "SourceAddress"; const value = new Element("span"); value.textContent = "8.8.8.8"; field.append(label, value);
  const headingWrapper = new Element("div"); headingWrapper.textContent = "Информация о событии";
  const heading = new Element("h2"); heading.textContent = "Информация о событии"; headingWrapper.append(heading);
  const plainTitleField = new Element("div"); plainTitleField.setAttribute("kuma-section", "event-field"); plainTitleField.setAttribute("kuma-id", "Message"); plainTitleField.setAttribute("kuma-data", "Информация о событии");
  const plainTitleLabel = new Element("span"); plainTitleLabel.textContent = "Message"; const plainTitle = new Element("span"); plainTitle.textContent = "Информация о событии"; plainTitleField.append(plainTitleLabel, plainTitle);
  const extraFields = [["Timestamp", "2026-09-08T10:00:00Z"], ["DeviceEventClassID", "1"]].map(([id, data]) => {
    const node = new Element("div"); node.setAttribute("kuma-section", "event-field"); node.setAttribute("kuma-id", id); node.setAttribute("kuma-data", data); return node;
  });
  const card = new Element("article"); card.append(headingWrapper, field, plainTitleField, ...extraFields);
  const correlationHeading = new Element("h2"); correlationHeading.textContent = "Информация о корреляционном событии";
  const correlationFields = [["Timestamp", "2026-09-08T10:00:00Z"], ["DeviceEventClassID", "correlation"], ["Type", "3"]].map(([id, data]) => {
    const node = new Element("div"); node.setAttribute("kuma-section", "event-field"); node.setAttribute("kuma-id", id); node.setAttribute("kuma-data", data); return node;
  });
  const correlationCard = new Element("article"); correlationCard.append(correlationHeading, ...correlationFields);
  const unrelatedWrapper = new Element("div"); const unrelatedTitle = new Element("span"); unrelatedTitle.textContent = "Информация о событии"; unrelatedWrapper.append(unrelatedTitle);
  document.documentElement.append(card, correlationCard, unrelatedWrapper);
  const kumaEvent = { ID: "event-id", SourceAddress: "8.8.8.8", Timestamp: "2026-09-08T10:00:00Z" };
  const context = vm.createContext({ URL, AbortController, document, location: { origin, href: `${origin}/events/event-id` }, innerWidth: 1200, innerHeight: 900,
    window: new Element("window"),
    navigator: { clipboard: { writeText: async (value) => { clipboard.push(value); } } },
    KumApePage: { extractPageContext: () => ({ event: kumaEvent }) },
    // Mutation callbacks are triggered explicitly, so tests don't rely on wall-clock timing.
    setTimeout: (fn) => { observers.push(fn); return observers.length; }, clearTimeout() {},
    MutationObserver: class { constructor(fn) { this.callback = fn; } observe() {} disconnect() {} },
    browser: { storage: { local: { get: async () => ({ uiOrigin: "https://kuma.test:7220" }) } }, runtime: { onMessage: { addListener() {} }, sendMessage: async (message) => {
      messages.push(message); return message.type === "investigation:event:add"
        ? { ok: true, investigation: { id: "inv-1", title: "Case 1" } }
        : message.type === "event:json"
          ? { ok: true, event: { ID: "event-id", Timestamp: "2026-09-08T07:00:00Z" } }
          : { ok: true, result: { provider: "Test", summary: "Synthetic report" } };
    } } },
  });
  for (const source of sources) vm.runInContext(source, context);
  const button = () => label.children[0]?.closedRoot.children[0];
  const eventButton = () => heading.children[0]?.closedRoot.children[0];
  const correlationButton = () => correlationHeading.children[0]?.closedRoot.children[0];
  const menu = () => [...elements].reverse().find((node) => node.isConnected && node.closedRoot?.children.some((child) => child.tag === "section"))?.closedRoot.children.find((node) => node.tag === "section");
  return { context, document, field, label, value, headingWrapper, heading, plainTitle, unrelatedTitle, button, eventButton, correlationButton, menu, messages, clipboard, elements, ready: () => vm.runInContext("KumApeIocMenu.start()", context) };
}

test("inline menu mounts once, sends nothing on open, and queries only the selected IOC", async () => {
  const app = fixture(); await app.ready();
  await app.ready(); assert.equal(app.label.children.length, 1);
  assert.equal(app.field.children[1], app.value);
  assert.match(app.button().style.cssText, /margin-inline-start:4px/);
  assert.match(app.button().attrs["aria-label"], /SourceAddress/);
  assert.equal(app.messages.length, 0);
  await app.button().emit("click");
  assert.equal(app.messages.length, 0);
  const menu = app.menu();
  assert.equal(menu.visible, true);
  const lookup = menu.children.find((node) => node.textContent === "Проверить: VirusTotal API");
  await lookup.emit("click");
  assert.equal(app.messages.length, 1);
  assert.equal(app.messages[0].ioc.value, "8.8.8.8");
  assert.equal(app.messages[0].event, undefined);
  assert.match(menu.children.at(-1).textContent, /Synthetic report/);
  assert.equal(menu.visible, true);
  await app.button().emit("click");
  assert.equal(app.menu(), undefined);
});

test("reused KUMA field reads the new value and Escape closes the menu", async () => {
  const app = fixture(); await app.ready();
  app.field.setAttribute("kuma-data", "1.1.1.1");
  await app.button().emit("click");
  const menu = app.menu();
  assert.match(menu.children[0].textContent, /1\.1\.1\.1/);
  await app.document.emit("keydown", { key: "Escape" });
  assert.equal(app.menu(), undefined);
  vm.runInContext("KumApeIocMenu.stop()", app.context);
  assert.equal(app.label.children.length, 0);
  await app.ready(); assert.equal(app.label.children.length, 1);
});

test("event header menu reuses the current event actions", async () => {
  const app = fixture(); await app.ready();
  assert.equal(app.headingWrapper.children.length, 1);
  assert.equal(app.plainTitle.children.length, 0);
  assert.equal(app.unrelatedTitle.children.length, 0);
  assert.equal(app.eventButton().textContent, "🐵 Действия");
  assert.equal(app.correlationButton().textContent, "🐵 Действия");
  await app.eventButton().emit("click");
  const menu = app.menu();
  assert.deepEqual([...menu.children.filter((node) => node.tag === "button").map((node) => node.textContent)], ["📌 В расследование", "Копировать JSON", "Запросить JSON по API", "Копировать ссылку", "Скачать JSON"]);
  await menu.children.find((node) => node.textContent === "📌 В расследование").emit("click");
  assert.equal(app.messages.at(-1).type, "investigation:event:add");
  assert.equal(app.messages.at(-1).event.ID, "event-id");
  await menu.children.find((node) => node.textContent === "Копировать JSON").emit("click");
  await menu.children.find((node) => node.textContent === "Запросить JSON по API").emit("click");
  await menu.children.find((node) => node.textContent === "Копировать ссылку").emit("click");
  assert.match(app.clipboard[0], /"ID": "event-id"/);
  assert.match(app.clipboard[1], /"Timestamp": "2026-09-08T07:00:00Z"/);
  assert.equal(app.clipboard[2], "https://kuma.test:7220/events/event-id");
  assert.equal(app.messages.find((message) => message.type === "event:json").event.ID, "event-id");
});

test("menu does not mount on another port of the permitted hostname", async () => {
  const app = fixture("https://kuma.test:7223"); await app.ready();
  assert.equal(app.label.children.length, 0);
  assert.equal(app.messages.length, 0);
});
