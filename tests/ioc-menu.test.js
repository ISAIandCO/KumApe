import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";
const sources = await Promise.all(["shared/kuma-adapter.js", "shared/ioc-providers.js", "content/ioc-menu.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));

function fixture(origin = "https://kuma.test:7220") {
  const observers = [];
  const messages = [];
  const fields = [];
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
    querySelectorAll(selector) { return selector === "*" ? fields : fields.filter((node) => node.isConnected); }
    getBoundingClientRect() { return { left: 50, top: 40, bottom: 60 }; }
    remove() { this.isConnected = false; if (this.parent) this.parent.children = this.parent.children.filter((node) => node !== this); }
    showPopover() { this.visible = true; }
    matches() { return this.visible; }
    focus() {}
  }
  const document = new Element("document");
  document.documentElement = new Element("html");
  document.createElement = (tag) => new Element(tag);
  const field = new Element("div");
  field.setAttribute("kuma-id", "SourceAddress"); field.setAttribute("kuma-data", "8.8.8.8");
  const label = new Element("span"); label.textContent = "SourceAddress"; const value = new Element("span"); value.textContent = "8.8.8.8"; field.append(label, value); fields.push(field);
  const context = vm.createContext({ URL, AbortController, document, location: { origin }, innerWidth: 1200, innerHeight: 900,
    window: new Element("window"),
    // Mutation callbacks are triggered explicitly, so tests don't rely on wall-clock timing.
    setTimeout: (fn) => { observers.push(fn); return observers.length; }, clearTimeout() {},
    MutationObserver: class { constructor(fn) { this.callback = fn; } observe() {} disconnect() {} },
    browser: { storage: { local: { get: async () => ({ uiOrigin: "https://kuma.test:7220" }) } }, runtime: { onMessage: { addListener() {} }, sendMessage: async (message) => {
      messages.push(message); return { ok: true, result: { provider: "Test", summary: "Synthetic report" } };
    } } },
  });
  for (const source of sources) vm.runInContext(source, context);
  const button = () => label.children[0]?.closedRoot.children[0];
  const menu = () => document.documentElement.children.at(-1)?.closedRoot.children.find((node) => node.tag === "section");
  return { context, document, field, label, value, button, menu, messages, elements, ready: () => vm.runInContext("KumApeIocMenu.start()", context) };
}

test("inline menu mounts once, sends nothing on open, and queries only the selected IOC", async () => {
  const app = fixture(); await app.ready();
  await app.ready(); assert.equal(app.label.children.length, 1);
  assert.equal(app.field.children[1], app.value);
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

test("menu does not mount on another port of the permitted hostname", async () => {
  const app = fixture("https://kuma.test:7223"); await app.ready();
  assert.equal(app.label.children.length, 0);
  assert.equal(app.messages.length, 0);
});
