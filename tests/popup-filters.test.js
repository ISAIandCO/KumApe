import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../src/popup/popup.js", import.meta.url), "utf8");
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.value = ""; }
  addEventListener() {}
  append(child) { child.parentElement = this; this.children.push(child); }
  add(child) { this.append(child); }
  replaceChildren() { this.children = []; }
  remove() { this.parentElement.children = this.parentElement.children.filter(child => child !== this); }
}

test("popup places built-ins and users inside their own optgroups", async () => {
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id); };
  const context = vm.createContext({ URL,
    document: { querySelector: get, createElement: tag => new Element(tag) },
    Option: function(text, value) { const option = new Element("option"); option.textContent = text; option.value = value; return option; },
    browser: { tabs: { query: async () => [{ url: "about:blank" }] }, runtime: { getManifest: () => ({ version: "test" }), sendMessage: async message => message.type === "config:get" ? { ok: true, config: {} } : { ok: true, filters: [
      { id: "host-events", title: "Узел", source: "builtin", applicable: true },
      { id: "user:custom", title: "Свой", source: "user", applicable: true },
      { id: "no-field", title: "Недоступен", source: "builtin", applicable: false, missing: ["FileHash"] },
    ] } } },
  });
  vm.runInContext(source, context);
  await vm.runInContext('initialize()', context);
  await vm.runInContext('state.context = {event: {DeviceHostName: "host"}}; renderFilters()', context);
  const select = get("#useful-filter");
  assert.deepEqual(select.children.map(group => group.label), ["Встроенные", "Пользовательские"]);
  assert.deepEqual(select.children[0].children.map(option => option.value).sort(), ["host-events", "no-field"]);
  assert.deepEqual(select.children[1].children.map(option => option.value), ["user:custom"]);
  assert.equal(select.children[0].children.find(option => option.value === "no-field").disabled, true);
});
