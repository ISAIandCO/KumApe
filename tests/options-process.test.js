import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";

const source = buildSync({ entryPoints: [fileURLToPath(new URL("../src/options/options.js", import.meta.url))], bundle: true, write: false, format: "iife" }).outputFiles[0].text;
const html = await readFile(new URL("../src/options/options.html", import.meta.url), "utf8");
const apiSources = ["shared/kuma-adapter.js", "shared/process-model.js"].map(path => buildSync({ entryPoints: [fileURLToPath(new URL(`../src/${path}`, import.meta.url))], bundle: true, write: false, format: "iife" }).outputFiles[0].text);

function options(mapping) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { style: {}, handlers: {}, replaceChildren() {}, append() {}, setAttribute() {}, addEventListener(name, fn) { this.handlers[name] = fn; } });
    return elements.get(id);
  };
  const writes = [];
  const context = vm.createContext({ URL, TextEncoder,
    KumApeFilters: { BUILTIN_FILTERS: [], normalizeFilterTemplate: item => item },
    document: { createElement: () => element(Symbol()), createTextNode: text => text, querySelector: element, querySelectorAll: () => [{ querySelectorAll: () => Object.entries(mapping).map(([key, value]) => ({ dataset: { key }, value: String(value) })) }] },
    browser: { runtime: { sendMessage: async () => ({ ok: false, error: "initial loading disabled for test" }) }, storage: { local: { set: async value => writes.push(value) } }, permissions: { request: () => assert.fail("Graph saving must not request permissions") } },
  });
  for (const apiSource of apiSources) vm.runInContext(apiSource, context);
  vm.runInContext(source, context);
  return { elements, writes, save: () => element("#save-process-mappings").handlers.click() };
}

test("graph save persists just the graph settings without validating other sections", async () => {
  assert.match(html, /id="save-process-mappings" type="button"/);
  const app = options({ name: "Execve", matchMode: "execve", eventIdField: "DeviceEventClassID", eventIdValue: "EXECVE", host: "DeviceHostName", pid: "DestinationProcessID", parentPid: "SourceProcessID" });
  await app.save();
  assert.equal(app.writes.length, 1);
  assert.deepEqual(Object.keys(app.writes[0]).sort(), ["graphMappingsRevision", "processMappings"]);
  assert.equal(app.writes[0].processMappings[0].matchMode, "execve");
  assert.equal(app.writes[0].processMappings[0].pid, "DestinationProcessID");
  assert.equal(app.elements.get("#process-mappings-status").textContent, "Настройки графа сохранены.");
  assert.equal(app.elements.get("#save-process-mappings").disabled, false);
});

test("invalid graph settings stay unsaved and show a local error", async () => {
  const app = options({ name: "Broken", eventIdField: "DeviceEventClassID", eventIdValue: "EXECVE", host: "DeviceHostName", pid: "", parentPid: "SourceProcessID" });
  await app.save();
  assert.equal(app.writes.length, 0);
  assert.match(app.elements.get("#process-mappings-status").textContent, /поле обязательно/);
  assert.equal(app.elements.get("#save-process-mappings").disabled, false);
});
