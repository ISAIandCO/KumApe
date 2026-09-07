import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const sources = await Promise.all(["shared/kuma-adapter.js", "shared/investigation-db.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));
function api(extra = {}) { const context = vm.createContext({ URL, Date, Math, ...extra }); for (const source of sources) vm.runInContext(source, context); return context.KumApeInvestigations; }

test("version 1 migration creates investigation stores and indexes", async () => {
  const stores = new Map();
  const indexedDB = { open(name, version) {
    assert.equal(name, "kumape-investigations"); assert.equal(version, 1);
    const db = { createObjectStore(storeName, options) { const indexes = []; const store = { options, createIndex: (...args) => indexes.push(args) }; stores.set(storeName, { store, indexes }); return store; } };
    const request = { result: db };
    queueMicrotask(() => { request.onupgradeneeded(); request.onsuccess(); });
    return request;
  } };
  await api({ indexedDB, queueMicrotask }).open();
  assert.deepEqual([...stores.keys()], ["investigations", "items"]);
  assert.ok(stores.get("items").indexes.some(([name]) => name === "byInvestigationTime"));
  assert.ok(stores.get("items").indexes.some(([name, , options]) => name === "byEntity" && options.multiEntry));
});

test("investigation event descriptions and entities are analyst-friendly", () => {
  const event = { DeviceEventClassID: "4688", DeviceHostName: "HOST01", DestinationProcessName: "powershell.exe", SourceUserName: "DOMAIN\\alice", SourceAddress: "10.0.0.1" };
  assert.match(api().describeEvent(event), /Запущен процесс powershell\.exe/);
  assert.deepEqual([...api().entityKeys(event)], ["host:host01", "account:domain\\alice", "process:powershell.exe", "ip:10.0.0.1"]);
});

test("Markdown export keeps timeline sorted by repository caller", () => {
  const investigation = { title: "Case 1", status: "open", updatedAt: "2026-09-07T00:00:00Z", tags: ["test"], notes: "Проверить родителя" };
  const markdown = api().toMarkdown(investigation, [{ timestamp: "2026-09-07T00:01:00Z", label: "Запущен процесс" }]);
  assert.match(markdown, /^# Case 1/);
  assert.match(markdown, /## Заметки/);
  assert.match(markdown, /Запущен процесс/);
});
