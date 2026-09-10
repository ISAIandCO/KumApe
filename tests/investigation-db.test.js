import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const sources = ["shared/kuma-adapter.js", "shared/investigation-db.js"].map(path => buildSync({ entryPoints: [fileURLToPath(new URL(`../src/${path}`, import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text);
function api(extra = {}) { const context = vm.createContext({ URL, Date, Math, crypto: webcrypto, TextEncoder, ...extra }); for (const source of sources) vm.runInContext(source, context); return context.KumApeInvestigations; }

test("version 2 opens the shared workspace and chat stores", async () => {
  const stores = new Map();
  const indexedDB = { open(name, version) {
    assert.equal(name, "kumape-investigations"); assert.equal(version, 2);
    const db = { objectStoreNames: { contains: name => stores.has(name) }, createObjectStore(storeName, options) { const indexes = []; const store = { options, createIndex: (...args) => indexes.push(args) }; stores.set(storeName, { store, indexes }); return store; } };
    const request = { result: db };
    queueMicrotask(() => { request.onupgradeneeded(); request.onsuccess(); });
    return request;
  } };
  await api({ indexedDB, queueMicrotask }).open();
  assert.deepEqual([...stores.keys()], ["workspaces", "aiChats"]);
  assert.ok(stores.get("workspaces").indexes.some(([name]) => name === "updatedAt"));
  assert.equal(stores.get("aiChats").store.options.keyPath, "workspaceId");
});

test("investigation event descriptions and entities are analyst-friendly", () => {
  const event = { DeviceEventClassID: "4688", DeviceHostName: "HOST01", DestinationProcessName: "powershell.exe", SourceUserName: "DOMAIN\\alice", SourceAddress: "10.0.0.1" };
  assert.match(api().describeEvent(event), /Запущен процесс «powershell\.exe»/);
  assert.deepEqual([...api().entityKeys(event)], ["host:host01", "account:domain\\alice", "process:powershell.exe", "ip:10.0.0.1"]);
});

test("Markdown export keeps timeline sorted by repository caller", () => {
  const investigation = { title: "Case 1", status: "open", updatedAt: Date.parse("2026-09-07T00:00:00Z"), tags: ["test"], notes: "Проверить родителя" };
  const markdown = api().toMarkdown({ ...investigation, items: [{ type: "event", value: "event1", snapshot: {}, label: "Запущен процесс" }] });
  assert.match(markdown, /^# Case 1/);
  assert.match(markdown, /## Analyst notes/);
  assert.match(markdown, /Запущен процесс/);
});
