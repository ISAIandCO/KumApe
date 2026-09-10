import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import { readFile, access } from "node:fs/promises";
const source = await readFile(new URL("../src/background/content-registration.js", import.meta.url), "utf8");

test("automatic menu registration uses a Firefox host pattern and injects existing KUMA tabs", async () => {
  const registrations = [], injections = [], stopped = [];
  const local = { uiOrigin: "https://kuma.test:7220" };
  let permitted = true;
  const listen = { addListener() {} };
  const context = vm.createContext({ URL,
    browser: {
      storage: { local: { get: async () => local }, onChanged: listen },
      permissions: { contains: async () => permitted, onAdded: listen, onRemoved: listen },
      scripting: {
        getRegisteredContentScripts: async () => registrations,
        unregisterContentScripts: async () => { registrations.length = 0; },
        registerContentScripts: async (items) => { registrations.push(...items); },
        executeScript: async (injection) => { injections.push(injection); },
      },
      tabs: { query: async () => [{ id: 1, url: "https://kuma.test:7220/events" }, { id: 2, url: "https://kuma.test:7223/api" }, { id: 3, url: "https://other.test" }],
        sendMessage: async (tab) => { stopped.push(tab); },
      },
    },
  });
  const adapter = buildSync({ entryPoints: [fileURLToPath(new URL("../src/shared/kuma-adapter.js", import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text;
  vm.runInContext(adapter, context);
  vm.runInContext(source, context);
  await vm.runInContext("contentSync", context);
  assert.deepEqual(Array.from(registrations[0].matches), ["https://kuma.test/*"]);
  for (const file of registrations[0].js) await access(new URL(`../src/${file}`, import.meta.url));
  assert.ok(registrations[0].js.indexOf("content/content.js") < registrations[0].js.indexOf("content/ioc-menu.js"));
  assert.equal(injections.length, 1);
  assert.equal(injections[0].target.tabId, 1);
  assert.ok(injections[0].files.every((file) => file.startsWith("/")));
  permitted = false;
  await vm.runInContext("syncIocContent()", context);
  assert.equal(registrations.length, 0);
  assert.equal(injections.length, 1);
  assert.deepEqual(stopped.slice(-3), [1, 2, 3]);
});
