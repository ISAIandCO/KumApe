import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const files = await Promise.all(["shared/kuma-adapter.js", "shared/ioc-providers.js", "background/ioc-lookup.js", "background/background.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));
function storage(data) {
  return {
    async get(keys) {
      if (typeof keys === "string") return { [keys]: data[keys] };
      if (Array.isArray(keys)) return Object.fromEntries(keys.filter((key) => key in data).map((key) => [key, data[key]]));
      return { ...keys, ...Object.fromEntries(Object.keys(keys).filter((key) => key in data).map((key) => [key, data[key]])) };
    },
    async set(values) { Object.assign(data, values); },
    async remove(keys) { for (const key of [keys].flat()) delete data[key]; },
  };
}
function background(local = {}, session = {}, fetchImpl = () => { throw new Error("Unexpected network call"); }, granted = true) {
  let handler;
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout, TextEncoder, btoa,
    fetch: fetchImpl,
    browser: {
      storage: { local: storage(local), session: storage(session) },
      permissions: { contains: async () => granted },
      runtime: { getURL: (path) => `moz-extension://test/${path}`, onMessage: { addListener: (fn) => { handler = fn; } }, openOptionsPage: async () => {} },
      tabs: { create: async () => {} },
    },
  });
  for (const file of files) vm.runInContext(file, context);
  return { context, message: (message, sender) => handler(message, sender) };
}

test("session token migrates once, survives background reload, and never appears in config", async () => {
  const local = { uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "saved-cluster", fieldProfiles: [] };
  const session = { apiToken: "synthetic-key", iocApiKeys: { virustotal: "synthetic-vt" } };
  const first = background(local, session);
  const config = await first.message({ type: "config:get" });
  assert.equal(config.config.tokenPresent, true);
  assert.equal(JSON.stringify(config).includes("synthetic"), false);
  assert.equal(local.apiToken, "synthetic-key");
  assert.deepEqual(session, {});
  const restarted = await background(local, {}).message({ type: "config:get" });
  assert.equal(restarted.config.tokenPresent, true);
  assert.equal(restarted.config.clusterId, "saved-cluster");
  assert.deepEqual(restarted.config.fieldProfiles, []);
});

test("persistent keys take precedence over older session keys", async () => {
  const local = { apiToken: "new", iocApiKeys: { virustotal: "new-vt" } };
  await background(local, { apiToken: "old", iocApiKeys: { virustotal: "old-vt" } }).message({ type: "config:get" });
  assert.equal(local.apiToken, "new");
  assert.equal(local.iocApiKeys.virustotal, "new-vt");
});

test("events 403 identifies the missing POST permission without retrying or changing authentication", async () => {
  let requests = 0;
  const app = background({ uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", apiToken: "synthetic", clusterId: "c" }, {}, async (url, options) => {
    requests++;
    assert.equal(url.pathname, "/api/v3/events");
    assert.equal(options.method, "POST");
    assert.equal(options.credentials, "omit");
    assert.equal(options.headers.Authorization, "Bearer synthetic");
    assert.match(JSON.parse(options.body).sql, /^SELECT /);
    return new Response("access denied", { status: 403 });
  });
  const event = { SourceAddress: "8.8.8.8", Timestamp: "2026-09-07T00:00:00Z" };
  const actions = await app.message({ type: "related:actions", event });
  const response = await app.message({ type: "related:search", event, action: actions.actions[0] });
  assert.equal(response.ok, false);
  assert.match(response.error, /POST \/api\/v3\/events: HTTP 403/);
  assert.match(response.error, /одних GET-прав недостаточно/);
  assert.equal(requests, 1);
});

test("content senders are restricted to configured KUMA and IOC messages; extension options still work", async () => {
  const app = background({ uiOrigin: "https://kuma.test" });
  assert.equal((await app.message({ type: "config:get" }, { tab: { id: 1 }, url: "moz-extension://test/options/options.html" })).ok, true);
  assert.equal((await app.message({ type: "config:get" }, { tab: { id: 1 }, url: "https://kuma.test/events" })).ok, false);
  assert.equal((await app.message({ type: "ioc:options" }, { tab: { id: 1 }, url: "https://other.test" })).ok, false);
  assert.equal((await app.message({ type: "ioc:options" }, { tab: { id: 1 }, url: "https://kuma.test/events" })).ok, true);
});

test("IOC lookups use persistent provider keys, fixed endpoints and GET only", async () => {
  const cases = [
    ["virustotal", "ip", "8.8.8.8", "www.virustotal.com", "/api/v3/ip_addresses/8.8.8.8", "x-apikey", { data: { attributes: { last_analysis_stats: { malicious: 1 } } } }],
    ["opentip", "sha256", "a".repeat(64), "opentip.kaspersky.com", "/api/v1/search/hash", "x-api-key", { Zone: "Red" }],
    ["abuseipdb", "ip", "8.8.8.8", "api.abuseipdb.com", "/api/v2/check", "Key", { data: { abuseConfidenceScore: 10 } }],
  ];
  for (const [provider, type, value, hostname, path, header, body] of cases) {
    const app = background({ iocApiKeys: { [provider]: "provider-key" }, apiToken: "kuma-key" }, {}, async (url, options) => {
      assert.equal(url.hostname, hostname);
      assert.equal(url.pathname, path);
      assert.equal(options.method, "GET");
      assert.equal(options.headers[header], "provider-key");
      assert.equal(options.headers.Authorization, undefined);
      assert.equal(options.credentials, "omit");
      assert.equal(options.redirect, "error");
      assert.equal(options.body, undefined);
      return Response.json(body);
    });
    const response = await app.message({ type: "ioc:lookup", provider, ioc: { type, value } });
    assert.equal(response.ok, true, response.error);
    assert.ok(response.result.summary);
  }
});

test("invalid IOC, unknown provider, missing key and denied permissions never send a request", async () => {
  const app = background({ iocApiKeys: { virustotal: "key" } });
  for (const message of [
    { provider: "unknown", ioc: { type: "ip", value: "8.8.8.8" } },
    { provider: "virustotal", ioc: { type: "ip", value: "::::" } },
    { provider: "virustotal", ioc: { type: "url", value: "https://user:password@example.org" } },
    { provider: "opentip", ioc: { type: "domain", value: "example.org" } },
  ]) assert.equal((await app.message({ type: "ioc:lookup", ...message })).ok, false);
  assert.equal((await background({ iocApiKeys: { virustotal: "key" } }, {}, undefined, false).message({ type: "ioc:lookup", provider: "virustotal", ioc: { type: "ip", value: "8.8.8.8" } })).ok, false);
});

test("provider 404 is unknown, 429 is a rate limit, and malformed reports are errors", async () => {
  for (const [response, expected] of [[new Response("", { status: 404 }), /Отчёт не найден/], [new Response("", { status: 429 }), /Лимит запросов/], [Response.json({}), /нет результатов/]]) {
    const app = background({ iocApiKeys: { virustotal: "key" } }, {}, async () => response);
    const result = await app.message({ type: "ioc:lookup", provider: "virustotal", ioc: { type: "ip", value: "8.8.8.8" } });
    assert.match(result.error || result.result.summary, expected);
  }
});
