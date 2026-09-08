import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const files = await Promise.all(["shared/kuma-adapter.js", "shared/process-model.js", "shared/useful-filters.js", "shared/ai-privacy.js", "shared/ioc-providers.js", "background/ioc-lookup.js", "background/background.js"].map((path) => (["shared/ioc-providers.js", "background/ioc-lookup.js"].includes(path) ? buildSync({ entryPoints: [fileURLToPath(new URL(`../src/${path}`, import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text : readFile(new URL(`../src/${path}`, import.meta.url), "utf8"))));
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
  const createdTabs = [];
  const context = vm.createContext({ URL, AbortController, setTimeout, clearTimeout, TextEncoder, btoa,
    fetch: fetchImpl,
    browser: {
      storage: { local: storage(local), session: storage(session) },
      permissions: { contains: async () => granted },
      runtime: { getURL: (path) => `moz-extension://test/${path}`, onMessage: { addListener: (fn) => { handler = fn; } }, openOptionsPage: async () => {} },
      tabs: { create: async (options) => { createdTabs.push(options); return { id: createdTabs.length, ...options }; }, get: async id => id === 99 ? {id,url:"https://kuma.test/events"} : {id,...createdTabs[id-1]}, update: async (id,options) => ({id,...options}) },
    },
  });
  for (const file of files) vm.runInContext(file, context);
  return { context, createdTabs, message: (message, sender) => handler(message, sender) };
}

test("session token migrates once, survives background reload, and secrets never appear in config", async () => {
  const local = { uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "saved-cluster", fieldProfiles: [], aiApiKey: "synthetic-ai-key" };
  const session = { apiToken: "synthetic-key", iocApiKeys: { virustotal: "synthetic-vt" } };
  const first = background(local, session);
  const config = await first.message({ type: "config:get" });
  assert.equal(config.config.tokenPresent, true);
  assert.equal(config.config.aiKeyPresent, true);
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

test("related query is rebuilt in background and opens the native KUMA threat-hunting URI", async () => {
  const session = {};
  const app = background({ uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "c", fieldProfiles: [] }, session);
  const event = { SourceAddress: "8.8.8.8", Timestamp: "2026-09-07T00:00:00Z" };
  const action = (await app.message({ type: "related:actions", event })).actions[0];
  const query = await app.message({ type: "related:query", event, action: { ...action, where: "malicious = 'yes'" } });
  assert.match(query.query, /SourceAddress = '8\.8\.8\.8'/);
  assert.doesNotMatch(query.query, /malicious/);
  const opened = await app.message({ type: "related:open-tab", event, action, rangeSeconds: 900 });
  assert.equal(opened.ok, true);
  assert.equal(app.createdTabs.length, 1);
  const url = new URL(app.createdTabs[0].url);
  assert.equal(url.origin, "https://kuma.test");
  assert.equal(url.pathname, "/threat-hunting");
  assert.match(url.hash, /^#\/threat-hunting\?search=%257B/);
  const encoded = new URLSearchParams(url.hash.split("?")[1]).get("search");
  const payload = JSON.parse(decodeURIComponent(encoded));
  assert.match(payload.sql, /SourceAddress = '8\.8\.8\.8'/);
  assert.deepEqual(payload.period, { relative: "now-15m", relativeTo: "now" });
  assert.deepEqual(session, {});
});

test("legacy processGraph settings migrate to separate Event ID mappings", async () => {
  const local = { fieldProfiles: [{ name: "Custom 4688", when: { DeviceEventClassID: ["4688"] }, fields: { host: ["HostX"] }, processGraph: { host: ["HostX"], pid: ["DeviceCustomString3"], parentPid: ["DeviceCustomString5"], image: ["ImageX"] } }] };
  const app = background(local);
  const response = await app.message({ type: "config:get" });
  assert.equal(response.config.processMappings[0].pid, "DeviceCustomString3");
  assert.equal(response.config.processMappings[0].parentPid, "DeviceCustomString5");
  assert.equal("processGraph" in local.fieldProfiles[0], false);
});

test("stored Event ID 1 mappings gain Sysmon categories", async () => {
  const local = { processMappings: [
    { name: "Sysmon Process Create 1", eventIdField: "DeviceEventClassID", eventIdValue: "1" },
    { name: "Custom", eventIdField: "DeviceEventClassID", eventIdValue: "1" },
  ] };
  await background(local).message({ type: "config:get" });
  assert.deepEqual([...local.processMappings[0].eventCategories], ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"]);
  assert.deepEqual([...local.processMappings[1].eventCategories], ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"]);
});

test("process graph request uses configured PID fields and opens graph page", async () => {
  const mappings = [{ name: "Custom", eventIdField: "DeviceEventClassID", eventIdValue: "4688", host: "HostX", pid: "DeviceCustomString3", parentPid: "DeviceCustomString5", processGuid: "", parentGuid: "", image: "ImageX", commandLine: "", user: "", eventRecordId: "ID" }];
  const session = {}; const app = background({ uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "c", processMappings: mappings }, session);
  const response = await app.message({ type: "process:open-graph", event: { DeviceEventClassID: "4688", HostX: "pc", DeviceCustomString3: "42", DeviceCustomString5: "7" } });
  assert.equal(response.ok, true, response.error);
  const url = new URL(app.createdTabs[0].url);
  assert.equal(url.pathname, "/process-graph/graph.html");
  assert.ok(session[`processRequest:${url.searchParams.get("id")}`]);
});

test("useful filters are typed, hide predicates from UI, and reject an inapplicable id", async () => {
  const app = background({ uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "c" });
  const event = { DeviceEventClassID: "4688", DeviceHostName: "host01", DestinationProcessID: "42", SourceProcessID: "7" };
  const result = await app.message({ type: "filters:list", event });
  const processes = result.filters.find((filter) => filter.id === "process-on-host");
  assert.equal(processes.applicable, true);
  assert.equal("where" in processes, false);
  assert.match(processes.preview, /DeviceHostName = 'host01'/);
  const query = await app.message({ type: "filters:query", filterId: processes.id, event });
  assert.match(query.query, /DeviceHostName = 'host01'/);
  assert.equal((await app.message({ type: "filters:query", filterId: "events-by-hash", event })).ok, false);
});

test("custom useful filters are rebuilt from stored templates", async () => {
  const usefulFilters = [{ id: "custom-ip", name: "Мой IP", description: "Локальный шаблон", template: "SourceAddress = '${SourceAddress}'", timeRange: "7d", enabled: true }];
  const app = background({ uiOrigin: "https://kuma.test", apiOrigin: "https://kuma.test:7223", clusterId: "c", usefulFilters });
  const event = { SourceAddress: "10.0.0.1" };
  const listed = await app.message({ type: "filters:list", event });
  assert.equal(listed.filters.find((filter) => filter.id === "custom-ip").rangeSeconds, 604800);
  const query = await app.message({ type: "filters:query", filterId: "custom-ip", event });
  assert.match(query.query, /SourceAddress = '10\.0\.0\.1'/);
});

test("local AI keeps event data out of URLs and sends only the prepared payload with its own key", async () => {
  const session = {};
  let body;
  const app = background({ ai: { enabled: true, endpoint: "http://127.0.0.1:8080/v1", model: "synthetic", privacyMode: "strict" }, aiApiKey: "local-ai-secret" }, session, async (url, options) => {
    assert.equal(url.href, "http://127.0.0.1:8080/v1/chat/completions");
    assert.equal(options.headers.Authorization, "Bearer local-ai-secret");
    body = JSON.parse(options.body);
    return Response.json({ choices: [{ message: { content: "Локальный ответ" } }] });
  });
  const opened = await app.message({ type: "ai:open", event: { DeviceHostName: "host01", Raw: "SECRET-RAW", RequestCookies: "SECRET-COOKIE" } });
  assert.equal(opened.ok, true);
  const url = new URL(app.createdTabs[0].url);
  assert.equal(url.pathname, "/ai/assistant.html");
  assert.equal(url.href.includes("host01"), false);
  const response = await app.message({ type: "ai:chat", id: url.searchParams.get("id"), messages: [{ role: "user", content: "Что произошло?" }] });
  assert.equal(response.content, "Локальный ответ");
  assert.match(JSON.stringify(body), /host01/);
  assert.doesNotMatch(JSON.stringify(body), /SECRET-RAW|SECRET-COOKIE/);
});

test("local AI accepts LAN endpoints and rejects public endpoints before network access", async () => {
  const lan = background({ ai: { enabled: true, endpoint: "http://192.168.1.10:8080/v1", model: "x", privacyMode: "strict" } });
  assert.equal((await lan.message({ type: "ai:open", event: { DeviceHostName: "host01" } })).ok, true);
  const app = background({ ai: { enabled: true, endpoint: "https://example.org/v1", model: "x", privacyMode: "strict" } });
  const response = await app.message({ type: "ai:open", event: { DeviceHostName: "host01" } });
  assert.equal(response.ok, false);
  assert.match(response.error, /локальн/i);
  assert.equal(app.createdTabs.length, 0);
});

test("content senders are restricted to configured KUMA and IOC messages; extension options still work", async () => {
  const app = background({ uiOrigin: "https://kuma.test" });
  assert.equal((await app.message({ type: "config:get" }, { tab: { id: 1 }, url: "moz-extension://test/options/options.html" })).ok, true);
  assert.equal((await app.message({ type: "config:get" }, { tab: { id: 1 }, url: "https://kuma.test/events" })).ok, false);
  assert.equal((await app.message({ type: "ioc:options" }, { tab: { id: 1 }, url: "https://other.test" })).ok, false);
  assert.equal((await app.message({ type: "investigation:event:add", event: {} }, { tab: { id: 1 }, url: "https://other.test" })).ok, false);
  assert.equal((await app.message({ type: "ioc:options" }, { tab: { id: 1 }, url: "https://kuma.test/events" })).ok, true);
});

test("event header action adds the event to the latest open investigation", async () => {
  const app = background({ uiOrigin: "https://kuma.test" });
  let added;
  app.context.KumApeInvestigations = {
    listInvestigations: async () => [{ id: "inv-1", title: "Case 1", status: "open" }],
    createInvestigation: async () => { throw new Error("Unexpected investigation creation"); },
    addEvent: async (...args) => { added = args; },
  };
  const event = { ID: "event-id" };
  const response = await app.message({ type: "investigation:event:add", event }, { tab: { id: 1 }, url: "https://kuma.test/events/event-id" });
  assert.equal(response.ok, true, response.error);
  assert.equal(response.investigation.title, "Case 1");
  assert.equal(added[0], "inv-1");
  assert.equal(added[1], event);
  assert.equal(added[2].url, "https://kuma.test/events/event-id");
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

test("provider 401 distinguishes a rejected saved key from a missing key", async () => {
  const app = background({ iocApiKeys: { virustotal: "  rejected-key  " } }, {}, async (_url, options) => {
    assert.equal(options.headers["x-apikey"], "rejected-key");
    return new Response("", { status: 401 });
  });
  const result = await app.message({ type: "ioc:lookup", provider: "virustotal", ioc: { type: "ip", value: "8.8.8.8" } });
  assert.match(result.error, /Сохранённый ключ отклонён API провайдера/);
});

test("step mode queries selected relations, merges expansions and rejects foreign node IDs", async () => {
 const event=(id,pid,parent,time)=>({ID:id,DeviceEventClassID:'4688',DeviceEventCategory:'Microsoft-Windows-Security-Auditing',DeviceHostName:'pc',DeviceCustomString5:pid,DeviceCustomString3:parent,Timestamp:`2026-09-07T10:${time}:00Z`});
 const source=event('source','20','10','01'),parent=event('parent','10','1','00'),child=event('child','30','20','02'),foreign=event('foreign','99','1','00');
 let calls=0;
 const app=background({uiOrigin:'https://kuma.test',apiOrigin:'https://kuma.test:7223',clusterId:'c',apiToken:'synthetic'}, {}, async(url,options)=>{
   const query=JSON.parse(options.body).sql; assert.match(query,/DeviceHostName = 'pc'/);assert.doesNotMatch(query,/(?:SourceProcessID|DestinationProcessID|DeviceProcessID) = '/);
   calls++; return Response.json({events:calls===1?[source,parent,foreign]:[child,foreign]});
 });
 const opened=await app.message({type:'process:open-graph',event:source});const id=opened.result.id;
 const first=await app.message({type:'process:request:run',id,mode:'step'});assert.equal(first.ok,true,first.error);
 assert.deepEqual([...first.result.graph.nodes.map(n=>n.pid)].sort(),['10','20']);
 const sourceId=first.result.graph.sourceNodeId;
 const expanded=await app.message({type:'process:expand',id,nodeId:sourceId,direction:'children'});assert.equal(expanded.ok,true,expanded.error);
 assert.deepEqual([...expanded.result.graph.nodes.map(n=>n.pid)].sort(),['10','20','30']);
 const rejected=await app.message({type:'process:expand',id,nodeId:'not-in-graph',direction:'parents'});assert.equal(rejected.ok,false);assert.equal(calls,2);
});

test("graph nodes fall back to the universal KUMA ID when the mapped ID is unavailable", async () => {
 const mappings=[{name:"Custom",eventIdField:"DeviceEventClassID",eventIdValue:"4688",host:"HostX",pid:"PidX",parentPid:"ParentX",processGuid:"",parentGuid:"",image:"",commandLine:"",user:"",eventRecordId:"CustomEventId",fallbackPid:"",fallbackParentPid:""}];
 const session={};const app=background({uiOrigin:"https://kuma.test",apiOrigin:"https://kuma.test:7223",clusterId:"c",processMappings:mappings},session);
 const occurredAt="2026-09-07T10:01:21.123Z";
 const event={ID:"event-uuid",DeviceEventClassID:"4688",HostX:"pc",PidX:"20",ParentX:"10",Timestamp:occurredAt};
 const opened=await app.message({type:"process:event:open",event,rangeSeconds:900});
 assert.equal(opened.ok,true,opened.error);
 const url=new URL(app.createdTabs[0].url);
 const encoded=new URLSearchParams(url.hash.split("?")[1]).get("search");
 const payload=JSON.parse(decodeURIComponent(encoded));
 assert.match(payload.sql,/ID = 'event-uuid'/);
 assert.doesNotMatch(payload.sql,/Timestamp =/);
 assert.match(payload.sql,/LIMIT 250$/);
 const from=Math.floor(Date.parse(occurredAt)/60_000)*60_000;
 assert.deepEqual(payload.period,{from,to:from+59_999});
 assert.deepEqual(session,{});
});

test('AI reuses a chat for a source tab and sanitizes appended events',async()=>{
 const session={};const local={uiOrigin:'https://kuma.test',ai:{enabled:true,endpoint:'http://127.0.0.1:8080/v1',privacyMode:'strict'}};const app=background(local,session);
 assert.equal((await app.message({type:'ai:open',sourceTabId:99,event:{DeviceHostName:'first',Raw:'SECRET'}})).ok,true);
 assert.equal((await app.message({type:'ai:open',sourceTabId:99,event:{DeviceHostName:'second',Raw:'SECRET'}})).ok,true);
 assert.equal(app.createdTabs.length,1);
 const payload=Object.entries(local).find(([key])=>key.startsWith('aiRequest:'))[1].payload;
 assert.equal(payload.Events.length,2);assert.equal(JSON.stringify(payload).includes('SECRET'),false);
});


test("AI preserves complete ApePatrol endpoints and rejects stale previews", async () => {
  for (const endpoint of ["http://192.168.1.10:1234/v1/chat/completions", "http://192.168.1.10:1234/custom/completions/"]) {
    let calls = 0;
    const local = {ai:{enabled:true,endpoint,model:"model",privacyMode:"strict"}};
    const app = background(local, {}, async (url, options) => {
      calls++; assert.equal(url.href, endpoint); assert.equal(options.redirect,"error");
      return Response.json({choices:[{message:{content:"OK"}}]});
    });
    const input = {event:{DeviceHostName:"host"},messages:[{role:"user",content:"Analyze"}]};
    const {preview} = await app.message({...input,type:"ai:preview"});
    assert.equal(calls,0);
    assert.equal((await app.message({...input,type:"ai:chat",preview})).ok,true);
    local.ai.model="changed";
    assert.equal((await app.message({...input,type:"ai:chat",preview})).ok,false);
    assert.equal(calls,1);
  }
});

test("ThreatFox uses the common client through KumApe key and permission adapters", async () => {
  const app = background({ iocApiKeys: { threatfox: "  fox-key  " }, apiToken: "kuma-key" }, {}, async (url, options) => {
    assert.equal(url.href, "https://threatfox-api.abuse.ch/api/v1/");
    assert.equal(options.method, "POST");
    assert.equal(options.headers["Auth-Key"], "fox-key");
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.credentials, "omit");
    assert.equal(options.redirect, "error");
    assert.deepEqual(JSON.parse(options.body), { query: "search_hash", hash: "a".repeat(64) });
    return Response.json({ query_status: "ok", data: [{ malware: "test", confidence_level: 90 }] });
  });
  const result = await app.message({ type: "ioc:lookup", provider: "threatfox", ioc: { type: "sha256", value: "a".repeat(64) } });
  assert.equal(result.ok, true, result.error);
  assert.equal(result.result.verdict, "malicious");
  assert.equal(app.context.KumApeIoc.PROVIDERS.threatfox.origin, "https://threatfox-api.abuse.ch");
  const denied = background({ iocApiKeys: { threatfox: "key" } }, {}, undefined, false);
  assert.equal((await denied.message({ type: "ioc:lookup", provider: "threatfox", ioc: { type: "domain", value: "evil.example" } })).ok, false);
});
