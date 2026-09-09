import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";

const source = buildSync({ entryPoints: [fileURLToPath(new URL("../src/shared/ai-privacy.js", import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text;
function api() { const context = vm.createContext({ TextEncoder, structuredClone }); vm.runInContext(source, context); return context.KumApeAiPrivacy; }

test("strict AI preview excludes raw data, cookies and secrets", () => {
  const result = api().preview({ Timestamp: "2026-09-07T00:00:00Z", DeviceHostName: "host01", Raw: "SECRET-RAW", RequestCookies: "session=secret", ApiToken: "secret" }, "strict");
  assert.deepEqual([...result.fields], ["Timestamp", "DeviceHostName"]);
  assert.equal(JSON.stringify(result.payload).includes("SECRET"), false);
  assert.ok(result.bytes > 0);
});

test("redacted AI mode recursively masks secret fields and inline tokens", () => {
  const result = api().prepareEvent({ Extra: { password: "one", note: "token=two" } }, "redacted");
  assert.equal(result.Extra.password, "[REDACTED]");
  assert.equal(result.Extra.note, "token=[REDACTED]");
});

test("investigation AI sanitizes every event in strict mode", () => {
 const prepared=api().prepareEvent({Events:[{DeviceHostName:'pc',Raw:'secret',ApiToken:'secret'}]},'strict');
 assert.equal(prepared.Events[0].DeviceHostName,'pc');assert.equal(JSON.stringify(prepared).includes('secret'),false);
});

test("AI context merge and stored history keep each event once", () => {
  const privacy = api();
  const first = { DeviceHostName: "first" };
  const second = { DeviceHostName: "second" };
  const merged = privacy.mergeContexts([first, first, { Events: [first, second] }], "strict");
  assert.deepEqual(JSON.parse(JSON.stringify(merged.payload)), { Events: [first, second] });
  const compacted = privacy.compactMessageContexts([
    { role: "user", content: "one", context: first },
    { role: "user", content: "two", context: { Events: [first, second] } },
    { role: "user", content: "three", context: second },
  ]);
  assert.deepEqual(JSON.parse(JSON.stringify(compacted.map((message) => message.context ?? null))), [first, second, null]);
});
