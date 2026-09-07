import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/shared/ai-privacy.js", import.meta.url), "utf8");
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
