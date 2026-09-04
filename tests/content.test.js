import test from "node:test";
import assert from "node:assert/strict";

await import("../src/content/content.js");
const page = globalThis.KumApePage;

test("parses JSON event candidates and ignores arbitrary text", () => {
  assert.deepEqual(page.parseJsonCandidate('{"SourceAddress":"192.0.2.1"}'), { SourceAddress: "192.0.2.1" });
  assert.equal(page.parseJsonCandidate("CEF:0|vendor|product"), null);
});

test("scores event-shaped JSON above unrelated JSON", () => {
  const unrelated = { hello: "world", value: 1 };
  const event = { Timestamp: "2026-09-04T08:00:00Z", Message: "login", SourceAddress: "192.0.2.1" };
  assert.ok(page.candidateScore(event, JSON.stringify(event)) > page.candidateScore(unrelated, JSON.stringify(unrelated)));
});

test("extracts route identifiers without depending on KUMA DOM", () => {
  const context = page.routeContext("https://kuma.example.local/events?tenantId=t1&eventId=e1#/details");
  assert.equal(context.origin, "https://kuma.example.local");
  assert.equal(context.eventId, "e1");
  assert.equal(context.tenantId, "t1");
});
