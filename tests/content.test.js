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

test("extracts KUMA 4.6 event fields and raw text from marked DOM", () => {
  const field = (id, data, displayed = data) => ({
    getAttribute: (name) => ({ "kuma-id": id, "kuma-data": data }[name] ?? null),
    querySelector: () => ({ textContent: displayed }),
  });
  const rawNode = {
    tagName: "PRE",
    textContent: "<30>1 2024-01-01T00:00:00Z example.invalid app - - - synthetic event",
    parentElement: { textContent: "Исходное событие" },
  };
  const fields = [
    field("TenantID", "tenant-1", "Synthetic tenant"),
    field("Timestamp", "1704067200000", "01.01.2024 00:00:00.000"),
    field("Message", "service stopped"),
    field("DeviceHostName", "host-01"),
    field("SpaceID", "", "Synthetic space"),
  ];
  const documentObject = {
    title: "KUMA",
    body: { innerText: "KUMA event" },
    querySelector: (selector) => selector === '[kuma-section="raw"] pre' ? rawNode : null,
    querySelectorAll: (selector) => ({
      "pre, textarea, code": [rawNode],
      '[kuma-section="event-field"][kuma-id]': fields,
      "table, dl, [role='dialog'], [class*='detail']": [],
      pre: [rawNode],
    }[selector] || []),
  };

  const context = page.extractPageContext(documentObject, "https://kuma.example.local/events");
  assert.deepEqual({ ...context.event }, {
    TenantID: "tenant-1",
    Timestamp: "1704067200000",
    Message: "service stopped",
    DeviceHostName: "host-01",
    SpaceID: "Synthetic space",
  });
  assert.equal(context.raw, rawNode.textContent);
  assert.equal(context.source, "kuma-fields");
});
