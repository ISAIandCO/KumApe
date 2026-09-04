import test from "node:test";
import assert from "node:assert/strict";

await import("../src/shared/kuma-adapter.js");
const api = globalThis.KumApeAdapter;

test("normalizes KUMA origins without credentials or paths", () => {
  assert.equal(api.normalizeOrigin("kuma.example.local:7220/path"), "https://kuma.example.local:7220");
  assert.throws(() => api.normalizeOrigin("ftp://kuma.example.local"));
  assert.throws(() => api.normalizeOrigin("https://user:pass@kuma.example.local"));
});

test("escapes SQL values and rejects statement chaining", () => {
  assert.equal(api.escapeSqlString("o'hara\\host"), "o\\'hara\\\\host");
  assert.equal(
    api.buildEventsQuery(api.equalityWhere(["SourceAddress", "DestinationAddress"], "10.0.0.1"), 5000),
    "SELECT * FROM `events` WHERE (SourceAddress = '10.0.0.1' OR DestinationAddress = '10.0.0.1') ORDER BY Timestamp DESC LIMIT 1000",
  );
  assert.throws(() => api.buildEventsQuery("1 = 1; DROP TABLE events"));
});

test("creates related actions from normalized KUMA fields", () => {
  const actions = api.buildRelatedActions({
    Timestamp: "2026-09-04T08:00:00Z",
    SourceAddress: "10.0.0.1",
    DestinationAddress: "10.0.0.2",
    DeviceHostName: "host-01",
    SourceUserName: "ivan",
  });
  assert.deepEqual(actions.map((item) => [item.kind, item.value]), [
    ["ip", "10.0.0.1"],
    ["ip", "10.0.0.2"],
    ["host", "host-01"],
    ["account", "ivan"],
  ]);
});

test("builds a bounded ISO period around the event", () => {
  assert.deepEqual(api.eventPeriod({ Timestamp: "2026-09-04T08:00:00Z" }, 300), {
    from: "2026-09-04T07:55:00.000Z",
    to: "2026-09-04T08:05:00.000Z",
  });
});

test("normalizes common cluster and event response envelopes", () => {
  assert.deepEqual(api.clustersFromResponse({ data: { clusters: [{ ID: "c1", Name: "Main" }] } })[0], {
    id: "c1",
    name: "Main",
    raw: { ID: "c1", Name: "Main" },
  });
  assert.deepEqual(api.eventsFromResponse({ data: { events: [{ ID: "e1" }] } }), [{ ID: "e1" }]);
});

test("extracts IOC values only from likely event fields", () => {
  const iocs = api.iocsFromEvent({ SourceAddress: "192.0.2.1", RequestURL: "https://example.org/a", Message: "192.0.2.2" });
  assert.deepEqual(iocs.map((item) => item.value), ["192.0.2.1", "https://example.org/a"]);
});

test("sends a bounded read-only events request through the adapter", async () => {
  const calls = [];
  const adapter = new api.KumaAdapter({
    uiOrigin: "https://kuma.example.local:7220",
    apiOrigin: "https://kuma.example.local:7223",
    clusterId: "cluster-1",
    token: "secret",
  }, async (request) => {
    calls.push(request);
    return { events: [{ ID: "event-1" }] };
  });
  const event = { Timestamp: "2026-09-04T08:00:00Z", SourceAddress: "192.0.2.1" };
  const [action] = api.buildRelatedActions(event);
  const result = await adapter.searchRelated(action, event, 300, 250);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].path, "/api/v3/events");
  assert.equal(calls[0].body.clusterID, "cluster-1");
  assert.equal(calls[0].body.period.from, "2026-09-04T07:55:00.000Z");
  assert.deepEqual(result.events, [{ ID: "event-1" }]);
});
