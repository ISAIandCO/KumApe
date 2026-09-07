import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const sources = await Promise.all(["shared/kuma-adapter.js", "shared/process-model.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));
function api() { const context = vm.createContext({ URL, TextEncoder }); for (const source of sources) vm.runInContext(source, context); return context.KumApeProcess; }
const mapping = { name: "4688 custom", eventIdField: "DeviceEventClassID", eventIdValue: "4688", host: "HostX", pid: "PidX", parentPid: "ParentX", processGuid: "GuidX", parentGuid: "ParentGuidX", image: "ImageX", commandLine: "CmdX", user: "UserX", eventRecordId: "IdX" };
const event = (id, pid, parentPid, time, host = "pc", extra = {}) => ({ DeviceEventClassID: "4688", HostX: host, PidX: pid, ParentX: parentPid, ImageX: `${id}.exe`, IdX: id, Timestamp: time, ...extra });

test("custom Event ID mapping builds a host-wide process query", () => {
  const action = api().graphSearchAction(event("e2", "20", "10", "2026-09-07T10:01:00Z"), [mapping]);
  assert.match(action.where, /DeviceEventClassID = '4688'/);
  assert.match(action.where, /HostX = 'pc'/);
  assert.equal(action.source.pid, "20");
});

test("graph links parent to child, isolates hosts and resolves PID reuse to closest prior process", () => {
  const events = [
    event("old", "10", "1", "2026-09-07T09:00:00Z"), event("new", "10", "1", "2026-09-07T10:00:00Z"),
    event("child", "20", "10", "2026-09-07T10:01:00Z"), event("other", "10", "1", "2026-09-07T10:00:30Z", "other"),
  ];
  const graph = api().buildGraph(events, events[2], [mapping]);
  assert.ok(graph.edges.some((edge) => edge.source === "event:new" && edge.target === "event:child"));
  assert.ok(!graph.edges.some((edge) => edge.source === "event:old" && edge.target === "event:child"));
  assert.ok(!graph.edges.some((edge) => edge.source === "event:other" && edge.target === "event:child"));
  assert.equal(graph.sourceNodeId, "event:child");
});

test("GUID relationship takes precedence over a reused PID", () => {
  const parent = event("p", "10", "1", "2026-09-07T10:00:00Z", "pc", { GuidX: "parent-guid" });
  const wrong = event("w", "10", "1", "2026-09-07T10:00:30Z", "pc", { GuidX: "wrong-guid" });
  const child = event("c", "20", "10", "2026-09-07T10:01:00Z", "pc", { GuidX: "child-guid", ParentGuidX: "parent-guid" });
  const graph = api().buildGraph([parent, wrong, child], child, [mapping]);
  assert.ok(graph.edges.some((edge) => edge.source.includes("parent-guid") && edge.target.includes("child-guid")));
});

test("legacy Sysmon profile migrates by DeviceEventClassID rather than category", () => {
  const migrated = api().mappingsFromLegacyProfiles([{ name: "Sysmon", when: { DeviceEventCategory: ["Sysmon"], DeviceEventClassID: ["1"] }, processGraph: { host: ["HostX"], pid: ["PidX"], parentPid: ["ParentX"] } }]);
  assert.equal(migrated[0].eventIdField, "DeviceEventClassID");
  assert.equal(migrated[0].eventIdValue, "1");
});
