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
  assert.ok(graph.edges.some((edge) => edge.source === "event:pc:new" && edge.target === "event:pc:child"));
  assert.ok(!graph.edges.some((edge) => edge.source === "event:pc:old" && edge.target === "event:pc:child"));
  assert.ok(!graph.edges.some((edge) => edge.source === "event:other:other" && edge.target === "event:pc:child"));
  assert.equal(graph.sourceNodeId, "event:pc:child");
});

test("GUID relationship takes precedence over a reused PID", () => {
  const parent = event("p", "10", "1", "2026-09-07T10:00:00Z", "pc", { GuidX: "parent-guid" });
  const wrong = event("w", "10", "1", "2026-09-07T10:00:30Z", "pc", { GuidX: "wrong-guid" });
  const child = event("c", "20", "10", "2026-09-07T10:01:00Z", "pc", { GuidX: "child-guid", ParentGuidX: "parent-guid" });
  const graph = api().buildGraph([parent, wrong, child], child, [mapping]);
  assert.ok(graph.edges.some((edge) => edge.source.includes("parent-guid") && edge.target.includes("child-guid")));
});

test("graph removes duplicate KUMA IDs and correlation events", () => {
  const source = event("source", "20", "10", "2026-09-07T10:01:00Z", "pc", { ID: "source-id" });
  const first = event("first", "30", "20", "2026-09-07T10:02:00Z", "pc", { ID: "duplicate-id", GuidX: "guid-a" });
  const duplicate = event("duplicate", "31", "20", "2026-09-07T10:02:01Z", "pc", { ID: "duplicate-id", GuidX: "guid-b" });
  const correlation = event("correlation", "40", "20", "2026-09-07T10:03:00Z", "pc", { ID: "correlation-id", Type: 3 });
  const graph = api().buildGraph([source, first, duplicate, correlation], source, [mapping]);
  assert.deepEqual([...graph.nodes.map((node) => node.event.ID)].sort(), ["duplicate-id", "source-id"]);
  assert.equal(api().mappingForEvent(correlation, [mapping]), null);
});

test("legacy Sysmon profile migrates by DeviceEventClassID rather than category", () => {
  const migrated = api().mappingsFromLegacyProfiles([{ name: "Sysmon", when: { DeviceEventCategory: ["Sysmon"], DeviceEventClassID: ["1"] }, processGraph: { host: ["HostX"], pid: ["PidX"], parentPid: ["ParentX"] } }]);
  assert.equal(migrated[0].eventIdField, "DeviceEventClassID");
  assert.equal(migrated[0].eventIdValue, "1");
  assert.deepEqual([...migrated[0].eventCategories], ["Sysmon"]);
});

test("built-in process mappings qualify ambiguous Event IDs by category", () => {
  const model = api();
  const legacy = { ...model.BUILTIN_PROCESS_MAPPINGS[1], name: "Old custom mapping", eventCategories: [] };
  assert.equal(model.mappingForEvent({ DeviceEventClassID: "1", DeviceEventCategory: "qemu-ga" }, [legacy]), null);
  const legacyAction = model.graphSearchAction({ DeviceEventClassID: "1", DeviceEventCategory: "Sysmon", DeviceHostName: "pc", DeviceProcessID: "20", SourceProcessID: "10" }, [legacy]);
  assert.equal(legacyAction.sourceMapping.name, "Old custom mapping");
  assert.match(legacyAction.where, /DeviceEventCategory IN \('Microsoft-Windows-Sysmon'/);
  assert.equal(model.mappingForEvent({ DeviceEventClassID: "1", DeviceEventCategory: "qemu-ga" }), null);
  assert.equal(model.mappingForEvent({ DeviceEventClassID: "1", DeviceEventCategory: "Microsoft-Windows-Sysmon/Operational" }).name, "Sysmon Process Create 1");
  assert.equal(model.mappingForEvent({ DeviceEventClassID: "4688" }), null);
  const event4688 = { DeviceEventClassID: "4688", DeviceEventCategory: "Microsoft-Windows-Security-Auditing", DeviceHostName: "pc", DeviceCustomString5: "20", DeviceCustomString3: "10" };
  const action = model.graphSearchAction(event4688);
  assert.match(action.where, /DeviceEventClassID = '4688' AND DeviceEventCategory = 'Microsoft-Windows-Security-Auditing'/);
  assert.match(action.where, /DeviceEventClassID = '1' AND DeviceEventCategory IN \('Microsoft-Windows-Sysmon'/);
});

test("4688 chooses a coherent PID pair, normalizes hex, and preserves custom mappings", () => {
  const model=api(); const defaults=model.BUILTIN_PROCESS_MAPPINGS;
  const e={DeviceEventClassID:'4688',DeviceEventCategory:'Microsoft-Windows-Security-Auditing',DeviceHostName:'pc',DeviceCustomString5:'0x14',DeviceCustomString3:'0x0a',DestinationProcessID:'999',SourceProcessID:'888'};
  assert.equal(model.processFields(e,model.mappingForEvent(e)).pid,'20');
  assert.equal(model.processFields(e,model.mappingForEvent(e)).parentPid,'10');
  delete e.DeviceCustomString5;
  assert.equal(model.processFields(e,model.mappingForEvent(e)).pid,'999');
  assert.equal(model.processFields(e,model.mappingForEvent(e)).parentPid,'888');
  const custom={...defaults[0],pid:'MyPid',parentPid:'MyParent',fallbackPid:'',fallbackParentPid:''};
  assert.equal(model.processFields({...e,MyPid:'42',MyParent:'1'},custom).pid,'42');
});

test("step graph excludes unrelated candidates, other hosts, and later PID reuse", () => {
  const model=api();
  const child=event('child','20','10','2026-09-07T10:01:00Z');
  const parent=event('parent','10','1','2026-09-07T10:00:00Z');
  const unrelated=event('unrelated','99','1','2026-09-07T10:00:00Z');
  const later=event('later','10','1','2026-09-07T10:02:00Z');
  const graph=model.buildGraph([child,parent,unrelated,later],child,[mapping]);
  const step=model.connectedGraph(graph,graph.sourceNodeId,'parents');
  assert.deepEqual([...step.nodes.map(n=>n.pid)].sort(),['10','20']);
  const action=model.relatedAction(child,[mapping],'parents');
  assert.match(action.where,/HostX = 'pc'/);assert.match(action.where,/PidX = '10'/);assert.doesNotMatch(action.where,/ParentX = '20'/);
});

test("step queries use numeric literals for KUMA process ID fields and keep hex variants for strings", () => {
  const model = api();
  const source = { DeviceEventClassID: "4688", DeviceEventCategory: "Microsoft-Windows-Security-Auditing", DeviceHostName: "pc", DeviceCustomString5: "0x14", DeviceCustomString3: "0x0a" };
  const action = model.relatedAction(source, model.BUILTIN_PROCESS_MAPPINGS, "both");
  assert.match(action.where, /DeviceCustomString5 = '10'/);
  assert.match(action.where, /DeviceCustomString5 = '0xa'/);
  assert.match(action.where, /DestinationProcessID = 10/);
  assert.match(action.where, /SourceProcessID = 20/);
  assert.doesNotMatch(action.where, /(?:SourceProcessID|DestinationProcessID|DeviceProcessID) = '/);
});
