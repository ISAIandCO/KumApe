import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const sources = await Promise.all(["shared/kuma-adapter.js", "shared/useful-filters.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));
function api() { const context = vm.createContext({ URL, TextEncoder }); for (const source of sources) vm.runInContext(source, context); return context.KumApeFilters; }

test("catalog explains unavailable filters and builds useful Windows predicates", () => {
  const filters = api().buildUsefulFilters({ DeviceEventClassID: "4688", DeviceHostName: "host01", DestinationProcessID: "4120", SourceProcessID: "2032", DestinationProcessName: "powershell.exe" });
  assert.equal(filters.find((item) => item.id === "process-on-host").applicable, true);
  assert.match(filters.find((item) => item.id === "process-relatives").where, /SourceProcessID = '4120'/);
  assert.equal(filters.find((item) => item.id === "events-by-hash").applicable, false);
  assert.match(filters.find((item) => item.id === "events-by-hash").reason, /хеш/);
});

test("profile override controls process relationship fields", () => {
  const profiles = [{ name: "Custom", when: { DeviceEventClassID: ["custom"] }, fields: { host: ["HostX"], process: ["ImageX"] }, processGraph: { host: ["HostX"], pid: ["PidX"], parentPid: ["ParentX"], image: ["ImageX"] } }];
  const relative = api().buildUsefulFilters({ DeviceEventClassID: "custom", HostX: "h", PidX: "10", ParentX: "5", ImageX: "x" }, profiles).find((item) => item.id === "process-relatives");
  assert.equal(relative.applicable, true);
  assert.match(relative.where, /ParentX = '10'/);
  assert.match(relative.where, /PidX = '5'/);
});
