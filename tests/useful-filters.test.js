import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const sources = await Promise.all(["shared/kuma-adapter.js", "shared/process-model.js", "shared/useful-filters.js"].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));
function api() { const context = vm.createContext({ URL, TextEncoder }); for (const source of sources) vm.runInContext(source, context); return context.KumApeFilters; }

test("catalog explains unavailable filters and builds useful Windows predicates", () => {
  const filters = api().buildUsefulFilters({ DeviceEventClassID: "4688", DeviceEventCategory: "Microsoft-Windows-Security-Auditing", DeviceHostName: "host01", DestinationProcessID: "4120", SourceProcessID: "2032", DestinationProcessName: "powershell.exe" });
  assert.equal(filters.find((item) => item.id === "process-on-host").applicable, true);
  assert.match(filters.find((item) => item.id === "process-on-host").where, /DeviceEventClassID IN \('4688', '1', 'EXECVE'\)/);
  assert.match(filters.find((item) => item.id === "powershell-host").where, /DeviceProcessName ILIKE '%powershell\.exe'/);
  assert.match(filters.find((item) => item.id === "process-relatives").where, /DeviceEventClassID = '4688'/);
  assert.equal(filters.find((item) => item.id === "events-by-hash").applicable, false);
  assert.match(filters.find((item) => item.id === "events-by-hash").missing[0], /FileHash/);
  assert.ok(filters.length >= 50);
});

test("separate Event ID mapping controls process relationship fields", () => {
  const profiles = [{ name: "Custom", when: { DeviceEventClassID: ["custom"] }, fields: { host: ["HostX"], process: ["ImageX"] } }];
  const mappings = [{ name: "Custom graph", eventIdField: "DeviceEventClassID", eventIdValue: "custom", host: "HostX", pid: "PidX", parentPid: "ParentX", image: "ImageX" }];
  const relative = api().buildUsefulFilters({ DeviceEventClassID: "custom", HostX: "h", PidX: "10", ParentX: "5", ImageX: "x" }, profiles, mappings).find((item) => item.id === "process-relatives");
  const processSearch = api().buildUsefulFilters({ DeviceEventClassID: "custom", HostX: "h", PidX: "10", ParentX: "5", ImageX: "x" }, profiles, mappings).find((item) => item.id === "process-on-host");
  assert.equal(relative.applicable, true);
  assert.match(relative.where, /HostX = 'h'/);
  assert.match(relative.where, /DeviceEventClassID = 'custom'/);
  assert.match(processSearch.where, /HostX = 'h'/);
});

test("editable templates report every missing field and escape inserted values", () => {
  const filters = [{ id: "custom", name: "Свой фильтр", description: "Тест", template: "SourceAddress = '${SourceAddress}' AND DestinationPort = ${DestinationPort}", timeRange: "7d", enabled: true }];
  const missing = api().buildUsefulFilters({ SourceAddress: "10.0.0.1" }, undefined, undefined, filters)[0];
  assert.deepEqual([...missing.missing], ["DestinationPort"]);
  const rendered = api().buildUsefulFilters({ sourceaddress: "x' OR '1'='1", DestinationPort: 443 }, undefined, undefined, filters)[0];
  assert.equal(rendered.rangeSeconds, 7 * 86400);
  assert.match(rendered.where, /x\\' OR \\'1\\'=\\'1/);
  assert.match(rendered.where, /DestinationPort = 443/);
});

test("legacy numeric placeholders and built-in OR chains migrate to typed compact SQL", () => {
  const filters = api();
  const numeric = filters.renderFilterTemplate("SourcePort = '${SourcePort}'", { SourcePort: 443 });
  assert.equal(numeric.where, "SourcePort = 443");
  assert.equal(filters.renderFilterTemplate("SourcePort = ${SourcePort}", { SourcePort: "not-a-number" }).ok, false);
  const [migrated] = filters.migrateBuiltinFilters([{
    id: "auth-by-ip",
    template: "${@ip} AND (DeviceEventClassID = '4624' OR DeviceEventClassID = '4625' OR DeviceEventClassID = '4648' OR DeviceEventClassID = '4771' OR DeviceEventClassID = '4776' OR DeviceEventClassID = 'USER_AUTH' OR DeviceEventClassID = 'USER_LOGIN')",
  }]);
  assert.match(migrated.template, /DeviceEventClassID IN \('4624'/);
  assert.doesNotMatch(migrated.template, /OR DeviceEventClassID/);
});

test("filter settings reject unsafe SQL and duplicate ids", () => {
  assert.throws(() => api().normalizeFilterTemplates([{ id: "x", template: "Field = ${Field}; DROP TABLE events" }]), /SQL-шаблон/);
  assert.throws(() => api().normalizeFilterTemplates([{ id: "x", template: "Field = ${Field}" }, { id: "x", template: "Other = ${Other}" }]), /Повторяется id/);
});
