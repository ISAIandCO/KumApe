import { buildSync } from "esbuild";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

const sources = ["shared/kuma-adapter.js", "shared/process-model.js", "shared/useful-filters.js"].map(path => buildSync({ entryPoints: [fileURLToPath(new URL(`../src/${path}`, import.meta.url))], bundle: true, write: false, format: "iife", platform: "browser" }).outputFiles[0].text);
function api() { const context = vm.createContext({ URL, TextEncoder }); for (const source of sources) vm.runInContext(source, context); return context.KumApeFilters; }

test("catalog explains unavailable filters and builds useful Windows predicates", () => {
  const filters = api().buildUsefulFilters({ DeviceEventClassID: "4688", DeviceEventCategory: "Microsoft-Windows-Security-Auditing", DeviceHostName: "host01", DestinationProcessID: "4120", SourceProcessID: "2032", DestinationProcessName: "powershell.exe" });
  assert.equal(filters.find((item) => item.id === "process-on-host").applicable, true);
  assert.match(filters.find((item) => item.id === "process-on-host").where, /DeviceEventClassID IN \('4688', '1'\)/);
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

test("Windows-only templates are absent for Unix and unknown sources, including saved defaults", () => {
  const filters = api();
  const saved = JSON.parse(JSON.stringify(filters.BUILTIN_FILTERS));
  saved.forEach(item => delete item.platforms);
  for (const event of [{ DeviceProduct: "Linux", DeviceHostName: "h" }, { DeviceHostName: "h" }, { destinationprocessname: "/usr/bin/bash", DeviceHostName: "h" }]) {
    const result = filters.buildUsefulFilters(event, undefined, undefined, saved);
    assert.equal(result.some(item => item.id === "service-install-host"), false);
    assert.equal(result.some(item => item.id === "command-line-4688"), false);
    assert.equal(result.find(item => item.id === "host-events").applicable, true);
  }
  assert.equal(filters.buildUsefulFilters({ DeviceProduct: "Microsoft Windows", DeviceHostName: "h" }).find(item => item.id === "service-install-host").applicable, true);
});

test("mixed built-in templates use the detected OS while custom queries remain intact", () => {
  const filters = api();
  const event = { DeviceProduct: "Linux", DeviceHostName: "h" };
  const query = filters.buildUsefulFilters(event).find(item => item.id === "process-on-host").where;
  assert.match(query, /DeviceEventClassID IN \('EXECVE'\)/);
  assert.doesNotMatch(query, /4688/);
  const custom = [{ id: "process-on-host", template: "DeviceHostName = '${DeviceHostName}' AND DeviceEventClassID = 'CUSTOM'" }];
  assert.match(filters.buildUsefulFilters(event, undefined, undefined, custom)[0].where, /CUSTOM/);
});

test("SQL mode supports static and parameterized queries without WHERE wrapping", () => {
  const filters = api();
  const userFilters = [{ id: "agg", mode: "sql", template: "SELECT DestinationAddress, count(ID) AS attempts FROM `events` WHERE SourceAddress = '${SourceAddress}' GROUP BY DestinationAddress HAVING attempts > 1 ORDER BY attempts DESC LIMIT 500", timeRange: "24h" }];
  const catalog = { userFilters, disabledBuiltinFilterIds: ["host-events"] };
  const results = filters.buildUsefulFilters({ SourceAddress: "x' OR 1=1 --", DeviceHostName: "host" }, undefined, undefined, catalog);
  assert.equal(results.some(item => item.id === "host-events"), false);
  const query = results.find(item => item.id === "user:agg");
  assert.equal(query.where, undefined);
  assert.match(query.sql, /GROUP BY DestinationAddress HAVING attempts > 1 ORDER BY attempts DESC LIMIT 500$/);
  assert.match(query.sql, /x\\' OR 1=1 --/);
  const staticFilters = filters.buildUsefulFilters({}, undefined, undefined, { userFilters: [{ id: "static", mode: "sql", template: "SELECT count(ID) AS attempts FROM `events`" }] });
  assert.equal(staticFilters.find(item => item.id === "user:static").applicable, true);
  assert.throws(() => filters.normalizeFilterTemplates([{ id: "bad", mode: "sql", template: "SELECT * FROM `events` WHERE Message LIKE '%${Message}%'" }]), /Подстановка/);
});

test("legacy edits migrate once and survive newer built-ins", () => {
  const filters = api();
  const saved = JSON.parse(JSON.stringify(filters.BUILTIN_FILTERS));
  saved[0].name = "Мой узел";
  saved[1].enabled = false;
  const migrated = filters.migrateFilterCatalog(saved);
  assert.equal(migrated.userFilters.length, 1);
  assert.equal(migrated.userFilters[0].name, "Мой узел");
  assert.ok(migrated.disabledBuiltinFilterIds.includes("host-events"));
  assert.ok(migrated.disabledBuiltinFilterIds.includes("event-id"));
});

test("an incompatible legacy template is preserved without disabling other filters", () => {
  const filters = api();
  const legacy = [{ id: "partial", template: "Message LIKE '%${Message}%'" }];
  const migrated = filters.migrateFilterCatalog(legacy);
  assert.equal(migrated.userFilters[0].template, legacy[0].template);
  const result = filters.buildUsefulFilters({ Message: "hello", DeviceHostName: "h" }, undefined, undefined, migrated);
  assert.equal(result.find(item => item.id === "host-events").applicable, true);
  assert.equal(result.find(item => item.id === "user:partial").applicable, false);
});

test("formatted templates persist verbatim and only executable placeholders are required", () => {
  const filters = api();
  const template = "  -- пояснение ${Absent} и даже ${незакончено\nSELECT\n    Timestamp,\n    CASE\n      -- Проверяем Sub status\n      WHEN DeviceCustomString1 = '0xc000006a' THEN 'Неверный пароль'\n      ELSE concat('Sub: ', DeviceCustomString1, ' / Status: ', DeviceCustomString6)\n    END AS Failure_Reason\nFROM `events`\nWHERE DestinationUserName = '${DestinationUserName}'\nORDER BY Timestamp DESC;\n";
  const stored = filters.normalizeFilterTemplate({ id: "failed-logons", name: "Входы", mode: "sql", template });
  assert.equal(stored.template, template);
  assert.deepEqual([...filters.requiredTemplateFields(template)], ["DestinationUserName"]);
  const compiled = filters.buildUsefulFilters({ DestinationUserName: "a'--b" }, undefined, undefined, { userFilters: [stored] }).find(item => item.id === "user:failed-logons");
  assert.equal(compiled.applicable, true);
  assert.match(compiled.sql, /CASE WHEN DeviceCustomString1/);
  assert.doesNotMatch(compiled.sql, /пояснение|Проверяем|Absent/);
  assert.match(compiled.sql, /a\\'--b/);
  assert.match(compiled.sql, /ORDER BY Timestamp DESC$/);
  assert.equal(stored.template, template);
});

test("the complete 4625 CASE example survives storage and compiles without its comments", async () => {
  const { readFile } = await import("node:fs/promises");
  const template = await readFile(new URL("./fixtures/sql/windows-logon-failures.sql", import.meta.url), "utf8");
  const filters = api();
  const stored = filters.normalizeFilterTemplate({ id: "4625", mode: "sql", template });
  assert.equal(stored.template, template);
  const result = filters.buildUsefulFilters({ DestinationUserName: "test-user" }, undefined, undefined, { userFilters: [stored] }).find(item => item.id === "user:4625");
  assert.equal(result.applicable, true);
  assert.doesNotMatch(result.sql, /--|\n/);
  assert.match(result.sql, /THEN 'Неверный пароль'/);
  assert.match(result.sql, /DestinationUserName = 'test-user'/);
  assert.equal((result.sql.match(/WHEN /g) || []).length, (template.match(/WHEN /g) || []).length);
});
