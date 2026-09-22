import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { buildSync } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { searchKumaOperations, DEFAULT_OPERATION_PROFILES } from '../src/shared/operation-search.js';
const source = buildSync({ entryPoints: [fileURLToPath(new URL('../src/shared/kuma-adapter.js', import.meta.url))], bundle: true, write: false, format: 'iife' }).outputFiles[0].text;
const context = vm.createContext({ URL, TextEncoder }); vm.runInContext(source, context);
const api = context.KumApeAdapter;
const from = Date.parse('2026-01-01T00:00:00Z');
const process = { host: 'workstation.example', pid: '42', guid: '', from, to: from + 60000, platform: 'windows' };
const profile = { ...DEFAULT_OPERATION_PROFILES[0], enabled: true, pid: 'ActorPid', target: 'CustomPath', guid: 'ActorGuid' };
const event = id => ({ ID: String(id), DeviceHostName: process.host, DeviceEventCategory: 'Sysmon', DeviceEventClassID: '11', ActorPid: '42', CustomPath: '/example/file', Timestamp: from + 1000 });
test('KUMA requests exactly 25 records on the server and advances stable SQL offset', async () => {
  const requests = [];
  const client = new api.KumaAdapter({ uiOrigin: 'https://kuma.example', apiOrigin: 'https://kuma.example', clusterId: 'test' }, async request => { requests.push(request); return { events: Array.from({ length: 25 }, (_, i) => event(i)) }; });
  const options = { api, client, config: { operationProfiles: { version: 1, profiles: [profile] } } };
  const first = await searchKumaOperations({ process, category: 'files' }, options);
  assert.equal(first.facts.length, 25); assert.equal(first.facts[0].label, '/example/file');
  await searchKumaOperations({ process, category: 'files', cursor: first.cursor }, options);
  assert.match(requests[0].body.sql, /ORDER BY Timestamp ASC, ID ASC LIMIT 25 OFFSET 0$/);
  assert.match(requests[1].body.sql, /LIMIT 25 OFFSET 25$/);
  assert.match(requests[0].body.sql, /ActorPid IN/); assert.match(requests[0].body.sql, /Type != 3/);
  assert.match(requests[0].body.sql, /DeviceHostName = 'workstation.example'/);
  assert.equal(requests[0].body.period.from, new Date(from).toISOString());
  assert.equal(requests[0].path, '/api/v3/events');
});
test('KUMA source GUID query and configured targets do not confuse actor with target', async () => {
  let sql;
  const result = await searchKumaOperations({ process: { ...process, guid: 'abc' }, category: 'access' }, {
    api, config: { operationProfiles: [{ ...profile, category: 'access', target: 'DestinationProcessName', targetPid: 'DestinationProcessID' }] },
    client: { searchRelated: async action => { sql = action.sql; return { events: [{ ...event(1), ActorGuid: '{ABC}', DestinationProcessName: 'target.exe', DestinationProcessID: 999 }] }; } },
  });
  assert.match(sql, /ActorGuid/); assert.doesNotMatch(sql, /DestinationProcessID =/);
  assert.equal(result.facts[0].pid, '42'); assert.match(result.facts[0].label, /999/);
});
test('KUMA empty, unsupported OS and API errors are not conflated', async () => {
  const options = { api, config: { operationProfiles: [profile] }, client: { searchRelated: async () => ({ events: [] }) } };
  assert.equal((await searchKumaOperations({ process, category: 'files' }, options)).scanned, 0);
  assert.ok((await searchKumaOperations({ process: { ...process, platform: 'unix' }, category: 'files' }, options)).unsupported);
  options.client.searchRelated = async () => { throw new Error('HTTP 500'); };
  await assert.rejects(searchKumaOperations({ process, category: 'files' }, options), /HTTP 500/);
});
test('configured Linux syscall profile narrows operation as well as source and event type', async () => {
  let sql;
  const profile = { ...DEFAULT_OPERATION_PROFILES[0], id: 'custom-audit', enabled: true, platform: 'unix', sourceField: 'DeviceProduct', sourceValues: 'audit', eventValues: 'SYSCALL', operationField: 'Name', operationValues: 'openat', target: 'FilePath' };
  const result = await searchKumaOperations({ process: { ...process, platform: 'unix' }, category: 'files' }, {
    api, config: { operationProfiles: [profile] }, client: { searchRelated: async action => { sql = action.sql; return { events: [{ ID: 'synthetic', Timestamp: from + 1000, DeviceHostName: process.host, SourceProcessID: 42, DeviceProduct: 'audit', DeviceEventClassID: 'SYSCALL', Name: 'openat', FilePath: '/example/file' }] }; } },
  });
  assert.match(sql, /Name IN \('openat'\)/); assert.match(sql, /DeviceEventClassID IN \('SYSCALL'\)/);
  assert.equal(result.facts.length, 1);
});
test('malformed KUMA response is not displayed as an empty search', async () => {
  const client = new api.KumaAdapter({ uiOrigin: 'https://kuma.example', apiOrigin: 'https://kuma.example', clusterId: 'test' }, async () => ({ unexpected: true }));
  await assert.rejects(searchKumaOperations({ process, category: 'files' }, { api, client, config: { operationProfiles: [profile] } }), /неизвестный формат/);
});

test('Windows Security and Linux catalog profiles apply their configured classifiers and initiators in SQL and parsing', async () => {
  for (const preset of DEFAULT_OPERATION_PROFILES.filter(item => !item.id.startsWith('sysmon-'))) {
    const configured = { ...preset, enabled: true, sourceField: 'DeviceProduct', sourceValues: 'synthetic-source', pid: 'DestinationProcessID', target: 'FilePath', operationField: preset.selectorRequired ? 'DeviceCustomString1' : '', action: 'DeviceCustomString2', outcome: 'DeviceAction' };
    const record = { ID: `fixture-${preset.id}`, Timestamp: from + 1000, DeviceHostName: process.host, DeviceProduct: 'synthetic-source', DeviceEventClassID: preset.eventValues.split(',')[0].trim(), DestinationProcessID: 42, SourceProcessID: 999, FilePath: preset.category === 'access' ? '73' : '/example/target', DeviceCustomString1: preset.operationValues?.split(',')[0].trim(), DeviceCustomString2: 'read', DeviceAction: 'success' };
    let sql;
    const result = await searchKumaOperations({ process: { ...process, platform: preset.platform }, category: preset.category }, {
      api, config: { operationProfiles: [configured] }, client: { searchRelated: async action => { sql = action.sql; return { events: [record] }; } },
    });
    assert.match(sql, /DestinationProcessID = 42/); assert.doesNotMatch(sql, /SourceProcessID =/);
    if (preset.selectorRequired) assert.match(sql, /DeviceCustomString1 IN/);
    assert.equal(result.facts.length, 1, preset.id); assert.equal(String(result.facts[0].pid), '42');
    assert.match(result.facts[0].operation, /read · success$/);
  }
});
