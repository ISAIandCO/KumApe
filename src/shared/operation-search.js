import { AUDIT_OPERATION_RECIPES } from '@isaiandco/ape-share-core/settings/operation-recipes';
import { detectEventPlatform } from "@isaiandco/ape-share-core/filters/platform";
import { searchOperationPage, pidTextValues } from '@isaiandco/ape-share-core/graph/operation-search';
import { migrateOperationProfiles } from '@isaiandco/ape-share-core/settings/operation-profiles';
// These are editable starting points, not a claim about a custom normalizer.
// Enable a profile after checking it against an event from the actual source.
const SYSMON_OPERATION_PROFILES = [
  ['files', '11, 2, 15, 23, 26', 'FilePath'], ['network', '3', 'DestinationAddress'],
  ['dns', '22', 'DestinationHostName'], ['registry', '12, 13, 14', 'DeviceCustomString1'],
  ['access', '8, 10', 'DestinationProcessName'], ['modules', '7', 'FilePath'],
].map(([category, eventValues, target]) => ({
  id: `sysmon-${category}`, name: `Sysmon: ${category}`, category, platform: 'windows', enabled: false,
  sourceField: 'DeviceEventCategory', sourceValues: 'Microsoft-Windows-Sysmon, Microsoft-Windows-Sysmon/Operational, Sysmon',
  eventField: 'DeviceEventClassID', eventValues, host: 'DeviceHostName', pid: 'SourceProcessID', guid: '',
  target, targetPort: category === 'network' ? 'DestinationPort' : '', targetPid: category === 'access' ? 'DestinationProcessID' : '',
  protocol: category === 'network' ? 'TransportProtocol' : '', recordId: 'ID', time: 'Timestamp',
}));
export const DEFAULT_OPERATION_PROFILES = [...SYSMON_OPERATION_PROFILES, ...AUDIT_OPERATION_RECIPES.map(recipe => ({
  ...recipe, enabled: false,
  sourceField: 'DeviceProduct', sourceValues: recipe.platform === 'unix' ? 'auditd' : 'Windows',
  eventField: 'DeviceEventClassID', host: 'DeviceHostName',
  pid: recipe.platform === 'unix' ? 'DestinationProcessID' : 'SourceProcessID', guid: '',
  // No universal KUMA mapping exists for ObjectType/syscall. The editor requires
  // the deployment's real normalized field before these profiles can be enabled.
  operationField: '',
  target: recipe.category === 'network' ? 'DestinationAddress' : recipe.category === 'files' || recipe.id === 'auditd-modules' ? 'FilePath' : '',
  targetPort: recipe.category === 'network' ? 'DestinationPort' : '',
  targetPid: '', protocol: recipe.category === 'network' ? 'TransportProtocol' : '',
  action: '', outcome: '', targetDetail: '', recordId: 'ID', time: 'Timestamp',
}))];
export function processOperationIdentity(event, processApi, mappings, api) {
  const mapping = processApi.mappingForEvent(event, mappings);
  const fact = processApi.processFields(event, mapping);
  if (!fact) throw new Error('Не определён процесс выбранного узла');
  const read = fields => api.valuesForAliases(event, fields);
  const detected = detectEventPlatform({ os: read(['DeviceOS', 'DeviceOSName', 'OperatingSystem']), source: read(['DeviceProduct', 'DeviceEventCategory']), paths: [fact.image] });
  return { host: fact.host, pid: fact.pid, guid: fact.processGuid, time: fact.timestamp,
    platform: detected !== 'unknown' ? detected : mapping.matchMode === 'execve' ? 'unix' : mapping.eventIdValue === '4688' ? 'windows' : 'unknown' };
}
export async function searchKumaOperations(input, { config, client, api }) {
  const profiles = migrateOperationProfiles(config.operationProfiles, DEFAULT_OPERATION_PROFILES).profiles;
  const field = value => api.sqlIdentifier(value);
  const literal = value => `'${api.escapeSqlString(String(value))}'`;
  const equal = (key, value) => `${field(key)} = ${literal(value)}`;
  return searchOperationPage({ ...input, profiles,
    dialect: { equal, in: (key, values) => `${field(key)} IN (${values.map(literal).join(', ')})`,
      and: values => values.map(value => `(${value})`).join(' AND '), factual: 'Type != 3',
      guid: (key, value) => `lower(replaceAll(replaceAll(${field(key)}, '{', ''), '}', '')) = ${literal(value)}`,
      pid: (key, value, format) => {
        if (!/^\d+$/.test(value)) return equal(key, value);
        if (format === 'number' || (format !== 'text' && /^(SourceProcessID|DestinationProcessID|DeviceProcessID|DeviceCustomNumber[1-3]|FlexNumber[1-2])$/.test(key))) return `${field(key)} = ${value}`;
        return `${field(key)} IN (${pidTextValues(value).map(literal).join(', ')})`;
      } },
    isFact: event => !api.valuesForAliases(event, ["Type"]).includes("3"),
    read: (event, key) => api.valuesForAliases(event, [key])[0] ?? '',
    parseTime: value => /^\d+(\.\d+)?$/.test(String(value)) ? Number(value) * (Number(value) > 1e10 ? 1 : 1000) : Date.parse(value),
    async fetch({ where, profile, offset, limit, from, to }) {
      const sql = `SELECT * FROM \`events\` WHERE ${where} ORDER BY ${field(profile.time)} ASC, ${field(profile.recordId)} ASC LIMIT ${limit} OFFSET ${offset}`;
      const response = await client.searchRelated({ sql, period: { from: new Date(from).toISOString(), to: new Date(to).toISOString() } }, {});
      if (response.raw !== undefined) {
        const raw = response.raw;
        const arrays = [raw, raw?.data, ...['events', 'items', 'rows', 'result'].flatMap(key => [raw?.[key], raw?.data?.[key]])];
        if (!arrays.some(Array.isArray)) throw new Error('KUMA вернула неизвестный формат событий');
      }
      return response.events;
    },
  });
}
