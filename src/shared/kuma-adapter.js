(function initKumaAdapter(global) {
  "use strict";

  const DEFAULT_RANGE_SECONDS = 15 * 60;
  const DEFAULT_LIMIT = 250;
  const MAX_LIMIT = 1000;
  const FIELD_KINDS = Object.freeze(["ip", "host", "account", "process", "command", "file", "hash", "domain", "url"]);

  const FIELD_GROUPS = Object.freeze([
    {
      kind: "ip",
      title: "IP-адрес",
      aliases: ["SourceAddress", "DestinationAddress", "DeviceAddress", "src.ip", "dst.ip"],
      queryFields: ["SourceAddress", "DestinationAddress", "DeviceAddress"],
    },
    {
      kind: "host",
      title: "Узел",
      aliases: ["DeviceHostName", "SourceHostName", "DestinationHostName", "Hostname", "HostName"],
      queryFields: ["DeviceHostName", "SourceHostName", "DestinationHostName"],
    },
    {
      kind: "account",
      title: "Учетная запись",
      aliases: ["SourceUserName", "DestinationUserName", "SourceAccountName", "DestinationAccountName", "UserName"],
      queryFields: ["SourceUserName", "DestinationUserName"],
    },
    {
      kind: "process",
      title: "Процесс",
      aliases: ["SourceProcessName", "DestinationProcessName", "DeviceProcessName", "ProcessName"],
      queryFields: ["SourceProcessName", "DestinationProcessName", "DeviceProcessName"],
    },
    {
      kind: "command",
      title: "Командная строка",
      aliases: [],
      queryFields: [],
    },
    {
      kind: "file",
      title: "Файл",
      aliases: ["FilePath", "FileName", "OldFilePath", "OldFileName"],
      queryFields: ["FilePath", "FileName", "OldFilePath", "OldFileName"],
    },
    {
      kind: "hash",
      title: "Хеш",
      aliases: ["FileHash", "OldFileHash", "Hash"],
      queryFields: ["FileHash", "OldFileHash"],
    },
    {
      kind: "domain",
      title: "Домен",
      aliases: ["SourceDnsDomain", "DestinationDnsDomain", "DeviceDnsDomain"],
      queryFields: ["SourceDnsDomain", "DestinationDnsDomain", "DeviceDnsDomain"],
    },
    {
      kind: "url",
      title: "URL",
      aliases: ["RequestUrl"],
      queryFields: ["RequestUrl"],
    },
  ]);

  // Start set derived from the public KUMA Community normalizers. It is editable
  // because custom and version-specific normalizers may map the same source data
  // into different KUMA fields.
  const BUILTIN_FIELD_PROFILES = Object.freeze([
    {
      name: "Windows Security: создание процесса (4688)",
      when: { DeviceEventClassID: ["4688"] },
      fields: {
        process: ["DestinationProcessName"],
        command: ["DeviceCustomString4"],
        account: ["SourceUserName", "DestinationUserName"],
        host: ["DeviceHostName"],
      },
    },
    {
      name: "Windows Security: вход (4624, 4625, 4648)",
      when: { DeviceEventClassID: ["4624", "4625", "4648"] },
      fields: {
        ip: ["SourceAddress"],
        host: ["DeviceHostName", "SourceHostName"],
        account: ["SourceUserName", "DestinationUserName"],
        process: ["SourceProcessName", "DestinationProcessName"],
      },
    },
    {
      name: "Windows Security: учетные записи (4720–4767)",
      when: { DeviceEventClassID: ["4720", "4722", "4725", "4726", "4728", "4732", "4738", "4740", "4756", "4767"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "DestinationUserName"],
      },
    },
    {
      name: "Windows Security: доступ к объекту (4656, 4660, 4663)",
      when: { DeviceEventClassID: ["4656", "4660", "4663"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["DestinationUserName"],
        process: ["DestinationProcessName"],
        file: ["FileName", "FilePath"],
      },
    },
    {
      name: "Windows Security: общий ресурс SMB (5140, 5145)",
      when: { DeviceEventClassID: ["5140", "5145"] },
      fields: {
        ip: ["SourceAddress"],
        host: ["DeviceHostName", "SourceHostName"],
        account: ["DestinationUserName"],
        file: ["FileName", "FilePath"],
      },
    },
    {
      name: "Windows Security: сетевое соединение WFP (5156, 5157)",
      when: { DeviceEventClassID: ["5156", "5157"] },
      fields: {
        ip: ["SourceAddress", "DestinationAddress"],
        host: ["DeviceHostName", "SourceHostName", "DestinationHostName"],
        process: ["DestinationProcessName", "DeviceProcessName"],
      },
    },
    {
      name: "Windows: установка службы (4697, 7045)",
      when: { DeviceEventClassID: ["4697", "7045"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "DestinationUserName"],
        process: ["DestinationProcessName", "DeviceProcessName"],
        file: ["FilePath", "FileName"],
      },
    },
    {
      name: "PowerShell: Script Block (4104)",
      when: { DeviceEventClassID: ["4104"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "SourceUserID"],
        process: ["SourceProcessName"],
      },
    },
    {
      name: "Sysmon: Process Create (1)",
      when: { DeviceEventCategory: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"], DeviceEventClassID: ["1"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "SourceUserID"],
        process: ["DeviceProcessName"],
        command: ["DeviceCustomString2", "DeviceCustomString4"],
        file: ["FilePath", "FileName", "DeviceCustomString3"],
        hash: ["FileHash"],
      },
    },
    {
      name: "Sysmon: Network Connect (3)",
      when: { DeviceEventCategory: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"], DeviceEventClassID: ["3"] },
      fields: {
        ip: ["SourceAddress", "DestinationAddress"],
        host: ["DeviceHostName", "SourceHostName", "DestinationHostName"],
        account: ["SourceUserName", "SourceUserID"],
        process: ["DeviceProcessName"],
        file: ["FilePath"],
      },
    },
    {
      name: "Sysmon: Image Load / Process Access (7, 8, 10)",
      when: { DeviceEventCategory: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"], DeviceEventClassID: ["7", "8", "10"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "SourceUserID"],
        process: ["SourceProcessName", "DestinationProcessName", "DeviceProcessName"],
        file: ["FilePath", "FileName", "OldFilePath", "OldFileName"],
        hash: ["FileHash"],
      },
    },
    {
      name: "Sysmon: File Create/Delete (11, 23, 26)",
      when: { DeviceEventCategory: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"], DeviceEventClassID: ["11", "23", "26"] },
      fields: {
        host: ["DeviceHostName"],
        process: ["DeviceProcessName"],
        file: ["FilePath", "FileName", "OldFilePath", "OldFileName", "DeviceCustomString2"],
        hash: ["FileHash"],
      },
    },
    {
      name: "Sysmon: DNS Query (22)",
      when: { DeviceEventCategory: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"], DeviceEventClassID: ["22"] },
      fields: {
        host: ["DeviceHostName"],
        process: ["DeviceProcessName"],
        file: ["FilePath"],
        domain: ["DeviceCustomString2", "DestinationDnsDomain"],
      },
    },
    {
      name: "Linux auditd: EXECVE",
      when: [{ DeviceEventClassID: ["EXECVE"] }, { Name: ["execve"] }],
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "DestinationUserName", "SourceUserID", "DestinationUserID"],
        process: ["DestinationProcessName", "DeviceProcessName"],
        command: ["FlexString1", "FlexString2"],
        file: ["FileName", "FilePath"],
      },
    },
    {
      name: "Linux auditd: SYSCALL",
      when: { DeviceEventClassID: ["SYSCALL"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "DestinationUserName", "SourceUserID", "DestinationUserID"],
        process: ["DestinationProcessName"],
        command: ["FlexString1"],
        file: ["FileName", "FilePath"],
      },
    },
    {
      name: "Linux auditd: аутентификация",
      when: { DeviceEventClassID: ["USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP"] },
      fields: {
        ip: ["SourceAddress"],
        host: ["DeviceHostName", "SourceHostName"],
        account: ["SourceUserName", "DestinationUserName", "SourceUserID", "DestinationUserID"],
        process: ["DestinationProcessName", "SourceProcessName"],
      },
    },
    {
      name: "Linux auditd: PATH",
      when: { DeviceEventClassID: ["PATH"] },
      fields: {
        host: ["DeviceHostName"],
        account: ["SourceUserName", "DestinationUserName"],
        process: ["DestinationProcessName"],
        file: ["FileName", "FilePath"],
      },
    },
  ]);

  const TIME_FIELDS = ["Timestamp", "EventTime", "DeviceReceiptTime", "EndTime", "StartTime", "time"];
  const RULE_ID_FIELDS = ["CorrelationRuleID", "CorrelationRuleId", "RuleID", "RuleId", "correlationRuleID"];

  function normalizeOrigin(value) {
    const input = String(value ?? "").trim();
    if (!input) throw new TypeError("Адрес не указан");
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input) && !/^https?:\/\//i.test(input)) {
      throw new TypeError("Разрешены только HTTP(S)-адреса");
    }
    const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`;
    const url = new URL(withScheme);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) {
      throw new TypeError("Разрешены только HTTP(S)-адреса без учетных данных");
    }
    return url.origin;
  }

  function flattenObject(value, prefix = "", output = {}) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return output;
    for (const [key, item] of Object.entries(value)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (item && typeof item === "object" && !Array.isArray(item)) flattenObject(item, path, output);
      else output[path] = item;
    }
    return output;
  }

  function eventEntries(event) {
    const flat = flattenObject(event);
    const byLowerName = new Map();
    for (const [name, value] of Object.entries(flat)) byLowerName.set(name.toLowerCase(), [name, value]);
    return { flat, byLowerName };
  }

  function valuesForAliases(event, aliases) {
    const { byLowerName } = eventEntries(event);
    const values = [];
    for (const alias of aliases) {
      const entry = byLowerName.get(alias.toLowerCase());
      const value = entry?.[1];
      if (value === undefined || value === null || value === "") continue;
      for (const item of Array.isArray(value) ? value : [value]) {
        const text = String(item).trim();
        if (text && !values.includes(text)) values.push(text);
      }
    }
    return values;
  }

  function escapeSqlString(value) {
    return String(value).replaceAll("\\", "\\\\").replaceAll("'", "\\'");
  }

  function sqlIdentifier(value) {
    const identifier = String(value);
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(identifier)) throw new TypeError(`Недопустимое имя поля: ${identifier}`);
    return identifier;
  }

  function normalizeFieldList(value, context) {
    if (!Array.isArray(value) || !value.length || value.length > 32) {
      throw new TypeError(`${context}: ожидается массив из 1–32 имен полей`);
    }
    return [...new Set(value.map((field) => sqlIdentifier(field)))];
  }

  function normalizeFieldProfiles(value) {
    if (!Array.isArray(value) || value.length > 50) throw new TypeError("Профили полей должны быть массивом (не более 50 профилей)");
    return value.map((profile, profileIndex) => {
      const context = `Профиль ${profileIndex + 1}`;
      if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new TypeError(`${context}: ожидается объект`);
      const name = String(profile.name ?? "").trim();
      if (!name || name.length > 120) throw new TypeError(`${context}: укажите короткое имя`);
      const clauses = Array.isArray(profile.when) ? profile.when : [profile.when];
      if (!clauses.length || clauses.length > 10) throw new TypeError(`${name}: when должен содержать 1–10 условий`);
      const when = clauses.map((clause) => {
        if (!clause || typeof clause !== "object" || Array.isArray(clause)) throw new TypeError(`${name}: условие when должно быть объектом`);
        const entries = Object.entries(clause);
        if (!entries.length || entries.length > 10) throw new TypeError(`${name}: условие when должно содержать 1–10 полей`);
        return Object.fromEntries(entries.map(([field, accepted]) => {
          const safeField = sqlIdentifier(field);
          if (!Array.isArray(accepted) || !accepted.length || accepted.length > 32) {
            throw new TypeError(`${name}.${safeField}: ожидается массив из 1–32 значений`);
          }
          const values = [...new Set(accepted.map((item) => String(item).trim()))];
          if (values.some((item) => !item || item.length > 256)) throw new TypeError(`${name}.${safeField}: недопустимое значение`);
          return [safeField, values];
        }));
      });
      if (!profile.fields || typeof profile.fields !== "object" || Array.isArray(profile.fields)) {
        throw new TypeError(`${name}: fields должен быть объектом`);
      }
      const fieldEntries = Object.entries(profile.fields);
      if (!fieldEntries.length) throw new TypeError(`${name}: добавьте хотя бы одну группу fields`);
      const fields = Object.fromEntries(fieldEntries.map(([kind, fieldList]) => {
        if (!FIELD_KINDS.includes(kind)) throw new TypeError(`${name}: неизвестная группа ${kind}`);
        return [kind, normalizeFieldList(fieldList, `${name}.${kind}`)];
      }));
      return { name, when, fields };
    });
  }

  function profileMatches(event, profile) {
    const { byLowerName } = eventEntries(event);
    return profile.when.some((clause) => Object.entries(clause).every(([field, accepted]) => {
      const value = byLowerName.get(field.toLowerCase())?.[1];
      if (value === undefined || value === null) return false;
      const current = (Array.isArray(value) ? value : [value]).map((item) => String(item).trim().toLowerCase());
      return accepted.some((item) => current.includes(item.toLowerCase()));
    }));
  }

  function fieldGroupsForEvent(event, profiles = BUILTIN_FIELD_PROFILES) {
    const groups = FIELD_GROUPS.map((group) => ({ ...group, aliases: [...group.aliases], queryFields: [...group.queryFields] }));
    for (const profile of normalizeFieldProfiles(profiles)) {
      if (!profileMatches(event, profile)) continue;
      for (const [kind, fields] of Object.entries(profile.fields)) {
        const group = groups.find((candidate) => candidate.kind === kind);
        group.aliases = fields;
        group.queryFields = fields;
      }
    }
    return groups;
  }

  function equalityWhere(fields, value) {
    const literal = `'${escapeSqlString(value)}'`;
    const predicates = [...new Set(fields)].map((field) => `${sqlIdentifier(field)} = ${literal}`);
    return predicates.length === 1 ? predicates[0] : `(${predicates.join(" OR ")})`;
  }

  function buildEventsQuery(where, limit = DEFAULT_LIMIT) {
    const predicate = String(where ?? "").trim();
    if (!predicate || predicate.length > 4000 || /[;\0]/.test(predicate)) throw new TypeError("Недопустимое условие поиска");
    const safeLimit = Math.max(1, Math.min(MAX_LIMIT, Number(limit) || DEFAULT_LIMIT));
    return `SELECT * FROM \`events\` WHERE ${predicate} ORDER BY Timestamp DESC LIMIT ${safeLimit}`;
  }

  function buildRelatedActions(event, profiles = BUILTIN_FIELD_PROFILES) {
    if (!event || typeof event !== "object") return [];
    const actions = [];
    for (const group of fieldGroupsForEvent(event, profiles)) {
      for (const value of valuesForAliases(event, group.aliases)) {
        actions.push({
          kind: group.kind,
          title: group.title,
          value,
          where: equalityWhere(group.queryFields, value),
        });
      }
    }
    return actions;
  }

  function eventTimestamp(event) {
    for (const field of TIME_FIELDS) {
      const value = valuesForAliases(event, [field])[0];
      if (value === undefined) continue;
      if (/^\d+(?:\.\d+)?$/.test(value)) {
        const number = Number(value);
        const milliseconds = number > 10_000_000_000 ? number : number * 1000;
        if (Number.isFinite(milliseconds)) return milliseconds;
      }
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    return Date.now();
  }

  function eventPeriod(event, rangeSeconds = DEFAULT_RANGE_SECONDS) {
    const center = eventTimestamp(event);
    const radius = Math.max(60, Math.min(30 * 86400, Number(rangeSeconds) || DEFAULT_RANGE_SECONDS)) * 1000;
    return {
      from: new Date(center - radius).toISOString(),
      to: new Date(center + radius).toISOString(),
    };
  }

  function correlationRuleId(event) {
    return valuesForAliases(event, RULE_ID_FIELDS)[0] ?? null;
  }

  function arrayFromResponse(response, keys) {
    if (Array.isArray(response)) return response;
    for (const key of keys) {
      if (Array.isArray(response?.[key])) return response[key];
      if (Array.isArray(response?.data?.[key])) return response.data[key];
    }
    if (Array.isArray(response?.data)) return response.data;
    return [];
  }

  function clustersFromResponse(response) {
    return arrayFromResponse(response, ["clusters", "items", "rows", "result"])
      .map((cluster) => ({
        id: cluster?.id ?? cluster?.ID ?? cluster?.clusterID ?? cluster?.uuid ?? null,
        name: cluster?.name ?? cluster?.title ?? cluster?.Name ?? null,
        raw: cluster,
      }))
      .filter((cluster) => cluster.id);
  }

  function eventsFromResponse(response) {
    return arrayFromResponse(response, ["events", "items", "rows", "result"]);
  }

  function isIPv4(value) {
    const parts = value.split(".");
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }

  function iocType(value) {
    const text = String(value ?? "").trim();
    if (!text || text.length > 2048) return null;
    if (/^https?:\/\/[^\s]+$/i.test(text)) return "url";
    if (isIPv4(text) || (/^[0-9a-f:]+$/i.test(text) && text.includes(":"))) return "ip";
    if (/^[a-f0-9]{32}$/i.test(text)) return "md5";
    if (/^[a-f0-9]{40}$/i.test(text)) return "sha1";
    if (/^[a-f0-9]{64}$/i.test(text)) return "sha256";
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(text)) return "domain";
    return null;
  }

  function iocsFromEvent(event) {
    const { flat } = eventEntries(event);
    const results = [];
    const likelyField = /(address|\bip\b|domain|url|uri|hash|md5|sha1|sha256|host)/i;
    for (const [field, rawValue] of Object.entries(flat)) {
      if (!likelyField.test(field)) continue;
      for (const value of Array.isArray(rawValue) ? rawValue : [rawValue]) {
        const text = String(value ?? "").trim();
        const type = iocType(text);
        if (!type || results.some((item) => item.value === text)) continue;
        results.push({ field, value: text, type });
      }
    }
    return results;
  }

  function iocLinks(ioc) {
    const value = encodeURIComponent(ioc.value);
    return [
      { provider: "Kaspersky OpenTIP", url: `https://opentip.kaspersky.com/${value}/` },
      { provider: "VirusTotal", url: `https://www.virustotal.com/gui/search/${value}` },
    ];
  }

  class KumaAdapter {
    constructor(config, request) {
      this.uiOrigin = normalizeOrigin(config.uiOrigin);
      this.apiOrigin = normalizeOrigin(config.apiOrigin);
      this.clusterId = config.clusterId || null;
      this.token = config.token || null;
      this.request = request;
    }

    getCurrentUser() {
      return this.request({ origin: this.uiOrigin, path: "/api/whoami", method: "GET" });
    }

    async getClusters() {
      const response = await this.request({
        origin: this.apiOrigin,
        path: "/api/v3/events/clusters",
        method: "GET",
        token: this.token,
      });
      return clustersFromResponse(response);
    }

    async searchRelated(action, event, rangeSeconds = DEFAULT_RANGE_SECONDS, limit = DEFAULT_LIMIT) {
      let clusterId = this.clusterId;
      if (!clusterId) {
        const clusters = await this.getClusters();
        if (clusters.length > 1) throw new Error("KUMA вернула несколько кластеров хранения. Выберите нужный в настройках KumApe");
        clusterId = clusters[0]?.id;
      }
      if (!clusterId) throw new Error("KUMA не вернула ни одного доступного кластера хранения");
      const body = {
        clusterID: clusterId,
        period: eventPeriod(event, rangeSeconds),
        emptyFields: true,
        rawTimestamps: true,
        sql: buildEventsQuery(action.where, limit),
      };
      const response = await this.request({
        origin: this.apiOrigin,
        path: "/api/v3/events",
        method: "POST",
        token: this.token,
        body,
      });
      return { clusterId, query: body.sql, period: body.period, events: eventsFromResponse(response), raw: response };
    }

    getCorrelationRule(id) {
      return this.request({
        origin: this.uiOrigin,
        path: `/api/private/resources/correlationRule/${encodeURIComponent(id)}`,
        method: "GET",
      });
    }
  }

  global.KumApeAdapter = Object.freeze({
    BUILTIN_FIELD_PROFILES,
    DEFAULT_RANGE_SECONDS,
    KumaAdapter,
    buildEventsQuery,
    buildRelatedActions,
    clustersFromResponse,
    correlationRuleId,
    equalityWhere,
    escapeSqlString,
    eventPeriod,
    eventsFromResponse,
    fieldGroupsForEvent,
    iocLinks,
    iocType,
    iocsFromEvent,
    normalizeOrigin,
    normalizeFieldProfiles,
  });
})(globalThis);
