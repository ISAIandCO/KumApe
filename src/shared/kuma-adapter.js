(function initKumaAdapter(global) {
  "use strict";

  const DEFAULT_RANGE_SECONDS = 15 * 60;
  const DEFAULT_LIMIT = 250;
  const MAX_LIMIT = 1000;

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
      aliases: ["SourceProcessName", "DestinationProcessName", "DeviceProcessName", "ProcessName", "FileName"],
      queryFields: ["SourceProcessName", "DestinationProcessName", "DeviceProcessName", "FileName"],
    },
    {
      kind: "hash",
      title: "Хеш",
      aliases: ["FileHash", "OldFileHash", "Hash"],
      queryFields: ["FileHash", "OldFileHash"],
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

  function buildRelatedActions(event) {
    if (!event || typeof event !== "object") return [];
    const actions = [];
    for (const group of FIELD_GROUPS) {
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
      const clusterId = this.clusterId || (await this.getClusters())[0]?.id;
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
    iocLinks,
    iocType,
    iocsFromEvent,
    normalizeOrigin,
  });
})(globalThis);
