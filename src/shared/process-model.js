(function initProcessModel(global) {
  "use strict";

  const api = global.KumApeAdapter;
  const FIELD_KEYS = Object.freeze(["host", "pid", "parentPid", "processGuid", "parentGuid", "image", "commandLine", "user", "eventRecordId", "fallbackPid", "fallbackParentPid"]);
  const NUMERIC_PID_FIELDS = /^(?:SourceProcessID|DestinationProcessID|DeviceProcessID|DeviceCustomNumber[1-3]|FlexNumber[1-2])$/i;
  const BUILTIN_PROCESS_MAPPINGS = Object.freeze([
    Object.freeze({
      name: "Windows Security 4688", eventIdField: "DeviceEventClassID", eventIdValue: "4688",
      eventCategories: ["Microsoft-Windows-Security-Auditing"],
      host: "DeviceHostName", pid: "DeviceCustomString5", parentPid: "DeviceCustomString3",
      fallbackPid: "DestinationProcessID", fallbackParentPid: "SourceProcessID",
      processGuid: "", parentGuid: "", image: "DestinationProcessName", commandLine: "DeviceCustomString4",
      user: "SourceUserName", eventRecordId: "ID",
    }),
    Object.freeze({
      name: "Sysmon Process Create 1", eventIdField: "DeviceEventClassID", eventIdValue: "1",
      eventCategories: ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "Sysmon"],
      host: "DeviceHostName", pid: "DeviceProcessID", parentPid: "SourceProcessID",
      processGuid: "FlexString1", parentGuid: "FlexString2", image: "DeviceProcessName", commandLine: "DeviceCustomString2",
      user: "SourceUserName", eventRecordId: "ID",
    }),
    Object.freeze({
      name: "Linux auditd EXECVE", eventIdField: "DeviceEventClassID", eventIdValue: "EXECVE",
      host: "DeviceHostName", pid: "DeviceProcessID", parentPid: "SourceProcessID",
      processGuid: "", parentGuid: "", image: "DestinationProcessName", commandLine: "FlexString1",
      user: "SourceUserName", eventRecordId: "ID",
    }),
  ]);

  function safeField(value, required, context) {
    const field = String(value ?? "").trim();
    if (!field) {
      if (required) throw new TypeError(`${context}: поле обязательно`);
      return "";
    }
    return api.sqlIdentifier(field);
  }

  function normalizeMappings(value) {
    if (!Array.isArray(value) || value.length > 50) throw new TypeError("Настройки графа должны содержать не более 50 Event ID");
    return value.map((mapping, index) => {
      const context = `Граф процессов ${index + 1}`;
      if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) throw new TypeError(`${context}: некорректная запись`);
      const name = String(mapping.name ?? "").trim() || `Event ${index + 1}`;
      const eventIdValue = String(mapping.eventIdValue ?? "").trim();
      if (!eventIdValue || eventIdValue.length > 256) throw new TypeError(`${context}: укажите значение Event ID`);
      const normalized = {
        name: name.slice(0, 120),
        eventIdField: safeField(mapping.eventIdField, true, context),
        eventIdValue,
        eventCategories: [...new Set((Array.isArray(mapping.eventCategories) ? mapping.eventCategories : String(mapping.eventCategories || "").split(","))
          .map((value) => String(value).trim()).filter(Boolean))],
      };
      const defaultMapping = BUILTIN_PROCESS_MAPPINGS.find((candidate) => candidate.eventIdValue === "1" && candidate.eventIdField.toLowerCase() === normalized.eventIdField.toLowerCase() && candidate.eventIdValue.toLowerCase() === normalized.eventIdValue.toLowerCase());
      if (!normalized.eventCategories.length && defaultMapping?.eventCategories) normalized.eventCategories = [...defaultMapping.eventCategories];
      if (normalized.eventCategories.length > 20 || normalized.eventCategories.some((value) => value.length > 256)) throw new TypeError(`${context}: слишком много или слишком длинные категории событий`);
      for (const key of FIELD_KEYS) normalized[key] = safeField(mapping[key], ["host", "pid", "parentPid"].includes(key), `${context}.${key}`);
      if (Boolean(normalized.fallbackPid) !== Boolean(normalized.fallbackParentPid)) throw new TypeError(`${context}: укажите оба резервных PID-поля`);
      return normalized;
    });
  }

  function mappingMatches(event, mapping) {
    if (api.valuesForAliases(event, ["Type"]).includes("3")) return false;
    const eventIdMatches = api.valuesForAliases(event, [mapping.eventIdField]).some((value) => value.toLowerCase() === mapping.eventIdValue.toLowerCase());
    return eventIdMatches && (!mapping.eventCategories.length || api.valuesForAliases(event, ["DeviceEventCategory"])
      .some((value) => mapping.eventCategories.some((category) => value.toLowerCase() === category.toLowerCase())));
  }

  function mappingWhere(mapping) {
    const predicates = [api.equalityWhere([mapping.eventIdField], mapping.eventIdValue)];
    if (mapping.eventCategories.length === 1) predicates.push(api.equalityWhere(["DeviceEventCategory"], mapping.eventCategories[0]));
    if (mapping.eventCategories.length > 1) predicates.push(`DeviceEventCategory IN (${mapping.eventCategories.map((value) => `'${api.escapeSqlString(value)}'`).join(", ")})`);
    return predicates.join(" AND ");
  }

  function mappingForEvent(event, mappings = BUILTIN_PROCESS_MAPPINGS) {
    return normalizeMappings(mappings).find((mapping) => mappingMatches(event, mapping)) || null;
  }

  function first(event, field) {
    return field ? api.valuesForAliases(event, [field])[0] || "" : "";
  }

  function normalizePid(value) {
    const text = String(value || "").trim();
    try { return /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(text) ? BigInt(text).toString() : text; } catch { return text; }
  }

  function processFields(event, mapping) {
    if (!mapping) return null;
    const fallback = (!first(event, mapping.pid) || !first(event, mapping.parentPid)) && first(event, mapping.fallbackPid);
    const pid = first(event, fallback ? mapping.fallbackPid : mapping.pid);
    const parentPid = first(event, fallback ? mapping.fallbackParentPid : mapping.parentPid);
    return {
      host: first(event, mapping.host), pid: normalizePid(pid), parentPid: normalizePid(parentPid),
      processGuid: first(event, mapping.processGuid), parentGuid: first(event, mapping.parentGuid),
      image: first(event, mapping.image), commandLine: first(event, mapping.commandLine), user: first(event, mapping.user),
      eventRecordId: first(event, mapping.eventRecordId), timestamp: api.eventTimestamp(event),
    };
  }

  function graphSearchAction(event, mappings = BUILTIN_PROCESS_MAPPINGS) {
    const normalized = normalizeMappings(mappings);
    const sourceMapping = normalized.find((mapping) => mappingMatches(event, mapping));
    if (!sourceMapping) throw new Error("Для Event ID текущего события не задано сопоставление полей графа");
    const source = processFields(event, sourceMapping);
    if (!source.host) throw new Error(`В поле ${sourceMapping.host} не найден узел процесса`);
    if (!source.pid) throw new Error(`В поле ${sourceMapping.pid} не найден PID процесса`);
    const clauses = normalized.map((mapping) => `(${mappingWhere(mapping)} AND ${api.equalityWhere([mapping.host], source.host)})`);
    return { kind: "processGraph", title: "Граф процессов", value: source.pid, where: clauses.length === 1 ? clauses[0] : `(${clauses.join(" OR ")})`, sourceMapping, source };
  }

  function eventKey(fields) {
    if (fields.processGuid) return `guid:${fields.host.toLowerCase()}:${fields.processGuid.toLowerCase()}`;
    if (fields.eventRecordId) return `event:${fields.host.toLowerCase()}:${fields.eventRecordId}`;
    return `pid:${fields.host.toLowerCase()}:${fields.pid}:${fields.timestamp}:${fields.image.toLowerCase()}`;
  }

  function normalizeEvent(event, mappings = BUILTIN_PROCESS_MAPPINGS) {
    if (!event) return null;
    const mapping = mappingForEvent(event, mappings);
    const fields = processFields(event, mapping);
    if (!fields?.host || !fields.pid) return null;
    return { raw: event, recordId: api.valuesForAliases(event, ["ID"])[0] || fields.eventRecordId || "", host: fields.host.toLowerCase(), time: fields.timestamp,
      identity: { id: eventKey(fields), kind: fields.processGuid ? "guid" : "pid", value: fields.processGuid || fields.pid },
      references: [fields.processGuid && { kind: "guid", value: fields.processGuid.toLowerCase() }, { kind: "pid", value: fields.pid }].filter(Boolean),
      parentRefs: [fields.parentGuid && { kind: "guid", value: fields.parentGuid.toLowerCase() }, fields.parentPid && { kind: "pid", value: fields.parentPid }].filter(Boolean),
    };
  }

  function relatedAction(event, mappings, direction = "both") {
    if (!["parents", "children", "both", "siblings"].includes(direction)) throw new Error("Неизвестное направление поиска");
    const source = processFields(event, mappingForEvent(event, mappings));
    if (!source?.host || !source.pid) throw new Error("Не найдены узел/PID процесса");
    const clauses = [];
    for (const mapping of normalizeMappings(mappings)) {
      const relations = [];
      const pairs = [[mapping.pid, mapping.parentPid], [mapping.fallbackPid, mapping.fallbackParentPid]].filter(([pid, parent]) => pid && parent);
      const eq = (field, value) => {
        if (NUMERIC_PID_FIELDS.test(field)) return /^[0-9]+$/.test(value) ? `${field} = ${value}` : null;
        const values = new Set([value]);
        if (/^[0-9]+$/.test(value)) values.add(`0x${BigInt(value).toString(16)}`);
        return `(${[...values].map(v => api.equalityWhere([field], v)).join(" OR ")})`;
      };
      for (const [pid, parent] of pairs) {
        if (["parents", "both"].includes(direction) && source.parentPid) relations.push(eq(pid, source.parentPid));
        if (["children", "both"].includes(direction)) relations.push(eq(parent, source.pid));
        if (direction === "siblings" && source.parentPid) relations.push(eq(parent, source.parentPid));
      }
      const validRelations = relations.filter(Boolean);
      if (validRelations.length) clauses.push(`(${mappingWhere(mapping)} AND ${api.equalityWhere([mapping.host], source.host)} AND (${validRelations.join(" OR ")}))`);
    }
    if (!clauses.length) throw new Error("Нет полей для выбранного направления");
    return { where: `(${clauses.join(" OR ")})` };
  }

  function mappingsFromLegacyProfiles(profiles) {
    const result = [];
    for (const profile of Array.isArray(profiles) ? profiles : []) {
      if (!profile?.processGraph) continue;
      const clauses = Array.isArray(profile.when) ? profile.when : [profile.when];
      for (const clause of clauses) {
        const entries = Object.entries(clause || {});
        const [eventIdField, accepted] = entries.find(([field, values]) => field.toLowerCase() === "deviceeventclassid" && Array.isArray(values) && values.length)
          || entries.find(([, values]) => Array.isArray(values) && values.length) || [];
        if (!eventIdField) continue;
        for (const eventIdValue of accepted) {
          const mapping = { name: profile.name, eventIdField, eventIdValue: String(eventIdValue) };
          mapping.eventCategories = entries.find(([field, values]) => field.toLowerCase() === "deviceeventcategory" && Array.isArray(values))?.[1] || [];
          for (const key of FIELD_KEYS) mapping[key] = String(profile.processGraph[key]?.[0] || "");
          if (mapping.host && mapping.pid && mapping.parentPid) result.push(mapping);
        }
      }
    }
    return result;
  }

  global.KumApeProcess = Object.freeze({ normalizeEvent, BUILTIN_PROCESS_MAPPINGS, FIELD_KEYS, relatedAction, normalizePid, graphSearchAction, mappingForEvent, mappingsFromLegacyProfiles, normalizeMappings, processFields });
})(globalThis);
