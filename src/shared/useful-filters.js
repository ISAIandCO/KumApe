(function initUsefulFilters(global) {
  "use strict";

  const api = global.KumApeAdapter;
  const eventClass = (...ids) => `(${ids.map((id) => `DeviceEventClassID = '${api.escapeSqlString(id)}'`).join(" OR ")})`;
  const and = (...parts) => parts.filter(Boolean).map((part) => `(${part})`).join(" AND ");
  const or = (...parts) => parts.filter(Boolean).map((part) => `(${part})`).join(" OR ");

  function matchingProcessGraph(event, profiles) {
    for (const profile of api.normalizeFieldProfiles(profiles)) {
      if (!profile.processGraph) continue;
      const clauses = profile.when;
      const matches = clauses.some((clause) => Object.entries(clause).every(([field, accepted]) => {
        const values = api.valuesForAliases(event, [field]).map((value) => value.toLowerCase());
        return accepted.some((value) => values.includes(value.toLowerCase()));
      }));
      if (matches) return profile.processGraph;
    }
    if (profiles !== api.BUILTIN_FIELD_PROFILES) return matchingProcessGraph(event, api.BUILTIN_FIELD_PROFILES);
    return null;
  }

  function buildUsefulFilters(event, profiles = api.BUILTIN_FIELD_PROFILES) {
    if (!event || typeof event !== "object") return [];
    const groups = new Map(api.fieldGroupsForEvent(event, profiles).map((group) => [group.kind, {
      ...group,
      value: api.valuesForAliases(event, group.aliases)[0] || null,
    }]));
    const groupWhere = (kind) => {
      const group = groups.get(kind);
      return group?.value ? api.equalityWhere(group.queryFields, group.value) : null;
    };
    const host = groupWhere("host");
    const account = groupWhere("account");
    const process = groupWhere("process");
    const hash = groupWhere("hash");
    const file = groupWhere("file");
    const ip = groupWhere("ip");
    const ruleId = api.correlationRuleId(event);
    const graph = matchingProcessGraph(event, profiles);
    const pid = graph && api.valuesForAliases(event, graph.pid || [])[0];
    const parentPid = graph && api.valuesForAliases(event, graph.parentPid || [])[0];
    const relatives = graph && host && or(
      pid && graph.parentPid?.length ? api.equalityWhere(graph.parentPid, pid) : null,
      parentPid && graph.pid?.length ? api.equalityWhere(graph.pid, parentPid) : null,
    );
    const definitions = [
      ["auth-failures", "Неуспешные входы", "Ошибки входа для текущей учётной записи", account && and(account, eventClass("4625", "4771", "4776", "USER_AUTH", "USER_LOGIN")), "Не найдена учётная запись"],
      ["auth-by-ip", "Аутентификация с IP", "Попытки входа с текущего адреса", ip && and(ip, eventClass("4624", "4625", "4648", "4771", "4776", "USER_AUTH", "USER_LOGIN")), "Не найден исходный или целевой IP"],
      ["process-on-host", "Запуски процессов на узле", "Windows 4688, Sysmon 1 и Linux EXECVE", host && and(host, eventClass("4688", "1", "EXECVE")), "Не найден узел"],
      ["process-relatives", "Родительские и дочерние процессы", "Один слой связей по PID на том же узле", relatives && and(host, relatives, eventClass("4688", "1", "EXECVE")), graph ? "Не найдены PID/Parent PID" : "Для типа события не задан processGraph"],
      ["powershell-on-host", "PowerShell на узле", "Script Block 4104 и запуск PowerShell", host && and(host, or(eventClass("4104"), `DeviceProcessName = 'powershell.exe'`, `DestinationProcessName = 'powershell.exe'`)), "Не найден узел"],
      ["service-install", "Установка служб", "События 4697 и 7045 на текущем узле", host && and(host, eventClass("4697", "7045")), "Не найден узел"],
      ["network-by-process", "Сеть текущего процесса", "Sysmon 3 и Windows Filtering Platform 5156/5157", process && and(process, host, eventClass("3", "5156", "5157")), "Не найден процесс"],
      ["dns-by-process", "DNS текущего процесса", "Sysmon DNS Query 22", process && and(process, host, eventClass("22")), "Не найден процесс"],
      ["events-by-hash", "События по хешу", "Все события с текущим файловым хешем", hash, "Не найден файловый хеш"],
      ["events-by-file", "События по файлу", "Все события с текущим именем или путём", file, "Не найден файл или путь"],
      ["correlation-rule", "События правила корреляции", "Все срабатывания текущего правила", ruleId && api.equalityWhere(["CorrelationRuleID", "CorrelationRuleId"], ruleId), "Не найден ID правила корреляции"],
    ];
    return definitions.map(([id, title, description, where, reason]) => ({
      id, title, description, applicable: Boolean(where), reason: where ? null : reason, ...(where ? { where } : {}),
    }));
  }

  function findUsefulFilter(id, event, profiles) {
    return buildUsefulFilters(event, profiles).find((filter) => filter.id === id && filter.applicable) || null;
  }

  global.KumApeFilters = Object.freeze({ buildUsefulFilters, findUsefulFilter });
})(globalThis);
