(function initUsefulFilters(global) {
  "use strict";

  const api = global.KumApeAdapter;
  const processApi = global.KumApeProcess;
  const eventClass = (...ids) => `(${ids.map((id) => `DeviceEventClassID = '${api.escapeSqlString(id)}'`).join(" OR ")})`;
  const and = (...parts) => parts.filter(Boolean).map((part) => `(${part})`).join(" AND ");
  const or = (...parts) => parts.filter(Boolean).map((part) => `(${part})`).join(" OR ");

  function buildUsefulFilters(event, profiles = api.BUILTIN_FIELD_PROFILES, processMappings = processApi.BUILTIN_PROCESS_MAPPINGS) {
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
    let graphAction = null;
    let graphReason = "Для Event ID не настроены поля графа";
    try { graphAction = processApi.graphSearchAction(event, processMappings); } catch (error) { graphReason = error.message; }
    const definitions = [
      ["auth-failures", "Неуспешные входы", "Ошибки входа для текущей учётной записи", account && and(account, eventClass("4625", "4771", "4776", "USER_AUTH", "USER_LOGIN")), "Не найдена учётная запись"],
      ["auth-by-ip", "Аутентификация с IP", "Попытки входа с текущего адреса", ip && and(ip, eventClass("4624", "4625", "4648", "4771", "4776", "USER_AUTH", "USER_LOGIN")), "Не найден исходный или целевой IP"],
      ["process-on-host", "Запуски процессов на узле", "Windows 4688, Sysmon 1 и Linux EXECVE", host && and(host, eventClass("4688", "1", "EXECVE")), "Не найден узел"],
      ["process-relatives", "Родительские и дочерние процессы", "Интерактивный граф процессов на том же узле", graphAction?.where, graphReason],
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

  function findUsefulFilter(id, event, profiles, processMappings) {
    return buildUsefulFilters(event, profiles, processMappings).find((filter) => filter.id === id && filter.applicable) || null;
  }

  global.KumApeFilters = Object.freeze({ buildUsefulFilters, findUsefulFilter });
})(globalThis);
