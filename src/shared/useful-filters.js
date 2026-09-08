(function initUsefulFilters(global) {
  "use strict";

  const api = global.KumApeAdapter;
  const processApi = global.KumApeProcess;
  const TIME_RANGES = Object.freeze({ "5m": 300, "15m": 900, "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000 });
  const PLACEHOLDER = /\$\{(@?[A-Za-z][A-Za-z0-9_]*)\}/g;
  const RENDER_PLACEHOLDER = /('?)\$\{(@?[A-Za-z][A-Za-z0-9_]*)\}\1/g;
  const INTEGER_FIELD = /^(?:BytesIn|BytesOut|DestinationPort|DestinationProcessID|DestinationTranslatedPort|DeviceProcessID|DeviceReceiptTime|EndTime|FileCreateTime|FileModificationTime|FileSize|OldFileCreateTime|OldFileModificationTime|OldFileSize|SourcePort|SourceProcessID|SourceTranslatedPort|StartTime|Timestamp|Type|BaseEventCount|DeviceDirection|DeviceCustom(?:Date|Number)\d+|Flex(?:Date|Number)\d+)$/i;
  const FLOAT_FIELD = /^(?:DestinationLatitude|DestinationLongitude|DeviceLatitude|DeviceLongitude|SourceLatitude|SourceLongitude|DeviceCustomFloatingPoint\d+)$/i;
  const NUMERIC_LITERAL = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i;
  const LOGICAL_FIELDS = new Set(["@ip", "@host", "@account", "@process", "@command", "@file", "@hash", "@domain", "@url"]);
  const RESERVED_IDS = new Set(["process-relatives"]);

  const BUILTIN_FILTERS = Object.freeze([
    { id: "host-events", name: "Все события узла", description: "Показывает активность текущего узла.", template: "DeviceHostName = '${DeviceHostName}'", timeRange: "1h", enabled: true },
    { id: "event-id", name: "Текущее событие по ID", description: "Находит конкретное событие KUMA по его идентификатору.", template: "ID = '${ID}'", timeRange: "5m", enabled: true },
    { id: "event-class-host", name: "Такой же тип события на узле", description: "Ищет тот же Event ID на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND DeviceEventClassID = '${DeviceEventClassID}'", timeRange: "24h", enabled: true },
    { id: "event-class-global", name: "Такой же тип события", description: "Ищет текущий Event ID во всей доступной области.", template: "DeviceEventClassID = '${DeviceEventClassID}'", timeRange: "1h", enabled: true },
    { id: "source-account", name: "Активность исходной учётной записи", description: "Ищет учётную запись источника в обеих ролях.", template: "SourceUserName = '${SourceUserName}' OR DestinationUserName = '${SourceUserName}'", timeRange: "24h", enabled: true },
    { id: "destination-account", name: "Активность целевой учётной записи", description: "Ищет целевую учётную запись в обеих ролях.", template: "SourceUserName = '${DestinationUserName}' OR DestinationUserName = '${DestinationUserName}'", timeRange: "24h", enabled: true },
    { id: "source-account-host", name: "Исходная учётная запись на узле", description: "Ограничивает активность учётной записи текущим узлом.", template: "DeviceHostName = '${DeviceHostName}' AND (SourceUserName = '${SourceUserName}' OR DestinationUserName = '${SourceUserName}')", timeRange: "24h", enabled: true },
    { id: "destination-account-host", name: "Целевая учётная запись на узле", description: "Ограничивает активность целевой учётной записи текущим узлом.", template: "DeviceHostName = '${DeviceHostName}' AND (SourceUserName = '${DestinationUserName}' OR DestinationUserName = '${DestinationUserName}')", timeRange: "24h", enabled: true },
    { id: "source-user-id", name: "Активность исходного User ID", description: "Ищет идентификатор пользователя источника в обеих ролях.", template: "SourceUserID = '${SourceUserID}' OR DestinationUserID = '${SourceUserID}'", timeRange: "24h", enabled: true },
    { id: "destination-user-id", name: "Активность целевого User ID", description: "Ищет идентификатор целевого пользователя в обеих ролях.", template: "SourceUserID = '${DestinationUserID}' OR DestinationUserID = '${DestinationUserID}'", timeRange: "24h", enabled: true },
    { id: "source-ip", name: "Активность исходного IP", description: "Ищет исходный IP с обеих сторон соединения.", template: "SourceAddress = '${SourceAddress}' OR DestinationAddress = '${SourceAddress}'", timeRange: "24h", enabled: true },
    { id: "destination-ip", name: "Активность целевого IP", description: "Ищет IP назначения с обеих сторон соединения.", template: "SourceAddress = '${DestinationAddress}' OR DestinationAddress = '${DestinationAddress}'", timeRange: "24h", enabled: true },
    { id: "device-ip", name: "Активность IP устройства", description: "Ищет адрес устройства в основных IP-полях.", template: "DeviceAddress = '${DeviceAddress}' OR SourceAddress = '${DeviceAddress}' OR DestinationAddress = '${DeviceAddress}'", timeRange: "24h", enabled: true },
    { id: "ip-pair", name: "Связь между двумя IP", description: "Ищет обмен между src и dst в обоих направлениях.", template: "(SourceAddress = '${SourceAddress}' AND DestinationAddress = '${DestinationAddress}') OR (SourceAddress = '${DestinationAddress}' AND DestinationAddress = '${SourceAddress}')", timeRange: "24h", enabled: true },
    { id: "source-ip-destination-port", name: "Исходный IP и порт назначения", description: "Сужает поиск до текущего источника и целевого порта.", template: "SourceAddress = '${SourceAddress}' AND DestinationPort = ${DestinationPort}", timeRange: "24h", enabled: true },
    { id: "source-port", name: "Исходный порт", description: "Ищет события с тем же исходным портом.", template: "SourcePort = ${SourcePort}", timeRange: "24h", enabled: true },
    { id: "destination-port", name: "Порт назначения", description: "Ищет события с тем же портом назначения.", template: "DestinationPort = ${DestinationPort}", timeRange: "24h", enabled: true },
    { id: "network-flow", name: "Точный сетевой поток", description: "Ищет совпадение IP, портов и протокола.", template: "SourceAddress = '${SourceAddress}' AND SourcePort = ${SourcePort} AND DestinationAddress = '${DestinationAddress}' AND DestinationPort = ${DestinationPort} AND TransportProtocol = '${TransportProtocol}'", timeRange: "1h", enabled: true },
    { id: "protocol-host", name: "Тот же протокол на узле", description: "Ищет события протокола на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND TransportProtocol = '${TransportProtocol}'", timeRange: "24h", enabled: true },
    { id: "application-protocol", name: "Тот же прикладной протокол", description: "Ищет события с текущим ApplicationProtocol.", template: "ApplicationProtocol = '${ApplicationProtocol}'", timeRange: "24h", enabled: true },
    { id: "source-hostname", name: "Активность исходного имени узла", description: "Ищет текущее SourceHostName.", template: "SourceHostName = '${SourceHostName}'", timeRange: "7d", enabled: true },
    { id: "destination-hostname", name: "Активность имени узла назначения", description: "Ищет текущее DestinationHostName.", template: "DestinationHostName = '${DestinationHostName}'", timeRange: "7d", enabled: true },
    { id: "source-domain", name: "Активность исходного домена", description: "Ищет SourceDnsDomain.", template: "SourceDnsDomain = '${SourceDnsDomain}'", timeRange: "7d", enabled: true },
    { id: "destination-domain", name: "Активность домена назначения", description: "Ищет DestinationDnsDomain.", template: "DestinationDnsDomain = '${DestinationDnsDomain}'", timeRange: "7d", enabled: true },
    { id: "source-mac", name: "Активность исходного MAC", description: "Ищет события с тем же MAC-адресом источника.", template: "SourceMacAddress = '${SourceMacAddress}'", timeRange: "7d", enabled: true },
    { id: "destination-mac", name: "Активность MAC назначения", description: "Ищет события с тем же MAC-адресом назначения.", template: "DestinationMacAddress = '${DestinationMacAddress}'", timeRange: "7d", enabled: true },
    { id: "auth-failures", name: "Неуспешные входы", description: "Ищет ошибки входа для текущей учётной записи.", template: "${@account} AND DeviceEventClassID IN ('4625', '4771', '4776', 'USER_AUTH', 'USER_LOGIN')", timeRange: "24h", enabled: true },
    { id: "auth-by-ip", name: "Аутентификация с IP", description: "Ищет попытки входа с текущего адреса.", template: "${@ip} AND DeviceEventClassID IN ('4624', '4625', '4648', '4771', '4776', 'USER_AUTH', 'USER_LOGIN')", timeRange: "24h", enabled: true },
    { id: "process-on-host", name: "Запуски процессов на узле", description: "Ищет Windows 4688, Sysmon 1 и Linux EXECVE на текущем узле.", template: "${@host} AND DeviceEventClassID IN ('4688', '1', 'EXECVE')", timeRange: "1h", enabled: true },
    { id: "destination-process-host", name: "Процесс с таким именем на узле", description: "Ищет имя целевого процесса во всех основных процессных полях.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${DestinationProcessName}' OR SourceProcessName = '${DestinationProcessName}' OR DeviceProcessName = '${DestinationProcessName}')", timeRange: "7d", enabled: true },
    { id: "device-process-host", name: "DeviceProcessName на узле", description: "Ищет основной процесс нормализатора на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${DeviceProcessName}' OR SourceProcessName = '${DeviceProcessName}' OR DeviceProcessName = '${DeviceProcessName}')", timeRange: "7d", enabled: true },
    { id: "source-process-host", name: "Исходный процесс на узле", description: "Ищет SourceProcessName во всех основных процессных полях.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${SourceProcessName}' OR SourceProcessName = '${SourceProcessName}' OR DeviceProcessName = '${SourceProcessName}')", timeRange: "7d", enabled: true },
    { id: "device-pid-host", name: "Device PID на узле", description: "Ищет PID процесса только на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = ${DeviceProcessID} OR DestinationProcessID = ${DeviceProcessID} OR SourceProcessID = ${DeviceProcessID})", timeRange: "1h", enabled: true },
    { id: "destination-pid-host", name: "Destination PID на узле", description: "Ищет целевой PID только на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = ${DestinationProcessID} OR DestinationProcessID = ${DestinationProcessID} OR SourceProcessID = ${DestinationProcessID})", timeRange: "1h", enabled: true },
    { id: "children-by-pid", name: "Дочерние процессы по PID", description: "Ищет процессы, у которых PID текущего процесса указан как родительский.", template: "DeviceHostName = '${DeviceHostName}' AND SourceProcessID = ${DestinationProcessID}", timeRange: "1h", enabled: true },
    { id: "command-line-4688", name: "Та же командная строка 4688", description: "Ищет точное совпадение DeviceCustomString4.", template: "DeviceCustomString4 = '${DeviceCustomString4}'", timeRange: "7d", enabled: true },
    { id: "powershell-host", name: "PowerShell на узле", description: "Ищет Script Block 4104 и запуски PowerShell без учёта регистра и пути.", template: "${@host} AND (DeviceEventClassID = '4104' OR DeviceProcessName ILIKE '%powershell.exe' OR DestinationProcessName ILIKE '%powershell.exe')", timeRange: "24h", enabled: true },
    { id: "service-install-host", name: "Установка служб на узле", description: "Ищет Windows 4697 и 7045.", template: "${@host} AND DeviceEventClassID IN ('4697', '7045')", timeRange: "7d", enabled: true },
    { id: "network-by-process", name: "Сеть текущего процесса", description: "Ищет Sysmon 3 и Windows Filtering Platform 5156/5157 для текущего процесса.", template: "${@process} AND ${@host} AND DeviceEventClassID IN ('3', '5156', '5157')", timeRange: "1h", enabled: true },
    { id: "dns-by-process", name: "DNS текущего процесса", description: "Ищет Sysmon DNS Query 22 для текущего процесса.", template: "${@process} AND ${@host} AND DeviceEventClassID = '22'", timeRange: "24h", enabled: true },
    { id: "dns-query-host", name: "DNS-запросы на узле", description: "Ищет Sysmon DNS Query 22.", template: "${@host} AND DeviceEventClassID = '22'", timeRange: "24h", enabled: true },
    { id: "file-path-host", name: "Файл по полному пути на узле", description: "Ищет текущий FilePath на выбранном узле.", template: "DeviceHostName = '${DeviceHostName}' AND FilePath = '${FilePath}'", timeRange: "7d", enabled: true },
    { id: "file-name-host", name: "Файл с таким именем на узле", description: "Ищет текущее FileName на выбранном узле.", template: "DeviceHostName = '${DeviceHostName}' AND FileName = '${FileName}'", timeRange: "7d", enabled: true },
    { id: "events-by-file", name: "События по файлу", description: "Ищет текущее имя или путь файла во всех полях профиля.", template: "${@file}", timeRange: "7d", enabled: true },
    { id: "events-by-hash", name: "События с тем же хешем", description: "Ищет текущий файловый хеш во всех полях профиля.", template: "${@hash}", timeRange: "30d", enabled: true },
    { id: "old-file-hash", name: "События со старым хешем", description: "Ищет OldFileHash среди текущих и прежних значений.", template: "FileHash = '${OldFileHash}' OR OldFileHash = '${OldFileHash}'", timeRange: "30d", enabled: true },
    { id: "request-url", name: "События с тем же URL", description: "Ищет точное совпадение RequestUrl.", template: "RequestUrl = '${RequestUrl}'", timeRange: "7d", enabled: true },
    { id: "http-method", name: "Тот же HTTP-метод", description: "Ищет RequestMethod на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND RequestMethod = '${RequestMethod}'", timeRange: "24h", enabled: true },
    { id: "http-client", name: "Тот же HTTP-клиент", description: "Ищет RequestClientApplication.", template: "RequestClientApplication = '${RequestClientApplication}'", timeRange: "7d", enabled: true },
    { id: "correlation-rule-id", name: "Срабатывания того же правила", description: "Ищет события по CorrelationRuleID.", template: "CorrelationRuleID = '${CorrelationRuleID}'", timeRange: "7d", enabled: true },
    { id: "correlation-rule-name", name: "Срабатывания правила с тем же именем", description: "Ищет события по CorrelationRuleName.", template: "CorrelationRuleName = '${CorrelationRuleName}'", timeRange: "7d", enabled: true },
    { id: "aggregation-rule-id", name: "События правила агрегации", description: "Ищет события по AggregationRuleID.", template: "AggregationRuleID = '${AggregationRuleID}'", timeRange: "7d", enabled: true },
    { id: "source-product-host", name: "Тот же продукт-источник на узле", description: "Ищет активность DeviceProduct на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND DeviceProduct = '${DeviceProduct}'", timeRange: "24h", enabled: true },
    { id: "vendor-product", name: "События того же продукта", description: "Ищет сочетание DeviceVendor и DeviceProduct.", template: "DeviceVendor = '${DeviceVendor}' AND DeviceProduct = '${DeviceProduct}'", timeRange: "24h", enabled: true },
    { id: "device-action", name: "То же действие события", description: "Ищет текущее DeviceAction.", template: "DeviceAction = '${DeviceAction}'", timeRange: "24h", enabled: true },
    { id: "event-outcome", name: "Тот же результат события", description: "Ищет EventOutcome для того же типа события.", template: "DeviceEventClassID = '${DeviceEventClassID}' AND EventOutcome = '${EventOutcome}'", timeRange: "24h", enabled: true },
    { id: "severity", name: "События той же критичности", description: "Ищет события с текущим Severity.", template: "Severity = '${Severity}'", timeRange: "24h", enabled: true },
    { id: "external-id", name: "События с тем же внешним ID", description: "Ищет DeviceExternalID.", template: "DeviceExternalID = '${DeviceExternalID}'", timeRange: "24h", enabled: true },
  ].map(Object.freeze));

  const LEGACY_BUILTIN_TEMPLATES = Object.freeze({
    "source-ip-destination-port": "SourceAddress = '${SourceAddress}' AND DestinationPort = '${DestinationPort}'",
    "source-port": "SourcePort = '${SourcePort}'",
    "destination-port": "DestinationPort = '${DestinationPort}'",
    "network-flow": "SourceAddress = '${SourceAddress}' AND SourcePort = '${SourcePort}' AND DestinationAddress = '${DestinationAddress}' AND DestinationPort = '${DestinationPort}' AND TransportProtocol = '${TransportProtocol}'",
    "auth-failures": "${@account} AND (DeviceEventClassID = '4625' OR DeviceEventClassID = '4771' OR DeviceEventClassID = '4776' OR DeviceEventClassID = 'USER_AUTH' OR DeviceEventClassID = 'USER_LOGIN')",
    "auth-by-ip": "${@ip} AND (DeviceEventClassID = '4624' OR DeviceEventClassID = '4625' OR DeviceEventClassID = '4648' OR DeviceEventClassID = '4771' OR DeviceEventClassID = '4776' OR DeviceEventClassID = 'USER_AUTH' OR DeviceEventClassID = 'USER_LOGIN')",
    "process-on-host": "${@host} AND (DeviceEventClassID = '4688' OR DeviceEventClassID = '1' OR DeviceEventClassID = 'EXECVE')",
    "device-pid-host": "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = '${DeviceProcessID}' OR DestinationProcessID = '${DeviceProcessID}' OR SourceProcessID = '${DeviceProcessID}')",
    "destination-pid-host": "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = '${DestinationProcessID}' OR DestinationProcessID = '${DestinationProcessID}' OR SourceProcessID = '${DestinationProcessID}')",
    "children-by-pid": "DeviceHostName = '${DeviceHostName}' AND SourceProcessID = '${DestinationProcessID}'",
    "powershell-host": "${@host} AND (DeviceEventClassID = '4104' OR DeviceProcessName = 'powershell.exe' OR DestinationProcessName = 'powershell.exe')",
    "service-install-host": "${@host} AND (DeviceEventClassID = '4697' OR DeviceEventClassID = '7045')",
    "network-by-process": "${@process} AND ${@host} AND (DeviceEventClassID = '3' OR DeviceEventClassID = '5156' OR DeviceEventClassID = '5157')",
  });

  function migrateBuiltinFilters(filters) {
    if (!Array.isArray(filters)) return filters;
    const current = new Map(BUILTIN_FILTERS.map((filter) => [filter.id, filter.template]));
    return filters.map((filter) => filter && filter.template === LEGACY_BUILTIN_TEMPLATES[filter.id]
      ? { ...filter, template: current.get(filter.id) }
      : filter);
  }

  function requiredTemplateFields(template) {
    return [...new Set([...String(template).matchAll(PLACEHOLDER)].map((match) => match[1]))];
  }

  function normalizeFilterTemplate(filter, index = 0) {
    if (!filter || typeof filter !== "object" || Array.isArray(filter)) throw new TypeError(`Фильтр ${index + 1}: ожидается объект`);
    const template = String(filter.template ?? "").trim();
    if (!template || template.length > 4000 || /[;\0]/.test(template)) throw new TypeError(`Фильтр ${index + 1}: недопустимый SQL-шаблон`);
    const requiredFields = requiredTemplateFields(template);
    const placeholderCount = [...template.matchAll(PLACEHOLDER)].length;
    if (!requiredFields.length || template.includes("${") && placeholderCount !== (template.match(/\$\{/g) || []).length) {
      throw new TypeError(`Фильтр ${index + 1}: используйте подстановки вида \${ИмяПоля}`);
    }
    requiredFields.forEach((field) => {
      if (field.startsWith("@")) {
        if (!LOGICAL_FIELDS.has(field)) throw new TypeError(`Фильтр ${index + 1}: неизвестная группа ${field}`);
        if (template.includes(`'\${${field}}'`)) throw new TypeError(`Фильтр ${index + 1}: логическую группу ${field} не нужно заключать в кавычки`);
      } else api.sqlIdentifier(field);
    });
    const id = String(filter.id || `filter-${index + 1}`).replace(/[^a-z0-9_-]/gi, "-").slice(0, 64);
    if (!id || RESERVED_IDS.has(id)) throw new TypeError(`Фильтр ${index + 1}: недопустимый id`);
    const name = String(filter.name || filter.title || `Фильтр ${index + 1}`).trim().slice(0, 120);
    if (!name) throw new TypeError(`Фильтр ${index + 1}: укажите название`);
    const timeRange = Object.hasOwn(TIME_RANGES, filter.timeRange) ? filter.timeRange : "15m";
    return { id, name, description: String(filter.description || "Пользовательский SQL-фильтр KUMA.").trim().slice(0, 300), template, timeRange, enabled: filter.enabled !== false };
  }

  function normalizeFilterTemplates(filters = BUILTIN_FILTERS) {
    if (!Array.isArray(filters) || filters.length > 100) throw new TypeError("Полезные фильтры должны быть массивом не более чем из 100 записей");
    const normalized = filters.map(normalizeFilterTemplate);
    const ids = new Set();
    for (const filter of normalized) {
      if (ids.has(filter.id)) throw new TypeError(`Повторяется id полезного фильтра: ${filter.id}`);
      ids.add(filter.id);
    }
    return normalized;
  }

  function renderFilterTemplate(template, event, profiles = api.BUILTIN_FIELD_PROFILES) {
    const fields = requiredTemplateFields(template);
    const groups = new Map(api.fieldGroupsForEvent(event, profiles).map((group) => [group.kind, group]));
    const values = new Map(fields.map((field) => {
      if (!field.startsWith("@")) {
        const value = api.valuesForAliases(event, [field])[0] || "";
        if ((INTEGER_FIELD.test(field) || FLOAT_FIELD.test(field)) && (!NUMERIC_LITERAL.test(value) || INTEGER_FIELD.test(field) && !/^[+-]?\d+$/.test(value))) return [field, ""];
        return [field, value];
      }
      const group = groups.get(field.slice(1));
      const value = api.valuesForAliases(event, group?.aliases || [])[0] || "";
      return [field, value ? api.equalityWhere(group.queryFields, value) : ""];
    }));
    const missing = fields.filter((field) => !values.get(field)).map((field) => {
      if (!field.startsWith("@")) return field;
      const group = groups.get(field.slice(1));
      return group?.aliases?.join(" / ") || field;
    });
    if (missing.length) return { ok: false, missing, where: null };
    const where = String(template).replace(RENDER_PLACEHOLDER, (match, quote, field) => {
      if (field.startsWith("@")) return `(${values.get(field)})`;
      if (INTEGER_FIELD.test(field) || FLOAT_FIELD.test(field)) return values.get(field);
      return `'${api.escapeSqlString(values.get(field))}'`;
    });
    return { ok: true, missing: [], where };
  }

  function processGraphFilter(event, processMappings) {
    try {
      const action = processApi.graphSearchAction(event, processMappings);
      return { id: "process-relatives", title: "Родительские и дочерние процессы", description: "Интерактивный граф процессов на том же узле.", type: "processGraph", timeRange: "15m", rangeSeconds: TIME_RANGES["15m"], applicable: true, missing: [], where: action.where };
    } catch (error) {
      const field = /В поле ([A-Za-z][A-Za-z0-9_]*)/.exec(error.message)?.[1];
      return { id: "process-relatives", title: "Родительские и дочерние процессы", description: "Интерактивный граф процессов на том же узле.", type: "processGraph", timeRange: "15m", rangeSeconds: TIME_RANGES["15m"], applicable: false, missing: field ? [field] : ["сопоставление полей графа"], reason: error.message };
    }
  }

  function buildUsefulFilters(event, profiles = api.BUILTIN_FIELD_PROFILES, processMappings = processApi.BUILTIN_PROCESS_MAPPINGS, filterTemplates = BUILTIN_FILTERS) {
    if (!event || typeof event !== "object") return [];
    const filters = normalizeFilterTemplates(filterTemplates).filter((filter) => filter.enabled).map((filter) => {
      const rendered = renderFilterTemplate(filter.template, event, profiles);
      return {
        id: filter.id, title: filter.name, description: filter.description, type: "query", timeRange: filter.timeRange,
        rangeSeconds: TIME_RANGES[filter.timeRange], applicable: rendered.ok, missing: rendered.missing,
        ...(rendered.ok ? { where: rendered.where } : { reason: `Нет полей: ${rendered.missing.join(", ")}` }),
      };
    });
    filters.push(processGraphFilter(event, processMappings));
    return filters;
  }

  function findUsefulFilter(id, event, profiles, processMappings, filterTemplates) {
    return buildUsefulFilters(event, profiles, processMappings, filterTemplates).find((filter) => filter.id === id && filter.applicable) || null;
  }

  global.KumApeFilters = Object.freeze({ BUILTIN_FILTERS, TIME_RANGES, buildUsefulFilters, findUsefulFilter, migrateBuiltinFilters, normalizeFilterTemplates, renderFilterTemplate, requiredTemplateFields });
})(globalThis);
