import { composeFilterCatalog, splitLegacyFilters } from "@isaiandco/ape-share-core/filters/catalog";
import { validatePlaceholderPositions, compactSql, prepareSelectQuery } from "./sql-query.js";
import { detectEventPlatform, filterSupportsPlatform, normalizeFilterPlatforms } from "@isaiandco/ape-share-core/filters/platform";
import { TIME_RANGES, requiredTemplateFields as requiredFields, renderTemplate } from "@isaiandco/ape-share-core/filters/templates";
(function initUsefulFilters(global) {
  "use strict";

  const api = global.KumApeAdapter;
  const processApi = global.KumApeProcess;

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
    { id: "event-class-global", name: "Такой же тип события (глобально)", description: "Ищет текущий Event ID во всей доступной области.", template: "DeviceEventClassID = '${DeviceEventClassID}'", timeRange: "1h", enabled: true },
    { id: "source-account", name: "Активность исходной учётной записи (глобально)", description: "Ищет учётную запись источника в обеих ролях.", template: "SourceUserName = '${SourceUserName}' OR DestinationUserName = '${SourceUserName}'", timeRange: "24h", enabled: true },
    { id: "destination-account", name: "Активность целевой учётной записи (глобально)", description: "Ищет целевую учётную запись в обеих ролях.", template: "SourceUserName = '${DestinationUserName}' OR DestinationUserName = '${DestinationUserName}'", timeRange: "24h", enabled: true },
    { id: "source-account-host", name: "Активность исходной учётной записи (локально)", description: "Ограничивает активность учётной записи текущим узлом.", template: "DeviceHostName = '${DeviceHostName}' AND (SourceUserName = '${SourceUserName}' OR DestinationUserName = '${SourceUserName}')", timeRange: "24h", enabled: true },
    { id: "destination-account-host", name: "Активность целевой учётной записи (локально)", description: "Ограничивает активность целевой учётной записи текущим узлом.", template: "DeviceHostName = '${DeviceHostName}' AND (SourceUserName = '${DestinationUserName}' OR DestinationUserName = '${DestinationUserName}')", timeRange: "24h", enabled: true },
    { id: "source-user-id", name: "Активность исходного User ID (глобально)", description: "Ищет идентификатор пользователя источника в обеих ролях.", template: "SourceUserID = '${SourceUserID}' OR DestinationUserID = '${SourceUserID}'", timeRange: "24h", enabled: true },
    { id: "destination-user-id", name: "Активность целевого User ID (глобально)", description: "Ищет идентификатор целевого пользователя в обеих ролях.", template: "SourceUserID = '${DestinationUserID}' OR DestinationUserID = '${DestinationUserID}'", timeRange: "24h", enabled: true },
    { id: "source-ip", name: "Активность исходного IP", description: "Ищет исходный IP с обеих сторон соединения.", template: "SourceAddress = '${SourceAddress}' OR DestinationAddress = '${SourceAddress}'", timeRange: "24h", enabled: true },
    { id: "destination-ip", name: "Активность целевого IP", description: "Ищет IP назначения с обеих сторон соединения.", template: "SourceAddress = '${DestinationAddress}' OR DestinationAddress = '${DestinationAddress}'", timeRange: "24h", enabled: true },
    { id: "device-ip", name: "Активность IP устройства", description: "Ищет адрес устройства в основных IP-полях.", template: "DeviceAddress = '${DeviceAddress}' OR SourceAddress = '${DeviceAddress}' OR DestinationAddress = '${DeviceAddress}'", timeRange: "24h", enabled: true },
    { id: "ip-pair", name: "Связь между двумя IP", description: "Ищет обмен между src и dst в обоих направлениях.", template: "(SourceAddress = '${SourceAddress}' AND DestinationAddress = '${DestinationAddress}') OR (SourceAddress = '${DestinationAddress}' AND DestinationAddress = '${SourceAddress}')", timeRange: "24h", enabled: true },
    { id: "source-ip-destination-port", name: "Активность пары Исходный IP+порт назначения", description: "Сужает поиск до текущего источника и целевого порта.", template: "SourceAddress = '${SourceAddress}' AND DestinationPort = ${DestinationPort}", timeRange: "24h", enabled: true },
    { id: "source-port", name: "Исходный порт", description: "Ищет события с тем же исходным портом.", template: "SourcePort = ${SourcePort}", timeRange: "24h", enabled: false },
    { id: "destination-port", name: "Порт назначения", description: "Ищет события с тем же портом назначения.", template: "DestinationPort = ${DestinationPort}", timeRange: "24h", enabled: false },
    { id: "network-flow", name: "Точный сетевой поток", description: "Ищет совпадение IP, портов и протокола.", template: "SourceAddress = '${SourceAddress}' AND SourcePort = ${SourcePort} AND DestinationAddress = '${DestinationAddress}' AND DestinationPort = ${DestinationPort} AND TransportProtocol = '${TransportProtocol}'", timeRange: "1h", enabled: true },
    { id: "protocol-host", name: "Тот же протокол на узле", description: "Ищет события протокола на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND TransportProtocol = '${TransportProtocol}'", timeRange: "24h", enabled: true },
    { id: "application-protocol", name: "Тот же прикладной протокол", description: "Ищет события с текущим ApplicationProtocol.", template: "ApplicationProtocol = '${ApplicationProtocol}'", timeRange: "24h", enabled: true },
    { id: "source-hostname", name: "Активность исходного имени узла", description: "Ищет текущее SourceHostName.", template: "SourceHostName = '${SourceHostName}' or DestinationHostName = '${SourceHostName}'", timeRange: "7d", enabled: true },
    { id: "destination-hostname", name: "Активность имени узла назначения", description: "Ищет текущее DestinationHostName.", template: "DestinationHostName = '${DestinationHostName}' or SourceHostName = '${DestinationHostName}'", timeRange: "7d", enabled: true },
    { id: "source-domain", name: "Активность исходного домена", description: "Ищет SourceDnsDomain.", template: "SourceDnsDomain = '${SourceDnsDomain}'", timeRange: "7d", enabled: false },
    { id: "destination-domain", name: "Активность домена назначения", description: "Ищет DestinationDnsDomain.", template: "DestinationDnsDomain = '${DestinationDnsDomain}'", timeRange: "7d", enabled: false },
    { id: "source-mac", name: "Активность исходного MAC", description: "Ищет события с тем же MAC-адресом источника.", template: "SourceMacAddress = '${SourceMacAddress}' or DestinationMacAddress = '${SourceMacAddress}'", timeRange: "7d", enabled: true },
    { id: "destination-mac", name: "Активность MAC назначения", description: "Ищет события с тем же MAC-адресом назначения.", template: "SourceMacAddress = '${DestinationMacAddress}' or DestinationMacAddress = '${DestinationMacAddress}'", timeRange: "7d", enabled: true },
    { id: "auth-failures", name: "Неуспешные входы", description: "Ищет ошибки входа для текущей учётной записи.", template: "${@account} AND DeviceEventClassID IN ('4625', '4771', '4776', 'USER_AUTH', 'USER_LOGIN')", timeRange: "24h", enabled: true },
    { id: "auth-by-ip", name: "Аутентификация с IP", description: "Ищет попытки входа с текущего адреса.", template: "${@ip} AND DeviceEventClassID IN ('4624', '4625', '4648', '4771', '4776', 'USER_AUTH', 'USER_LOGIN')", timeRange: "24h", enabled: true },
    { id: "process-on-host", name: "Запуски процессов на узле", description: "Ищет Windows 4688, Sysmon 1 и Linux EXECVE на текущем узле.", template: "${@host} AND DeviceEventClassID IN ('4688', '1', 'EXECVE')", timeRange: "1h", enabled: true },
    { id: "destination-process-host", name: "Процесс с таким именем на узле", description: "Ищет имя целевого процесса во всех основных процессных полях.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${DestinationProcessName}' OR SourceProcessName = '${DestinationProcessName}' OR DeviceProcessName = '${DestinationProcessName}')", timeRange: "7d", enabled: true },
    { id: "device-process-host", name: "DeviceProcessName на узле", description: "Ищет основной процесс нормализатора на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${DeviceProcessName}' OR SourceProcessName = '${DeviceProcessName}' OR DeviceProcessName = '${DeviceProcessName}')", timeRange: "7d", enabled: true },
    { id: "source-process-host", name: "Исходный процесс на узле", description: "Ищет SourceProcessName во всех основных процессных полях.", template: "DeviceHostName = '${DeviceHostName}' AND (DestinationProcessName = '${SourceProcessName}' OR SourceProcessName = '${SourceProcessName}' OR DeviceProcessName = '${SourceProcessName}')", timeRange: "7d", enabled: true },
    { id: "device-pid-host", name: "Device PID на узле", description: "Ищет PID процесса только на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = ${DeviceProcessID} OR DestinationProcessID = ${DeviceProcessID} OR SourceProcessID = ${DeviceProcessID})", timeRange: "1h", enabled: true },
    { id: "destination-pid-host", name: "Destination PID на узле", description: "Ищет целевой PID только на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND (DeviceProcessID = ${DestinationProcessID} OR DestinationProcessID = ${DestinationProcessID} OR SourceProcessID = ${DestinationProcessID})", timeRange: "1h", enabled: true },
    { id: "children-by-pid", name: "Дочерние процессы по PID", description: "Ищет процессы, у которых PID текущего процесса указан как родительский.", template: "DeviceHostName = '${DeviceHostName}' AND (SourceProcessID = ${DestinationProcessID} or (DeviceCustomString5 = '${DeviceCustomString3}' and DeviceCustomString5Label ilike '%process id%'))", timeRange: "1h", enabled: true },
    { id: "command-line-4688", platforms: ["windows"], name: "Та же командная строка 4688 (Глобально)", description: "Ищет точное совпадение DeviceCustomString4.", template: "DeviceCustomString4 = '${DeviceCustomString4}'", timeRange: "7d", enabled: true },
    { id: "powershell-host", platforms: ["windows"], name: "PowerShell на узле", description: "Ищет Script Block 4104 и запуски PowerShell без учёта регистра и пути.", template: "${@host} AND (DeviceEventClassID = '4104' OR DeviceProcessName ILIKE '%powershell.exe' OR DestinationProcessName ILIKE '%powershell.exe')", timeRange: "24h", enabled: true },
    { id: "service-install-host", platforms: ["windows"], name: "Установка служб на узле", description: "Ищет Windows 4697 и 7045.", template: "${@host} AND DeviceEventClassID IN ('4697', '7045')", timeRange: "7d", enabled: true },
    { id: "network-by-process", platforms: ["windows"], name: "Сеть текущего процесса", description: "Ищет Sysmon 3 и Windows Filtering Platform 5156/5157 для текущего процесса.", template: "${@process} AND ${@host} AND DeviceEventClassID IN ('3', '5156', '5157')", timeRange: "1h", enabled: true },
    { id: "dns-by-process", platforms: ["windows"], name: "DNS текущего процесса", description: "Ищет Sysmon DNS Query 22 для текущего процесса.", template: "${@process} AND ${@host} AND DeviceEventClassID = '22'", timeRange: "24h", enabled: true },
    { id: "dns-query-host", platforms: ["windows"], name: "DNS-запросы на узле", description: "Ищет Sysmon DNS Query 22.", template: "${@host} AND DeviceEventClassID = '22'", timeRange: "24h", enabled: true },
    { id: "file-path-host", name: "Файл по полному пути на узле", description: "Ищет текущий FilePath на выбранном узле.", template: "DeviceHostName = '${DeviceHostName}' AND FilePath = '${FilePath}'", timeRange: "7d", enabled: true },
    { id: "file-name-host", name: "Файл с таким именем на узле", description: "Ищет текущее FileName на выбранном узле.", template: "DeviceHostName = '${DeviceHostName}' AND FileName = '${FileName}'", timeRange: "7d", enabled: true },
    { id: "events-by-file", name: "События по файлу", description: "Ищет текущее имя или путь файла во всех полях профиля.", template: "${@file}", timeRange: "7d", enabled: true },
    { id: "events-by-hash", name: "События с тем же хешем", description: "Ищет текущий файловый хеш во всех полях профиля.", template: "${@hash}", timeRange: "30d", enabled: true },
    { id: "old-file-hash", name: "События со старым хешем", description: "Ищет OldFileHash среди текущих и прежних значений.", template: "FileHash = '${OldFileHash}' OR OldFileHash = '${OldFileHash}'", timeRange: "30d", enabled: true },
    { id: "request-url", name: "События с тем же URL", description: "Ищет точное совпадение RequestUrl.", template: "RequestUrl = '${RequestUrl}'", timeRange: "7d", enabled: true },
    { id: "http-method", name: "Тот же HTTP-метод", description: "Ищет RequestMethod на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND RequestMethod = '${RequestMethod}'", timeRange: "24h", enabled: false },
    { id: "http-client", name: "Тот же HTTP-клиент", description: "Ищет RequestClientApplication.", template: "RequestClientApplication = '${RequestClientApplication}'", timeRange: "7d", enabled: true },
    { id: "correlation-rule-id", name: "Срабатывания того же правила", description: "Ищет события по CorrelationRuleID.", template: "CorrelationRuleID = '${CorrelationRuleID}'", timeRange: "7d", enabled: true },
    { id: "correlation-rule-name", name: "Срабатывания правила с тем же именем", description: "Ищет события по CorrelationRuleName.", template: "CorrelationRuleName = '${CorrelationRuleName}'", timeRange: "7d", enabled: true },
    { id: "aggregation-rule-id", name: "События правила агрегации", description: "Ищет события по AggregationRuleID.", template: "AggregationRuleID = '${AggregationRuleID}'", timeRange: "7d", enabled: true },
    { id: "source-product-host", name: "Тот же продукт-источник на узле", description: "Ищет активность DeviceProduct на текущем узле.", template: "DeviceHostName = '${DeviceHostName}' AND DeviceProduct = '${DeviceProduct}'", timeRange: "24h", enabled: true },
    { id: "vendor-product", name: "События того же продукта", description: "Ищет сочетание DeviceVendor и DeviceProduct.", template: "DeviceVendor = '${DeviceVendor}' AND DeviceProduct = '${DeviceProduct}'", timeRange: "24h", enabled: true },
    { id: "device-action", name: "То же действие события", description: "Ищет текущее DeviceAction.", template: "DeviceAction = '${DeviceAction}'", timeRange: "24h", enabled: false },
    { id: "event-outcome", name: "Тот же результат события", description: "Ищет EventOutcome для того же типа события.", template: "DeviceEventClassID = '${DeviceEventClassID}' AND EventOutcome = '${EventOutcome}'", timeRange: "24h", enabled: false },
    { id: "severity", name: "События той же критичности", description: "Ищет события с текущим Severity.", template: "Severity = '${Severity}'", timeRange: "24h", enabled: false },
    { id: "external-id", name: "События с тем же внешним ID", description: "Ищет DeviceExternalID.", template: "DeviceExternalID = '${DeviceExternalID}'", timeRange: "24h", enabled: true },
    { id: "source-destinations-summary", mode: "sql", name: "Куда обращался исходный IP", description: "Направления соединений, число событий и уникальных исходных портов.", template: "SELECT DestinationAddress AS dest_ip, DestinationNtDomain AS dest_domain, DestinationPort AS dest_port, TransportProtocol AS protocol, count(ID) AS attempts, uniq(SourcePort) AS source_ports_used FROM `events` WHERE SourceAddress = '${SourceAddress}' GROUP BY DestinationAddress, DestinationNtDomain, DestinationPort, TransportProtocol ORDER BY attempts DESC LIMIT 250", timeRange: "24h", enabled: true },
    { id: "ssh-successful-logins", mode: "sql", platforms: ["unix"], name: "Успешные SSH-входы", description: "Входы audit/USER_ACCT с вычисляемыми колонками результата и описания.", template: "SELECT Timestamp, DeviceHostName AS SSH_Server, DestinationUserName AS Username, SourceAddress AS Client_IP, CASE WHEN EventOutcome = 'success' THEN 'Successful login' WHEN EventOutcome = 'failed' THEN 'Failed login attempt' ELSE EventOutcome END AS Result, concat('User ', DestinationUserName, ' logged in via SSH to ', DeviceHostName, ' from IP ', SourceAddress) AS Description FROM `events` WHERE DeviceProduct = 'audit' AND DeviceEventClassID = 'USER_ACCT' AND DestinationProcessName LIKE '%sshd%' AND EventOutcome = 'success' ORDER BY Timestamp DESC LIMIT 500", timeRange: "24h", enabled: true },
    {
      "id": "all_OpenVpnConnections",
      "name": "[man] Соединения всех УЗ к OpenVPN",
      "mode": "sql",
      "platforms": [],
      "description": "События OpenVPN с заполненным SourceUserName. VPN_IP извлекается из ifconfig в том же Message; отдельные события назначения адреса не объединяются.",
      "template": "SELECT \n    Timestamp,\n    SourceAddress AS External_IP,\n    SourcePort AS External_Port,\n    SourceUserName AS Username,\n    extract(Message, 'ifconfig\\\\s+([0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3})') AS VPN_IP,\n    Message\nFROM `events` \nWHERE DeviceProduct = 'OpenVPN' \n  AND (Message LIKE '%Peer Connection Initiated%' \n   OR Message LIKE '%Authenticate%'\n   OR Message LIKE '%client connected%'\n   OR Message LIKE '%assign_ip%'\n   OR Message LIKE '%ifconfig%')\n  AND SourceUserName != ''\nORDER BY Timestamp DESC \nLIMIT 500",
      "timeRange": "1h",
      "enabled": false
    },
    {
      "id": "subject_OpenVpnConnect",
      "name": "[man] Соединения УЗ к OpenVpn",
      "mode": "sql",
      "platforms": [],
      "description": "События OpenVPN для SourceUserName текущего события. VPN_IP извлекается из ifconfig в том же Message; отдельные события назначения адреса не объединяются.",
      "template": "SELECT \n    Timestamp,\n    SourceAddress AS External_IP,\n    SourcePort AS External_Port,\n    SourceUserName AS Username,\n    extract(Message, 'ifconfig\\\\s+([0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3})') AS VPN_IP,\n    Message\nFROM `events` \nWHERE DeviceProduct = 'OpenVPN' \n  AND (Message LIKE '%Peer Connection Initiated%' \n   OR Message LIKE '%Authenticate%'\n   OR Message LIKE '%client connected%'\n   OR Message LIKE '%assign_ip%'\n   OR Message LIKE '%ifconfig%')\n  AND SourceUserName = '${SourceUserName}'\nORDER BY Timestamp DESC \nLIMIT 500",
      "timeRange": "24h",
      "enabled": true
    },
    {
      "id": "blocked_onCurrentHost",
      "name": "[man] Блокировки УЗ на указанном хосте",
      "mode": "sql",
      "platforms": [
        "windows"
      ],
      "description": "Блокировки учётных записей на указанном хосте",
      "template": "SELECT * FROM `events` WHERE DeviceAddress = '${DeviceAddress}' AND DeviceEventClassID = '4740' ORDER BY Timestamp DESC LIMIT 250",
      "timeRange": "24h",
      "enabled": true
    },
    {
      "id": "Blocked_currentSubject",
      "name": "[man] Блокировки указанной УЗ",
      "mode": "sql",
      "platforms": [
        "windows"
      ],
      "description": "Когда и где была заблокирована указанная учётная запись",
      "template": "SELECT * FROM `events` WHERE DestinationUserName = '${DestinationUserName}' AND DeviceEventClassID = '4740' ORDER BY Timestamp DESC LIMIT 250",
      "timeRange": "15m",
      "enabled": true
    },
    {
      "id": "exec_commandSSH_currentUser",
      "name": "[man] Терминальные команды текущего пользователя",
      "mode": "sql",
      "platforms": [
        "unix"
      ],
      "description": "Команды execve от имени УЗ с псевдотерминалом pts. Наличие pts само по себе не подтверждает SSH; поля команды и терминала зависят от нормализатора.",
      "template": "SELECT \n    Timestamp,\n    DeviceHostName AS Server,\n    DestinationUserName AS Role,\n    SourceUserName AS User,\n    FlexString1 AS Command,\n    DestinationProcessName AS Binary,\n    DeviceCustomString2 AS Terminal,\n    EventOutcome AS Outcome\nFROM `events`\nWHERE DeviceProduct = 'audit'\n  AND (Message ILIKE '%execve%' OR Name ILIKE '%execve%' OR DeviceEventCategory ILIKE '%execve%' OR DeviceEventClassID ILIKE '%execve%')\n  AND DeviceCustomString2 LIKE '%pts%'\n  AND SourceUserName = '${SourceUserName}'\nORDER BY Timestamp DESC\nLIMIT 500",
      "timeRange": "1h",
      "enabled": true
    },
    {
      "id": "exec_commandSSH_onCurrentHost",
      "name": "[man] Терминальные команды на текущем хосте",
      "mode": "sql",
      "platforms": [
        "unix"
      ],
      "description": "Команды execve с псевдотерминалом pts на указанном хосте. Наличие pts само по себе не подтверждает SSH; поля команды и терминала зависят от нормализатора.",
      "template": "SELECT \n    Timestamp,\n    DeviceHostName AS Server,\n    DestinationUserName AS Role,\n    SourceUserName AS User,\n    FlexString1 AS Command,\n    DestinationProcessName AS Binary,\n    DeviceCustomString2 AS Terminal,\n    EventOutcome AS Outcome\nFROM `events`\nWHERE DeviceProduct = 'audit'\n  AND (Message ILIKE '%execve%' OR Name ILIKE '%execve%' OR DeviceEventCategory ILIKE '%execve%' OR DeviceEventClassID ILIKE '%execve%')\n  AND DeviceCustomString2 LIKE '%pts%'\n  AND DeviceHostName = '${DeviceHostName}'\nORDER BY Timestamp DESC\nLIMIT 500",
      "timeRange": "1h",
      "enabled": true
    },
    {
      "id": "subject_changedPassword",
      "name": "[man] Смена пароля УЗ",
      "mode": "sql",
      "platforms": [
        "windows"
      ],
      "description": "Показывает менялся ли пароль конкретной УЗ и кем",
      "template": "SELECT \n    Timestamp,\n    DeviceHostName AS DC,\n    SourceUserName AS Who_Did,\n    DestinationUserName AS Target_User,\n    CASE \n        WHEN SourceUserName = DestinationUserName THEN 'User changed own password'\n        WHEN SourceUserName LIKE '%$' AND DestinationUserName NOT LIKE '%$' THEN 'Computer changed user password'\n        WHEN SourceUserName NOT LIKE '%$' AND DestinationUserName LIKE '%$' THEN 'Admin reset computer password'\n        ELSE 'One user changed another user password'\n    END AS Comment,\n    CASE \n        WHEN DeviceEventClassID = '4723' THEN 'Password Change'\n        WHEN DeviceEventClassID = '4724' THEN 'Password Reset'\n    END AS Event_Type,\n    Message AS Description\nFROM `events`\nWHERE DeviceEventClassID IN ('4723', '4724')\nAND DestinationUserName = '${DestinationUserName}'\nORDER BY Timestamp DESC\nLIMIT 500",
      "timeRange": "7d",
      "enabled": true
    },
    {
      "id": "external_connection_fromHost",
      "name": "[man] Исходящие соединения вне частных IPv4-сетей",
      "mode": "sql",
      "platforms": [],
      "description": "Соединения с SourceAddress текущего события, кроме RFC1918, IPv4 loopback и имён с суффиксом z-it.ru. Это не строгий отбор публичных адресов: другие специальные диапазоны и IPv6 не исключаются.",
      "template": "SELECT \n  DestinationAddress AS ExternalIP,\n  DestinationPort AS Port,\n  TransportProtocol AS Protocol,\n  COUNT(*) AS ConnectionCount\nFROM `events` \nWHERE SourceAddress = '${SourceAddress}'\n  AND NOT inSubnet(DestinationAddress, '10.0.0.0/8')\n  AND NOT inSubnet(DestinationAddress, '172.16.0.0/12')\n  AND NOT inSubnet(DestinationAddress, '192.168.0.0/16')\n  AND NOT inSubnet(DestinationAddress, '127.0.0.0/8')\n  AND NOT DestinationHostName LIKE '%z-it.ru'\nGROUP BY DestinationAddress, DestinationPort, TransportProtocol\nORDER BY ConnectionCount DESC",
      "timeRange": "1h",
      "enabled": true
    },
    {
      "id": "incoming_connection_toHost",
      "name": "[man] Входящие соединения на указанный хост",
      "mode": "sql",
      "platforms": [],
      "description": "Все входящие соединения на указанный хост",
      "template": "SELECT\n    SourceAddress AS source_ip,\n    SourcePort AS source_port,\n    DestinationPort AS dest_port,\n    TransportProtocol AS protocol,\n    DeviceHostName AS target_host,\n    count(ID) AS attempts\nFROM `events`\nWHERE DestinationAddress = '${DestinationAddress}'\nGROUP BY SourceAddress, SourcePort, DestinationPort, TransportProtocol, DeviceHostName\nORDER BY attempts DESC\nLIMIT 250",
      "timeRange": "24h",
      "enabled": true
    },
    {
      "id": "all_unsuccessfull_logins_from_subject",
      "name": "[man] Неудачные попытки входа УЗ (dst)",
      "mode": "sql",
      "platforms": [
        "windows"
      ],
      "description": "Неудачные Windows входы УЗ (4625) с обогащением по виду и причине",
      "template": "SELECT \n    Timestamp,\n    DeviceHostName AS Server,\n    DestinationUserName AS Target_User,\n    SourceAddress AS Source_IP,\n    SourcePort AS Source_Port,\n    DeviceCustomNumber1 AS Logon_Type,\n    CASE \n        -- Проверяем Sub status (DeviceCustomString1)\n        WHEN DeviceCustomString1 = '0xc000006a' THEN 'Неверный пароль'\n        WHEN DeviceCustomString1 = '0xc0000064' THEN 'Пользователь не существует'\n        WHEN DeviceCustomString1 = '0xc000006d' THEN 'Неверное имя пользователя или пароль'\n        WHEN DeviceCustomString1 = '0xc000006f' THEN 'Вход запрещён в это время'\n        WHEN DeviceCustomString1 = '0xc0000070' THEN 'Вход запрещён с этого компьютера'\n        WHEN DeviceCustomString1 = '0xc0000071' THEN 'Срок действия пароля истёк'\n        WHEN DeviceCustomString1 = '0xc0000072' THEN 'Учётная запись отключена'\n        WHEN DeviceCustomString1 = '0xc0000193' THEN 'Срок действия учётной записи истёк'\n        WHEN DeviceCustomString1 = '0xc0000224' THEN 'Требуется смена пароля'\n        WHEN DeviceCustomString1 = '0xc0000234' THEN 'Учётная запись заблокирована'\n        -- Проверяем Status (DeviceCustomString6)\n        WHEN DeviceCustomString6 = '0xc000015b' THEN 'Режим входа для пользователя не предусмотрен'\n        WHEN DeviceCustomString6 = '0xc000006d' THEN 'Неверное имя пользователя или пароль'\n        WHEN DeviceCustomString6 = '0xc000006a' THEN 'Неверный пароль'\n        WHEN DeviceCustomString6 = '0xc0000064' THEN 'Пользователь не существует'\n        WHEN DeviceCustomString6 = '0xc000006f' THEN 'Вход запрещён в это время'\n        WHEN DeviceCustomString6 = '0xc0000070' THEN 'Вход запрещён с этого компьютера'\n        WHEN DeviceCustomString6 = '0xc0000071' THEN 'Срок действия пароля истёк'\n        WHEN DeviceCustomString6 = '0xc0000072' THEN 'Учётная запись отключена'\n        WHEN DeviceCustomString6 = '0xc0000193' THEN 'Срок действия учётной записи истёк'\n        WHEN DeviceCustomString6 = '0xc0000224' THEN 'Требуется смена пароля'\n        WHEN DeviceCustomString6 = '0xc0000234' THEN 'Учётная запись заблокирована'\n        WHEN DeviceCustomString6 = '0xc000018c' THEN 'Доверительные отношения с доменом нарушены'\n        WHEN DeviceCustomString6 = '0xc000018d' THEN 'Доверительные отношения с доменом нарушены'\n        WHEN DeviceCustomString6 = '0xc00001a5' THEN 'Доверительные отношения с доменом нарушены'\n        WHEN DeviceCustomString6 = '0xc000005e' THEN 'Нет доступных серверов входа'\n        WHEN DeviceCustomString6 = '0xc0000133' THEN 'Разница во времени между серверами'\n        WHEN DeviceCustomString6 = '0xc0000413' THEN 'Не пройдена проверка подлинности'\n        -- Если оба пустые — показываем заглушку\n        WHEN DeviceCustomString1 = '0x0' AND DeviceCustomString6 = '0x0' THEN 'Причина не указана'\n        -- Иначе — показываем оба кода\n        ELSE concat('Sub: ', DeviceCustomString1, ' / Status: ', DeviceCustomString6)\n    END AS Failure_Reason,\n    CASE \n        WHEN DeviceCustomNumber1 = 2 THEN 'Интерактивный (локальный)'\n        WHEN DeviceCustomNumber1 = 3 THEN 'Сетевой (SMB/Share)'\n        WHEN DeviceCustomNumber1 = 4 THEN 'Пакетный (Batch)'\n        WHEN DeviceCustomNumber1 = 5 THEN 'Служба'\n        WHEN DeviceCustomNumber1 = 7 THEN 'Разблокировка'\n        WHEN DeviceCustomNumber1 = 8 THEN 'Сетевой Cleartext'\n        WHEN DeviceCustomNumber1 = 9 THEN 'Новые учётные данные'\n        WHEN DeviceCustomNumber1 = 10 THEN 'RemoteInteractive (RDP)'\n        WHEN DeviceCustomNumber1 = 11 THEN 'Кэшированный интерактивный'\n        ELSE concat('Тип ', toString(DeviceCustomNumber1))\n    END AS Logon_Type_Desc\nFROM `events`\nWHERE DeviceEventClassID = '4625'\n  AND DeviceProduct = 'Windows'\n  AND DestinationUserName = '${DestinationUserName}'\nORDER BY Timestamp DESC\nLIMIT 500",
      "timeRange": "24h",
      "enabled": true
    }
  ].map(Object.freeze));

  const PLATFORM_EVENT_IDS = Object.freeze({
    "auth-failures": { windows: "'4625', '4771', '4776'", unix: "'USER_AUTH', 'USER_LOGIN'" },
    "auth-by-ip": { windows: "'4624', '4625', '4648', '4771', '4776'", unix: "'USER_AUTH', 'USER_LOGIN'" },
    "process-on-host": { windows: "'4688', '1'", unix: "'EXECVE'" },
  });

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

  function requiredTemplateFields(template) { return requiredFields(compactSql(template), PLACEHOLDER); }

  function normalizeFilterTemplate(filter, index = 0) {
    if (!filter || typeof filter !== "object" || Array.isArray(filter)) throw new TypeError(`Фильтр ${index + 1}: ожидается объект`);
    const mode = filter.mode ?? "where";
    if (!["where", "sql"].includes(mode)) throw new TypeError(`Фильтр ${index + 1}: mode должен быть where или sql`);
    const template = String(filter.template ?? "");
    const executable = mode === "sql" ? prepareSelectQuery(template) : compactSql(template);
    if (!executable || template.length > (mode === "sql" ? 64000 : 4000) || (mode === "where" && /[;\0]/.test(template))) throw new TypeError(`Фильтр ${index + 1}: недопустимый SQL-шаблон`);
    const requiredFields = requiredTemplateFields(template);
    const placeholderCount = [...executable.matchAll(PLACEHOLDER)].length;
    validatePlaceholderPositions(executable);
    if (executable.includes("${") && placeholderCount !== (executable.match(/\$\{/g) || []).length) {
      throw new TypeError(`Фильтр ${index + 1}: используйте подстановки вида \${ИмяПоля}`);
    }
    requiredFields.forEach((field) => {
      if (field.startsWith("@")) {
        if (!LOGICAL_FIELDS.has(field)) throw new TypeError(`Фильтр ${index + 1}: неизвестная группа ${field}`);
        if (executable.includes(`'\${${field}}'`)) throw new TypeError(`Фильтр ${index + 1}: логическую группу ${field} не нужно заключать в кавычки`);
      } else api.sqlIdentifier(field);
    });
    const id = String(filter.id || `filter-${index + 1}`).replace(/[^a-z0-9_-]/gi, "-").slice(0, 64);
    if (!id || RESERVED_IDS.has(id)) throw new TypeError(`Фильтр ${index + 1}: недопустимый id`);
    const name = String(filter.name || filter.title || `Фильтр ${index + 1}`).trim().slice(0, 120);
    if (!name) throw new TypeError(`Фильтр ${index + 1}: укажите название`);
    const timeRange = Object.hasOwn(TIME_RANGES, filter.timeRange) ? filter.timeRange : "15m";
    return { id, name, mode, platforms: normalizeFilterPlatforms(filter.platforms ?? BUILTIN_FILTERS.find(item => item.id === id && item.template === template)?.platforms), description: String(filter.description || "Пользовательский SQL-фильтр KUMA.").trim().slice(0, 300), template, timeRange, enabled: filter.enabled !== false };
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
    template = compactSql(template);
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
    const rendered = renderTemplate(template, { pattern: PLACEHOLDER, renderPattern: RENDER_PLACEHOLDER,
      resolve: field => values.get(field) || null,
      missingLabel: field => field.startsWith("@") ? groups.get(field.slice(1))?.aliases?.join(" / ") || field : field,
      render: (resolved, match, quote, field) => {
        if (field.startsWith("@")) return `(${resolved.get(field)})`;
        if (INTEGER_FIELD.test(field) || FLOAT_FIELD.test(field)) return resolved.get(field);
        return `'${api.escapeSqlString(resolved.get(field))}'`;
      },
    });
    return { ok: rendered.ok, missing: rendered.missing, where: rendered.query };
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
    const platform = detectEventPlatform({
      os: api.valuesForAliases(event, ["DeviceOS", "DeviceOSName", "DeviceOperatingSystem", "OperatingSystem", "host.os.name", "host.os.family", "os.name", "os.family"]),
      source: api.valuesForAliases(event, ["DeviceProduct", "DeviceEventCategory"]),
      paths: api.valuesForAliases(event, ["FilePath", "DeviceProcessName", "SourceProcessName", "DestinationProcessName"]),
    });
    const catalog = Array.isArray(filterTemplates) ? normalizeFilterTemplates(filterTemplates).map(item => ({ ...item, source: "builtin" }))
      : composeFilterCatalog(normalizeFilterTemplates(BUILTIN_FILTERS), (filterTemplates.userFilters || []).map(storedFilter), filterTemplates.disabledBuiltinFilterIds || []);
    const filters = catalog.filter((filter) => filter.enabled !== false && filterSupportsPlatform(filter, platform)).map((filter) => {
      const unavailable = error => ({ id: filter.id, source: filter.source, title: filter.name || filter.id, description: filter.description, type: "query", applicable: false, missing: [], reason: error.message });
      if (filter.validationError) return unavailable(new Error(filter.validationError));
      try {
      const eventIds = PLATFORM_EVENT_IDS[filter.id]?.[platform];
      const builtin = BUILTIN_FILTERS.find(item => item.id === filter.id);
      const template = eventIds && filter.template === builtin?.template
        ? filter.template.replace(/DeviceEventClassID IN \([^)]*\)/, `DeviceEventClassID IN (${eventIds})`)
        : filter.template;
      const rendered = renderFilterTemplate(template, event, profiles);
      return {
        id: filter.id, source: filter.source, mode: filter.mode, title: filter.name, description: filter.description, type: "query", timeRange: filter.timeRange,
        rangeSeconds: TIME_RANGES[filter.timeRange], applicable: rendered.ok, missing: rendered.missing,
        ...(rendered.ok ? (filter.mode === "sql" ? { sql: prepareSelectQuery(rendered.where) } : { where: rendered.where }) : { reason: `Нет полей: ${rendered.missing.join(", ")}` }),
      };
      } catch (error) { return unavailable(error); }
    });
    filters.push({ ...processGraphFilter(event, processMappings), source: "builtin" });
    return filters;
  }

  function findUsefulFilter(id, event, profiles, processMappings, filterTemplates) {
    return buildUsefulFilters(event, profiles, processMappings, filterTemplates).find((filter) => filter.id === id && filter.applicable) || null;
  }

  function storedFilter(filter, index) {
    try { return normalizeFilterTemplate(filter, index); }
    catch (error) { return { ...filter, validationError: error.message }; }
  }

  function migrateFilterCatalog(legacy) {
    const migrated = splitLegacyFilters(migrateBuiltinFilters(legacy || []).map(storedFilter), normalizeFilterTemplates(BUILTIN_FILTERS));
    // Preserve incompatible older templates for correction in the editor, without executing them.
    migrated.userFilters = migrated.userFilters.map(({ validationError, ...filter }) => filter);
    return migrated;
  }

  function prepareFilterTemplate(filter) { return filter.mode === "sql" ? prepareSelectQuery(filter.template) : compactSql(filter.template); }

  global.KumApeFilters = Object.freeze({ prepareFilterTemplate, normalizeFilterTemplate, migrateFilterCatalog, BUILTIN_FILTERS, TIME_RANGES, buildUsefulFilters, findUsefulFilter, migrateBuiltinFilters, normalizeFilterTemplates, renderFilterTemplate, requiredTemplateFields });
})(globalThis);

