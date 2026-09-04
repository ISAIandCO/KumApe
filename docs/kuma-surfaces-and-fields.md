# Поверхности KUMA и модель полей

Актуальность исследования: 2026-09-04. Документ нужен для дальнейшего развития KumApe без доступа к рабочей KUMA. Он разделяет официальный контракт, поведение веб-интерфейса и выводы из community-проектов.

## Три поверхности интеграции

| Поверхность | Вход и авторизация | Что полезно KumApe | Надёжность |
|---|---|---|---|
| Public REST KUMA Core | `:7223`, Bearer token | кластеры хранения, SQL-поиск событий, дальнейшие read-only сущности | порт и авторизация описаны официально; конкретные маршруты нужно проверять на целевой версии |
| Web API интерфейса | origin веб-интерфейса (`:7220` по умолчанию), cookie текущей сессии | ресурсы, зависимости, службы, папки, строки Active List | private API, может меняться без обратной совместимости |
| DOM веб-интерфейса | открытая вкладка и разрешение Firefox на её origin | поля уже открытой карточки и Raw без повторного запроса | зависит от DOM; используются машинные `kuma-*` атрибуты, а не CSS-классы |

Прямой доступ к коллекторам и ClickHouse/storage KumApe не нужен. В распределённой установке запросы направляются в Core, а хранилище выбирается логическим `clusterID`. В HA используется адрес балансировщика/VIP для `7220` и `7223`.

### Подтверждённый минимум KumApe

- `GET :7220/api/whoami` — проверка существующей web-сессии;
- `GET :7223/api/v3/events/clusters` — список доступных storage clusters;
- `POST :7223/api/v3/events` — read-only SQL-поиск событий;
- `GET :7220/api/private/resources/correlationRule/{id}` — чтение правила по ID;
- `[kuma-section="event-field"][kuma-id]` + `kuma-data` — поля открытой карточки;
- `[kuma-section="raw"] pre` — Raw открытой карточки.

Первые четыре маршрута получены из community-клиентов и должны быть подтверждены на KUMA 4.6. DOM-селекторы подтверждены только для исследованной разметки. Read-only allowlist расширения намеренно не включает другие маршруты.

### Кандидаты для следующих read-only функций

В `KUMA-Community/kapi` встречаются публичные операции чтения событий, alerts, incidents, assets, reports, users/whoami, tenants, dictionaries, resources, folders, services, Active Lists, context tables и extended fields. В community-клиентах web API встречаются:

- `/api/private/tenants/`;
- `/api/private/resources/{kind}` и `/api/private/resources/{kind}/{id}`;
- `/api/private/resources/dependencies/{resource-id}`;
- `/api/private/services/...`;
- `/api/private/folders/...`;
- `/api/private/services/id/{correlator-id}/activeLists/scan/{list-id}`.

Это карта для исследования Network/Fetch/XHR, а не обещанный API. Перед добавлением каждого маршрута нужны фактические method, URL, query, response schema, права, пагинация и поведение CSRF. Изменяющие `POST`/`PUT`/`DELETE` маршруты в KumApe не переносятся.

## Откуда брать знания о нормализации и правилах

Репозиторий [KUMA-Community/kuma_content](https://github.com/KUMA-Community/kuma_content) содержит нормализаторы и пакеты правил для Windows, Sysmon, Linux/auditd, Sigma, Kaspersky-продуктов, сетевых устройств, приложений и облаков. Это практический источник пар `source field → KUMA field` и используемых в правилах `DeviceVendor` / `DeviceProduct` / `DeviceEventClassID`.

KumApe не импортирует эти пакеты и не исполняет правила. Из них взят только стартовый каталог наименований нормализованных полей. Конкретная организация может изменить нормализатор, применить extra normalization или extended event schema, поэтому пользовательские профили важнее встроенных предположений.

## Какие данные бывают в событии KUMA

Официальная [Normalized event data model](https://support.kaspersky.com/kuma/4.6/217941) делит данные на нормализованные поля, пользовательские слоты, служебные поля и вложенные структуры.

| Семейство | Типичные поля | Содержимое |
|---|---|---|
| Идентичность события | `ID`, `ExternalID`, `DeviceExternalID`, `DeviceEventClassID` | UUID KUMA и идентификаторы источника; `DeviceEventClassID` — тип события у источника |
| Время | `Timestamp`, `StartTime`, `EndTime`, `DeviceReceiptTime` | время события, начала/окончания и приёма |
| Классификация | `Name`, `Message`, `Type`, `Severity`, `EventOutcome`, `Reason`, `DeviceAction`, `DeviceEventCategory` | человекочитаемое описание, результат, действие и категория |
| Источник | `SourceAddress`, `SourceHostName`, `SourceDnsDomain`, `SourcePort`, `SourceMacAddress`, `SourceUserName`, `SourceUserID`, `SourceProcessName`, `SourceProcessID` | инициатор сетевого, пользовательского или процессного действия |
| Назначение | `DestinationAddress`, `DestinationHostName`, `DestinationDnsDomain`, `DestinationPort`, `DestinationMacAddress`, `DestinationUserName`, `DestinationUserID`, `DestinationProcessName`, `DestinationProcessID` | объект или сторона назначения |
| Устройство | `DeviceAddress`, `DeviceHostName`, `DeviceDnsDomain`, `DeviceProduct`, `DeviceVendor`, `DeviceVersion`, `DeviceProcessName`, `DeviceProcessID` | источник телеметрии и его продукт/процесс |
| Сеть | `ApplicationProtocol`, `TransportProtocol`, `BytesIn`, `BytesOut`, translated address/port, interface и direction-поля | соединения, объём трафика и NAT |
| Файл | `FileName`, `FilePath`, `FileHash`, `FileSize`, `FileType`, `FileID`, timestamps/permissions и `OldFile*` | текущий и предыдущий объект файла |
| HTTP/приложение | `RequestUrl`, `RequestMethod`, `RequestClientApplication`, `RequestContext`, `RequestCookies` | web-запрос и клиентский контекст |
| Detection | `Tactic`, `Technique`, `TI`, `Code` | MITRE/TI enrichment и код результата операции |
| Связи KUMA | `TenantID`, `SpaceID`, `ServiceID`, `ServiceName`, `CorrelationRuleID`, `CorrelationRuleName`, asset/account IDs | tenancy, сервисы, правила и сущности KUMA |
| Агрегация/корреляция | `BaseEventCount`, `BaseEvents`, `GroupedBy`, `AggregationRuleID`, `AggregationRuleName` | происхождение агрегированного или correlation event |

`Type` различает base, aggregated, correlation, audit и monitoring events. Не каждое поле присутствует в каждом типе события.

### Поля с меняющимся смыслом

KUMA предоставляет универсальные слоты:

- `DeviceCustomString1`–`DeviceCustomString6`;
- `DeviceCustomNumber1`–`DeviceCustomNumber3`;
- `DeviceCustomFloatingPoint1`–`DeviceCustomFloatingPoint4`;
- `DeviceCustomIPv6Address1`–`DeviceCustomIPv6Address4`;
- `DeviceCustomDate1`–`DeviceCustomDate2`;
- `FlexString1`–`FlexString2`, `FlexNumber1`–`FlexNumber2`, `FlexDate1`.

Их назначение задаётся соседним полем `...Label`. Например, в community-нормализаторе Windows `DeviceCustomString4` для 4688 означает command line, а в другом событии тот же слот может означать совсем другое. Поэтому нельзя глобально считать `DeviceCustomString4` командной строкой.

`Extra` — вложенный словарь `string:string` для исходных полей, не сопоставленных со схемой; он доступен только у base events и может занимать до 4 MB. `Raw` содержит ненормализованный текст исходного события и ограничен 16 384 байтами. Оба поля могут содержать чувствительные данные и не должны автоматически уходить во внешние сервисы или логи расширения.

Extended event schema позволяет создавать собственные поля. Их имена заранее неизвестны KumApe, поэтому они добавляются в локальные профили явно.

## Встроенный стартовый каталог профилей

Профили собраны по mapping-таблицам community-нормализаторов и покрывают частые расследовательские точки. Это не полный перечень всех Event ID источников, а полный стартовый набор, поставляемый в текущей версии KumApe.

| Источник | События | Основные группы |
|---|---|---|
| Windows Security | 4688 | процесс, command line, пользователь, узел |
| Windows Security | 4624, 4625, 4648 | IP, узел, пользователь, процесс |
| Windows Security | 4720, 4722, 4725, 4726, 4728, 4732, 4738, 4740, 4756, 4767 | изменение учётных записей и групп |
| Windows Security | 4656, 4660, 4663 | объект/файл, процесс, пользователь |
| Windows Security | 5140, 5145 | SMB-ресурс, IP, пользователь, путь |
| Windows Security | 5156, 5157 | сетевое соединение и процесс |
| Windows | 4697, 7045 | установка службы, процесс/файл |
| PowerShell | 4104 | узел, пользователь, process identity; полный script block намеренно не превращается в related query |
| Sysmon | 1 | процесс, command line, parent image, hash |
| Sysmon | 3 | сетевое соединение и image |
| Sysmon | 7, 8, 10 | image load / remote thread / process access |
| Sysmon | 11, 23, 26 | создание и удаление файла |
| Sysmon | 22 | DNS query и process image |
| Linux auditd | EXECVE, SYSCALL | executable, arguments, user, file/path |
| Linux auditd | USER_AUTH, USER_LOGIN, USER_ACCT, CRED_ACQ, CRED_DISP | аутентификация, IP, user, process |
| Linux auditd | PATH | файл/path, процесс и user |

Sysmon-профили дополнительно проверяют `DeviceEventCategory`, чтобы короткие ID `1`, `3` и т. п. не совпали со сторонним источником.

## Формат пользовательского профиля

Профили хранятся только в `browser.storage.local`. Один объект `when` означает логическое AND между его полями; массив объектов `when` означает OR между вариантами. Сравнение значений регистронезависимое и точное.

```json
[
  {
    "name": "Локальный нормализатор запуска процесса",
    "when": {
      "DeviceEventClassID": ["process-start"],
      "DeviceProduct": ["Example EDR"]
    },
    "fields": {
      "process": ["FlexString2"],
      "command": ["DeviceCustomString6"],
      "account": ["SourceUserName"],
      "host": ["DeviceHostName"]
    }
  }
]
```

Поддерживаются группы `ip`, `host`, `account`, `process`, `command`, `file`, `hash`, `domain`, `url`. Для совпавшего профиля список заменяет общие поля соответствующей группы и используется одновременно для извлечения значения из карточки и построения SQL. Если совпали несколько профилей, более поздний профиль переопределяет уже заданные им группы.

Имена полей принимаются только в формате KUMA identifier (`A–Z`, `a–z`, цифры и `_`, первый символ — буква). Значения экранируются отдельно. Это не позволяет настройке превратиться в произвольный SQL.

## Источники

- [KUMA 4.6: ports used during installation](https://support.kaspersky.com/kuma/4.6/217770)
- [KUMA 4.6: normalized event data model](https://support.kaspersky.com/kuma/4.6/217941)
- [KUMA 4.6: manually creating an SQL query](https://support.kaspersky.com/kuma/4.6/228356)
- [KUMA-Community/kapi](https://github.com/KUMA-Community/kapi)
- [KUMA-Community/kuma_content](https://github.com/KUMA-Community/kuma_content)
- [kmssrv/pykumizer](https://github.com/kmssrv/pykumizer) — старый community-клиент private web API; использовать только как подсказку для DevTools
