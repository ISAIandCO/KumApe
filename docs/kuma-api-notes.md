# KUMA 4.6: заметки по API для KumApe

Актуальность: 2026-09-04. Цель документа — не выдать найденные community-endpoint-ы за гарантированный контракт KUMA, а явно разделить подтвержденное документацией и то, что ещё нужно проверить через DevTools конкретной инсталляции.

## Статус источников

| Возможность | Endpoint / механизм | Основание | Статус |
|---|---|---|---|
| Авторизация public REST | `Authorization: Bearer <token>` | Официальная документация KUMA 4.6 | Подтверждено документацией |
| Получение storage clusters | `GET :7223/api/v3/events/clusters` | `KUMA-Community/kapi` | Нужна проверка на целевой KUMA |
| Поиск событий | `POST :7223/api/v3/events` | `KUMA-Community/kapi` | Нужна проверка на целевой KUMA |
| Проверка web-сессии | `GET :7220/api/whoami` | `KUMA-Community/kapi` private client | Нужна проверка на KUMA 4.6 |
| Чтение correlation rule | `GET :7220/api/private/resources/correlationRule/{id}` | `KUMA-Community/kapi` private client | Нужна проверка на KUMA 4.6 |
| Извлечение открытого Raw | `pre` / JSON / таблица полей | `KUMA-Community/kuma-improver` и DOM fallback | Нужна проверка верстки KUMA 4.6 |

## Public Events API

Текущая библиотека `KUMA-Community/kapi` строит запрос так:

```http
POST https://<KUMA_CORE>:7223/api/v3/events
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "clusterID": "<storage-cluster-id>",
  "period": {
    "from": "2026-09-04T07:45:00.000Z",
    "to": "2026-09-04T08:15:00.000Z"
  },
  "emptyFields": true,
  "rawTimestamps": true,
  "sql": "SELECT * FROM `events` WHERE SourceAddress = '192.0.2.1' ORDER BY Timestamp DESC LIMIT 250"
}
```

Список кластеров запрашивается отдельно:

```http
GET https://<KUMA_CORE>:7223/api/v3/events/clusters
Authorization: Bearer <token>
```

Официальная документация KUMA 4.6 подтверждает, что REST-запросы авторизуются Bearer-токеном, а права API настраиваются для пользователя отдельно. Она также описывает SQL поиска событий: источник ``events``, одинарные кавычки для значений, `WHERE`, `IN`, `BETWEEN`, `LIKE`/`ILIKE`, `match`, `ORDER BY`, `OFFSET` и `LIMIT`.

Полезные ссылки:

- [Authorizing API requests](https://support.kaspersky.com/kuma/4.6/217974)
- [Configuring permissions to access the API](https://support.kaspersky.com/kuma/4.6/235388)
- [Manually creating an SQL query](https://support.kaspersky.com/kuma/4.6/228356)
- [Normalized event data model](https://support.kaspersky.com/kuma/4.6/217941)
- [KUMA-Community/kapi](https://github.com/KUMA-Community/kapi)

## Как формируется related search

KumApe разрешает только заранее известные имена полей и экранирует обратную косую черту и одинарную кавычку в значении. Пример:

```sql
SELECT * FROM `events`
WHERE (SourceAddress = '192.0.2.1' OR DestinationAddress = '192.0.2.1' OR DeviceAddress = '192.0.2.1')
ORDER BY Timestamp DESC
LIMIT 250
```

Период берется из `Timestamp`, `EventTime`, `DeviceReceiptTime`, `EndTime`, `StartTime` или `time`. Если ни одно поле не распознано, центром диапазона становится текущее время.

## Private API и сессия веб-интерфейса

В community-клиенте используются cookie веб-сессии и XSRF-токен после логина на `:7220`. KumApe не повторяет логин и не хранит пароль. Для spike выполняется только безопасный `GET /api/whoami` с `credentials: include`.

Чтение ресурса правила сейчас пробуется через:

```http
GET /api/private/resources/correlationRule/{rule-id}
```

Если endpoint изменился в 4.6, нужно заменить только метод `getCorrelationRule()` в `src/shared/kuma-adapter.js`; popup и извлечение события от этого не зависят.

## Что снять в DevTools KUMA 4.6

Для каждого пункта сохранить method, URL, query, request JSON, структуру response и обязательные headers:

1. Открытие карточки обычного события и области Raw.
2. Открытие correlation event и его правила.
3. Поиск `SourceAddress = '...'` в Events.
4. Смена storage cluster и tenant.
5. Открытие Active List и просмотр строк.
6. Открытие alert и incident.

Перед публикацией HAR удалить `Cookie`, `Authorization`, XSRF-токены, имена реальных узлов, пользователей и содержимое событий.

## Решение по архитектуре после spike

Приоритет остается таким:

1. public REST API;
2. read-only private API веб-интерфейса;
3. DOM только как fallback.

Не следует добавлять process graph, Active List editing или workspace, пока не подтверждены получение полного события и хотя бы один related search на целевой KUMA 4.6.
