# KumApe

<p align="center"><img src="assets/icons/icon-128.png" width="128" alt="KumApe"></p>

Экспериментальное Firefox-расширение для аналитика Kaspersky KUMA. Идея та же, что у [ApePatrol](https://github.com/ISAIandCO/ApePatrol): меньше ручного копирования между карточкой события, поиском и TI-порталами. Реализация при этом отдельная и рассчитана на модель данных и API KUMA.

> [!IMPORTANT]
> Версия `0.1.1` — технический MVP для KUMA 4.6. Работа публичного REST API опирается на документацию KUMA и библиотеку `KUMA-Community/kapi`; private API и DOM веб-интерфейса нужно подтвердить на реальной инсталляции KUMA 4.6.

## Что уже есть

- чтение JSON из открытой карточки события или области Raw;
- запасное извлечение полей из таблицы карточки;
- копирование события и ссылки на него;
- связанные события по IP, узлу, учетной записи, процессу и хешу;
- поиск через `POST /api/v3/events` с выбором storage cluster;
- IOC-ссылки на Kaspersky OpenTIP и VirusTotal — только после явного клика;
- read-only получение ресурса correlation rule по его ID;
- проверка текущей web-сессии через `GET /api/whoami`;
- разрешение Firefox только на конкретные адреса KUMA, указанные пользователем.

Расширение не запрашивает логин или пароль KUMA и не выполняет изменяющих API-запросов. REST API-токен хранится в `storage.session`: после закрытия Firefox его потребуется ввести снова.

## Установка для проверки

Нужен Node.js 20+ и системная утилита `zip` только для упаковки.

```bash
npm test
npm run build
```

После сборки:

1. Откройте в Firefox `about:debugging#/runtime/this-firefox`.
2. Нажмите **Load Temporary Add-on / Загрузить временное дополнение**.
3. Выберите `dist/firefox/manifest.json`.
4. Откройте KUMA и нажмите иконку KumApe.
5. Разрешите доступ к адресу веб-интерфейса и REST API.

Архив для установки собирается командой:

```bash
npm run package
```

Результат появится в `artifacts/`.

## Сборка и релиз на GitHub

Workflow **CI** запускается для каждого pull request и push в `main`. Он выполняет тесты, собирает ZIP для ревью, проверяет воспроизводимость каталога расширения и сохраняет архив `kumape-firefox-review` в артефактах запуска.

Workflow **Release signed XPI** запускается вручную из GitHub Actions на нужном commit. Для него в настройках репозитория должны быть заданы secrets `AMO_JWT_ISSUER` и `AMO_JWT_SECRET` от Mozilla Add-ons API. Workflow:

1. собирает self-hosted вариант с `update_url`;
2. получает у Mozilla unlisted-подпись;
3. проверяет ID, версию и адрес обновлений внутри XPI;
4. создает `updates.json`, SBOM, архив исходников и SHA-256 checksums;
5. публикует GitHub Release с тегом `v<version>`.

Перед повторным запуском релиза нужно поднять версию в `package.json` и `package-lock.json`: существующий GitHub tag не перезаписывается.

## Настройка KUMA

По умолчанию предполагаются два адреса одного KUMA Core:

```text
Web UI:   https://kuma.example.local:7220
REST API: https://kuma.example.local:7223
```

В настройках расширения укажите реальные адреса и API-токен. Для токена нужны права как минимум на чтение кластеров хранения и событий. Если используется внутренний сертификат, сначала откройте оба адреса в Firefox и подтвердите доверие сертификату.

Подробности и статус проверенных endpoint-ов: [docs/kuma-api-notes.md](docs/kuma-api-notes.md). Сценарий проверки на реальной KUMA: [docs/manual-tests.md](docs/manual-tests.md).

## Почему не копия ApePatrol

У MaxPatrol SIEM и KUMA разные API, поля событий и устройство веб-интерфейса. Поэтому KumApe использует простой поток:

```text
карточка KUMA → content extractor → popup → background → KumaAdapter → read-only API
```

DOM используется только для получения открытого события. Поиск выполняется через публичный REST API, где это возможно. Private API изолирован в адаптере и не считается стабильным, пока его не подтвердит Network/Fetch/XHR в KUMA 4.6.

## Что пока не включено

- process graph и investigation workspace;
- редактирование Active Lists, правил и ресурсов;
- AI Assistant;
- автоматическая отправка IOC внешним сервисам;
- перехват сетевых запросов или учетных данных KUMA.

Эти функции имеет смысл добавлять после проверки базового spike на реальной системе и фиксации фактических ответов API.

## Лицензия

[Apache License 2.0](LICENSE). Проект независимый и не связан с AO Kaspersky Lab и не одобрен им.
