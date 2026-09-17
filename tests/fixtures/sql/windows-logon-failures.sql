SELECT
    Timestamp,
    DeviceHostName AS Server,
    DestinationUserName AS Target_User,
    SourceAddress AS Source_IP,
    SourcePort AS Source_Port,
    DeviceCustomNumber1 AS Logon_Type,
    CASE
        -- Проверяем Sub status (DeviceCustomString1)
        WHEN DeviceCustomString1 = '0xc000006a' THEN 'Неверный пароль'
        WHEN DeviceCustomString1 = '0xc0000064' THEN 'Пользователь не существует'
        WHEN DeviceCustomString1 = '0xc000006d' THEN 'Неверное имя пользователя или пароль'
        WHEN DeviceCustomString1 = '0xc000006f' THEN 'Вход запрещён в это время'
        WHEN DeviceCustomString1 = '0xc0000070' THEN 'Вход запрещён с этого компьютера'
        WHEN DeviceCustomString1 = '0xc0000071' THEN 'Срок действия пароля истёк'
        WHEN DeviceCustomString1 = '0xc0000072' THEN 'Учётная запись отключена'
        WHEN DeviceCustomString1 = '0xc0000193' THEN 'Срок действия учётной записи истёк'
        WHEN DeviceCustomString1 = '0xc0000224' THEN 'Требуется смена пароля'
        WHEN DeviceCustomString1 = '0xc0000234' THEN 'Учётная запись заблокирована'
        -- Проверяем Status (DeviceCustomString6)
        WHEN DeviceCustomString6 = '0xc000015b' THEN 'Режим входа для пользователя не предусмотрен'
        WHEN DeviceCustomString6 = '0xc000006d' THEN 'Неверное имя пользователя или пароль'
        WHEN DeviceCustomString6 = '0xc000006a' THEN 'Неверный пароль'
        WHEN DeviceCustomString6 = '0xc0000064' THEN 'Пользователь не существует'
        WHEN DeviceCustomString6 = '0xc000006f' THEN 'Вход запрещён в это время'
        WHEN DeviceCustomString6 = '0xc0000070' THEN 'Вход запрещён с этого компьютера'
        WHEN DeviceCustomString6 = '0xc0000071' THEN 'Срок действия пароля истёк'
        WHEN DeviceCustomString6 = '0xc0000072' THEN 'Учётная запись отключена'
        WHEN DeviceCustomString6 = '0xc0000193' THEN 'Срок действия учётной записи истёк'
        WHEN DeviceCustomString6 = '0xc0000224' THEN 'Требуется смена пароля'
        WHEN DeviceCustomString6 = '0xc0000234' THEN 'Учётная запись заблокирована'
        WHEN DeviceCustomString6 = '0xc000018c' THEN 'Доверительные отношения с доменом нарушены'
        WHEN DeviceCustomString6 = '0xc000018d' THEN 'Доверительные отношения с доменом нарушены'
        WHEN DeviceCustomString6 = '0xc00001a5' THEN 'Доверительные отношения с доменом нарушены'
        WHEN DeviceCustomString6 = '0xc000005e' THEN 'Нет доступных серверов входа'
        WHEN DeviceCustomString6 = '0xc0000133' THEN 'Разница во времени между серверами'
        WHEN DeviceCustomString6 = '0xc0000413' THEN 'Не пройдена проверка подлинности'
        -- Если оба пустые — показываем заглушку
        WHEN DeviceCustomString1 = '0x0' AND DeviceCustomString6 = '0x0' THEN 'Причина не указана'
        -- Иначе — показываем оба кода
        ELSE concat('Sub: ', DeviceCustomString1, ' / Status: ', DeviceCustomString6)
    END AS Failure_Reason,
    CASE
        WHEN DeviceCustomNumber1 = '2' THEN 'Интерактивный (локальный)'
        WHEN DeviceCustomNumber1 = '3' THEN 'Сетевой (SMB/Share)'
        WHEN DeviceCustomNumber1 = '4' THEN 'Пакетный (Batch)'
        WHEN DeviceCustomNumber1 = '5' THEN 'Служба'
        WHEN DeviceCustomNumber1 = '7' THEN 'Разблокировка'
        WHEN DeviceCustomNumber1 = '8' THEN 'Сетевой Cleartext'
        WHEN DeviceCustomNumber1 = '9' THEN 'Новый учётные данные'
        WHEN DeviceCustomNumber1 = '10' THEN 'RemoteInteractive (RDP)'
        WHEN DeviceCustomNumber1 = '11' THEN 'Кэшированный интерактивный'
        ELSE concat('Тип ', DeviceCustomNumber1)
    END AS Logon_Type_Desc
FROM `events`
WHERE DeviceEventClassID = '4625'
  AND DeviceProduct = 'Windows'
  AND DestinationUserName = '${DestinationUserName}'
ORDER BY Timestamp DESC
