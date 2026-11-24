# Wazuh на пилотной VM 103

Wazuh 4.14.10 принимает события только от испытательных Windows. У проекта
`exam-wazuh-vm103` 14 именованных томов и отдельная закрытая конфигурация
в `$HOME/exam-wazuh-vm103`. Общий запуск пилота вызывает её `private/control.sh`
с действием `up`. При восстановлении используйте тот же каталог, имя проекта
и тома. Храните резервную копию закрытой конфигурации вместе с регистрациями
и состоянием за пределами диска VM и Git.
[Запуск пилота](../../../scripts/vm/start-proxmox-pilot.sh)

При восстановлении без приватной конфигурации используйте закреплённые версии
официального Wazuh Docker single-node и набора `deploy/wazuh` из Deployment.
В закрытой конфигурации серверной VM задайте собственные пароли Indexer и API
и выпустите TLS штатным генератором. Для сохранённого состояния восстановите
его прежние пароли и сертификаты из закрытой копии. При отсутствии исходного
`client.keys` выдайте тестовому ПК новый ключ и согласуйте повторную подготовку
его выделенной установки с оператором Windows. Сохранённому агенту с прежней
регистрацией повторная выдача ключа не требуется.
[Wazuh Docker](https://github.com/wazuh/wazuh-docker/tree/76ddb88b9c8b618a254a287f2684f93d3c5ac2f4/single-node) · [Набор Deployment](https://github.com/Afonenko-Course-Tools/prairielearn-deployment/tree/0566bd7958a56e2515d6394420800277c0c56094/deploy/wazuh)

## Проверка после запуска

На VM 103 проверьте три контейнера и опубликованные порты, конфигурацию правил
и реакции, затем состояние демонов менеджера.

```bash
docker ps --filter label=com.docker.compose.project=exam-wazuh-vm103 \
    --format '{{.Names}} {{.Status}} {{.Ports}}'
manager=exam-wazuh-vm103-wazuh.manager-1
docker exec "$manager" /var/ossec/bin/wazuh-analysisd -t
docker exec "$manager" /var/ossec/bin/wazuh-execd -t
docker exec "$manager" /var/ossec/bin/wazuh-control status
docker exec "$manager" /var/ossec/bin/agent_control -l
```

В проекте должны работать Manager, Indexer и Dashboard. Менеджер публикует
`10.135.250.231:1514/tcp`, Dashboard — `127.0.0.1:15601/tcp`.
Порты регистрации `1515` и Indexer закрыты на границе хоста. С путями и именами
сертификатов из официального single-node выполните на VM две пробы. Для второй
задайте имя существующего пользователя Indexer в `indexer_user` и введите
его пароль в интерактивном запросе `curl`.

```bash
dashboard=exam-wazuh-vm103-wazuh.dashboard-1
dashboard_ca=/usr/share/wazuh-dashboard/certs/root-ca.pem
indexer=exam-wazuh-vm103-wazuh.indexer-1
indexer_ca=/usr/share/wazuh-indexer/config/certs/root-ca.pem
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
    --cacert <(docker exec "$dashboard" cat "$dashboard_ca") \
    --resolve wazuh.dashboard:15601:127.0.0.1 https://wazuh.dashboard:15601/
docker exec -it "$indexer" curl --fail --silent --show-error \
    --cacert "$indexer_ca" --user "$indexer_user" \
    --resolve wazuh.indexer:9200:127.0.0.1 \
    'https://wazuh.indexer:9200/_cluster/health?filter_path=status,number_of_nodes'
```

Ожидаются HTTP `302` от Dashboard, TLS-проверка обоих имён и статус `green`
с одним узлом от Indexer. Агент проверяемой машины должен перейти в `Active` после
начала сбора. Если новая регистрация есть в ключах, а назначение группы
`default` возвращает ошибку 2003, проверьте состояние базы менеджера.
[Результаты пилота 19 ноября](../../../docs/execution-2026-11-19-20.md) · [Результаты 20 ноября](../../../docs/execution-2026-11-20.md)

### Подготовка партии регистраций из CLI

Создайте каждому испытательному ПК отдельную запись командой `manage_agents -a
<IP> -n <имя>` и сохраните вывод `manage_agents -e <ID>` в закрытом файле
только этого ПК. Если локальный `wazuh-authd` недоступен, CLI Wazuh 4.14.10
записывает ключ в `client.keys`, а строка `global.db` появляется при штатной
синхронизации на старте менеджера. Ошибка назначения группы и пустой
`last_keepalive` сами по себе не подтверждают сбой Windows.
[Источник CLI Wazuh 4.14.10](https://github.com/wazuh/wazuh/blob/v4.14.10/src/addagent/manage_agents.c#L365-L430)

Перед запуском клиентов сравните идентификаторы. В примере `004 005 006` —
проверенная партия текущей кампании. Команда чтения показывает только номера
и завершится ошибкой, если найдёт неожиданное расхождение или осиротевшую БД.

```bash
manager=exam-wazuh-vm103-wazuh.manager-1
docker exec -i "$manager" /var/ossec/framework/python/bin/python3 - 004 005 006 <<'PY'
from pathlib import Path
import sqlite3
import sys

expected = {int(value) for value in sys.argv[1:]}
keys = set()
for line in Path('/var/ossec/etc/client.keys').read_text().splitlines():
    fields = line.split()
    if len(fields) == 4 and fields[0].isdigit() and not fields[1].startswith(('!', '#')):
        keys.add(int(fields[0]))
path = Path('/var/ossec/queue/db')
with sqlite3.connect(f'file:{path}/global.db?mode=ro', uri=True) as db:
    rows = {row[0] for row in db.execute('SELECT id FROM agent WHERE id <> 0')}
files = {int(file.stem) for file in path.glob('*.db') if file.stem.isdigit()}
print('Только ключ:', sorted(keys - rows))
print('Только БД:', sorted(rows - keys))
print('Осиротевшие файлы БД:', sorted(files - rows - keys - {0}))
if expected - keys or (keys - rows) - expected or rows - keys or files - rows - keys - {0}:
    raise SystemExit('Расхождение вне согласованной партии.')
PY
```

Если проверка прошла и «Только ключ» содержит новые ID, один раз перезапустите
только выделенный контейнер менеджера. Модуль Wazuh сверяет `client.keys` и
строки `global.db` на старте и добавляет недостающие записи с теми же ключами.
Сверьте прежние ID и новую партию после запуска. Для включённого агента
дождитесь `Active` с новым keepalive и проверьте `default`. Выключенный клиент
может получить группу при первом подключении.
[Синхронизация при запуске Wazuh 4.14.10](https://github.com/wazuh/wazuh/blob/v4.14.10/src/wazuh_modules/wm_database.c#L97-L125)

```bash
docker restart "$manager"
docker exec "$manager" /var/ossec/bin/wazuh-control status
docker exec "$manager" /var/ossec/bin/agent_control -l
docker exec "$manager" /var/ossec/bin/agent_groups -s -i 004
```

## Проверка одного события

### Контрольная проба через TUI

На одноразовой Windows VM назначьте экзамен и дождитесь `Active` для выделенного
агента. Оставьте Guest на разблокированной консоли с открытым проектом IDEA и
несохранённым синтетическим изменением. Выполните в повышенном 64-битном Windows
PowerShell через имеющийся административный канал. Задача использует системный
токен, чтобы проверить защищённые данные текущего консольного входа.

```powershell
$name = 'ExamLab-Pilot-ControlProbe-' + [guid]::NewGuid().ToString('N')
$powerShell = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$alert = Join-Path $env:ProgramFiles 'ExamLabAlert\ExamLabAlert.ps1'
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action ControlProbe' -f $alert
$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName $name
```

После завершения задачи проверьте `LastTaskResult` и локальный статус пробы.
Сохраните номер `EventRecordId`, ID агента и `RunId`. В журнале менеджера
сверьте правило `110610`, ID агента, тот же номер записи Windows и время
пробы. Ожидается одна запись для этой тройки.

```powershell
Get-ScheduledTaskInfo -TaskName $name
$statusKey = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
Get-ItemPropertyValue $statusKey Status | ConvertFrom-Json |
    Select-Object RunId, Phase, EventRecordId, ReceivedUtc, ShownUtc, AcknowledgedUtc, AcknowledgedBy, AcknowledgementId
```

Убедитесь, что окно открыто именно в Guest с проектом IDEA, а в TUI появилась
причина «контрольный сигнал». Владелец снимает эту тревогу в TUI. Дождитесь
статуса `Acknowledged` в Windows и результата в TUI. Сверьте ID и учётную
запись владельца, закрытие экрана, тот же сеанс, проект и черновик IDEA.
Проверьте отказ для другой учётной записи, повтор снятия и новый Guest без
прежней тревоги. Пока Windows сообщает `Closing`, снятие ещё проверяется.

После фиксации результата удалите одноразовую задачу запуска.

```powershell
Unregister-ScheduledTask -TaskName $name -Confirm:$false
```

`normal` снимает экран и останавливает выделенного агента. Перед отдельной
контрольной пробой в том же сеансе администратор завершает предыдущий запуск
командой `& $alert -Action Disarm`.

### Контрольное чтение с NTFS-аудитом

По инструкции контроля чтения подготовьте отдельный доступный файл и наблюдатель,
затем прочитайте файл один раз в текущем Guest. Зафиксируйте Security `4663`,
Application `6101` от `ExamLab-Alert` и номер записи Application. В журнале
`/var/ossec/logs/alerts/alerts.json` менеджера найдите ровно одну тревогу с
правилом `110610`, ID этого агента и тем же номером записи после начала пробы.
Проверьте `Pending` и полноэкранное окно в том же Guest. Результат подтверждения
преподавателем фиксируйте по фактическому действию оператора.
[Агент Windows](../../../docs/windows-wazuh-pilot.md) · [Контроль чтения](../../../docs/windows-alert-file-audit.md)

## Короткое окно FileIO.light

Передайте оператору VM сценарий
[`tests/windows-fileio-light.ps1`](../../../tests/windows-fileio-light.ps1).
Выполните из повышенного PowerShell испытательной машины с согласованным именем.

```powershell
.\windows-fileio-light.ps1 -ExpectedComputerName EXAM-LAB-VM -Seconds 35
```

После сообщения о запуске откройте один синтетический файл Guest или выполните
`java -version`. Сценарий включает запись в файл и останавливает свой
именованный экземпляр по истечении окна. В `metrics.jsonl` остаются замеры
доступной физической памяти, времена фаз, распознанные счётчики потерь,
размер и SHA-256. Сверьте потери, действие Guest и интервалы опроса
контроллера. Трасса остаётся в закрытом
`Program Files\ExamLabSetupReports\ExamLabFileIO-*`. Сохраняйте в
отчёте итоговые показатели и храните ETL, пути и сырые данные вне Git.
[Команды WPR](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options)

Отдельно запустите в настоящем Guest
[`tests/installed-files-guest-probe.ps1`](../../../tests/installed-files-guest-probe.ps1)
с `-ExpectedComputerName` этой VM. Сценарий открывает существующие пути со
штатными правами чтения, записи и удаления и сверяет права родителей на запись,
переименование и удаление дочерней записи. Он выполняет создание, чтение,
переименование и удаление на отдельном синтетическом файле Guest. Для
недоступного или отсутствующего пути сохраните отдельный результат. Для
Program Files нормален читаемый клиент при запрете изменения, а в рабочей
папке Guest все четыре операции должны пройти.
