# Windows-оповещение на одноразовой VM

Кандидат кампании 19 ноября 2026 года по
[задаче №6](https://github.com/Afonenko-Course-Tools/exam-lab/issues/6).
Установка и завершение пробы выполняются отдельными командами.
Для одной пробы нужны Windows x64, Windows PowerShell 5.1, настоящий Shared PC
Guest, существующий локальный администратор и тестовый Wazuh 4.x.

## Как проходит сигнал

1. Оператор открывает сеанс Guest на консоли и связывает пробу с его SID и
   номером сеанса. Сценарий проверяет владельца Explorer, а выбор настоящего
   Shared PC Guest делает оператор. Одна административная команда создаёт контрольное событие
   `Application / ExamLab-Alert / 6101`.
2. Правило Wazuh `110610` запускает `exam-lab-alert.cmd` у агента-источника
   (`location=local`, реакция без тайм-аута). Команда принимает одну строку JSON
   Wazuh 4.x через stdin. Windows сверяет номер правила, источник, канал, код
   события и `eventRecordID` с номером локальной контрольной записи. Событие
   действительно две минуты с момента записи при наличии указанного
   гостевого сеанса. Реакция относится к ПК агента-источника.
3. Планировщик запускает экран с интерактивным токеном указанного Guest и
   передаёт ему идентификатор пробы, SID и номер сеанса. Экран сверяет эти
   данные со своим токеном и статусом в HKLM, доступным Guest для чтения.
   При переходе на другой виртуальный рабочий стол экран проверяет положение
   своего окна через IVirtualDesktopManager и создаёт окно на выбранном
   пользователем столе. Пока состояние Pending, планировщик повторяет попытку
   запуска раз в минуту, если процесс экрана закончился. Задачу и статус меняют
   SYSTEM и Administrators. Их записи статуса сериализует файловая блокировка
   в закрытом каталоге.
4. Преподаватель нажимает «Подтвердить как администратор» и вводит учётные данные
   в защищённом системном диалоге UAC. Административное действие в том же
   интерактивном сеансе проверяет идентификатор запуска и сохраняет имя и SID
   подтверждающей учётки, время UTC и прежний номер сеанса. Окно убирается
   после чтения сохранённого статуса. В Windows Application остаётся запись
   `ExamLab-Alert / 6102` с этими полями. Подтверждение работает с локальной
   учёткой при отключённой сети.
5. `Disarm` снимает задачу экрана и переводит пробу в `Disarmed`. Текущий
   статус сохраняет сведения о последней тревоге до следующего `Arm`. Отправленная ранее реакция
   Wazuh после `Acknowledged` или `Disarmed` игнорируется. При новом `Arm`
   принимается только номер записи, созданной новой командой `Signal`.
   Экзаменационный фильтр Wazuh отбирает контрольный сигнал `6101`.

Правило, настройки менеджера и развёртывание Wazuh принадлежат Deployment.
Windows-сценарий работает с локальными идентификаторами и временем. В данные
события не включаются LTI UID, учебные файлы и содержимое студенческого ответа.
[Протокол Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)

## Установка и запуск

На одноразовой VM из повышенного **64-битного Windows PowerShell 5.1**,
из корня проверенной копии репозитория:

```powershell
$dir = Join-Path $env:ProgramFiles 'ExamLabAlert'
New-Item -ItemType Directory -Path $dir -ErrorAction Stop
Copy-Item .\windows\alert\*.ps1 -Destination $dir
& "$dir\ExamLabAlert.ps1" -Action Initialize
icacls $dir
icacls "$dir\Private"
(Get-Acl 'HKLM:\SOFTWARE\ExamLabAlertPilot').Access
```

У `ExamLabAlert` должны быть стандартные права нового подкаталога Program
Files. В `Private` и ключ реестра могут писать SYSTEM и Administrators.
Встроенные группы Users и Guests получают чтение ключа. Проверьте пробой
под Guest чтение статуса и отказ записи в ключ, в каталог сценариев,
в `Private` и в каталог команды Wazuh. При конфликте с существующим каталогом
или источником остановите установку. Сценарии вызываются в установленном
защищённом каталоге.

На VM с тестовым Wazuh скопируйте `windows\alert\exam-lab-alert.cmd` в
`active-response\bin` установленного агента. Уточните путь установки, штатный
путь агента x86 приведён для ориентира:

```powershell
$agent = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
Copy-Item .\windows\alert\exam-lab-alert.cmd -Destination "$agent\active-response\bin"
```

На стороне менеджера нужен тестовый агент с правилом `110610` и реакцией
`exam-lab-alert.cmd`. Агент собирает канал `Application` и работает от SYSTEM.
Перед `Signal` проверьте состояние соединения с менеджером. Для первой пробы
проверьте доставку до включения экзаменационной сетевой политики. Затем отдельно
повторите проверку с разрешённым транспортом Wazuh и действующей политикой.

Оператор входит на консоли через плитку Shared PC Guest. Из неповышенного
PowerShell в этом сеансе получите SID и номер сеанса:

```powershell
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[Diagnostics.Process]::GetCurrentProcess().SessionId
```

Подготовьте открытый учебный проект и несданный тестовый ответ. Передайте два
значения из Guest повышенному PowerShell, например через WinRM в тестовой VM.
`Arm` создаёт задачу экрана с ограниченными правами указанного Guest.

```powershell
$alert = Join-Path $env:ProgramFiles 'ExamLabAlert\ExamLabAlert.ps1'
$key = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
& $alert -Action Arm -GuestSid $guestSid -GuestSessionId $guestSessionId
& $alert -Action Signal
Get-ItemPropertyValue $key Status | ConvertFrom-Json
```

После доставки сравните `EventUtc`, `ReceivedUtc` и время появления окна.
Перед проверкой подтверждения отключите сетевой адаптер тестовой VM через
консоль или гипервизор. Укажите существующую локальную учётку
`.\Администратор` (на тестовой англоязычной Windows используйте фактическое
имя созданного локального администратора). Для проверки подтверждения
используйте локальное чтение статуса и записи `Application / ExamLab-Alert / 6102`.
По окончании пробы сохраните результат
перед следующим `Arm` и вызовите `& $alert -Action Disarm` из повышенного
PowerShell. `Disarm` выполняется отдельно от `normal` в этом кандидате.

## Локальная проверка экрана без менеджера Wazuh

Используйте эту пробу, если тестовая VM ещё не связана с менеджером. Подставьте
синтетическую строку Active Response к настоящему локальному событию. Для
доставки через Wazuh сохраните `NOT_TESTED`. В повышенном Windows PowerShell
выполните после `Arm`, пока выбранный Guest открыт:

```powershell
$private = Join-Path $env:ProgramFiles 'ExamLabAlert\Private'
$wrapper = Join-Path $private 'exam-lab-alert.cmd'
$fixture = Join-Path $private 'fixture.json'
Copy-Item .\windows\alert\exam-lab-alert.cmd -Destination $wrapper
$command = '/d /s /c ""{0}" < "{1}""' -f $wrapper, $fixture
$taskAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $command
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$task = 'ExamLab-Alert-Pilot-Probe'
Register-ScheduledTask -TaskName $task -Action $taskAction -Principal $principal

& $alert -Action Signal
$status = Get-ItemPropertyValue $key Status | ConvertFrom-Json
$eventFields = @{
    providerName = 'ExamLab-Alert'; channel = 'Application'
    eventID = '6101'; eventRecordID = [string]$status.EventRecordId
}
$response = @{
    version = 1; command = 'add'
    parameters = @{ alert = @{ rule = @{ id = '110610' }; data = @{ win = @{ system = $eventFields } } } }
}
$response | ConvertTo-Json -Compress -Depth 8 | Set-Content -LiteralPath $fixture -Encoding Ascii
Start-ScheduledTask -TaskName $task
```

Для своевременной доставки запустите задачу в пределах двух минут после
`Signal`. Для пробы запоздалой доставки запустите её впервые после этой
границы. Повтор той же задачи воспроизводит то же сообщение. Снимите задачу
после испытания, выполнив `Unregister-ScheduledTask -TaskName $task -Confirm:$false`.

## Что проверить на VM

| Проверка | Наблюдение |
| --- | --- |
| Готовность экрана | В обычной работе и в Guest до события полноэкранной тревоги нет. |
| Показ | После одного сигнала появляется полноэкранное окно правильного Guest. Измерена задержка. |
| Видимость после вмешательства | Попробовать Alt+F4, Win+Tab, новый виртуальный рабочий стол, затем вернуться. После выбора другого стола окно должно снова появиться. Измерить задержку. Отдельно завершить процесс экрана и засечь время восстановления по расписанию. |
| Защита статуса | Guest может прочитать статус. Попытка изменить реестр, сценарий или задачу либо подтвердить тревогу без повышенного токена получает отказ. Отмена UAC сохраняет Pending. |
| Подтверждение | Запрос учётных данных появляется на защищённом рабочем столе UAC. Без сети локальный администратор подтверждает тревогу. Сверить SID и SessionId Guest, PID IDEA, открытый проект и несданный тестовый ответ до и после. |
| Повтор | Доставка той же реакции до и после ACK сохраняет одну тревогу. |
| Запоздалое событие | Событие, впервые доставленное через две минуты после создания, игнорируется. Для контроля повторите с новым запуском и своевременной доставкой. |
| Смена Guest | После Disarm и следующего чистого Guest старое событие не открывает окно. Остаточное состояние старого Guest без Disarm также проверяется по SID и сеансу. |

Окно использует WinForms `TopMost` на одном дисплее и отменяет обычное закрытие.
Доступность экрана после переключения стола, оставленного открытым Task View,
системных экранов и завершения процесса проверяется отдельно. Подтверждение
сохраняется в HKLM, где Guest имеет только чтение. Влияние `normal` на расширенный
сбор проверяется при его настройке в общей поставке.

[Интерфейс виртуальных рабочих столов Windows](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ivirtualdesktopmanager) ·
[Интерактивный запуск через планировщик](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-runex)
