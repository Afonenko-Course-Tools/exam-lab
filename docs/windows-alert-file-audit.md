# Тревога Wazuh при чтении контрольного файла

Проба выполняется на одноразовой Windows VM с настоящим Shared PC Guest и
работающим Wazuh. Используйте настройки менеджера из Deployment №9,
штатный узкий сбор `Application / ExamLab-Alert / 6101` и установку из
[инструкции оповещения](windows-alert.md). Нужны все сценарии из
`windows/alert` одной ревизии в защищённом установленном каталоге.

1. Администратор создаёт один новый синтетический файл в защищённом каталоге
   NTFS. У целевого Guest есть чтение, а замена файла, запись в него и
   переименование каталога доступны только администратору или SYSTEM.
   Соседний доступный файл без аудита и отдельный файл с отказом NTFS служат
   контрольными проверками.
2. Администратор проверяет подкатегорию File System командой
   `auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /r`.
   Если Success выключен, сначала проверяет область уже существующих
   SACL в изолированном образе. Только в фазе этой пробы допускается
   `auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable`.
   После пробы возвращает Success в исходное состояние и повторяет
   `/get`. Сценарии сами политику Windows не меняют. Менеджер Wazuh
   по-прежнему получает только узкие записи 6101.
3. Администратор добавляет одну ACE аудита успеха `ReadData` для SID
   Guest к новому файлу без наследования. Используйте
   `Get-Acl -Audit -LiteralPath $canary`, затем `AddAuditRule` и
   `Set-Acl -LiteralPath $canary -AclObject $acl` с правилом:

   ```powershell
   $sid = [Security.Principal.SecurityIdentifier]::new($guestSid)
   $auditRule = [Security.AccessControl.FileSystemAuditRule]::new(
       $sid, 'ReadData', 'None', 'None', 'Success')
   ```

   Проверьте прочитанное правило перед началом. После пробы прочтите
   свежий ACL, вызовите `RemoveAuditRuleSpecific($auditRule)` и запишите ACL.
   Сверьте удаление пробной ACE и сохранение остальных записей.
4. В настоящем Guest прочтите SID пользователя и номер сеанса в обычном
   PowerShell. Оставьте этот PowerShell открытым и выполните контрольное
   чтение файла именно в нём, без смены пользователя или повышения прав.

   ```powershell
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   [Diagnostics.Process]::GetCurrentProcess().SessionId
   ```

   Идентификатор для `SubjectLogonId` возьмите из `AuthenticationId`
   токена этого консольного входа. Для этого используйте установленный
   модуль контроллера из той же проверенной поставки. Администратор
   сохраняет следующий одноразовый сценарий в защищённом
   `C:\Program Files\ExamLabAlert\Private` и запускает его штатным
   планировщиком от LocalSystem (`S-1-5-18`) в 64-битном Windows
   PowerShell 5.1. Файл сценария и новый файл результата должны быть
   доступны для записи только SYSTEM и администраторам. Предыдущий
   файл результата перед запуском удалите.

   ```powershell
   $ErrorActionPreference = 'Stop'
   Import-Module 'C:\Program Files\ExamLab\ExamLab.Controller.psm1' -Force
   $console = Get-ControllerConsoleLogon
   if (-not $console -or -not $console.AuthenticationId) {
       throw 'Не получен токен текущего консольного входа.'
   }
   [pscustomobject]@{
       Sid = $console.Sid
       SessionId = $console.SessionId
       LogonId = '0x{0:x}' -f [uint64]$console.AuthenticationId
   } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'canary-console-logon.json') -Encoding UTF8
   ```

   Убедитесь, что задача завершилась с кодом 0 и SID с номером сеанса
   в свежем файле совпали с выводом PowerShell Guest. Передайте `LogonId`
   как `$guestLogonId` наблюдателю из шага 5. При смене входа получите
   значения заново. После считывания удалите одноразовую задачу, сценарий
   и файл результата. Вывод `whoami /logonid` в пробе не совпал с
   `SubjectLogonId` события Security и для этой сверки не используется.

5. Администратор выполняет `Arm` для SID и сеанса, проверяет подключение
   выделенного агента Wazuh и фиксирует текущий номер записи Security.
   Когда наблюдатель запущен, оператор просит Guest прочитать ровно один
   раз содержимое файла штатной командой `Get-Content -LiteralPath`.
   Пример повышенного вызова:

   ```powershell
   $base = Join-Path $env:ProgramFiles 'ExamLabAlert'
   $status = Get-ItemPropertyValue 'HKLM:\SOFTWARE\ExamLabAlertPilot' Status | ConvertFrom-Json
   $baseline = (Get-WinEvent -LogName Security -MaxEvents 1).RecordId
   & "$base\Wait-ExamLabFileRead.ps1" -RunId $status.RunId -AuditBaseline $baseline `
       -CanaryPath $canary -GuestLogonId $guestLogonId -TimeoutSeconds 60
   ```

6. Сверьте локальные `SecurityReadRecordId` и `EventRecordId` в статусе,
   ровно одну тревогу менеджера `110610` с данным номером записи Application
   и нужным идентификатором агента, `Pending` и окно именно в проверяемом
   Guest. Повторное чтение и повтор команды оставляют одну запись 6101
   на запуск. Если сценарий прервался, а в статусе уже есть
   `SecurityReadRecordId`, повторять сигнал в том же запуске нельзя,
   даже если `EventRecordId` ещё равен нулю. Сверьте Windows Application
   и менеджер Wazuh. Без полного совпадения номеров и статуса отметьте
   результат как неподтверждённый. Для новой пробы выполните `Disarm`,
   затем `Arm`, запишите новую границу Security и заново прочтите файл.
   Для отрицательной пробы запустите отдельный `Arm` и окно
   ожидания, прочтите соседний файл или получите ожидаемый отказ на
   защищённом файле. Тайм-аут и отсутствие новой записи 6101 подтверждают
   отрицательную пробу. Сохраните только номера записей и итоговые статусы.
   При любом исходе, включая тайм-аут, отмену и частичный сбой, выполните
   `Disarm`, снимите только добавленную пробную ACE и восстановите
   исходное значение Success, если меняли его. Сверьте оба изменения
   повторным чтением. Если один шаг завершения дал ошибку, выполните
   остальные и отдельно зафиксируйте, что осталось восстановить.

Наблюдатель опрашивает журнал Security в поднятом сеансе администратора до
истечения указанного времени. Такой режим предназначен для контролируемой
пробы. Подтверждение преподавателя использует существующий сценарий
оповещения и его требования к защищённому запросу UAC.

## Результат на изолированной VM 19 ноября 2026 года

Две первые попытки зарегистрировали успешное `ReadData` в Security.
Значение из `whoami /logonid` отличалось от `SubjectLogonId`.
Сценарий отклонил обе записи, и событий 6101 не было. С идентификатором
из токена консольного входа настоящее чтение Guest дало запись Security
4663 №3324, затем Application 6101 №222 и ровно одну тревогу Wazuh
110610 у агента 001. Полноэкранное окно открылось в том же Guest и осталось
на переднем плане при `Alt+Tab`.
