# Компонент запрета чтения съёмных дисков

`windows/ExamLab.Usb.psm1` применяет штатную пользовательскую политику
**Removable Disks: Deny read access** через Non-Administrators MLGPO.
Ограничение относится ко всем локальным неадминистраторам, включая обычные
учебные учётные записи во время экзамена. Это не Guest-only ограничение.
После `normal` обычным пользователям нужен новый настоящий вход и проверка чтения.
Полная готовность экзамена остаётся `FullReady=false`: этот компонент не принимает
файловые и сетевые ограничения за всю систему.

## Установка и запуск

Компонент доставляет общий [Install-LocalPilot](windows-preparation.md#установка-экспериментального-локального-пилота).
Сам установщик пока разрешён только на отмеченной одноразовой QEMU/KVM копии.
USB API использует обычный повышенный административный токен и не требует
отдельной SYSTEM-задачи. Его собственный gate допускает standalone Windows client
build 19041+ и Windows PowerShell 5.1 x64; это граница отказа, а не подтверждение
всех редакций и сборок. Domain, legacy `state.json`, изменённый код, неподходящие
ACL и конфликтующая политика приводят к отказу до изменения source.

Для offline-доставки один раз подготовьте точный готовый
[PolicyFileEditor 3.0.1 из PowerShell Gallery](https://www.powershellgallery.com/packages/PolicyFileEditor/3.0.1)
в новом каталоге. Это сторонний модуль Dave Wyatt под Apache License 2.0;
исходный `LICENSE` сохраняется вместе со всеми 15 файлами пакета, включая
служебные NuGet-файлы и DSC resources. Глобальная установка не нужна.

```powershell
Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/PolicyFileEditor/3.0.1' -OutFile '.\PolicyFileEditor.3.0.1.zip'
if ((Get-FileHash -LiteralPath '.\PolicyFileEditor.3.0.1.zip' -Algorithm SHA256).Hash -ne '6269BC40AE5885C27B48D3B2B593BE4AD858CAE6DBA04EDA0706F8823C25FAB0') { throw 'Неизвестный пакет PolicyFileEditor' }
Expand-Archive -LiteralPath '.\PolicyFileEditor.3.0.1.zip' -DestinationPath '.\PolicyFileEditor-3.0.1'
```

Передайте корень распакованного пакета в `-PolicyFileEditorPath` установщика:
в нём должны непосредственно находиться `PolicyFileEditor.psd1`, `Commands.ps1`
и `LICENSE`. Установщик проверяет фиксированный список и SHA256 исходных файлов
и доставляет их в
`%ProgramFiles%\ExamLab\PolicyFileEditor\3.0.1`. Во время действий нет скачиваний.
Код доступен пользователям только на чтение/выполнение; `pc.json`, `usb.json`
и общий `operation.lock` находятся в приватном `%ProgramData%\ExamLab`.
Существующие небезопасные ACL не исправляются автоматически.

Для проверенного установленного кода откройте повышенный процесс:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass
```

`Bypass` действует только в этом процессе, не меняет LocalMachine/CurrentUser;
доменная Group Policy имеет приоритет. В открытом процессе:

```powershell
Import-Module "$env:ProgramFiles\ExamLab\ExamLab.Usb.psm1" -Force
Get-ExamLabUsbStatus
Set-ExamLabUsbMode -Mode exam
# После завершения экзамена и выхода неадминистраторов:
Set-ExamLabUsbMode -Mode normal
```

Явный standalone `exam` применяет только USB-компонент. Основной экзамен
[локального модуля](local-pilot.md) остаётся заблокирован, пока не принят весь
учебный путь. Новое применение и снятие source требуют выхода загруженных
неадминистративных профилей. Уже применённый `exam` и завершённый `normal`
при неизменной source допускают честный повтор без записей, в том числе
при активной обычной сессии.

## Что изменяется и как снимается

Единственная собственная запись:

```text
%SystemRoot%\System32\GroupPolicyUsers\S-1-5-32-545\User\registry.pol
Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
Deny_Read = DWORD:1
```

Применение использует готовый LGPO 3.0 `/t` с scope
`User:Non-Administrators`. `normal` вызывает готовый
`Remove-PolicyFileEntry` для этой точной записи с обычным обновлением GPT.ini.
Это возвращает source в Not Configured; `DELETE` с постоянным
`**Del.Deny_Read`, принудительный DWORD 0 и очистка всего класса `CLEAR`
не используются. Чужой USB class sibling вызывает отказ; способность codec
сохранять соседние значения не означает разрешение забрать чужую USB-политику.
Иные vendor-политики не переписываются. Снимков Windows, загрузки hive,
своего Registry.pol codec, `**SecureKey` и ручных registry ACL здесь нет.

Сканер проверяет все найденные machine/user `registry.pol` в GroupPolicy и
GroupPolicyUsers, USB-поддерево и ancestor `**` commands, а также effective HKLM
и все загруженные HKU-корни, кроме `.DEFAULT` и `*_Classes`
(служебные alias классов). Это включает SID вне локального S-1-5-21 формата. Чужая source или effective запись блокирует изменение.
Совпадающий `Deny_Read=1` без собственной защищённой metadata тоже чужой.
Недоступное чтение приводит к отказу. Незагруженные hive не исследуются и не
подключаются; результат всегда отмечает `UnloadedHivesInspected=false`.

`usb.json` содержит только `Schema=1`, `ConfigRevision` (SHA256 единой `pc.json`)
и собственную intent `Applying/Applied/Removing/Normal`. Старых значений Windows
там нет. Intent записывается до изменения source; после прерванного удаления
повтор завершает GPT update готовым PFE. Завершённый `normal` с пустой своей
source не переписывает metadata или GPT. После смены `pc.json` активная прежняя
intent блокирует новый `exam`; адресный `normal` может снять точную свою запись,
сохранив прежнюю revision в metadata. Переданная dispatcher revision должна
совпадать с фактической текущей `pc.json`.

## Договор общего dispatcher

Экспортируются только три функции:

| Функция | Договор |
| --- | --- |
| `Get-ExamLabUsbStatus [-ConfigRevision SHA256]` | Свежий read-only status; `NotConfigured` без metadata, иначе собственная intent; `Conflicts`, `NormalAllowed/Blockers`, `ExamAllowed/Blockers`, точная `KnownOwnSource`, revision и границы effective readback. |
| `Set-ExamLabUsbMode -Mode exam\|normal` | Повышенный admin wrapper: общий exclusive `operation.lock`, свежая проверка после acquire, finally Dispose. |
| `Invoke-ExamLabUsbModeUnderLock -Mode exam\|normal -ConfigRevision SHA256 -OperationLock FileStream` | Только доверенный dispatcher с уже открытым тем же exclusive lock; повторяет свежий preflight, не захватывает lock повторно. |

Проверка живого FileStream и точного имени не доказывает способ открытия
произвольного чужого handle; `FileShare.None` — обязанность доверенного caller.
Общий `normal` проверяет **все** компоненты под общим lock до первого setter,
затем вызывает их UnderLock API. При частичном отказе он не объявляет общий
Normal и не запускает движок отката. USB остаётся единственным сканером своих
конфликтов: main потребляет его результат, не пропускает целый чужой GPO-файл.

`SourceNormal` означает только отсутствие своей source при `Normal` или
`NotConfigured` и отсутствие найденных конфликтов. `Changed=true` возвращает
`RequiresUserSignIn=true`; `EffectiveReadbackPending=true` остаётся и при no-op.
Ни статус source, ни общий `normal` сами по себе не доказывают фактическое чтение
USB. Microsoft также описывает возможную необходимость перезапуска при изменении
прав съёмных устройств; автоматический reboot компонент не назначает.
См. [ADMX Removable Storage: mapping и reboot caveat](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-removablestorage),
[Non-Administrators MLGPO](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789197(v=ws.11))
и [исходник Remove-PolicyFileEntry 3.0.1](https://www.powershellgallery.com/packages/PolicyFileEditor/3.0.1/Content/Commands.ps1).

## Фактическая проверка и оставшиеся границы

15 ноября 2026 на отдельной Windows 10 build 19045 en-US x64 QEMU/KVM копии
проверен private прототип того же plain MLGPO/PFE механизма. Новый настоящий
Shared PC Guest получил Java USB-read deny; запись/удаление `Deny_Read`, получение
WRITE_DAC и переименование шести ключей от класса до Software были запрещены.
Explorer тоже показал Access denied. Дополнительные `SecureKey` или registry ACL
не применялись. Независимый reader подтвердил effective/source и отчёт Guest.

Та же обычная неадминистративная учётная запись сначала получила USB-read deny
при Applied, после выхода, адресного `normal` и нового входа прочитала исходные
56 байт с прежним SHA256 без перезагрузки. После повторного подключения своего
виртуального USB чтение снова прошло. Независимый reader подтвердил финальные
source Not Configured, effective отсутствие записи, совпадение выбранных хешей
двух учебных файлов, основного кода, конфигурации и metadata режима. Повтор `normal` не изменил source,
GPT и собственную metadata. Первая попытка QMP переподключения адресовала дочерний
SCSI device и потребовала восстановления того же USB backend из исходной команды;
это ограничение стендовой пробы, не проверка произвольного hotplug.

Это приёмка механизма на одной копии с виртуальным USB. Новый публичный модуль
и его общая доставка требуют отдельной интеграционной проверки. Физический USB,
Windows 11, другие сборки/редакции, ru-RU и полный экзамен этими результатами не
подтверждены. Файловые/сетевые ограничения и работа IDEA с USB здесь не принимались.
Переносимая `tests/usb-policy-logic.ps1 -PolicyFileEditorPath <offline-root>`
проверяет готовый codec на временных файлах и orchestration с явно подменёнными
Windows observations; GPT, ACL и настоящую Windows она не испытывает.
