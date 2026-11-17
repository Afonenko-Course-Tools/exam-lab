# Частный эксперимент: IDEA в AppContainer

Исходники воспроизводимой лабораторной пробы, **не установщик, Prepare, поставка
или основной exam**. Настоящий token IDEA подтверждён; GUI-старт v4 завершился
StartFailed/AccessDenied, редактор не открылся.
Испытания допускаются только на отдельной одноразовой Windows VM после разрешения
владельца; к аудиторным ПК этот результат не переносится автоматически.

Используются штатные Win32 API и уже установленный .NET Framework 4.5+.
Новая служба, драйвер, MSIX и VS/SDK не нужны.
Сам AppContainer не создаёт вторую ОС: целевой клиент с 8 ГБ не требует аппаратной
виртуализации. VM нужна для безопасного испытания этого ещё не принятого исходника.

Результаты одной отдельной Windows 10 VM; на другие ОС они не переносятся:

| Проверка | Результат |
| --- | --- |
| Штатная Framework64-компиляция | PASS, включая текущий v4 |
| Создание собственного AppContainer-профиля | PASS |
| Smoke: настоящий AC token и запись собственного файла, exit0 | PASS в v3 |
| Настоящий root token IDEA, exact SID/session/ACSID/capabilities | PASS в v4 |
| GUI-старт IDEA v4 | FAILED: StartFailed/AccessDenied |
| Редактор, consent, Run/Debug, Git и запрет чтения вне профиля | Не проверены |
| Повторное открытие проекта и полный клиентский путь | Пока pending |

## Подготовка и сборка

Нужны Windows 10/11 x64, штатный Framework64 csc, настоящий ограниченный Guest
в интерактивном сеансе и установленная IDEA Community 2025.2.6.4 по точному пути
`C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4\bin\idea64.exe`.
Этот путь фиксирован в исходнике; JDK используется существующий. Прежняя IDEA
должна штатно завершиться. Другие экспериментальные файловые ограничения сначала
снимаются своим Normal, чтобы не подменить эффект AppContainer.

Сборка в отдельном защищённом диагностическом каталоге, затем фиксация SHA256 exe:

```powershell
& C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:exe /platform:x64 /langversion:5 /r:System.Runtime.Serialization.dll /out:IdeaAppContainer.exe IdeaAppContainer.cs
if ($LASTEXITCODE -ne 0) { throw 'Compile failed' }
Get-FileHash .\IdeaAppContainer.cs, .\IdeaAppContainer.exe -Algorithm SHA256
```

Source SHA256: `f733e206dd4052200fc934595d0f9315cb569fa4dc471ddb4b9f6545a7c0d367`.
Обычный пользователь не должен изменять принятый exe. Windows/ProgramFiles ACL
не перестраиваются, глобальный ALL APPLICATION PACKAGES не добавляется.
Если требуется RX, его дают только SID собственного AppContainer на собственном
диагностическом каталоге. Workspace и состояние IDEA используют штатные права
собственного API-created профиля; отдельного ACL writer нет.

## Команды из того же limited Guest

Каждый вызов требует точные текущие SID и номер сеанса и проверяет настоящий primary token.
Сохраните stdout/stderr/exit каждого вызова **до parsing**, в отдельный собственный
журнал вне создаваемого AC-профиля: cleanup удаляет профиль вместе с проектом.

```powershell
$probe = (Resolve-Path .\IdeaAppContainer.exe).Path
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$name = 'ExamLabIdea-' + [Guid]::NewGuid().ToString('N')
$raw = @(& $probe prepare $sid $session $name 2>&1)
$exit = $LASTEXITCODE
$raw | Set-Content (Join-Path $env:TEMP ($name + '-prepare.jsonl')) -Encoding UTF8
if ($exit -ne 0) { throw 'Prepare failed; preserve early ProfileCreated' }
$prepared = @($raw | ForEach-Object { "$_" | ConvertFrom-Json } | Where-Object Event -eq 'ProfilePrepared')
if ($prepared.Count -ne 1) { throw 'Missing unique ProfilePrepared' }
$acPrepared = $prepared[0]
$acSid = $acPrepared.SID
```

**До первого launch обязателен отдельный ручной шаг размещения systemDir.**
При слишком длинном пути `.port` испытанная IDEA перенаправляла DirectoryLock
в Windows Temp, который AppContainer не обязан читать или изменять. Поддерживаемый
`idea.system.path` размещается в коротком `<actual API Folder>\s`. Автоматический
Prepare этой версии этого ещё не делает; его native PASS не означает готовый GUI.

```powershell
$systemDir = Join-Path $acPrepared.Folder 's'
$portPath = Join-Path $systemDir '.port'
if ($portPath.Length -gt 100 -or [Text.Encoding]::UTF8.GetByteCount($portPath) -gt 100) { throw 'DirectoryLock path exceeds limit' }
if (Test-Path -LiteralPath $systemDir) { throw 'Short systemDir collision' }
New-Item -ItemType Directory -Path $systemDir | Out-Null
icacls.exe $systemDir
# Проверить native Low MIC и FullControl exact $acSid, сохранив вывод.
# Если stock-права не подтвердились, остановиться; ACL не дописывать.
$properties = Join-Path $acPrepared.Root 'idea.properties'
$text = [IO.File]::ReadAllText($properties)
$acSystemMatches = [regex]::Matches($text, '(?m)^idea\.system\.path=[^\r\n]*')
if ($acSystemMatches.Count -ne 1) { throw 'Expected one system property' }
$acSystemMatch = $acSystemMatches[0]
$value = 'idea.system.path=' + $systemDir.Replace('\', '/')
$text = $text.Remove($acSystemMatch.Index, $acSystemMatch.Length).Insert($acSystemMatch.Index, $value)
[IO.File]::WriteAllText($properties, $text, (New-Object Text.UTF8Encoding($false)))
```

Затем, сохраняя stdout/stderr/exit каждого вызова отдельно:

```powershell
& $probe smoke $sid $session $name $acSid
& $probe launch $sid $session $name $acSid
# Для живого IDEA/JPS/JVM/Git: фактические PID, точный birth UTC и путь exe.
& $probe inspect $sid $session $name $acSid $targetPid $birthUtc $exactExePath
```

`prepare` отказывает при существующем profile name. Config/plugins/log/workspace
находятся под фактическим `GetAppContainerFolderPath\Temp\IdeaLab`; system после
ручного шага находится в `GetAppContainerFolderPath\s`. В диагностической v2
фактические TEMP/TMP дочернего AC-процесса перенаправлялись в штатный
`GetAppContainerFolderPath\Temp`, несмотря на переданный environment block.
Ошибку selfwrite ищут в этом фактическом TEMP как `selfwrite-error-<PID>.txt`.
`smoke` проверяет запись настоящим AC-процессом до GUI. `launch` читает target token
IDEA до ResumeThread и после него; `inspect` проверяет отдельного ребёнка через
один process handle, его birth/exe/SID/session/ACSID и полный capability-набор.
Само окно, package identity или флаги CreateProcess не заменяют эти результаты.

В smoke путь workspace передаёт проверивший его родитель; child сохраняет тот же
actual token gate. Дополнительное чтение атрибутов предков выше собственного AC
профиля запрещено самому AC и не требуется для записи внутри него. Полная проверка
пути родителем сохранена; новые ACL для доступа к этим предкам не добавляются.

V4 создаёт ownRoot/roaming и пытается передать его как APPDATA в environment ребёнка.
Фактическое APPDATA во v4 не измерено. GUI показал AccessDenied в
PathManager.getCommonDataPath → EndUserAgreement; полный путь и причина неизвестны.
Новой записи v4 в idea.log нет, прежняя ошибка v3 не считается доказательством v4.
Согласие не подделывается и EULA не отключается; диалоги consent не пройдены.
IDEA_PROPERTIES/TEMP/TMP/APPDATA меняются только в environment block ребёнка. Унаследованные
JAVA overrides/CLASSPATH/IDEA overrides вызывают отказ. Capabilities явно равны
internetClient и privateNetworkClientServer; LoopbackExempt не добавляется.
Run42, JPS/JVM/Git, Debug/JDWP, чтение известных outside-файлов и повторное открытие
сохранённого проекта проверяются отдельно. Ошибка loopback/COM/ACL сохраняется;
системные исключения и списки разрешений отдельных exe молча не добавляются.

## Адресное завершение и границы

До удаления профиля экспортируйте проект и журналы, запишите хеши. Штатно закройте
IDEA и независимо подтвердите завершение всего собственного дерева с точным AC SID,
включая JPS/JVM/Git. Затем из того же Guest:

```powershell
& $probe cleanup $sid $session $name $acSid
```

Cleanup требует собственную запись Name/UserSID/ACSID, дополнительно проверяет
доступные tokens и не восстанавливает DACL из снимка. Ранний ProfileCreated сохраняет
созданный профиль даже при дальнейшей ошибке подготовки: такой partial case разбирают
адресно, не усыновляют повторным prepare и не удаляют чужое имя.

AppContainer не заставляет весь Guest-сеанс работать внутри него. Независимый
unboxed Explorer/Notepad/Java остаётся обходом; эта проба не решает whole-Guest
AppControl. Доступный через существующий AAP grant outside-файл также может читаться.
Полный файловый барьер, HTTPS/PL/Moodle, USB и готовность экзамена не заявляются.

Лицензия эксперимента — [MIT](LICENSE). Win32 API сверены с официальным
[Microsoft LaunchAppContainer](https://github.com/microsoft/SandboxSecurityTools/tree/main/LaunchAppContainer)
([MIT](https://github.com/microsoft/SandboxSecurityTools/blob/main/LICENSE)) и
[документацией AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
