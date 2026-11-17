# Частный эксперимент: IDEA в AppContainer

Исходники воспроизводимой лабораторной пробы, **не установщик, Prepare, поставка
или основной exam**. Запуск IDEA, Run/Debug и запрет чтения пока не подтверждены
на Windows.
Испытания допускаются только на отдельной одноразовой Windows VM после разрешения
владельца; к аудиторным ПК этот результат не переносится автоматически.

Используются штатные Win32 API и уже установленный .NET Framework 4.5+.
Новая служба, драйвер, MSIX и VS/SDK не нужны.
Сам AppContainer не создаёт вторую ОС: целевой клиент с 8 ГБ не требует аппаратной
виртуализации. VM нужна для безопасного испытания этого ещё не принятого исходника.

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

Source SHA256: `dbc0ec8ce17ef2cd6e8b80ec7ea44e2f4279338c630d654c1eda462c6a1bcba7`.
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
& $probe prepare $sid $session $name
# Сохранить ProfileCreated и ProfilePrepared. Взять $acSid только из их поля SID.
& $probe smoke $sid $session $name $acSid
& $probe launch $sid $session $name $acSid
# Для живого IDEA/JPS/JVM/Git: фактические PID, точный birth UTC и путь exe.
& $probe inspect $sid $session $name $acSid $targetPid $birthUtc $exactExePath
```

`prepare` отказывает при существующем profile name. Все config/system/plugins/log,
temp и workspace находятся под фактическим `GetAppContainerFolderPath\Temp\IdeaLab`.
`smoke` проверяет запись настоящим AC-процессом до GUI. `launch` читает target token
IDEA до ResumeThread и после него; `inspect` проверяет отдельного ребёнка через
один process handle, его birth/exe/SID/session/ACSID и полный capability-набор.
Само окно, package identity или флаги CreateProcess не заменяют эти результаты.

IDEA_PROPERTIES/TEMP/TMP меняются только в environment block ребёнка. Унаследованные
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
