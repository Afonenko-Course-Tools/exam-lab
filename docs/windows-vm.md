# Локальная тестовая Windows VM

VM принадлежит только этому проекту. Все диски, ISO, журналы и секреты находятся
в игнорируемом `.local/`. Существующие libvirt VM, контейнеры, bridge, firewall
и данные Linux-хоста не изменяются. Используется отдельный процесс QEMU/KVM,
4 vCPU, 8 GiB RAM, собственный разреженный qcow2 на 100 GiB, штатные IDE/e1000
драйверы Windows и user-mode NAT.

Здесь описана разовая первоначальная подготовка собственного эталона. Для
существующей Windows используйте общий [Check/Prepare](windows-preparation.md).
Эти сценарии VM не являются обвязкой повторных испытаний.

## Источники

На 15 ноября 2026 года официальная страница Evaluation Center для Windows 10
перенаправляет на статью о завершении поддержки. Доступность ISO подтверждена
реальным HTTP 200 по [официальному fwlink Microsoft](https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US).
Редирект ведёт на:

```text
https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66750/19045.2006.220908-0225.22h2_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso
```

Загружено 5 550 497 792 байт, SHA256 локального ISO:
`ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668`.
Из WIM прочитана редакция
`Windows 10 Enterprise Evaluation`, x64, en-US; в образе есть пакет 22H2.
Точные установленные build/UBR фиксируются после запуска Windows, имя ISO
не считается результатом проверки установленной системы.

Это 90-дневная ознакомительная Windows для испытаний. Она не предназначена
для постоянной эксплуатации или переноса в аудиторию. Продление срока,
обход активации и превращение Evaluation в рабочую лицензию не выполняются.
Перед unattended установкой владелец один раз читает и принимает применимые
условия: текст извлечён из ISO, путь
`Windows/System32/en-US/Licenses/Eval/EnterpriseEval/license.rtf` внутри
`sources/install.wim`. Локальная читаемая копия:
`.local/iso/windows10-enterprise-eval-license.txt`.

| Инструмент | Официальный источник | SHA256 загруженного установщика |
| --- | --- | --- |
| IDEA Community 2025.2.6.4 | [JetBrains](https://download.jetbrains.com/idea/ideaIC-2025.2.6.4.exe) | `57301793b57b9f2b87a5c79fd06b619e6bbd881501d793ecd78482b20525ea34` |
| Temurin JDK 25.0.5+8 x64 | [Adoptium](https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi) | `e1d3c94032579dc16af9abb311f4552ba271466b74c8767e8ce39585a4c64d40` |
| Git for Windows 2.56.1 | [Git for Windows](https://github.com/git-for-windows/git/releases/download/v2.56.1.windows.1/Git-2.56.1-64-bit.exe) | `c330c72e10b408cc39994bfefdb63542b0d93d21699325c3e0bd874af8a5a559` |
| LGPO 3.0, архив SCT | [Microsoft](https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/LGPO.zip) | `cb7159d134a0a1e7b1ed2ada9a3ce8ce8f4de391d14403d55438af824247cc55` |

Хеши IDEA, JDK и Git сопоставлены с данными издателя. В Windows дополнительно
проверяется Authenticode перед запуском установщиков. Хеш загруженного Windows
ISO зафиксирован после окончания загрузки; без опубликованного Microsoft
эталонного SHA256 он подтверждает идентичность локального файла, а не подпись Microsoft.

## Первоначальная установка

Применимые условия [AcceptEula](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-setup-userdata-accepteula)
требуют явного принятия владельцем до unattended установки.

Сохраните указанный выше x64 ISO под точным именем
`.local/iso/windows10-enterprise-eval-x64.iso`: этот путь ожидает
`scripts/vm/start-reference.sh`. Сверьте SHA256 с разделом «Источники».
Команды выполняются из корня репозитория; на Linux нужны QEMU/KVM,
`qemu-img`, `xorriso` и Python 3.

```bash
python scripts/vm/prepare-seed.py --accept-eula
scripts/vm/start-reference.sh install
```

`install` отказывается запускаться, если `.local/vm/reference.qcow2` уже существует.
Ответ Windows Setup очищает только Disk 0 внутри новой VM. Не подключайте
физические диски или чужие qcow2 к этой установке.

Создаются администратор `examadmin` и обычный пользователь `labstudent`.
Случайные пароли хранятся в `.local/vm/credentials.json`, а также в ответе
`seed/Autounattend.xml` и `seed.iso`. Каталог `.local/vm` имеет права 0700,
секреты не коммитятся. После установки отключаются установочные CD и удаляются
оставленные Setup копии ответа из Windows Panther. Эталон не содержит
экзаменационных политик; SharedPC на нём не включается.

`vm/bootstrap.ps1` выполняется штатным `specialize/RunSynchronous` от SYSTEM.
Он подготавливает WinRM, сохраняет фактическую редакцию/сборку и журнал в
`C:\ProgramData\ExamLab-VM`, защищённом ACL SYSTEM/Administrators.
Готовность отмечается `bootstrap-complete`; отсутствие этого файла означает,
что подготовка не подтверждена.

На первом запуске обнаружен реальный отказ WSMan provider `Set-Item` в фазе
specialize на Public сети. В исправленной версии используются штатные
[WinRM ADMX значения](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotemanagement)
`AllowBasic=0` и `AllowUnencryptedTraffic=0`. Исправленный bootstrap выполнен
от SYSTEM через планировщик: `LastTaskResult=0`, собственное правило проверено
после применения, оба широких штатных WinRM правила отключены.

## Технический доступ

| Канал | Адрес на хосте | Назначение |
| --- | --- | --- |
| VNC | `127.0.0.1:5905` | Короткие ручные проверки настоящего Guest и IDEA |
| WinRM | `http://127.0.0.1:15985/wsman` | Автоматические административные команды |
| QMP | `.local/vm/qmp.sock` | Управление только этим процессом QEMU |

WinRM использует NTLM с обязательным шифрованием сообщений; Basic и
AllowUnencrypted отключены. Правило VM принимает TCP 5985 только от адреса
хоста QEMU `10.0.2.2`. Порты хоста слушают только loopback, bridge отсутствует.
Технический доступ не является производственным контроллером.

```bash
python -m venv .local/python
.local/python/bin/pip install pypsrp
.local/python/bin/python scripts/vm/guest-ps.py /absolute/path/check.ps1
```

`guest-ps.py` передаёт текст указанного файла в `execute_ps` под администратором
`examadmin`. Он сам не создаёт заданий и не переключается на SYSTEM. Если
вызывающему сценарию нужен SYSTEM для MDM bridge/SharedPC, этот сценарий должен
явно создать и запустить штатное одноразовое задание планировщика с principal
SYSTEM; обычный административный WinRM-сеанс этого не обеспечивает.

Для первой установки программ в эталон заранее подготовьте установочный CD.
В каталоге `exam_media_source` должны находиться три установщика из раздела
«Источники» и распакованный официальный архив LGPO 3.0 с файлом
`LGPO_30/LGPO.exe`. Укажите свой абсолютный путь вместо примера:

```bash
exam_media_source=/absolute/path/to/downloaded-installers
mkdir -p .local/vm/tools
cp -- "$exam_media_source/ideaIC-2025.2.6.4.exe" .local/vm/tools/ideaIC.exe
cp -- "$exam_media_source/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi" .local/vm/tools/temurin25.msi
cp -- "$exam_media_source/Git-2.56.1-64-bit.exe" .local/vm/tools/git.exe
cp -- "$exam_media_source/LGPO_30/LGPO.exe" .local/vm/tools/LGPO.exe
cp -- vm/install-tools.ps1 .local/vm/tools/install-tools.ps1
xorriso -as mkisofs -quiet -J -r -V EXAMTOOLS -o .local/vm/tools.iso .local/vm/tools
```

Именно эти пять имён должны находиться в корне CD с меткой `EXAMTOOLS`.
Перед первым установщиком `vm/install-tools.ps1` проверяет фиксированные SHA256
IDEA/JDK/Git и действительность их Authenticode-подписей; перед копированием
LGPO проверяет действительную подпись Microsoft. SHA256 архива LGPO указан
в разделе «Источники». CD собирается для первоначальной подготовки эталона,
а не заново для каждого испытания.

После выключения Windows следующий запуск без установочного ISO:

```bash
scripts/vm/start-reference.sh boot
```

Эта команда относится к подготовке. После завершения эталон штатно выключен,
`qemu-img check` не обнаружил ошибок, файл `.local/vm/reference.qcow2` защищён
режимом 0400. Изменяемые проверки выполняются только на qcow2 overlay,
ссылающейся на этот backing file. Первый отдельный клон имеет имя
`exam-lab-guest-pilot`, диск `.local/vm/pilot-guest.qcow2`, VNC `127.0.0.1:5906`,
WinRM `127.0.0.1:15986` и QMP `.local/vm/pilot-qmp.sock`. У него отсутствуют
установочные CD и секретный seed. `C:\ProgramData\ExamLab-TestVM` создаётся
только в клоне. Реальная команда WinRM на 15986 подтвердила `Marker=True` и
том `E:` с меткой `EXAMLAB_USB`; клон передан исполнителю Guest/USB.
Диск клона имеет backing именно `.local/vm/reference.qcow2`; отдельный процесс
эталона не запущен. Фикстура USB подключена как `usb-storage,removable=on`,
без проброса физического диска хоста. Это виртуальная проверка, которая
не заменяет физическую флешку. После холодного старта часы клона исправлены
по времени хоста; для новых запусков QEMU указан `-rtc base=localtime`.
Эталон маркера и экзаменационных настроек не содержит.

При подготовке `boot` подключает `.local/vm/tools.iso`, если этот файл существует.
Внутри Windows администратор с повышенным UAC token запускает проверенный локальный
`install-tools.ps1` с этого CD. Замените `X:` на фактическую букву тома `EXAMTOOLS`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\install-tools.ps1
```

Параметр политики действует только в этом процессе и дочерних процессах;
сохранённые LocalMachine/CurrentUser не меняются, Group Policy имеет приоритет.
Этот установщик предназначен только для первоначального собственного эталона;
он задаёт JDK/PATH этого эталона. Установка для всех пользователей не записывает
экзаменационные настройки в `C:\Users\Default`.

Обычный профиль подготавливается отдельно:

```bash
.local/python/bin/python scripts/vm/prepare-ordinary-profile.py
```

Штатный `userenv.CreateProfile` создаёт настоящий профиль `labstudent`.
Далее готовый WinRM выполняет `vm/ordinary-user-probe.ps1` именно от этого
пользователя с `AdministratorToken=false`. Доступ через группу Remote Management
Users выдаётся временно и удаляется в `finally` с чтением результата. В профиле
создаются контрольные `Documents\OrdinaryCourse\Hello.java` и `DoNotDelete.txt`,
выполняются реальные `javac`, `java` и `git init/status`. Новизна результата
проверяется по идентификатору запуска и SID. Гостевой сеанс этим не подменяется.

Отброшенные попытки `Start-Process -Credential` и Password Task Scheduler
не входят в рабочий путь. После диагностики исходное `SeBatchLogonRight`
восстановлено и независимо проверено; парольная задача удалена.

Фактически установлены Windows 10 Enterprise Evaluation 22H2, `19045.2006`,
IDEA Community `2025.2.6.4` (`252.28539.149`), Temurin/Javac `25.0.5+8 LTS`
и Git `2.56.1.windows.1`. Подписи трёх установщиков Windows проверены как Valid.
Начальный лицензионный статус был Notification с нулевым остатком. Однократный
штатный `slmgr /ato` завершился `Product activated successfully`; после него
фактические `LicenseStatus=1`, `GracePeriodRemaining=129600` минут (90 дней).
Смена ключей, `rearm` и обходы лицензирования не выполнялись.
Из установленной IDEA до первого запуска удалён из каталога плагинов
`org.jetbrains.completion.full.line` (Full Line Code Completion), архивная копия
лежит в защищённом `C:\ProgramData\ExamLab-VM\excluded-plugins`. Наличие
обычных дополнений кода, инспекций и отладки проверяется отдельным ручным входом.

В эталон не импортирован локальный PrairieLearn CA. Проверка автоматического
допуска отклонила расширение глобального доверия Windows/JDK без отдельного
согласия владельца; импорт отменён. Доступность PrairieLearn через браузер
и Java TLS в этом эталоне этим не подтверждается. Это не мешает первой
проверке Guest/USB на отдельной копии.

## Границы проверки

Разбор XML, синтаксиса shell/Python и наличие установщиков не подтверждают
установку Windows или действие её политик. Отдельно фиксируются реальная
доступность WinRM, фактическая ОС и версии инструментов. Эталон выключается
штатно и сохраняется; изменяемые политики испытываются на отдельном qcow2
overlay. Обвязка повторных испытаний появляется после проверки первого пилота.
Физические USB, Guest/IDEA и полный маршрут Moodle требуют предусмотренных
коротких ручных проверок.
