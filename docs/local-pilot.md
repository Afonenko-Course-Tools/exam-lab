# Локальный переключатель Windows

Текущий кандидат упрощён до `prepare`, `check`, `exam`, `normal`. Он не делает
снимков прежних настроек Windows и не восстанавливает их целиком. Нет общего
обратного импорта сохранённых firewall/GPO/registry, security templates, копий
пользовательских hive и общего rollback. Адресная установка собственных GPO entries
использует штатные средства. Чужие правила, настройки и ACL не исправляются.

**Совместная поставка USB/network ещё не прошла приёмку в Windows.** `FullReady=false`; `exam`
отказывает до чтения конфигурации, создания lock/metadata и любых изменений.
Причины: не приняты структурное ограничение файлового доступа Guest, сетевая
изоляция в совместной поставке и весь обычный учебный сценарий при постоянном SharedPC.
Сейчас допускается только отмеченная standalone QEMU/KVM VM, Windows x64,
Windows PowerShell 5.1 x64 и SYSTEM через административные задания. ARM исключён.
Текущий стенд en-US; русская Windows остаётся отдельной проверкой.

## Установка и конфигурация

Установка программ и установка переключателя — разные операции. Программную
подготовку обслуживает `setup/Prepare-ExamLab.ps1`; переключатель доставляет
`setup/Install-LocalPilot.ps1`. Установщик переключателя не запускает политики,
`prepare` или `check` автоматически. Его `-ConfigurationPath` указывает на
явно составленный список ordinary accounts, например
[pc.example.json](../examples/pc.example.json). Примерные SID нужно заменить.

`pc.json` хранится в закрытом `%ProgramData%\ExamLab`:

```json
{
  "OrdinaryAccounts": [
    { "Sid": "S-1-5-21-111111111-222222222-333333333-1001", "Name": "student" }
  ]
}
```

Необязательный `Network` в той же `pc.json` задаёт literal IPv4 proxy endpoint,
порт и массив явного технического inbound TCP-доступа; пример —
[pc.network.example.json](../examples/pc.network.example.json). Пустой
`TechnicalAccess: []` допустим. Каждый элемент содержит только `RemoteIP` и
`LocalPort`; имена сайтов, PL/Moodle destinations и произвольные firewall-поля
в этот Windows config не входят. Конфигурация без `Network` остаётся допустимой.
Добавление Network к уже подготовленному ПК не меняет его Revision автоматически.

Установщик принимает также `-PolicyFileEditorPath`: offline-каталог исходного
PolicyFileEditor3.0.1 из PowerShell Gallery. Он проверяет SHA256 всех15 известных
файлов, включая LICENSE, и доставляет их в
`%ProgramFiles%\ExamLab\PolicyFileEditor\3.0.1`. Пакеты в runtime не скачиваются.
Новая поставка содержит фиксированные `ExamLab.Usb.psm1` и `ExamNetwork.psm1`;
установка сама не применяет ограничения и не запускает задания.

SID и имя должны точно соответствовать существующей локальной учётке. Это
неизменная конфигурация подготовленного ПК, а не runtime-снимок всех пользователей.
Новый ordinary SID, переименование или изменение списка требуют отдельной
административной подготовки; список не расширяется автоматически. В первом
`prepare` все локальные RID>=1000 должны быть явно перечислены, включая обычного
администратора и отключённые обычные учётки. Эта проверка действует также при
повторном `prepare` и `check`. Новый SharedPC Guest тоже вызывает
безопасный отказ: его происхождение ещё не различается с новым ordinary SID,
по имени оно не угадывается. Это открытое ограничение кандидата.

Код и LGPO находятся в `%ProgramFiles%\ExamLab`; менять их могут только SYSTEM
и доверенные администраторы, Users могут читать код. В приватной `mode.json`
только `Prepared`, `Revision` и `LastCompletedMode`. `Revision` — SHA256 **нашей
pc.json**, а не прежних значений Windows. Изменение конфигурации после подготовки
отклоняется. Старый `state.json` прототипа блокирует новую установку и действия;
автоматического переноса или запуска прежнего `finish` нет. Исторические файлы
испытаний не удаляются.

## Четыре действия

Команды вызываются из повышенного административного сеанса через фиксированные
SYSTEM/Highest/ServiceAccount задания с доступом только SYSTEM/Administrators:

```powershell
Start-ScheduledTask -TaskName ExamLab-Local-check
Start-ScheduledTask -TaskName ExamLab-Local-prepare
Start-ScheduledTask -TaskName ExamLab-Local-exam
Start-ScheduledTask -TaskName ExamLab-Local-normal
```

`check` только читает. Он проверяет код/config ACL и reparse points, официальный
LGPO, roster, источник USB GPO, доступные effective user hives и SharedPC.
Отсутствующий `MDM_SharedPC` instance означает **Unknown**, не `false`/выключено.
Он не подгружает hive и не создаёт metadata. Отсутствие source entry в Registry.pol
не доказывает отсутствие effective HKCU policy у выгруженного профиля.

`prepare` — явная однократная подготовка: AccountModel=2, EnableAccountManager=true,
EnableSharedPCMode=true, DeletionPolicy=0, exemptions только заданного roster.
Образовательные, энергетические и RestrictLocalStorage политики не включаются.
Перед первым изменением проверяются конфликты source policies/ACL, roster,
загруженные student profiles и существующий SYSTEM MDM instance. Отсутствующий
instance остаётся Unknown и блокирует `prepare` до изменений: корень CSP не
создаётся, другой ParentID не подбирается. В [SharedPC DDF](https://learn.microsoft.com/en-us/windows/client-management/mdm/sharedpc-ddf-file)
корень указан как постоянный, с Get без Add; конфликтующий PowerShell-пример
не используется для создания корня. Чужая machine Registry.pol
с настройками сейчас консервативно требует адресного разбора до подготовки.
Существующие чужие SharedPC settings и exemptions не присваиваются программе.
До нашей первой metadata все семь полей `SharedPCSettings` должны быть `null`
(unset). Любое значение, отличное от `null`, включая0 или `false`, требует отдельного
разбора. `null` не преобразуется в число и не заменяется CSP default. Это узкая
проверка представления провайдера; другие представления пока дают ранний отказ,
совместимость с ними не заявляется.
ACL существующих объектов не сбрасываются. При частичном отказе остаётся
`Prepared=false`; прежние настройки не сохраняются и rollback не запускается.
Повтор проверяет тот же собственный target; непонятное состояние отклоняется.

`Prepared=true` означает только configuration-applied с readback. Оно не означает
принятые ordinary-сценарии: `OrdinaryScenariosVerified=false`,
`GuestLifecycleValidated=false`, `FullReady=false`. SharedPC остаётся включённым
при переключении normal/exam. Выбранный DeletionPolicy=0 по
[SharedPC CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/sharedpc-csp)
означает immediate deletion. В одной настоящей Guest-пробе очистка принята,
но точное время удаления не наблюдалось; мгновенность не заявляется.
Документация Microsoft описывает постоянные эффекты SharedPC и exemptions в
[руководстве настройки](https://learn.microsoft.com/en-us/windows/configuration/shared-pc/set-up-shared-or-guest-pc).

`exam` пока безусловно отказывает **до изменений**. Сетевого apply и неподтверждённого
filesystem setter нет. Обычный default Allow и чужие Allow-правила нельзя закрыть
добавлением своих Allow-правил. PersistentStore и profile defaults не меняются.
Возможное будущее владение отдельными computer-GPO полями потребует начального
NotConfigured, точного списка полей и нормального NotConfigured при снятии.

`normal` не выключает SharedPC и не зависит от готовности файловой политики.
Он под одним `operation.lock` заново читает конфигурацию и проверяет возможность
снять собственные настройки обоих установленных компонентов. До успешного
preflight обоих компонентов setters не вызываются; затем последовательно
выполняются фиксированные USB Normal и Network Normal. Каждый компонент повторяет
свои проверки перед записью. Ошибка второго не откатывает первый и возвращается
как незавершённый частичный результат, а не успешный normal.

USB снимает только точную собственную Non-Administrators MLGPO entry через
PolicyFileEditor: NotConfigured, без DWORD0/DELETE/CLEAR, замены чужого дерева
и сброса ACL. Это общее ограничение для nonadmin, включая ordinary, не Guest-only.
Снятие source policy не доказывает effective USB-доступ: нужен настоящий повторный
вход и чтение флешки. Сетевой компонент снимает только собственные проверенные
правила и computer-GPO поля; PersistentStore не импортируется и не очищается.
При отсутствующем Network и отсутствии сетевого intent его Normal — no-op;
при существующем intent без подходящей конфигурации возвращается отказ.

Статусы обоих компонентов присутствуют в `check`/`normal`; собственная Applied
политика не называется пустым набором или обычным режимом. `FullReady=false`,
публичный `exam` остаётся заблокированным. Прямые component Apply — отдельные
эксперименты, их исходники и интеграционная доставка ещё требуют native-приёмки.
Это не заявка на рабочее завершение всего экзамена.

Для `normal` новые неописанные SID не блокируют снятие только собственных entries:
возвращаются `IdentityUnconfirmed=true`, список SID, предупреждение и
`EffectiveMode=Unconfirmed`. Аккаунты не усыновляются ordinary roster, main metadata
не переписывается. Известные SID/Name, код/config/ACL и источники политик проверяются;
`prepare` и `check` сохраняют строгий roster. Полноценный общий offline-вызов без
сервера и Internet ещё не принят; проверка подписи LGPO остаётся включённой.

Структурная файловая политика должна быть широкой, без хрупкого списка частных
путей. Абсолютная home-only гарантия не заявляется; подмена системных файлов
вне threat model. Механизм ещё исследуется: кандидат не обходит диск и не
назначает массовые ACL/SACL/MIC labels.

## Проверки и границы результата

На отдельном свежем стенде Windows10 19045 x64 en-US предыдущий минимальный
SharedPC-кандидат прошёл независимые проверки установки, SYSTEM check, однократного
prepare, повторного prepare/no-op normal и reboot. Target seven raw settings и
exemptions explicit ordinary roster совпали; mode/config и два учебных файла
сохранились. Под настоящим labstudent приняты javac/java/git и чтение USB.
Затем через штатную Guest tile вошёл новый nonadmin; после GUI logout его exact SID,
профиль, ProfileList/HKU, каталог и созданный GUI marker отсутствовали в независимом
чтении. Logout был16:23:07UTC, отсутствие подтверждено к16:25:52UTC; точный момент
удаления не наблюдался. Это один lifecycle на одной сборке, не полная приёмка
экзамена или новой интеграционной поставки.


В Linux выполняются `tests/parse-windows.ps1` и `tests/pilot-logic.ps1`:
синтаксис, строгая конфигурация roster, ранний отказ exam и отсутствие старых
global restore/FW/ACL-reset команд. Они не подменяют Windows API и не являются
приёмкой нового SharedPC, USB, файловой или сетевой политики.
`tests/GuestProbe.ps1` и Java `file read|deny` — дополнительные наблюдения под
настоящим пользователем. Нужны заранее проверенные removable volume, путь и hash;
отсутствующий файл не считается USB deny. Основная USB-проверка — Explorer.

В прежнем отдельном прототипе на Windows10 Enterprise Evaluation 19045 root
наблюдал настоящий SharedPC Guest1003/nonadmin, Explorer USB access denied и
Java AccessDeniedException. В этом же Guest принята GUI-проба IDEA Community
2025.2.6.4/Temurin25: сборка/run, debug, completion, rename, inspection и отказ
открытия контрольного USB файла. Это исторические результаты, **не приёмка новой
реализации**. После logout старого Guest account/profile ещё существовали;
очистка и следующий чистый профиль не приняты. Сохранность ordinary USB во время
экзамена, физические носители и русская Windows остаются непроверенными.

Прежний код сохранён приватно в `.local/legacy` с SHA256, включая старую
`WindowsAuditRestore.ps1`. Он не входит в новый публичный путь. Старая VM15986
штатно выключена 15 ноября в14:55 UTC; диск со своим кодом/state и доказательства
испытаний сохранён. Её старый global finish/import не запускается.

Локальная SYSTEM-ветка Windows proxy была разовым экспериментом отдельной копии:
addon/runtime доставлены, временное доверие применено только по отдельному
разрешению для Guest CurrentUser Root и выделенного JVM store. В14:16 UTC
native-проверка и независимое чтение подтвердили очистку: CA отсутствует в
Guest store и тестовом JVM store, собственные trust tasks отсутствуют.
Рабочая интеграция и full network PASS не получены.
Направление централизовать proxy, файлы и будущий controller на основной
PrairieLearn VM пока не реализовано. Локальное снятие собственных экзаменационных
настроек должно работать без сервера; контроллер и исходящий опрос не построены.

Лицензия адресно использованной поставки 0.1.0 сохранена в
[LICENSE-exam-lab-0.1.0.txt](../windows/LICENSE-exam-lab-0.1.0.txt).
