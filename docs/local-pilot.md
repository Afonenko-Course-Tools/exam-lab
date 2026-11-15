# Локальный переключатель Windows

Текущий кандидат упрощён до `prepare`, `check`, `exam`, `normal`. Он не делает
снимков прежних настроек Windows и не восстанавливает их целиком. Нет экспорта
или импорта firewall/GPO/registry, security templates, копий пользовательских
hive и общего rollback. Чужие правила, настройки и ACL не исправляются.

**Новая реализация ещё не испытана в Windows.** `FullReady=false`; `exam`
отказывает до чтения конфигурации, создания lock/metadata и любых изменений.
Причины: не приняты структурное ограничение файлового доступа Guest, сетевая
изоляция, immediate Guest cleanup и обычные занятия при постоянном SharedPC.
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

SID и имя должны точно соответствовать существующей локальной учётке. Это
неизменная конфигурация подготовленного ПК, а не runtime-снимок всех пользователей.
Новый ordinary SID, переименование или изменение списка требуют отдельной
административной подготовки; список не расширяется автоматически. В первом
`prepare` все локальные RID>=1000 должны быть явно перечислены, включая обычного
администратора и отключённые обычные учётки. Эта проверка действует также при
повторном `prepare`, `check` и `normal`. Новый SharedPC Guest тоже вызывает
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
ACL существующих объектов не сбрасываются. При частичном отказе остаётся
`Prepared=false`; прежние настройки не сохраняются и rollback не запускается.
Повтор проверяет тот же собственный target; непонятное состояние отклоняется.

`Prepared=true` означает только configuration-applied с readback. Оно не означает
принятые ordinary-сценарии: `OrdinaryScenariosVerified=false`,
`GuestLifecycleValidated=false`, `FullReady=false`. SharedPC остаётся включённым
при переключении normal/exam. Выбранный DeletionPolicy=0 по
[SharedPC CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/sharedpc-csp)
означает immediate deletion; это ещё не подтверждённая native очистка Guest.
Документация Microsoft описывает постоянные эффекты SharedPC и exemptions в
[руководстве настройки](https://learn.microsoft.com/en-us/windows/configuration/shared-pc/set-up-shared-or-guest-pc).

`exam` пока безусловно отказывает **до изменений**. Сетевого apply и неподтверждённого
filesystem setter нет. Обычный default Allow и чужие Allow-правила нельзя закрыть
добавлением своих Allow-правил. PersistentStore и profile defaults не меняются.
Возможное будущее владение отдельными computer-GPO полями потребует начального
NotConfigured, точного списка полей и нормального NotConfigured при снятии.

`normal` не выключает SharedPC и не зависит от готовности filesystem/network.
Сейчас собственных переключаемых USB/GPO/FS/network entries ещё нет: возвращается
честный `Changed=false`/`OwnedEntriesRemoved=0`. Чужой Deny_Read не заменяется на0,
чужие class keys/родители и GPO-деревья не удаляются. Будущий адресный USB setter
потребует отдельной native проверки: normal = NotConfigured только собственных
entries, сохранность других Registry.pol entries и effective снятие после входа.
Любой partial статус не выдаётся за подтверждённый normal/exam.
Этот no-op пока не является рабочим учительским завершением экзамена: нет
принятого экзаменационного setter и пути проверки при активном новом Guest.

Структурная файловая политика должна быть широкой, без хрупкого списка частных
путей. Абсолютная home-only гарантия не заявляется; подмена системных файлов
вне threat model. Механизм ещё исследуется: кандидат не обходит диск и не
назначает массовые ACL/SACL/MIC labels.

## Проверки и границы результата

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
