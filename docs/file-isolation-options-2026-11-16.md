# Ограничение чтения файлов: обзор вариантов 16 ноября 2026 года

Это исторический срез поиска 16 ноября. 17 ноября владелец возобновил испытания
и затем выбрал AppContainer как перспективный вариант текущей сессии.
Действующие ограничения и результаты — в [отчёте 17 ноября](execution-2026-11-17.md).
Приведённая ниже остановка и ранжирование относятся к моменту составления обзора.

По последнему поручению владельца новые испытания, установки и запуски VM
остановлены. Выполнен расширенный поиск по документации производителей и
исходникам. Перечисленные ниже новые варианты не испытаны на нашей Windows.
Проприетарные инструменты исключены из выбора: требуется open source либо
небольшой сценарий поверх штатных механизмов Windows. Владелец теперь прямо
допускает рекурсивное изменение ACL для нашего Guest, если обычные занятия
сохраняют работоспособность. Это меняет прежнее ограничение на массовую обработку
ACL, но не разрешает новые эксперименты в этой сессии.

**Рекомендуемое направление при возобновлении — адресный запрет чтения содержимого
файлов для настоящего Guest через NTFS ACL.** Это штатный механизм без нового
драйвера. Второй кандидат — conditional ACE с устойчивой группой исключения
обычных пользователей; он лучше переносит смену Guest SID, но сложнее в настройке.
Готового открытого изолятора, одновременно подтвердившего весь наш учебный путь,
по источникам не найдено. Сохранность обычных занятий пока является условием
приёмки, а не установленным свойством новой ACL-политики.

## Что требуется именно нам

- Существующая Windows x64, установка повышенным администратором, независимость
  от русского языка групп и отображаемых имён каталогов. Эталон — Enterprise
  Evaluation 22H2, 19045.2006; поддержка Windows 10 вообще не доказывает поддержку
  конкретной старой сборки без обновлений.
- Настоящий Shared PC Guest и все его программы, включая отдельно запущенные
  Java, Notepad и Explorer. Проверяется известный полный путь к подсказке;
  скрытие буквы диска и ограничение одного экземпляра IDEA недостаточны.
- Крупные категории: Windows, Program Files и собственный чистый профиль/workspace.
  ProgramData требует отдельного решения по совместимости. Перечни исключений
  для каждого исполняемого файла не заменяют широкое правило.
- Работают файловые диалоги, IDEA/JDK/Git, сохранение, закрытие и повторное открытие
  проекта, компиляция и отладка. Следующий Guest получает согласованную защиту.
- Ordinary сохраняет свои файлы, проекты и устройства; локальный Normal без
  контроллера снимает только наши ограничения. Не применяются снимки ACL,
  полная замена DACL, захват владельца или обратный импорт состояния Windows.

В завершённой пробе Guest был прямым членом Users545, но не Guests546. Это
проверка SAM-членства, не полного токена. Non-Administrators MLGPO также не является
ACL-группой. Нельзя использовать Guests546 без проверки реальной идентичности.
Фактические результаты находятся в [отчёте сессии](execution-2026-11-16.md).

## Сравнение допустимых направлений

| Подход | Что даёт | Основная цена | Вывод для нас |
| --- | --- | --- | --- |
| Точный Guest SID, explicit DENY чтения на существующих файлах | Запрещает содержимое независимо от программы; не адресован ordinary | Обход дерева при каждом новом SID, незавершённые операции, новые файлы | Первый кандидат как самый небольшой сценарий |
| Conditional DENY и стабильная группа исключения ordinary | То же штатное NTFS-решение, условие зависит от токена, а не конкретного Guest SID | Начальная обработка дерева, clean home и управление членством | Второй кандидат, если повторный обход слишком дорог |
| Sandboxie Classic с обычными файловыми правилами | Открытое ядро; отдельные host-пути можно закрывать | Бесплатный порядок правил не даёт просто перекрыть общий запрет разрешёнными категориями; нужен полный охват Guest | Не найдена готовая широкая бесплатная конфигурация |
| AppContainer/MSIX | Изоляция доступа упакованных приложений | Упаковка, capabilities, все дочерние процессы и диалоги | Слишком большое изменение поставки для первого решения |
| Windows Sandbox | Отдельная виртуальная Windows | Установка ПО внутри и перенос результатов | Альтернативная архитектура, не ограничение существующего Guest |
| MIC Low | Ограничение записи; чтение зависит от меток объектов | Для чтения нужна объектная политика NR и проверка совместимости | Само по себе задачу не решает |

## 1. Рекурсивный запрет для точного Guest SID

### Чем отличается от неудачной пробы родительских каталогов

Предыдущий опыт запрещал ListDirectory только у C: и Users. Он не закрывал
содержимое дочерних файлов, мешал повторному открытию IDEA и оставил изменение
ACL metadata. Такой опыт отклонён; он не проверял рекурсивный file-read deny.

Windows проверяет разрешения самого файла. Поэтому предлагаемое широкое правило
направлено на **FILE_READ_DATA у файлов**, с сохранением навигации по каталогам.
Одна и та же маска RD у каталога означает ListDirectory; её нельзя без разбора
назначать всему дереву. Полный R также шире необходимого и содержит стандартные
права, которые могут мешать другим операциям. Работоспособность минимальной маски
ещё предстоит проверить.
[Права файлов и каталогов](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights),
[обозначения icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).

### Минимальная схема, пока без реализации

1. Получить настоящий SID нового Guest и фактический профиль, определить крупные
   области данных вне Windows, Program Files и собственного home. Для русской ОС
   использовать SID и фактические системные пути, а не переведённые строки.
2. Для существующих файлов в этих областях добавить собственный explicit DENY
   чтения только этому SID. Оставить остальных пользователей, owner и соседние
   права без намеренных изменений. Недоступный объект означает неполное покрытие,
   а не основание применять takeown или сбрасывать DACL.
3. Для будущих файлов рассмотреть file-only наследование. По таблице Microsoft
   OBJECT_INHERIT передаёт effective ACE файлам, а каталогам — inherit-only ACE.
   На самом каталоге-носителе нужен OBJECT_INHERIT + INHERIT_ONLY (OI + IO):
   один OI с RD всё ещё запретит listing этого каталога. Поэтому возможен запрет
   содержимого без запрета просмотра каталогов. Размещение и снятие таких правил
   ещё надо проверить на настоящем дереве.
4. Дождаться завершения применения до допуска студента к работе. Normal адресно
   удаляет свои ACE для сохранённого SID, включая остатки после удаления Guest.
   Следующий Guest не должен начинаться поверх незавершённой очистки.

Одного inherited DENY наверху недостаточно: explicit ALLOW дочернего объекта
предшествует inherited DENY; protected DACL может остановить наследование.
Это обосновывает разрешённый теперь рекурсивный проход существующих объектов,
а не объявление корневого правила универсальной защитой.
[Порядок ACE](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl),
[правила наследования](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules).

### Где проходит граница простоты и сохранности ordinary

- Точный Guest SID не совпадает с SID обычного пользователя. Но нельзя заменять
  DACL целиком или запрещать чтение Users545: это затронет ordinary. Сохранность
  прав и metadata проверяется отдельно; прежний AI drift уже показал важность writer.
- `icacls /deny` удаляет совпадающие права из явных разрешений того же SID;
  `/remove:d` удаляет все его deny. Простое добавление/удаление допустимо только
  при проверенном отсутствии прежних конфликтующих ACE и адресной очистке своих
  правил; этими командами нельзя стирать неизвестные права.
  [Контракт icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).
- Hardlinks имеют общий security descriptor. Изменение ACL по пути данных может
  затронуть тот же файл через разрешённый системный путь. Пересечения областей
  требуют отказа или контролируемого scope. Reparse points нельзя обходить вслепую.
  [Hardlink и security descriptor](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinka).
- Один проход не покрывает любой будущий файл: перемещение не создаёт новый
  descriptor, защищённая DACL или явные разрешения могут оставить обход.
  Это практический барьер для подготовленного экзаменационного набора данных,
  а не полная гарантия против изменений дерева во время работы.
  [Создание и перемещение](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
- FAT/exFAT не поддерживают эти ACL. Для флешек остаётся отдельный реальный запрет
  чтения съёмных носителей; скрытие диска его не заменяет.
  [Возможности файловых систем](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison).

Начать с остальных профилей и нескольких крупных категорий данных проще, чем со
всего C:, но это оставляет явные непокрытые места. Широкий вариант должен учитывать
ProgramData, Public и файлы в корне: без проверки нельзя ни закрывать их все,
ни обещать, что все они безопасны для открытия. Системные и программные каталоги,
доступные ordinary для записи, также остаются местом возможных подсказок.

**Главная нерешённая граница — смена SID и момент допуска.** Новый Shared PC Guest
получает новый SID; deny прежнему SID его не защищает. Применение после входа
создаёт окно до завершения обхода, а уже прочитанные данные не отзываются. Время
обхода и очистки зависит от числа объектов и ошибок; оно пока не измерено.
Постоянная экзаменационная учётка или группа упростила бы это, но не является
незаметной заменой согласованного настоящего Shared PC Guest.

## 2. Conditional ACE: ordinary исключён без привязки к Guest SID

Windows умеет оценивать условие ACE по SID в токене. Это возможно без AD claims:
Member_of проверяет SID_AND_ATTRIBUTES. FALSE у DENY означает пропустить именно
эту ACE и не выдаёт ordinary дополнительных разрешений. В документации
Not_Member_of доступен с Windows 8; базовый механизм подходит Windows 10/11.
[Семантика conditional ACE](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-),
[ограничения версий, примечание 87](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/11e1608c-6169-4fbc-9c33-373fc9b224f4).

Кандидат: адресовать DENY проверенной группе Users545, но включать его только при
отсутствии в токене отдельной стабильной группы обычных пользователей; отдельно
исключить нужные admin/service identities. Группа исключения сама по себе файловых
прав не выдаёт. Включённые в неё ordinary сохраняют исходные разрешения; новый
Guest может попадать под то же правило без переписывания всех ACE под новый SID.
Это **проект применения штатного механизма**, не готовая испытанная политика.

Есть готовый открытый writer **NtObjectManager** из sandbox-attacksurface-analysis-tools,
Apache-2.0: Add-NtSecurityDescriptorAce поддерживает DeniedCallback и Condition.
Свой драйвер или evaluator не требуется. Обычный FileSystemAccessRule не выражает
условие; у icacls нет такого параметра.
[Исходник cmdlet](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/852b1586b8c4527f8be3f486801e4830220c76d0/NtObjectManager/Cmdlets/Object/AddNtSecurityDescriptorAceCmdlet.cs),
[лицензия](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/LICENSE.txt).

Остаются существенные вопросы:

- Проверить реальные токены Guest, ordinary, SYSTEM и администраторов. Локальная
  запись SAM не доказывает участие группы при конкретном access check.
- Все ordinary, включая новые учётки, должны получать exemption SID в свежем
  logon token. Удаление/пересоздание этой группы меняет SID и ломает договор.
- Для нескольких исключений Member_of с набором означает членство во всех,
  а отрицание такого набора не означает отсутствие во всех. Нужна точная логика
  отдельных отрицаний; UNKNOWN у DENY может отказать в доступе.
- Условие различает пользователей, но не собственный home Guest и чужие профили.
  Нужны структурная граница нового чистого home, учёт Default Profile, protected
  DACL и будущего наследования. Исходный рекурсивный проход всё ещё может требоваться.
- Снимать нужно точные собственные callback ACE по type/mask/flags/условию.
  Уникальный SID группы внутри условия помогает опознать правило; удаление всех
  deny для Users545 недопустимо. Сохранность metadata writer ещё не доказана.

Этот путь уменьшает повторные обходы при смене Guest, но добавляет настройку групп
и более сложную запись ACL. Он второй по приоритету, если простого точного SID
окажется недостаточно по времени или моменту применения.

## 3. Sandboxie: что открыто и что доступно без сертификата

У Sandboxie открытое GPLv3 ядро; для SandMan действует отдельный LICENSE.Plus
с ограничениями. Нельзя считать всю поставку и все её возможности неограниченным
бесплатным GPL-продуктом. В официальной сборке Privacy Mode, App Compartment
(NoSecurityIsolation) и UseRuleSpecificity требуют сертификат; исходник драйвера
назначает пятиминутное завершение обычных процессов при отсутствии нужной capability.
Ручная запись INI и Classic GUI не устраняют проверку.
[LICENSE.Plus](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/LICENSE.Plus),
[сравнение возможностей](https://sandboxie-plus.com/feature-comparison/),
[условия сертификатов](https://sandboxie-plus.com/supporter-certificate/),
[проверка драйвера](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/process.c#L716-L746).

Обычные WriteFilePath, ReadFilePath и OpenFilePath по metadata 1.18.8 не требуют
сертификат. WriteFilePath скрывает host-содержимое, сохраняя работу с созданными
файлами внутри sandbox; Read разрешает host-чтение, Open — прямую работу с host.
Однако без Rule Specificity приоритет Closed > Write > Read > Open > Normal:
общий Write на все пути не перекрывается более узким Read для Windows/PF и Open
для своего профиля. Поэтому это не подтверждённая бесплатная замена широкому
Privacy default-deny. Отдельные конкретные пути закрыть можно, но их перечень
не удовлетворяет требованию устойчивого широкого правила.
[WriteFilePath](https://sandboxie-plus.github.io/sandboxie-docs/Content/WriteFilePath/),
[порядок правил](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/RuleSpecificity/),
[UseRuleSpecificity](https://sandboxie-plus.github.io/sandboxie-docs/Content/UseRuleSpecificity/),
[metadata параметров](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/install/SbieSettings.ini).

Переменные профиля/имени/SID и принудительный запуск программ документированы.
Но forcing относится к новым запускам и не переносит уже работающий Explorer;
unboxed программа не ограничивается правилами box. Избирательная IDEA не покрывает
произвольный Java/Notepad. Наша отрицательная full-desktop Privacy-проба относится
к конкретной конфигурации; App Compartment + Privacy с полным принудительным
desktop не испытан. С учётом сертификатных ограничений это не выбранный бесплатный
путь. Обход проверок и собственная сборка/подпись драйвера не предлагаются.
[Переменные](https://sandboxie-plus.github.io/sandboxie-docs/Content/ExpandableVariables/),
[forcing](https://sandboxie-plus.github.io/sandboxie-docs/Content/ProgramForcingControls/),
[App Compartment](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/compartment-mode/),
[unboxed в фильтре](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/file_flt.c#L529).

## Остальные встроенные механизмы

| Вариант | Применимость |
| --- | --- |
| Win32 app isolation / appSilo | Текущий минимум Windows 11 24H2/build26100; 19045 не подходит. Упаковка приложений; FullTrust fallback на неподдерживаемой ОС нельзя принимать за изоляцию. |
| Legacy MSIX AppContainer | Manifest route документирован на19041+, но требует упаковки и покрытия всей цепочки процессов. Обычный MSIX/full trust не означает read-deny. |
| Invoke-CommandInDesktopPackage | Cmdlet прямо не создаёт AppContainer, даже если приложение обычно работало бы в нём; PreventBreakaway этого не исправляет. |
| Windows Sandbox | Реальная VM-граница; ПО должно работать внутри, результаты сохраняются до закрытия. Меняет согласованный путь существующей Windows/Shared PC. |
| Assigned Access / kiosk | Ограничение интерфейса и запуска не превращает разрешённую Java в файловый изолятор. |
| Controlled Folder Access | Защита от изменения/удаления, не от чтения. |
| Application Guard / WIAL | Устаревший и удалённый с Windows 11 24H2 путь, не кандидат для устойчивого нового решения. |

Источники:
[Win32 isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-overview),
[release notes](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes),
[legacy manifest](https://learn.microsoft.com/en-us/windows/msix/msix-container),
[cmdlet](https://learn.microsoft.com/en-us/powershell/module/appx/invoke-commandindesktoppackage?view=windowsserver2025-ps),
[Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/),
[Assigned Access](https://learn.microsoft.com/en-us/windows/configuration/assigned-access/overview),
[CFA](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview),
[Application Guard](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview).

MIC остаётся другим объектным механизмом: Low без NoReadUp уже не запретил чтение
в нашей пробе. Массовая SACL/NR-переметка потребовала бы отдельной оценки всех
процессов и меток. Разрешение рекурсивных ACL не делает её доказанно проще DACL.
[Microsoft MIC](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).

## Коммерческие продукты: исследованы и исключены

Эта часть сохраняет результаты поиска, но **не рекомендует покупку или trial**.
Даже подходящий механизм не удовлетворяет последнему условию open source.

| Продукт | Результат проверки документации |
| --- | --- |
| Folder Guard | Наиболее предметный read-deny всех программ; default user подходит неизвестным пользователям. Но динамический собственный home и CLI import не подтверждены; фильтры требуют профессиональной лицензии. |
| FSPro Hide Folders | Lock/Hide & Lock — реальная блокировка; Hide допускает известный путь. CLI есть, системный корень защищать запрещено; scope нового Guest и широкие исключения не подтверждены. Платный продукт. |
| My Lockbox | Блокирует выбранные папки; нужная широкая политика и CLI не заявлены. Бесплатная редакция не означает open source. |
| NewSoftwares Folder Protect | No Access отличается от No Visible; нужная воспроизводимая автоматизация и динамический home не подтверждены. Коммерческая лицензия. |
| BeyondTrust EPM Content Control | Документирует запрет открытия/чтения, но EXE всегда исключены, DLL исключены по умолчанию; корпоративная лицензируемая поставка. |
| Ivanti Application Control | Контроль запуска не подтверждает универсальный запрет чтения данных разрешённой Java. Коммерческая поставка. |
| Fortres101 | Заявляет file/folder/drive block и standalone; точный API read-deny, home и CLI не установлены. Коммерческая поставка. |
| Faronics WINSelect | CLI/шаблон есть, API read-deny не установлен; руководство требует отключать защиту при создании профиля. Коммерческая поставка. |
| Inteset Secure Lockdown | Руководство прямо говорит: No Local Drives не запрещает filesystem access приложений; также требует logged-in administrator. Не подходит целевому Guest. |
| AppGuard Solo | Защищает назначенные приложения/области, не весь Guest автоматически; лицензия и активация. |
| ReHIPS | Актуальные официальные условия и поддержку подтвердить не удалось; не считается выбранным OSS-кандидатом. Это не утверждение о прекращении продукта. |

Первичные источники:
[Folder Guard filters](https://www.winability.com/folderguard/users-guide_filters.htm),
[пользователи](https://www.winability.com/folderguard/users-guide_user-specific-restrictions.htm),
[trusted bypass](https://www.winability.com/folderguard/users-guide_trusted-programs.htm),
[лицензии Folder Guard](https://www.winability.com/folderguard/users-guide_faq.htm),
[Hide Folders](https://fspro.net/hide-folders/faq/),
[методы Hide Folders](https://fspro.net/help/hide-folders/hide_folders_protection_methods.html),
[My Lockbox](https://fspro.net/help/my-lockbox/overview.html),
[Folder Protect](https://www.newsoftwares.net/folder-protect/faq/),
[BeyondTrust Content Groups](https://docs.beyondtrust.com/epm-wm/docs/policy-editor-content-groups),
[Ivanti architecture](https://help.ivanti.com/ap/help/en_US/am/2026/Content/Application_Manager/Product_Architecture.htm),
[Fortres](https://www.fortresgrand.com/products/f101/f101-more.htm),
[WINSelect manual](https://www.faronics.com/assets/WSS_Manual.pdf),
[Inteset manual, стр.14](https://downloads.inteset.com/Inteset%20Secure%20Lockdown%20v2%20User%20Guide%20-%20Multi%20Application%20Edition.pdf),
[AppGuard](https://www.appguard.us/solo-install-instructions/).

## Зафиксированное решение

При возможном возобновлении начать с небольшого адресного NTFS file-read deny,
сравнив охват крупных областей и сохранность ordinary. Если повторное назначение
новому Guest слишком дорого, рассмотреть conditional ACE с готовым OSS writer.
Не объявлять сохранность ordinary, отсутствие окна до Apply, обработку ProgramData
или полное покрытие новых файлов доказанными по одной документации.

Минимальная будущая приёмка: известный путь в Explorer/Notepad/Java действительно
не читается, собственный проект IDEA сохраняется и повторно открывается, Run/debug/Git
работают, обычный вход не теряет файлы/права и после локального Normal удалены только
наши ACE. Нужны также прерывание обхода и следующий настоящий Guest. Это перечень
для будущего разрешённого этапа, а не запускаемые сейчас испытания.

Файловая задача остаётся незакрытой, FullReady=false, основной exam заблокирован.
После поручения остановить попытки выполнены только поиск, документирование
и сохранение результатов в Git; новые эксперименты не выполнялись.
