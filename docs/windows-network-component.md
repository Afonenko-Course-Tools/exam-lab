# Экспериментальный сетевой компонент Windows

`windows/ExamNetwork.psm1` использует штатные NetSecurity и локальную GPO.
Он пока не включён в основной `exam`: `FullReady=false`, приёмка файловых
ограничений и общего экзаменационного пути остаётся отдельной.

Настройки находятся только в защищённом `pc.json`, в необязательном `Network`:

```json
{"ProxyEndpointIP":"192.0.2.10","ProxyEndpointPort":3128,"TechnicalAccess":[]}
```

Администратор задаёт реальный IPv4 сервера proxy и порт. `TechnicalAccess` —
явный массив технических входящих TCP-разрешений вида
`{"RemoteIP":"192.0.2.20","LocalPort":5985}`. Пустой массив не разрешает удалённое
управление. Адреса PL/Moodle и HTTPS Host-политика принадлежат конфигурации
серверного proxy и в Windows не дублируются.

Компонент поставляется существующим установщиком в `%ProgramFiles%\ExamLab`.
Единственный `pc.json` и `network-owned.json` находятся в защищённом
`%ProgramData%\ExamLab`. Ownership содержит только Schema, RunId,
ComputerIdentity и SHA256 конфигурации; предыдущие настройки Windows не сохраняются.
Изменение конфигурации при существующем intent запрещает продолжение/удаление.

Экспорты: чистая проверка `Test-ExamNetworkConfig`; чтение
`Get-ExamNetworkStatus -Config ... -ConfigRevision ...`; изменение
`Invoke-ExamNetworkUnderLock -Action Apply|Normal` с теми же аргументами и живым
`-OperationLock`. Главный диспетчер заранее открывает общий `operation.lock`
с `FileShare.None`, проверяет все компоненты и вызывает их последовательно.
Компонент не открывает повторный lock. Чтение ничего не создаёт.
`State=NotConfigured` означает отсутствие собственного ограничения;
`Applied` — полный собственный GPO-набор, `Applying` — частичный, `Conflict` —
изменённые/неопознанные собственные данные. `NormalAllowed` и `Blockers`
относятся к снятию; `ApplyAllowed` не заменяет полную проверку Apply.

Apply пока допускается только в отдельной неподключённой к домену QEMU/KVM
Windows client 19041+ с маркером `ExamLab-TestVM`, проверкой отсутствия
MDM/enrollment, работающими BFE/MpsSvc и одним заранее настроенным
Manual/Preferred IPv4. Статический адрес, gateway и аварийный локальный
административный вход готовят отдельно; компонент адаптер не исправляет.
Перед отключением merge в ActiveStore проверяются собственные технические
входящие правила. Для удалённой пробы обязательно явно разрешить свой WinRM
peer и иметь локальный административный Normal без сервера.

Собственный набор: Domain/Private/Public `Enabled=True`,
`DefaultInboundAction=Block`, `DefaultOutboundAction=Block`,
`AllowInboundRules=True`, `AllowLocalFirewallRules=False`,
`AllowLocalIPsecRules=False`; один выходящий TCP allow к proxy и по одному
входящему allow на TechnicalAccess; LocalAddress у правил равен Any,
чтобы локальный Normal не зависел от сохранения адреса/линка. Удалённый адрес
и порт всегда точные. В именах правил используется
`ExamLab.Network.*`; все фильтры проверяются перед удалением. Неописанная
локальная GPO до Apply вызывает отказ, даже если значения совпали.
Normal возвращает только эти шесть полей в `NotConfigured`, удаляет только
свои неизменённые правила и затем intent. PersistentStore не изменяется.
Конфигурация без Network и без intent допускает Normal no-op также на DHCP.

Частный canary на Windows10 подтвердил первый Apply/Normal: новые IPv4/IPv6
сокеты к запрещённому endpoint блокировались, два непрерывных старых сокета
прерывались, добавленный локальный PersistentStore Allow не обходил no-merge;
после Normal связь восстановилась. Независимо проверены сохранность выбранных
исходных правил/профилей PersistentStore и двух обычных файлов. Во втором
Apply штатный batch Set-NetFirewallProfile частично изменил профили и вернул
AccessDenied; повторяемость и публичная интеграция пока не приняты.
AppContainer, обычные пользовательские приложения, browser trust/routing,
полный HTTPS-клиентский путь и новый Guest не объявляются проверенными этим
компонентом. Чужой новый Allow при no-merge проверялся отдельно от HTTPS policy.
