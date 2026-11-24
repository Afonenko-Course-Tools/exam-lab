#Requires -Version 7.6
# Проверка договора и порядка записи статуса без вызова Windows API.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '..\windows\alert\ExamLabAlert.ps1'
$tokens = $errors = $null
$scriptAst = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Не удалось разобрать установленный сценарий тревоги.' }
$names = 'ConvertFrom-AlertState','Get-Acknowledgement','Get-AlertUtc','Test-AlertGuestBinding',
    'Get-ControllerAlert','Start-Acknowledgement','Complete-Acknowledgement'
$functions = $scriptAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -cin $names
}, $true)
if ($functions.Count -ne $names.Count) { throw 'Отсутствуют функции договора тревоги.' }
. ([scriptblock]::Create(($functions.Extent.Text -join [Environment]::NewLine)))

$legacy = ConvertFrom-AlertState '{"Phase":"Disarmed","RunId":"old-run","AcknowledgedUtc":null,"LastAcknowledgement":{"RunId":"old-ack"}}'
if ($null -ne (Get-Acknowledgement (ConvertFrom-AlertState $null)) -or $legacy.Revision -or $legacy.SignalIssued -or
    $legacy.SecurityReadRecordId -or (Get-Acknowledgement $legacy).RunId -cne 'old-ack') {
    throw 'Первый запуск или чтение записи предыдущего пилота требуют отсутствующих полей.'
}
$switchNode = $scriptAst.Find({
    param($node)
    $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -ceq '$Action'
}, $true)
$dispatch = [scriptblock]::Create($switchNode.Extent.Text)
foreach ($state in @($null, $legacy)) {
    $Action = 'GetControllerAlert'
    if ($null -ne (& $dispatch)) { throw 'Пустое или прежнее состояние попало в отчёт контроллера.' }
    $Action = 'AcknowledgeRemote'
    $message = $null
    try { & $dispatch } catch { $message = $_.Exception.Message }
    if ($message -cne 'Удалённое подтверждение не совпадает с текущим Guest и тревогой.') {
        throw "Пустое или прежнее состояние не отклонило удалённую команду ожидаемым способом: $message"
    }
}

$binding = [pscustomobject]@{
    Revision=5; BootUtc='2026-11-23T12:00:00.000Z'; GuestSessionId=('a' * 64)
    GuestSid='S-1-5-21-1-2-3-1111'; SessionId=3; AuthenticationId=12345
}
$alert = [pscustomobject]@{
    RunId='e75094e7-5e64-479e-a54a-8fb00b9d2150'; Phase='Pending'; Reason='control-signal'
    Revision=$binding.Revision; BootUtc=$binding.BootUtc; OpaqueGuestSessionId=$binding.GuestSessionId
    GuestSid=$binding.GuestSid; SessionId=$binding.SessionId; AuthenticationId=$binding.AuthenticationId
    ReceivedUtc='2026-11-23T12:02:00.000Z'; ShownUtc=$null
    AcknowledgedUtc=$null; AcknowledgedBy=$null; AcknowledgedBySid=$null; AcknowledgementId=$null
}

if (-not (Test-AlertGuestBinding $alert $binding)) { throw 'Согласованная связка Guest отклонена.' }
foreach ($change in @(@{Name='AuthenticationId';Value=12346}, @{Name='SessionId';Value=4},
    @{Name='GuestSid';Value='S-1-5-21-1-2-3-2222'}, @{Name='Revision';Value=6},
    @{Name='BootUtc';Value='2026-11-23T12:01:00.000Z'}, @{Name='GuestSessionId';Value=('b' * 64)})) {
    $other = $binding.PSObject.Copy()
    $other.($change.Name) = $change.Value
    if (Test-AlertGuestBinding $alert $other) { throw "Смена $($change.Name) не исключила старую тревогу." }
}
$wire = Get-ControllerAlert $alert
if ($wire.phase -cne 'received' -or $wire.reason -cne 'control-signal' -or $wire.guestSessionId -cne $binding.GuestSessionId -or
    $wire.PSObject.Properties['AuthenticationId'] -or $wire.PSObject.Properties['GuestSid']) {
    throw 'Первый отчёт о тревоге не соответствует договору.'
}

$script:committed = @()
$script:screenRunning = $true
function Save-State($Value) { $script:committed += $Value.Phase }
function Update-AlertShown($Value) { $Value.ShownUtc = '2026-11-23T12:02:01.000Z' }
function Remove-AlertScreen($Value) {
    if ($script:screenRunning) { throw 'Экран ещё работает.' }
}
$id = '62b87462-a3cf-4e31-bd68-58eed33085d0'
$blocked = $false
try { Start-Acknowledgement $alert 'owner' $null $id } catch { $blocked = $true }
if (-not $blocked -or $alert.Phase -cne 'Closing' -or $alert.AcknowledgedUtc -or
    -not $alert.AcknowledgementAcceptedUtc -or ($script:committed -join ',') -cne 'Closing') {
    throw 'При неудачной остановке была сохранена итоговая отметка.'
}
$script:screenRunning = $false
Complete-Acknowledgement $alert
$wire = Get-ControllerAlert $alert
if (($script:committed -join ',') -cne 'Closing,Acknowledged' -or $wire.phase -cne 'acknowledged' -or
    $wire.acknowledgementId -cne $id -or $wire.acknowledgedBy -cne 'owner' -or -not $wire.shownUtc -or
    $wire.acknowledgedUtc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$' -or
    $wire.acknowledgedUtc -cne $alert.AcknowledgementAcceptedUtc -or -not $alert.ScreenClosedUtc -or
    $alert.LastAcknowledgement.RunId -cne $alert.RunId) {
    throw 'Снятие не сохранило точную связку и результат обращения владельца.'
}
$expired = $alert.PSObject.Copy()
$expired.Phase = 'Pending'
$blocked = $false
try { Start-Acknowledgement $expired 'owner' $null $id ([DateTimeOffset]::UtcNow.AddSeconds(-1)) }
catch { $blocked = $true }
if (-not $blocked -or $expired.Phase -cne 'Pending') { throw 'Просроченная команда изменила статус тревоги.' }
'PASS: логика договора тревоги и записи подтверждения; Windows API не вызывались.'
