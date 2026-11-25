$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows/applocker/Invoke-ExamLabAppLockerPilot.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors -join "`n") }
$logic = 'Test-EmptyPolicy', 'Get-PolicySignature', 'New-AuditPolicy', 'Test-PolicyPair', 'Get-ClearDisposition', 'Test-SameGuest'
foreach ($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    if ($function.Name -in $logic) { . ([scriptblock]::Create($function.Extent.Text)) }
}
$guest = [pscustomobject]@{
    Sid = 'S-1-5-21-1-2-3-1001'; SessionId = 4; Revision = 8; BootUtc = '2026-11-25T04:30:00Z'; GuestSessionId = 'guest-one'
}
$intent = [pscustomobject]@{
    ProbeId = [guid]'ceded501-9d0e-411f-baa4-854b9152b9b2'; Guest = $guest
    AllowRuleId = [guid]'36fafe2a-ebbb-40af-8233-337efdf0be19'; DenyRuleId = [guid]'434cd190-c912-4431-95bc-ebca8955ffe2'
}
$path = 'C:\Program Files\Test & Pilot\AppLockerCanary.exe'
$policy = New-AuditPolicy $intent $path
$expected = Get-PolicySignature $policy.DocumentElement
$collection = $policy.SelectSingleNode('/AppLockerPolicy/RuleCollection')
$deny = $collection.SelectSingleNode('FilePathRule[@Action="Deny"]')
$allow = $collection.SelectSingleNode('FilePathRule[@Action="Allow"]')
if ($collection.GetAttribute('Type') -cne 'Exe' -or $collection.GetAttribute('EnforcementMode') -cne 'AuditOnly' -or
    $collection.SelectNodes('*').Count -ne 2 -or $deny.GetAttribute('UserOrGroupSid') -cne $guest.Sid -or
    $deny.SelectSingleNode('Conditions/FilePathCondition').GetAttribute('Path') -cne $path -or
    $allow.GetAttribute('UserOrGroupSid') -cne 'S-1-1-0' -or
    $allow.SelectSingleNode('Conditions/FilePathCondition').GetAttribute('Path') -cne '*') { throw 'Границы правил изменились.' }

$reordered = [xml]$policy.OuterXml
$reorderedCollection = $reordered.SelectSingleNode('/AppLockerPolicy/RuleCollection')
$reorderedDeny = $reorderedCollection.SelectSingleNode('FilePathRule[@Action="Deny"]')
[void]$reorderedCollection.PrependChild($reorderedDeny)
$reorderedDeny.SetAttribute('Id', $intent.DenyRuleId.ToString('B').ToUpperInvariant())
$reorderedDeny.SelectSingleNode('Conditions/FilePathCondition').SetAttribute('Path', $path.ToUpperInvariant())
if (-not (Test-PolicyPair @{ Local = $reordered; Effective = $policy } $expected)) { throw 'Семантически одинаковые правила отклонены.' }

$foreign = [xml]$policy.OuterXml
$foreign.SelectSingleNode('//FilePathRule[@Action="Deny"]').SetAttribute('UserOrGroupSid', 'S-1-1-0')
if (Test-PolicyPair @{ Local = $policy; Effective = $foreign } $expected) { throw 'Смена SID пропущена.' }
$foreign = [xml]$policy.OuterXml
$foreign.SelectSingleNode('//RuleCollection').SetAttribute('EnforcementMode', 'Enabled')
if (Test-PolicyPair @{ Local = $foreign; Effective = $policy } $expected) { throw 'Смена режима пропущена.' }
$foreign = [xml]$policy.OuterXml
$foreign.SelectSingleNode('//FilePathRule[@Action="Deny"]/Conditions/FilePathCondition').SetAttribute('Path', '*')
if (Test-PolicyPair @{ Local = $foreign; Effective = $foreign } $expected) { throw 'Расширение пути пропущено.' }

$empty = [xml]'<AppLockerPolicy Version="1" />'
$default = [xml]'<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
if (-not (Test-PolicyPair @{ Local = $empty; Effective = $default } '') -or
    (Test-PolicyPair @{ Local = $empty; Effective = $policy } '') -or (Test-EmptyPolicy $policy)) { throw 'Неверно определена пустая политика.' }
foreach ($candidate in @(
    '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly" /></AppLockerPolicy>',
    '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" Other="X" /></AppLockerPolicy>',
    '<AppLockerPolicy Version="1"><RuleCollection Type="NewType" EnforcementMode="NotConfigured" /></AppLockerPolicy>',
    '<AppLockerPolicy Version="1"><Unexpected /></AppLockerPolicy>'
)) {
    if (Test-EmptyPolicy ([xml]$candidate)) { throw 'Неизвестная настройка считается пустой.' }
}

$bothEmpty = @{ Local = $empty; Effective = $empty }
$bothOwned = @{ Local = $policy; Effective = $reordered }
$mixed = @{ Local = $empty; Effective = $policy }
if ((Get-ClearDisposition $bothEmpty $expected 'WriteStarted') -cne 'Pending' -or
    (Get-ClearDisposition $bothEmpty $expected 'Prepared') -cne 'Empty' -or
    (Get-ClearDisposition $bothEmpty $expected 'OwnObserved') -cne 'Empty' -or
    (Get-ClearDisposition $bothOwned $expected 'Prepared') -cne 'Conflict' -or
    (Get-ClearDisposition $bothOwned $expected 'WriteStarted') -cne 'Owned' -or
    (Get-ClearDisposition $mixed $expected 'OwnObserved') -cne 'Conflict') { throw 'Нарушена граница адресного восстановления.' }

$fresh = $guest.PSObject.Copy()
if (-not (Test-SameGuest $guest $fresh)) { throw 'Повтор текущего Guest отклонён.' }
foreach ($field in 'Sid','SessionId','Revision','BootUtc','GuestSessionId') {
    $fresh = $guest.PSObject.Copy()
    $fresh.$field = 'changed'
    if (Test-SameGuest $guest $fresh) { throw "Смена $field пропущена." }
}
if (Test-SameGuest $guest $null) { throw 'Принят отсутствующий Guest.' }
'Проверки структуры AppLocker и привязки Guest прошли. Windows API не вызывались.'
