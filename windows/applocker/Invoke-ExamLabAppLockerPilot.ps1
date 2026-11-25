#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Audit','Status','Normal')][string]$Action,
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [switch]$EnableVmAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-EmptyPolicy([xml]$Policy) {
    $root = $Policy.DocumentElement
    if ($root.LocalName -cne 'AppLockerPolicy' -or $root.NamespaceURI -ne '' -or
        $root.Attributes.Count -ne 1 -or $root.GetAttribute('Version') -cne '1') { return $false }
    $types = @()
    foreach ($node in $root.ChildNodes) {
        if ($node.NodeType -eq [Xml.XmlNodeType]::Whitespace) { continue }
        if ($node -isnot [Xml.XmlElement] -or $node.LocalName -cne 'RuleCollection' -or $node.NamespaceURI -ne '' -or
            $node.Attributes.Count -ne 2 -or $node.GetAttribute('Type') -cnotin @('Exe','Dll','Msi','Script','Appx') -or
            $node.GetAttribute('Type') -in $types -or $node.GetAttribute('EnforcementMode') -cne 'NotConfigured' -or
            @($node.ChildNodes | Where-Object NodeType -NE ([Xml.XmlNodeType]::Whitespace)).Count) { return $false }
        $types += $node.GetAttribute('Type')
    }
    return $true
}

function Get-PolicySignature([Xml.XmlElement]$Node) {
    $attributes = @(foreach ($attribute in $Node.Attributes | Sort-Object Name) {
        $value = switch ($attribute.Name) {
            'Id' { ([Guid]$attribute.Value).ToString('D') }
            'Path' { $attribute.Value.ToUpperInvariant() }
            default { $attribute.Value }
        }
        '{0}={1}' -f $attribute.Name, $value
    })
    $children = @(foreach ($child in $Node.SelectNodes('./*')) { Get-PolicySignature $child })
    [ordered]@{
        Name = $Node.Name; Namespace = $Node.NamespaceURI; Attributes = $attributes
        Text = @($Node.SelectNodes('./text()') | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } |
            ForEach-Object { $_.Value })
        Children = @($children | Sort-Object -CaseSensitive)
    } | ConvertTo-Json -Compress -Depth 4
}

function New-AuditPolicy($Intent, [string]$CanaryPath) {
    $tag = 'ExamLab-AppLocker-' + ([Guid]$Intent.ProbeId).ToString('N')
    $path = [Security.SecurityElement]::Escape($CanaryPath)
    [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="$($Intent.AllowRuleId)" Name="$tag Allow" Description="Разрешение запуска для испытания" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="$($Intent.DenyRuleId)" Name="$tag Canary" Description="Контрольный образ текущего Guest" UserOrGroupSid="$($Intent.Guest.Sid)" Action="Deny">
      <Conditions><FilePathCondition Path="$path" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
}

function Read-Policies {
    [ordered]@{ Local = [xml](Get-AppLockerPolicy -Local -Xml); Effective = [xml](Get-AppLockerPolicy -Effective -Xml) }
}

function Test-PolicyPair($Policies, [string]$Signature) {
    if (-not $Signature) { return ((Test-EmptyPolicy $Policies.Local) -and (Test-EmptyPolicy $Policies.Effective)) }
    return ((Get-PolicySignature $Policies.Local.DocumentElement) -ceq $Signature -and
        (Get-PolicySignature $Policies.Effective.DocumentElement) -ceq $Signature)
}

function Get-ClearDisposition($Policies, [string]$Signature, [string]$Phase) {
    if (Test-PolicyPair $Policies '') {
        if ($Phase -ceq 'WriteStarted') { return 'Pending' }
        return 'Empty'
    }
    if ($Phase -cne 'Prepared' -and (Test-PolicyPair $Policies $Signature)) { return 'Owned' }
    return 'Conflict'
}

function Wait-PolicyPair([string]$Signature) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $observed = Read-Policies
        if (Test-PolicyPair $observed $Signature) { return }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 12)
    throw 'За 12 секунд Local и Effective не подтвердили ожидаемую политику. Повторите чтение.'
}

function Assert-ProtectedPath([string]$Path, [switch]$Directory, [switch]$Readable) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        ($Directory -and $item -isnot [IO.DirectoryInfo]) -or (-not $Directory -and $item -isnot [IO.FileInfo])) {
        throw "Тип или путь защищённого объекта изменился: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [Security.Principal.SecurityIdentifier]
    if ($acl.GetOwner($sidType).Value -notin $trustedSids -or ($Directory -and -not $Readable -and -not $acl.AreAccessRulesProtected)) {
        throw "Владелец или наследование защищённого объекта изменились: $Path"
    }
    $mutation = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,$sidType)) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trustedSids -or
            ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly))) { continue }
        if (-not $Readable -or ($rule.FileSystemRights -band $mutation)) { throw "Небезопасный доступ к защищённому объекту: $Path" }
    }
}

function Assert-StandalonePolicyContext {
    $machine = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 8
    if ($machine.PartOfDomain -or $machine.Manufacturer -ne 'QEMU') { throw 'Пилот разрешён на отдельной VM QEMU вне домена.' }
    $registration = @(& (Join-Path ([Environment]::SystemDirectory) 'dsregcmd.exe') /status)
    if ($LASTEXITCODE -ne 0 -or -not ($registration -match '^\s*AzureAdJoined\s*:\s*NO\s*$') -or
        -not ($registration -match '^\s*EnterpriseJoined\s*:\s*NO\s*$')) { throw 'Не подтверждено отсутствие внешней регистрации устройства.' }
    $omadm = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    if ((Test-Path -LiteralPath $omadm) -and @(Get-ChildItem -LiteralPath $omadm).Count) { throw 'Обнаружены учётные записи MDM.' }
    if (@(Get-ScheduledTask | Where-Object { $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*' -and $_.State -ne 'Disabled' }).Count) {
        throw 'Обнаружена включённая задача EnterpriseMgmt.'
    }
    $namespace = 'root\cimv2\mdm\dmmap'
    $classes = @(Get-CimClass -Namespace $namespace -ClassName 'MDM_AppLocker*' -OperationTimeoutSec 8 |
        Where-Object { 'Policy' -in $_.CimClassProperties.Name })
    if (-not $classes.Count) { throw 'Источник MDM AppLocker недоступен.' }
    foreach ($class in $classes) {
        if (@(Get-CimInstance -Namespace $namespace -ClassName $class.CimClassName -OperationTimeoutSec 5 |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Policy) }).Count) { throw 'Обнаружена политика AppLocker CSP.' }
    }
}

function Read-GuestBinding {
    $pwsh = Join-Path $programFiles 'PowerShell\7\pwsh.exe'
    $command = @'
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab\ExamLab.psm1') -Scope Local
$guest = Get-ExamLabControllerGuestBinding
if ($guest) {
    $guest | Select-Object @{n='Sid';e={$_.GuestSid}},SessionId,Revision,BootUtc,GuestSessionId | ConvertTo-Json -Compress
}
'@
    $reply = @(& $pwsh -NoLogo -NoProfile -NonInteractive -Command $command)
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать действующий Guest.' }
    if ($reply.Count) { ($reply -join [Environment]::NewLine) | ConvertFrom-Json }
}

function Test-SameGuest($First, $Second) {
    return ($null -ne $First -and $null -ne $Second -and $First.Sid -ceq $Second.Sid -and
        $First.SessionId -eq $Second.SessionId -and $First.Revision -eq $Second.Revision -and
        $First.BootUtc -ceq $Second.BootUtc -and $First.GuestSessionId -ceq $Second.GuestSessionId)
}

function Read-AppIdService {
    Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -OperationTimeoutSec 8
}

function Read-AppLockerEvents([int]$Id, [datetime]$Since, [int]$Limit) {
    $filter = @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = $Id }
    if ($Since -gt [datetime]::MinValue) { $filter.StartTime = $Since }
    try { Get-WinEvent -FilterHashtable $filter -MaxEvents $Limit }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw } }
}

function Find-OwnAllow([datetime]$Since, [Guid]$RuleId) {
    foreach ($event in @(Read-AppLockerEvents 8002 $Since 512)) {
        $rule = ([xml]$event.ToXml()).SelectSingleNode('//*[local-name()="RuleId"]')
        $value = [Guid]::Empty
        if ($rule -and [Guid]::TryParse($rule.InnerText,[ref]$value) -and $value -eq $RuleId) { return $event }
    }
}

function Save-Intent([string]$Path, $Intent, [switch]$Replace) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Intent | ConvertTo-Json -Compress -Depth 4))
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ($Replace) {
            Assert-ProtectedPath $Path
            [IO.File]::Replace($temporary, $Path, [NullString]::Value)
        } else { [IO.File]::Move($temporary, $Path) }
    } finally { [IO.File]::Delete($temporary) }
}

function Read-Intent([string]$Path) {
    Assert-ProtectedPath $Path
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Read-Phase([string]$Path, [Guid]$ProbeId) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'Prepared' }
    $current = Read-Intent $Path
    if (([Guid]$current.ProbeId) -ne $ProbeId -or $current.Phase -cnotin @('WriteStarted','OwnObserved')) {
        throw 'Фаза записи неизвестна или относится к другой пробе AppLocker.'
    }
    return $current.Phase
}

function Save-Phase([string]$Path, [Guid]$ProbeId, [string]$Phase) {
    Save-Intent $Path ([ordered]@{ ProbeId = $ProbeId; Phase = $Phase; Utc = [DateTimeOffset]::UtcNow.ToString('o') }) `
        -Replace:($Phase -ceq 'OwnObserved')
}

function Get-PolicyStatus($Intent, [string]$Signature, [string]$Phase) {
    $service = Read-AppIdService
    $current = Read-Policies
    $matches = Test-PolicyPair $current $Signature
    $ready = $false
    $applied = $null
    $allowed = $null
    if ($Phase -cne 'Prepared' -and $matches -and $service.State -ceq 'Running' -and $service.StartMode -ceq 'Manual' -and
        (Test-SameGuest $Intent.Guest (Read-GuestBinding))) {
        $since = ([DateTimeOffset]$Intent.Utc).UtcDateTime
        $applied = Read-AppLockerEvents 8001 $since 32 | Where-Object { $_.RecordId -gt [long]$Intent.ApplyBaseline } |
            Sort-Object RecordId | Select-Object -First 1
        if ($applied) { $allowed = Find-OwnAllow $applied.TimeCreated ([Guid]$Intent.AllowRuleId) }
        $ready = $null -ne $allowed
    }
    $appliedRecordId = $null
    $allowedRecordId = $null
    if ($applied) { $appliedRecordId = $applied.RecordId }
    if ($allowed) { $allowedRecordId = $allowed.RecordId }
    [pscustomobject]@{
        ProbeId = $Intent.ProbeId; AuditOnly = $true; PolicyMatches = $matches; Loaded = $ready
        PolicyEmpty = (Test-PolicyPair $current ''); Phase = $Phase
        AppIdState = $service.State; AppIdStartMode = $service.StartMode
        AppliedRecordId = $appliedRecordId; AllowedRecordId = $allowedRecordId
        Utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess -or
    $env:COMPUTERNAME -ne $ExpectedComputerName -or -not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    throw 'Используйте 64-битный Windows PowerShell от SYSTEM на согласованной испытательной машине.'
}
if ($Action -eq 'Audit' -and -not $EnableVmAudit) { throw 'Для Audit нужно явное -EnableVmAudit на VM.' }
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$private = Join-Path $programFiles 'ExamLabAlert\Private'
if ($PSScriptRoot -ne $private) { throw 'Запустите проверенный сценарий из установленного ExamLabAlert Private.' }
$trustedSids = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') +
    @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
foreach ($directory in $programFiles, (Split-Path -Parent $private)) {
    Assert-ProtectedPath $directory -Directory -Readable
}
Assert-ProtectedPath $private -Directory
Assert-ProtectedPath $PSCommandPath
$intentPath = Join-Path $private 'app-locker-pilot-intent.json'
$phasePath = Join-Path $private 'app-locker-pilot-phase.json'
$lockPath = Join-Path $private 'app-locker-pilot.lock'
$lockExists = Test-Path -LiteralPath $lockPath
if ($Action -ne 'Audit' -and -not $lockExists) {
    if ((Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $phasePath)) { throw 'Отсутствует блокировка действующей пробы.' }
    [pscustomobject]@{ OwnedPolicy = $false; Loaded = $false }
    return
}
if ($lockExists) { Assert-ProtectedPath $lockPath }
$lockMode = if ($Action -eq 'Audit') { 'OpenOrCreate' } else { 'Open' }
$lockAccess = if ($Action -eq 'Status') { 'Read' } else { 'ReadWrite' }
$lock = [IO.File]::Open($lockPath, $lockMode, $lockAccess, 'None')
try {
    $intent = $null
    if (Test-Path -LiteralPath $intentPath) {
        $intent = Read-Intent $intentPath
        if ($intent.Version -ne 1 -or $intent.ComputerName -ne $ExpectedComputerName -or
            ([Guid]$intent.ProbeId) -eq [Guid]::Empty -or ([Guid]$intent.AllowRuleId) -eq [Guid]::Empty -or
            ([Guid]$intent.DenyRuleId) -eq [Guid]::Empty -or $intent.AllowRuleId -eq $intent.DenyRuleId -or
            $intent.Guest.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $intent.CanaryHash -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Намерение AppLocker не соответствует этой машине или формату.'
        }
    }
    if ($Action -eq 'Audit' -and $intent) { throw 'Сначала прочитайте Status или завершите текущую пробу действием Normal.' }
    if ($Action -ne 'Audit' -and -not $intent) {
        if (Test-Path -LiteralPath $phasePath) { throw 'Осталась фаза записи без намерения AppLocker.' }
        [pscustomobject]@{ OwnedPolicy = $false; Loaded = $false }
        return
    }

    $fixture = Join-Path $programFiles 'ExamLab-AppLockerCanary'
    $canary = Join-Path $fixture 'AppLockerCanary.exe'
    Assert-StandalonePolicyContext
    if ($Action -eq 'Audit') {
        if (-not (Test-PolicyPair (Read-Policies) '') -or (Test-Path -LiteralPath $phasePath)) {
            throw 'AppLocker уже настроен либо сохранилась неизвестная фаза записи.'
        }
        $guest = Read-GuestBinding
        if (-not $guest -or $guest.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $guest.SessionId -le 0) {
            throw 'Нужен подтверждённый текущий Guest действующего экзамена.'
        }
        $service = Read-AppIdService
        if ($service.StartMode -cne 'Manual' -or $service.State -cne 'Running') { throw 'Подготовьте AppIDSvc Running/Manual отдельным штатным шагом.' }
        $sourceExe = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
        Assert-ProtectedPath $fixture -Directory -Readable
        Assert-ProtectedPath $canary -Readable
        $canaryHash = (Get-FileHash -LiteralPath $canary -Algorithm SHA256).Hash
        if ($canaryHash -cne (Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash) { throw 'Контрольный образ отличается от System32 cmd.exe.' }
        $baseline = Read-AppLockerEvents 8001 ([datetime]::MinValue) 1 | Select-Object -First 1
        $baselineRecordId = 0
        if ($baseline) { $baselineRecordId = $baseline.RecordId }
        $intent = [pscustomobject]@{
            Version = 1; ComputerName = $env:COMPUTERNAME; ProbeId = [Guid]::NewGuid(); Guest = $guest
            AllowRuleId = [Guid]::NewGuid(); DenyRuleId = [Guid]::NewGuid(); CanaryHash = $canaryHash
            ApplyBaseline = $baselineRecordId; Utc = [DateTimeOffset]::UtcNow.ToString('o')
        }
    }

    $tag = 'ExamLab-AppLocker-' + ([Guid]$intent.ProbeId).ToString('N')
    $auditFile = Join-Path $private "$tag-audit.xml"
    $clearFile = Join-Path $private "$tag-clear.xml"
    $policy = New-AuditPolicy $intent $canary
    $signature = Get-PolicySignature $policy.DocumentElement
    $phase = Read-Phase $phasePath ([Guid]$intent.ProbeId)

    if ($Action -eq 'Status') {
        Get-PolicyStatus $intent $signature $phase
        return
    }
    if ($Action -eq 'Audit') {
        foreach ($path in $auditFile, $clearFile) {
            if (Test-Path -LiteralPath $path) { throw "Путь уже занят: $path" }
        }
        Save-Intent $intentPath $intent
        $policy.Save($auditFile)
        foreach ($path in $canary, $sourceExe) {
            $decision = @(Test-AppLockerPolicy -XmlPolicy $auditFile -Path $path -User $intent.Guest.Sid)
            $expected = if ($path -eq $canary) { 'Denied' } else { 'Allowed' }
            if ($decision.Count -ne 1 -or [string]$decision[0].PolicyDecision -cne $expected) { throw "Неожиданное предсказание для $path." }
        }
        # Нативное чтение может обновляться с задержкой, однако чужой GPO исключается перед единственной записью.
        Assert-StandalonePolicyContext
        Assert-ProtectedPath $fixture -Directory -Readable
        Assert-ProtectedPath $canary -Readable
        $service = Read-AppIdService
        if (-not (Test-SameGuest $intent.Guest (Read-GuestBinding)) -or -not (Test-PolicyPair (Read-Policies) '') -or
            $service.StartMode -cne 'Manual' -or $service.State -cne 'Running' -or
            (Get-FileHash -LiteralPath $canary -Algorithm SHA256).Hash -cne $intent.CanaryHash) {
            throw 'Изменились Guest, политика, AppIDSvc или контрольный образ.'
        }
        Save-Phase $phasePath ([Guid]$intent.ProbeId) 'WriteStarted'
        Set-AppLockerPolicy -XmlPolicy $auditFile
        Wait-PolicyPair $signature
        Save-Phase $phasePath ([Guid]$intent.ProbeId) 'OwnObserved'
        Get-PolicyStatus $intent $signature 'OwnObserved'
        return
    }

    $disposition = Get-ClearDisposition (Read-Policies) $signature $phase
    if ($disposition -ceq 'Pending') {
        # Set мог начаться до прерывания процесса. Исходное чтение ещё не решает, что произошло.
        Wait-PolicyPair $signature
        $disposition = Get-ClearDisposition (Read-Policies) $signature $phase
    }
    if ($disposition -ceq 'Conflict') { throw 'Обнаружена чужая или частичная политика AppLocker. Снятие остановлено.' }
    if ($disposition -ceq 'Pending') { throw 'Исход начатой записи неизвестен. Намерение сохранено для Status и повторной проверки.' }
    if ($disposition -ceq 'Owned') {
        if ($phase -ceq 'WriteStarted') {
            Save-Phase $phasePath ([Guid]$intent.ProbeId) 'OwnObserved'
        }
        $emptyXml = '<AppLockerPolicy Version="1" />'
        if (Test-Path -LiteralPath $clearFile) {
            Assert-ProtectedPath $clearFile
            if ([IO.File]::ReadAllText($clearFile) -cne $emptyXml) { throw 'Изменился файл адресного снятия.' }
        } else { [IO.File]::WriteAllText($clearFile, $emptyXml) }
        Assert-StandalonePolicyContext
        if (-not (Test-PolicyPair (Read-Policies) $signature)) { throw 'Политика AppLocker изменилась перед снятием.' }
        Set-AppLockerPolicy -XmlPolicy $clearFile
    }
    Wait-PolicyPair ''
    $service = Read-AppIdService
    foreach ($path in $auditFile, $clearFile, $phasePath, $intentPath) {
        if (Test-Path -LiteralPath $path) {
            Assert-ProtectedPath $path
            [IO.File]::Delete($path)
        }
    }
    [pscustomobject]@{
        ProbeId = $intent.ProbeId; LocalEmpty = $true; EffectiveEmpty = $true
        AppIdState = $service.State; AppIdStartMode = $service.StartMode; Utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
} finally { $lock.Dispose() }
