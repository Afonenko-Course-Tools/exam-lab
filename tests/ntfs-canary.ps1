#requires -Version 7.6
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Apply','NewFiles','Normal')][string]$Action,
    [Parameter(Mandatory)][Guid]$RunId,
    [string]$OrdinaryName,
    [string]$DataRoot,
    [string]$GuestSid,
    [switch]$StopAfterFirst,
    [switch]$OperatorConfirmedGuest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'Запустите 64-битный PowerShell 7.'
}
$timer = [Diagnostics.Stopwatch]::StartNew()
$sidType = [Security.Principal.SecurityIdentifier]
$admins = 'S-1-5-32-544'
$system = 'S-1-5-18'
$users = 'S-1-5-32-545'
$sections = [Security.AccessControl.AccessControlSections]'Owner,Group,Access'
$fsutil = Join-Path ([Environment]::SystemDirectory) 'fsutil.exe'
$tag = 'ExamLab-Ntfs-' + $RunId.ToString('N')
$osRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$stateRoot = Join-Path $programData ($tag + '-state')
$planPath = Join-Path $stateRoot 'plan.json'
$intentPath = Join-Path $stateRoot 'own-rules.json'

function Assert-LocalNtfs([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($Path) -ne $Path) {
        throw "Нужен абсолютный путь на локальном томе: $Path"
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if ($drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -ne 'NTFS') {
        throw "Нужен фиксированный том NTFS: $Path"
    }
    $cursor = $Path
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "В пути reparse point: $cursor" }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function New-Rule($Sid, $Rights, $Inheritance, $Propagation, $Type) {
    [Security.AccessControl.FileSystemAccessRule]::new(
        $sidType::new($Sid), $Rights, $Inheritance, $Propagation, $Type)
}

function New-FixtureAcl([bool]$Directory, [bool]$ReaderAccess) {
    if ($Directory) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = 'ObjectInherit,ContainerInherit'
    } else {
        $security = [Security.AccessControl.FileSecurity]::new()
        $inheritance = 'None'
    }
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system,$admins)) {
        $security.AddAccessRule((New-Rule $sid FullControl $inheritance None Allow))
    }
    if ($ReaderAccess) {
        $security.AddAccessRule((New-Rule $users ReadAndExecute $inheritance None Allow))
    }
    return $security
}

function New-Marker([string]$Path, [bool]$Inherit) {
    if ($Inherit) {
        $stream = [IO.File]::Open($Path, 'CreateNew', 'Write', 'None')
    } else {
        $stream = [IO.FileStream]::new($Path, 'CreateNew', 'Write', 'None', 4096, 'None', (New-FixtureAcl $false $true))
    }
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes("$tag`n$([IO.Path]::GetFileName($Path))`n")
        $stream.Write($bytes,0,$bytes.Length)
    } finally { $stream.Dispose() }
}

function Write-PrivateJson([string]$Path, $Value) {
    $temporary = Join-Path $stateRoot ([Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8))
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    [IO.File]::Move($temporary,$Path)
}

function Get-Security([string]$Path, [bool]$Directory) {
    if ($Directory) { return [IO.Directory]::GetAccessControl($Path,$sections) }
    return [IO.File]::GetAccessControl($Path,$sections)
}

function Get-Metadata([string]$Path, [bool]$Directory) {
    Assert-LocalNtfs $Path
    $item = Get-Item -LiteralPath $Path -Force
    if (($item -is [IO.DirectoryInfo]) -ne $Directory) { throw "Тип объекта изменился: $Path" }
    $query = @(& $fsutil file queryfileid $Path)
    if ($LASTEXITCODE -ne 0 -or ($query -join ' ') -notmatch '(0x[0-9a-f]+)\s*$') {
        throw "Не удалось определить NTFS File ID: $Path"
    }
    $fileId = $Matches[1]
    $hash = $null
    if (-not $Directory) {
        $links = @(& $fsutil hardlink list $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($LASTEXITCODE -ne 0 -or $links.Count -ne 1) { throw "Нужна единственная жёсткая ссылка: $Path" }
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
    $acl = Get-Security $Path $Directory
    if (-not $acl.AreAccessRulesCanonical) { throw "Неожиданный порядок ACE: $Path" }
    [pscustomobject]@{Path=$Path; Directory=$Directory; Id=$fileId; Hash=$hash; Sddl=$acl.GetSecurityDescriptorSddlForm($sections)}
}

function Assert-Identity($Item, $Current) {
    if ($Current.Id -ne $Item.Id -or $Current.Hash -ne $Item.Hash) {
        throw "Объект заменён или содержимое изменилось: $($Item.Path)"
    }
}

function Get-GuestRules($Acl, [string]$Sid) {
    $Acl.GetAccessRules($true,$true,$sidType) | Where-Object { $_.IdentityReference.Value -eq $Sid }
}

function Get-OwnRule($Item, [string]$Sid) {
    if ($Item.Directory) { return (New-Rule $Sid ReadData ObjectInherit InheritOnly Deny) }
    return (New-Rule $Sid ReadData None None Deny)
}

function Test-OwnRule($Candidate, $Expected) {
    return (-not $Candidate.IsInherited -and $Candidate.AccessControlType -eq 'Deny' -and
        [int]$Candidate.FileSystemRights -eq [int]$Expected.FileSystemRights -and
        $Candidate.InheritanceFlags -eq $Expected.InheritanceFlags -and
        $Candidate.PropagationFlags -eq $Expected.PropagationFlags)
}

function Set-FixtureSecurity($Item, $Acl) {
    if ($Item.Directory) { [IO.Directory]::SetAccessControl($Item.Path,$Acl) }
    else { [IO.File]::SetAccessControl($Item.Path,$Acl) }
}

function Initialize-FixtureAcl([string]$Path, [bool]$Directory) {
    # Вызов только на новых синтетических объектах до фиксации исходного состояния.
    $inheritance = 'None'
    if ($Directory) { $inheritance = 'ObjectInherit,ContainerInherit' }
    $acl = Get-Security $Path $Directory
    $acl.SetAccessRule((New-Rule $users ReadAndExecute $inheritance None Allow))
    Set-FixtureSecurity ([pscustomobject]@{Path=$Path; Directory=$Directory}) $acl
    $persisted = Get-Security $Path $Directory
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($persisted.GetSecurityDescriptorSddlForm($sections))
    if (-not $persisted.AreAccessRulesProtected -or
        -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)) {
        throw "Windows не подтвердила исходные флаги DACL нового объекта: $Path"
    }
}

function Write-Result([string]$Result, $Detail) {
    [pscustomobject]@{RunId=$RunId; Action=$Action; Result=$Result; Utc=[DateTime]::UtcNow.ToString('o');
        ElapsedMs=$timer.ElapsedMilliseconds; Detail=$Detail} | ConvertTo-Json -Depth 8
}

if ($Action -eq 'Prepare') {
    if (-not $OrdinaryName) { throw 'Prepare требует имя обычной учётки стенда.' }
    $local = @(Get-LocalUser)
    $ordinary = @($local | Where-Object { $_.Name -eq $OrdinaryName })
    if ($ordinary.Count -ne 1) { throw 'Обычная локальная учётка стенда не найдена.' }
    $ordinarySid = $ordinary[0].SID.Value
    $profile = @(Get-CimInstance Win32_UserProfile -Filter "SID='$ordinarySid'")
    if ($profile.Count -ne 1 -or $profile[0].Special -or $profile[0].Loaded) {
        throw 'Нужен существующий обычный профиль, из которого вышли.'
    }
    $parents = [ordered]@{OrdinaryProfile=$profile[0].LocalPath;
        PublicProfile=$env:PUBLIC; ProgramData=$programData}
    if ($DataRoot) {
        if ($DataRoot -notmatch '^[A-Za-z]:\\$' -or $DataRoot -eq $osRoot) { throw 'Укажите корень отдельного виртуального диска данных.' }
        $parents.DataVolume = $DataRoot
    }
    $folders = [ordered]@{}
    foreach ($key in $parents.Keys) {
        Assert-LocalNtfs $parents[$key]
        $folders[$key] = Join-Path $parents[$key] $tag
    }
    $rootMarker = Join-Path $osRoot ($tag + '.txt')
    Assert-LocalNtfs $osRoot
    foreach ($path in @($folders.Values) + @($stateRoot,$rootMarker)) {
        if (Test-Path -LiteralPath $path) { throw "Путь пробы уже занят: $path" }
    }
    [void][IO.FileSystemAclExtensions]::CreateDirectory((New-FixtureAcl $true $false), $stateRoot)
    $existing = [ordered]@{SystemRoot=$rootMarker}
    $future = [ordered]@{}
    New-Marker $rootMarker $false
    Initialize-FixtureAcl $rootMarker $false
    foreach ($key in $folders.Keys) {
        $path = $folders[$key]
        [void][IO.FileSystemAclExtensions]::CreateDirectory((New-FixtureAcl $true $true), $path)
        Initialize-FixtureAcl $path $true
        $existing[$key] = Join-Path $path 'existing.txt'
        New-Marker $existing[$key] $false
        Initialize-FixtureAcl $existing[$key] $false
        $future[$key] = Join-Path $path 'new.txt'
    }
    $items = @($existing.Values | ForEach-Object { Get-Metadata $_ $false }) +
        @($folders.Values | ForEach-Object { Get-Metadata $_ $true })
    $plan = [pscustomobject]@{RunId=$RunId; LocalSids=@($local | ForEach-Object { $_.SID.Value });
        Existing=$existing; Future=$future; Items=$items}
    Write-PrivateJson $planPath $plan
    Write-Result 'Prepared' @{Existing=$existing; Future=$future; Parents=$parents;
        DataVolume=([bool]$DataRoot); AutoInheritedFixtureCount=$items.Count}
    return
}

Assert-LocalNtfs $planPath
$stateAcl = Get-Security $stateRoot $true
$caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner = $stateAcl.GetOwner($sidType).Value
if ($owner -notin @($admins,$system,$caller) -or -not $stateAcl.AreAccessRulesProtected -or
    @($stateAcl.GetAccessRules($true,$true,$sidType) | Where-Object { $_.IdentityReference.Value -notin @($admins,$system) }).Count) {
    throw 'Каталог состояния пробы доступен посторонней учётке.'
}
$plan = [IO.File]::ReadAllText($planPath) | ConvertFrom-Json
if ([Guid]$plan.RunId -ne $RunId) { throw 'План относится к другому запуску.' }

if ($Action -eq 'Apply') {
    if (-not $OperatorConfirmedGuest -or $GuestSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
        throw 'Для Apply нужен проверенный SID настоящего Guest и подтверждение оператора.'
    }
    if (Test-Path -LiteralPath $intentPath) { throw 'Перед повторным Apply выполните Normal.' }
    $newAccounts = @(Get-LocalUser | Where-Object { $_.SID.Value -notin @($plan.LocalSids) })
    $guestProfile = @(Get-CimInstance Win32_UserProfile -Filter "SID='$GuestSid'")
    if ($newAccounts.Count -ne 1 -or $newAccounts[0].SID.Value -ne $GuestSid -or -not $newAccounts[0].Enabled -or
        $guestProfile.Count -ne 1 -or $guestProfile[0].Special -or -not $guestProfile[0].Loaded) {
        throw 'Указанный SID не совпал с единственной новой локальной учёткой с загруженным профилем.'
    }
    Assert-LocalNtfs $guestProfile[0].LocalPath
    foreach ($item in $plan.Items) {
        $current = Get-Metadata $item.Path $item.Directory
        Assert-Identity $item $current
        if ($current.Sddl -cne $item.Sddl -or
            @(Get-GuestRules (Get-Security $item.Path $item.Directory) $GuestSid).Count) {
            throw "Стороннее изменение ACL или ACE текущего Guest: $($item.Path)"
        }
    }
    Write-PrivateJson $intentPath ([pscustomobject]@{RunId=$RunId; Sid=$GuestSid})
    $changed = 0
    foreach ($item in $plan.Items) {
        $acl = Get-Security $item.Path $item.Directory
        $acl.AddAccessRule((Get-OwnRule $item $GuestSid))
        Set-FixtureSecurity $item $acl
        $changed++
        if ($StopAfterFirst) { throw "Контрольное прерывание после $changed ACE. Выполните Normal." }
    }
    foreach ($item in $plan.Items) {
        $expected = Get-OwnRule $item $GuestSid
        $rules = @(Get-GuestRules (Get-Security $item.Path $item.Directory) $GuestSid |
            Where-Object { Test-OwnRule $_ $expected })
        if ($rules.Count -ne 1) { throw "Явный ACE не подтверждён: $($item.Path)" }
    }
    Write-Result 'Applied' @{Changed=$changed; GuestSid=$GuestSid; Profile=$guestProfile[0].LocalPath}
    return
}

if ($Action -eq 'NewFiles') {
    Assert-LocalNtfs $intentPath
    $intent = [IO.File]::ReadAllText($intentPath) | ConvertFrom-Json
    if ([Guid]$intent.RunId -ne $RunId) { throw 'Чужая запись применения.' }
    foreach ($item in $plan.Items) {
        Assert-Identity $item (Get-Metadata $item.Path $item.Directory)
        $expected = Get-OwnRule $item $intent.Sid
        if (@(Get-GuestRules (Get-Security $item.Path $item.Directory) $intent.Sid |
            Where-Object { Test-OwnRule $_ $expected }).Count -ne 1) { throw "Применение неполное: $($item.Path)" }
    }
    foreach ($property in $plan.Future.PSObject.Properties) { New-Marker $property.Value $true }
    Write-Result 'Created' $plan.Future
    return
}

$hasIntent = Test-Path -LiteralPath $intentPath
$removed = 0
if ($hasIntent) {
    Assert-LocalNtfs $intentPath
    $intent = [IO.File]::ReadAllText($intentPath) | ConvertFrom-Json
    if ([Guid]$intent.RunId -ne $RunId -or $intent.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or
        $intent.Sid -in @($plan.LocalSids)) { throw 'Чужая запись применения.' }
    foreach ($item in @($plan.Items | Sort-Object -Property Directory -Descending)) {
        Assert-Identity $item (Get-Metadata $item.Path $item.Directory)
        $acl = Get-Security $item.Path $item.Directory
        $expected = Get-OwnRule $item $intent.Sid
        $rules = @(Get-GuestRules $acl $intent.Sid | Where-Object { -not $_.IsInherited })
        if ($rules.Count -gt 1 -or ($rules.Count -eq 1 -and -not (Test-OwnRule $rules[0] $expected))) {
            throw "Неизвестный ACE Guest сохранён: $($item.Path)"
        }
        if ($rules.Count -eq 1) {
            $acl.RemoveAccessRuleSpecific($expected)
            Set-FixtureSecurity $item $acl
            $removed++
        }
    }
    foreach ($property in $plan.Future.PSObject.Properties) {
        if (Test-Path -LiteralPath $property.Value) {
            Assert-LocalNtfs $property.Value
            if (@(Get-GuestRules (Get-Security $property.Value $false) $intent.Sid).Count) {
                throw "Остался ACE на новом файле: $($property.Value)"
            }
        }
    }
}
foreach ($item in $plan.Items) {
    $current = Get-Metadata $item.Path $item.Directory
    Assert-Identity $item $current
    if ($current.Sddl -cne $item.Sddl) { throw "ACL отличается от исходной: $($item.Path)" }
}
if ($hasIntent) { [IO.File]::Delete($intentPath) }
Write-Result 'Normal' @{Removed=$removed; Checked=@($plan.Items).Count}
