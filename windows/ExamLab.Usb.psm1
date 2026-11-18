#requires -Version 5.1
# Штатная Non-Administrators MLGPO: только свой Deny_Read, без снимков Windows.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$code=Join-Path $env:ProgramFiles 'ExamLab'
$data=Join-Path $env:ProgramData 'ExamLab'
$configPath=Join-Path $data 'pc.json'
$metaPath=Join-Path $data 'usb.json'
$operationPath=Join-Path $data 'operation.lock'
$usb='Software\Policies\Microsoft\Windows\RemovableStorageDevices'
$disk=$usb+'\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
$target=Join-Path $env:SystemRoot 'System32\GroupPolicyUsers\S-1-5-32-545\User\registry.pol'
$gpt=Join-Path $env:SystemRoot 'System32\GroupPolicyUsers\S-1-5-32-545\gpt.ini'
$lgpo=Join-Path $code 'LGPO.exe'
$loadedHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash

function Get-UsbItemIfPresent([string]$Path) {
    try { return Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [Management.Automation.ItemNotFoundException] { return $null }
}

function Test-UsbHiveRoot([string]$Name) { return $Name -ine '.DEFAULT' -and $Name -notlike '*_Classes' }

function Assert-SafeFilePath([string]$Path,[switch]$Readable) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $Path" }
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:trusted) { throw "Foreign owner: $Path" }
    foreach ($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -in $script:trusted) { continue }
        if ($r.IdentityReference.Value -eq 'S-1-3-0' -and ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $writes=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        # Code/GPO may be readable; metadata remains private. Never repair ACL.
        if (-not $Readable -or ($r.FileSystemRights -band $writes)) { throw "Foreign access: $Path" }
    }
}

function Get-PolFiles([string]$Path) {
    $item=Get-UsbItemIfPresent $Path
    if (-not $item) { return }
    if (-not $item.PSIsContainer) { throw "GPO directory expected: $Path" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "GPO reparse point: $Path" }
    Assert-SafeFilePath $Path -Readable
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "GPO reparse point: $($child.FullName)" }
        if ($child.PSIsContainer) { Get-PolFiles $child.FullName }
        elseif ($child.Name -ieq 'registry.pol') { Assert-SafeFilePath $child.FullName -Readable; $child.FullName }
        elseif ($child.Name -ieq 'gpt.ini') { Assert-SafeFilePath $child.FullName -Readable }
    }
}

function Test-UsbKey([string]$Key) { return $Key -ieq $usb -or $Key.StartsWith($usb+'\',[StringComparison]::OrdinalIgnoreCase) }

function Test-UsbSourceEntry($Entry) {
    if (Test-UsbKey $Entry.Key) { return $true }
    # An ancestor **DeleteKeys / **SecureKey may affect this subtree too.
    $ancestor=$Entry.Key.TrimEnd('\')
    return $Entry.ValueName.StartsWith('**') -and ([string]::IsNullOrEmpty($ancestor) -or
        $usb.StartsWith($ancestor+'\',[StringComparison]::OrdinalIgnoreCase))
}

function Test-OwnValue($Entry) {
    return $Entry.Key -ieq $disk -and $Entry.ValueName -ieq 'Deny_Read' -and $Entry.Type -eq 'DWord' -and $Entry.Data -eq 1
}

function Test-OwnedSource([string]$File,$Entry,$Own) {
    return $File -ieq $target -and $Own -and $Own.State -ne 'Normal' -and (Test-OwnValue $Entry)
}

function Get-EffectiveEntries($Root,[string]$Scope,[string]$Key=$usb) {
    $node=$Root.OpenSubKey($Key)
    if (-not $node) { return }
    try {
        foreach ($name in $node.GetValueNames()) {
            [pscustomobject]@{Scope=$Scope;Key=$Key;ValueName=$name;Type=$node.GetValueKind($name).ToString();Data=$node.GetValue($name)}
        }
        foreach ($name in $node.GetSubKeyNames()) { Get-EffectiveEntries $Root $Scope ($Key+'\'+$name) }
    } finally { $node.Dispose() }
}

function Read-UsbContext([string]$ConfigRevision) {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or
        -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Нужен Windows PowerShell 5.1 x64.' }
    $principal=New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Нужен повышенный административный токен.' }
    if ((Get-UsbItemIfPresent (Join-Path $data 'state.json'))) { throw 'Обнаружен state.json прежнего прототипа; миграция не выполняется.' }
    $os=Get-CimInstance Win32_OperatingSystem
    if ([int]$os.BuildNumber -lt 19041 -or [int]$os.ProductType -ne 1 -or (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Этот компонент требует standalone Windows client build19041+.' }
    if ($PSScriptRoot -ine $code -or (Get-FileHash -LiteralPath (Join-Path $code 'ExamLab.Usb.psm1')).Hash -cne $loadedHash) { throw 'Код не установлен или изменился после загрузки; запустите новый процесс.' }
    $script:trusted=@('S-1-5-18','S-1-5-32-544')+@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
    Assert-SafeFilePath $code -Readable; Assert-SafeFilePath $data
    Assert-SafeFilePath (Join-Path $code 'ExamLab.Usb.psm1') -Readable
    Assert-SafeFilePath $configPath
    $revision=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    if ($ConfigRevision -and $ConfigRevision -ine $revision) { throw 'Переданная revision не совпадает с текущей pc.json.' }
    Assert-SafeFilePath $lgpo -Readable
    if ((Get-FileHash -LiteralPath $lgpo).Hash -ne '0C97F29543418B30340C4FF5D930D31E6196DD59C2CC74B6B890FA7B90C910C7') { throw 'Неизвестный LGPO.exe.' }
    $signature=Get-AuthenticodeSignature -LiteralPath $lgpo
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Подпись LGPO Microsoft не подтверждена.' }
    $pfe=Join-Path $code 'PolicyFileEditor\3.0.1'
    foreach ($p in @((Join-Path $code 'PolicyFileEditor'),$pfe)) { Assert-SafeFilePath $p -Readable }
    $pins=@{
        'PolicyFileEditor.psd1'='E26456E3775665423051038358C25934DBE907B2DDCE99CF558C5D708C4A3CE1'
        'PolicyFileEditor.psm1'='2BFD389A380D40500D76A9E9C0F8238E093727A748A6702297DE4520767AA732'
        'Commands.ps1'='CA04433F2AAF20D8D7F3962337F075A3DE599FAFEB7D66B5A0AF1BFAF80D44B9'
        'Common.ps1'='31E69AD6F0C70883829FA376D9041026757E3819A426453FEF14B5DAC48D3D44'
        'PolFileEditor.dll'='F4A33DEEBC499AE70E479BA75B6161CAE9E1626D852AF7A40B96C7D69207E607'
        'LICENSE'='A8AD31B1C3F40DCA5A84119351B8FA8DDC868EDD77FAD8A8EBF6D8F2D16FA4AE'
    }
    foreach ($name in $pins.Keys) {
        $path=Join-Path $pfe $name; Assert-SafeFilePath $path -Readable
        if ((Get-FileHash -LiteralPath $path).Hash -ne $pins[$name]) { throw "Изменён файл PFE: $name" }
    }
    Import-Module (Join-Path $pfe 'PolicyFileEditor.psd1') -RequiredVersion 3.0.1 -Force -ErrorAction Stop
    return $revision
}

function Read-UsbMetadata {
    if (-not (Get-UsbItemIfPresent $metaPath)) { return $null }
    Assert-SafeFilePath $metaPath
    $m=[IO.File]::ReadAllText($metaPath) | ConvertFrom-Json
    if (@($m.PSObject.Properties.Name).Count -ne 3 -or
        $m.PSObject.Properties.Name -notcontains 'Schema' -or ($m.Schema -isnot [int] -and $m.Schema -isnot [long]) -or $m.Schema -ne 1 -or
        $m.PSObject.Properties.Name -notcontains 'ConfigRevision' -or $m.ConfigRevision -isnot [string] -or $m.ConfigRevision -notmatch '^[0-9A-Fa-f]{64}$' -or
        $m.PSObject.Properties.Name -notcontains 'State' -or $m.State -isnot [string] -or $m.State -notin @('Applying','Applied','Removing','Normal')) { throw 'Неизвестная USB metadata.' }
    return $m
}

function Write-UsbMetadata([string]$State,[string]$Revision) {
    $tmp=Join-Path $data ('usb-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    try {
        @{Schema=1;ConfigRevision=$Revision;State=$State} | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $metaPath -Force
    } finally { if (Get-UsbItemIfPresent $tmp) { Remove-Item -LiteralPath $tmp } }
}

function Get-ExamLabUsbStatus {
    [CmdletBinding()]
    param([ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ConfigRevision)
    $revision=Read-UsbContext $ConfigRevision
    $m=Read-UsbMetadata; $own=@(); $conflicts=@()
    foreach ($folder in @('GroupPolicy','GroupPolicyUsers')) {
        foreach ($file in @(Get-PolFiles (Join-Path $env:SystemRoot ('System32\'+$folder)))) {
            foreach ($e in @(PolicyFileEditor\Get-PolicyFileEntry -Path $file -All -ErrorAction Stop)) {
                if (-not (Test-UsbSourceEntry $e)) { continue }
                if (Test-OwnedSource $file $e $m) { $own+=$e }
                else { $conflicts+="Чужая USB source: $file : $($e.Key) : $($e.ValueName)" }
            }
        }
    }
    if ($own.Count -gt 1 -or ($m -and $m.State -eq 'Applied' -and $own.Count -ne 1)) { $conflicts+='Собственная USB source изменена.' }
    $effective=@(Get-EffectiveEntries ([Microsoft.Win32.Registry]::LocalMachine) 'HKLM')
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()) {
        if (-not (Test-UsbHiveRoot $sid)) { continue }
        $root=[Microsoft.Win32.Registry]::Users.OpenSubKey($sid)
        try { $effective+=@(Get-EffectiveEntries $root ('HKU\'+$sid)) } finally { $root.Dispose() }
    }
    foreach ($e in $effective) {
        if ($e.Scope -match '^HKU\\(S-\d+(?:-\d+)+)$' -and $Matches[1] -notin ($script:trusted+@('S-1-5-19','S-1-5-20')) -and $m -and (Test-OwnValue $e)) { continue }
        $conflicts+="Чужая effective USB policy: $($e.Scope) : $($e.Key) : $($e.ValueName)"
    }
    $state=if ($m) {$m.State} else {'NotConfigured'}
    $normalNoOp=$state -in @('Normal','NotConfigured') -and $own.Count -eq 0
    $revisionMatches=-not $m -or $m.ConfigRevision -ieq $revision
    $examNoOp=$state -eq 'Applied' -and $own.Count -eq 1 -and $revisionMatches
    $loaded=@(Get-CimInstance Win32_UserProfile | Where-Object {$_.Loaded -and -not $_.Special -and $_.SID -notin $script:trusted})
    $normalBlockers=@($conflicts);$examBlockers=@($conflicts)
    if ($loaded.Count) {
        if (-not $normalNoOp) { $normalBlockers+='Выйдите из nonadmin профилей перед изменением USB policy.' }
        if (-not $examNoOp) { $examBlockers+='Выйдите из nonadmin профилей перед изменением USB policy.' }
    }
    if ($m -and $state -ne 'Normal' -and -not $revisionMatches) { $examBlockers+='Активная USB intent относится к другой pc.json; сначала снимите собственное ограничение.' }
    if ($state -eq 'Removing') { $examBlockers+='Завершите normal перед новым применением.' }
    [pscustomobject]@{
        State=$state; SourcePath=$target; Scope='NonAdministrators'; OwnSourceEntries=$own.Count
        KnownOwnSource=if ($own.Count -eq 1) {[pscustomobject]@{Path=$target;Key=$disk;ValueName='Deny_Read';Type='DWord';Data=1}} else {$null}
        Conflicts=$conflicts; NormalAllowed=($normalBlockers.Count -eq 0); NormalBlockers=$normalBlockers
        ExamAllowed=($examBlockers.Count -eq 0); ExamBlockers=$examBlockers
        NormalNoOp=$normalNoOp; SourceNormal=($normalNoOp -and $conflicts.Count -eq 0); ExamNoOp=$examNoOp; ConfigRevision=$revision
        StoredConfigRevision=if ($m) {$m.ConfigRevision} else {$null}; MetadataRevisionMatches=$revisionMatches
        EffectiveEntries=$effective; EffectiveScope='MachineAndLoadedHivesOnly'; UnloadedHivesInspected=$false
        RequiresUserSignIn=$false; EffectiveReadbackPending=$true; FullReady=$false
    }
}

function Invoke-ExamLabUsbModeUnderLock {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ValidateSet('exam','normal')][string]$Mode,
          [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ConfigRevision,
          [Parameter(Mandatory=$true)][IO.FileStream]$OperationLock)
    # Trusted dispatcher owns FileShare.None; a live stream is not a general proof
    # of how somebody else opened the handle. Never acquire another lock here.
    if (-not $OperationLock.CanRead -or -not $OperationLock.CanWrite -or $OperationLock.Name -ine $operationPath) { throw 'Нужен живой общий operation.lock от вызывающего dispatcher.' }
    $status=Get-ExamLabUsbStatus -ConfigRevision $ConfigRevision
    $allowed=if ($Mode -eq 'normal') {$status.NormalAllowed} else {$status.ExamAllowed}
    $blockers=if ($Mode -eq 'normal') {$status.NormalBlockers} else {$status.ExamBlockers}
    if (-not $allowed) { throw ($blockers -join '; ') }
    $noop=if ($Mode -eq 'normal') {$status.NormalNoOp} else {$status.ExamNoOp}
    if ($noop) { $status | Add-Member -NotePropertyName Changed -NotePropertyValue $false; return $status }
    $revision=if ($Mode -eq 'normal') {$status.StoredConfigRevision} else {$status.ConfigRevision}
    if ($Mode -eq 'exam') {
        Write-UsbMetadata 'Applying' $revision
        $inputPath=Join-Path $data ('usb-input-'+[Guid]::NewGuid().ToString('N')+'.txt')
        try {
            @('User:Non-Administrators',$disk,'Deny_Read','DWORD:1') | Set-Content -LiteralPath $inputPath -Encoding Unicode
            $old=$ErrorActionPreference
            try { $ErrorActionPreference='Continue';$output=& $lgpo /t $inputPath 2>&1;$exitCode=$LASTEXITCODE }
            finally { $ErrorActionPreference=$old }
            if ($exitCode -ne 0) { throw "LGPO: код $exitCode : $($output|Out-String)" }
        } finally { if (Get-UsbItemIfPresent $inputPath) { Remove-Item -LiteralPath $inputPath } }
        $after=Get-ExamLabUsbStatus -ConfigRevision $ConfigRevision
        if ($after.Conflicts.Count -or $after.OwnSourceEntries -ne 1) { throw 'Точная собственная USB source после применения не подтверждена.' }
        Write-UsbMetadata 'Applied' $revision
    } else {
        Write-UsbMetadata 'Removing' $revision
        if ($status.OwnSourceEntries -eq 1) {
            PolicyFileEditor\Remove-PolicyFileEntry -Path $target -Key $disk -ValueName 'Deny_Read' -ErrorAction Stop
        } elseif (Get-UsbItemIfPresent $target) {
            PolicyFileEditor\Update-GptIniVersion -Path $gpt -PolicyType User -ErrorAction Stop
        }
        $after=Get-ExamLabUsbStatus -ConfigRevision $ConfigRevision
        if ($after.Conflicts.Count -or $after.OwnSourceEntries -ne 0) { throw 'Собственная USB source не снята.' }
        Write-UsbMetadata 'Normal' $revision
    }
    $result=Get-ExamLabUsbStatus -ConfigRevision $ConfigRevision
    $result.RequiresUserSignIn=$true
    $result | Add-Member -NotePropertyName Changed -NotePropertyValue $true
    return $result
}

function Set-ExamLabUsbMode {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ValidateSet('exam','normal')][string]$Mode)
    $revision=Read-UsbContext
    if (Get-UsbItemIfPresent $operationPath) { Assert-SafeFilePath $operationPath }
    $operation=[IO.File]::Open($operationPath,'OpenOrCreate','ReadWrite','None')
    try {
        # Refresh after waiting; never use a previously observed context as proof.
        $revision=Read-UsbContext
        Invoke-ExamLabUsbModeUnderLock -Mode $Mode -ConfigRevision $revision -OperationLock $operation
    } finally { $operation.Dispose() }
}
Export-ModuleMember -Function Get-ExamLabUsbStatus,Set-ExamLabUsbMode,Invoke-ExamLabUsbModeUnderLock
