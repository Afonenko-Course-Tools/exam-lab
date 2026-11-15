#requires -Version 5.1
<#
.SYNOPSIS
Устанавливает защищённые файлы и фиксированные SYSTEM-задачи локального пилота.
.DESCRIPTION
Пока допускается только отмеченная одноразовая QEMU/KVM VM. Действия модуля не запускаются.
LGPO.exe передаётся отдельно из официального Microsoft Security Compliance Toolkit.
#>
[CmdletBinding()]
param(
    [string]$SourceDirectory,
    [Parameter(Mandatory)][string]$LGPOPath,
    [Parameter(Mandatory)][string]$ConfigurationPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$lock = $null
$deliveryPending = $false
$sources = [Collections.Generic.List[object]]::new()
$actions = @('prepare','check','exam','normal')
$legacyActions = @('enable','finish')
$result = [ordered]@{ Installed=$false; ActionsExecuted=$false; PolicyActivationRequested=$false; Files=@(); Tasks=@() }

function Assert-NoLegacyState([string]$Path) {
    if (Test-Path -LiteralPath (Join-Path $Path 'state.json')) {
        throw 'Обнаружен legacy state.json: новая установка запрещена. Сохраните старые код и данные для отдельного разбора; новый normal не завершает старый цикл'
    }
}

function Get-ConfigurationHash([string]$Path) {
    $inputFile = [IO.File]::Open($Path,'Open','Read','Read')
    $sources.Add($inputFile)
    $hash = (Get-FileHash -InputStream $inputFile -Algorithm SHA256).Hash
    $inputFile.Position = 0
    $reader = [IO.StreamReader]::new($inputFile,[Text.Encoding]::UTF8,$true,4096,$true)
    try { $configuration = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    if ($configuration -isnot [pscustomobject] -or @($configuration.PSObject.Properties).Count -ne 1 -or
        $configuration.PSObject.Properties.Name -notcontains 'OrdinaryAccounts' -or
        $configuration.OrdinaryAccounts -isnot [array] -or $configuration.OrdinaryAccounts.Count -eq 0) {
        throw 'pc.json должен содержать только непустой массив OrdinaryAccounts'
    }
    $sids = @{}; $names = @{}
    foreach ($account in $configuration.OrdinaryAccounts) {
        if ($account -isnot [pscustomobject] -or @($account.PSObject.Properties).Count -ne 2 -or
            $account.PSObject.Properties.Name -notcontains 'Sid' -or $account.PSObject.Properties.Name -notcontains 'Name' -or
            $account.Sid -isnot [string] -or $account.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or
            $account.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($account.Name) -or $account.Name.Trim() -cne $account.Name -or
            $account.Name -match '[\\/\x00-\x1f]') {
            throw 'Каждый OrdinaryAccounts должен содержать только явные Sid и Name локального пользователя'
        }
        if ($sids.ContainsKey($account.Sid) -or $names.ContainsKey($account.Name)) { throw 'Повторяющиеся Sid/Name в OrdinaryAccounts недопустимы' }
        $sids[$account.Sid] = $true; $names[$account.Name] = $true
    }
    $hash
}

function Assert-ConfigurationRevision([string]$Path, [string]$Hash) {
    $modePath = Join-Path $Path 'mode.json'
    if (Test-Path -LiteralPath $modePath) {
        $mode = Get-Content -LiteralPath $modePath -Raw | ConvertFrom-Json
        if (-not $mode -or $mode.PSObject.Properties.Name -notcontains 'Revision' -or
            $mode.Revision -isnot [string] -or $mode.Revision -notmatch '^[0-9a-fA-F]{64}$' -or $mode.Revision -ne $Hash) {
            throw 'mode.json относится к другой или неизвестной конфигурации: смена roster требует отдельной административной подготовки'
        }
        $installed = Join-Path $Path 'pc.json'
        if ((Test-Path -LiteralPath $installed) -and (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $Hash) {
            throw 'Прежний pc.json не совпадает с mode.json: roster не заменяется установщиком'
        }
    }
}

function Assert-SafeDirectory([string]$Path, [switch]$Readable) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit','None','Allow')))
        }
        if ($Readable) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    $trusted = @('S-1-5-18','S-1-5-32-544') + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $mutation = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point недопустим: $($item.FullName)" }
        $acl = Get-Acl -LiteralPath $item.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "Недоверенный владелец: $($item.FullName)" }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            if ($rule.IdentityReference.Value -in $trusted) { continue }
            if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            if (-not $Readable -or ($rule.FileSystemRights -band $mutation)) { throw "Небезопасный прежний ACL: $($item.FullName)" }
        }
    }
}

function Copy-Source([string]$From, [string]$To, [string]$ExpectedHash) {
    $inputFile = [IO.File]::Open($From,'Open','Read','Read')
    $sources.Add($inputFile)
    $hash = (Get-FileHash -InputStream $inputFile -Algorithm SHA256).Hash
    if ($ExpectedHash -and $hash -ne $ExpectedHash) { throw "Не совпадает ожидаемый SHA256 перед записью $To" }
    $changed = -not (Test-Path -LiteralPath $To) -or (Get-FileHash -LiteralPath $To -Algorithm SHA256).Hash -ne $hash
    if ($changed) {
        $inputFile.Position = 0
        $outputFile = [IO.File]::Open($To,'Create','Write','None')
        try { $inputFile.CopyTo($outputFile) } finally { $outputFile.Dispose() }
    }
    if ((Get-FileHash -LiteralPath $To -Algorithm SHA256).Hash -ne $hash) { throw "Не совпадает копия $To" }
    [pscustomobject]@{ Name=[IO.Path]::GetFileName($To); SHA256=$hash; Changed=$changed }
}

try {
    if (-not $SourceDirectory) { $SourceDirectory = Join-Path $PSScriptRoot '..\windows' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Нужен повышенный административный UAC token'
    }
    if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Нужен native64 Windows PowerShell5.1' }
    $code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab'
    $state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
    # Старый активный цикл отказывается до создания каталогов/lock и изменения задач.
    Assert-NoLegacyState $state
    $machine = Get-CimInstance Win32_ComputerSystem
    $marker = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab-TestVM'
    if (($machine.Manufacturer+' '+$machine.Model) -notmatch 'QEMU|KVM|Red Hat' -or -not (Test-Path -LiteralPath $marker -PathType Leaf) -or $machine.PartOfDomain) {
        throw 'Экспериментальный пилот устанавливается только в отмеченную standalone QEMU/KVM копию. Маркер этим скриптом не создаётся'
    }
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $configurationHash = Get-ConfigurationHash $ConfigurationPath
    foreach ($name in @('ExamLab.psm1','exam-lab.ps1')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $SourceDirectory $name))
        if ($bytes.Length -lt 3 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191) { throw "$name должен иметь UTF-8 BOM для PS5.1" }
    }
    $lgpoLock = [IO.File]::Open($LGPOPath,'Open','Read','Read')
    $sources.Add($lgpoLock)
    if ((Get-FileHash -InputStream $lgpoLock -Algorithm SHA256).Hash -ne '0c97f29543418b30340c4ff5d930d31e6196dd59c2cc74b6b890fa7b90c910c7') { throw 'Не совпадает SHA256 LGPO3.0 из проверенного SCT' }
    $signature = Get-AuthenticodeSignature -LiteralPath $LGPOPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'LGPO.exe должен иметь действительную подпись Microsoft' }
    Assert-SafeDirectory $state
    $lock = [IO.File]::Open((Join-Path $state 'operation.lock'),'OpenOrCreate','ReadWrite','None')
    Assert-NoLegacyState $state
    Assert-ConfigurationRevision $state $configurationHash
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $deliveryPending = $true
    foreach ($action in @($actions + $legacyActions)) {
        $task = Get-ScheduledTask -TaskName ('ExamLab-Local-'+$action) -ErrorAction SilentlyContinue
        if ($task) { Disable-ScheduledTask -TaskName ('ExamLab-Local-'+$action) | Out-Null }
    }
    foreach ($action in @($actions + $legacyActions)) {
        $task = Get-ScheduledTask -TaskName ('ExamLab-Local-'+$action) -ErrorAction SilentlyContinue
        if ($task -and ($task.State -eq 'Running' -or $scheduler.GetFolder('\').GetTask('ExamLab-Local-'+$action).GetInstances(0).Count -gt 0)) {
            throw "Дождитесь завершения ExamLab-Local-$action; задачи оставлены Disabled, повторите установку"
        }
    }
    Assert-SafeDirectory $code -Readable
    $files = @()
    foreach ($name in @('ExamLab.psm1','exam-lab.ps1')) { $files += Copy-Source (Join-Path $SourceDirectory $name) (Join-Path $code $name) }
    $files += Copy-Source $LGPOPath (Join-Path $code 'LGPO.exe') '0c97f29543418b30340c4ff5d930d31e6196dd59c2cc74b6b890fa7b90c910c7'
    $files += Copy-Source $ConfigurationPath (Join-Path $state 'pc.json') $configurationHash
    $result.Files=$files
    $tasks = @()
    foreach ($action in $actions) {
        $wrapper = Join-Path $code ('task-'+$action+'.ps1')
        $log = Join-Path $state ($action+'.log')
        $body = @'
#requires -Version 5.1
$ErrorActionPreference='Stop'
try {
    $global:LASTEXITCODE=0
    & '__ENTRY__' -Action __ACTION__ *> '__LOG__'
    exit $LASTEXITCODE
} catch { $_ | Out-File -LiteralPath '__LOG__' -Encoding UTF8 -Append; exit 1 }
'@
        $body = $body.Replace('__ENTRY__',(Join-Path $code 'exam-lab.ps1').Replace("'","''")).Replace('__ACTION__',$action).Replace('__LOG__',$log.Replace("'","''"))
        [IO.File]::WriteAllText($wrapper,$body,(New-Object Text.UTF8Encoding($true)))
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$wrapper+'"')
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Disable
        $name = 'ExamLab-Local-'+$action
        Register-ScheduledTask -TaskName $name -Action $taskAction -Principal $principal -Settings $settings -Description 'ExamLab: локальный экспериментальный пилот VM' -Force | Out-Null
        $scheduler.GetFolder('\').GetTask($name).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
        $tasks += $name
        $result.Tasks=$tasks
    }
    Assert-SafeDirectory $code -Readable
    Assert-SafeDirectory $state
    foreach ($action in $legacyActions) {
        $name = 'ExamLab-Local-'+$action
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
        $wrapper = Join-Path $code ('task-'+$action+'.ps1')
        if (Test-Path -LiteralPath $wrapper) { Remove-Item -LiteralPath $wrapper }
    }
    # Публикуем задачи только после полной доставки и назначения их приватных SDDL.
    foreach ($name in $tasks) { Enable-ScheduledTask -TaskName $name | Out-Null }
    $deliveryPending = $false
    $result.Files=$files; $result.Tasks=$tasks; $result.Installed=$true
    $result | ConvertTo-Json -Depth 5
} catch {
    $failure = $_
    if ($deliveryPending) {
        foreach ($action in @($actions + $legacyActions)) {
            try { Disable-ScheduledTask -TaskName ('ExamLab-Local-'+$action) -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
    }
    $result.Error=$failure.Exception.Message
    $result | ConvertTo-Json -Depth 5
    Write-Error $failure -ErrorAction Continue
    exit 1
}
finally { if ($lock) { $lock.Dispose() }; foreach ($source in $sources) { $source.Dispose() } }
