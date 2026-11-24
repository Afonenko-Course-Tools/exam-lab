#requires -Version 7.6
<#
.SYNOPSIS
Устанавливает защищённые файлы и фиксированные SYSTEM-задачи локального пилота.
.DESCRIPTION
Устанавливается на существующую standalone Windows x64. Действия модуля не запускаются.
LGPO.exe передаётся отдельно из официального Microsoft Security Compliance Toolkit.
.PARAMETER UsePublishedInstallers
Внутренний режим локального пилота для пакетов из защищённой HTTPS-поставки.
.PARAMETER HumanOutput
Показывает в консоли путь к полному JSON-отчёту. Требует ReportPath.
#>
[CmdletBinding()]
param(
    [string]$SourceDirectory,
    [Parameter(Mandatory)][string]$LGPOPath,
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$PolicyFileEditorPath,
    [string]$ControllerConfigurationPath,
    [string[]]$TrustedRootCertificatePath = @(),
    [string[]]$TrustedRootSha256 = @(),
    [switch]$EnableLabControllerPolicyProbe,
    [switch]$UsePublishedInstallers,
    [switch]$DeferPolling,
    [string]$ReportPath,
    [switch]$HumanOutput
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if ($HumanOutput -and -not $ReportPath) { throw 'HumanOutput requires ReportPath.' }
$lock = $null
$maintenance = $null
$pollWasEnabled = $false
$backupFiles = @{}
$existingTasks = @{}
$deliveryPending = $false
. (Join-Path $PSScriptRoot 'ExamLabMaintenance.Core.ps1')
$sources = [Collections.Generic.List[object]]::new()
$actions = @('prepare','check','exam','normal')
$codeFiles = @('ExamLab.psm1','exam-lab.ps1','ExamLab.Usb.psm1','ExamNetwork.psm1','ExamLab.Controller.psm1')
$maintenanceFiles = @('ExamLabMaintenance.ps1', 'ExamLabMaintenance.Core.ps1', 'ExamLabRootTrust.ps1')
$pollTask = $examLabPollTask
$roots = @()
$lgpoSha256 = '0c97f29543418b30340c4ff5d930d31e6196dd59c2cc74b6b890fa7b90c910c7'
$pfeFiles = [ordered]@{
    'Commands.ps1'='ca04433f2aaf20d8d7f3962337f075a3de599fafeb7d66b5a0af1bfaf80d44b9'
    'Common.ps1'='31e69ad6f0c70883829fa376d9041026757e3819a426453fef14b5dac48d3d44'
    'DscResources/PshOrg_AccountAdminTemplateSetting/PshOrg_AccountAdminTemplateSetting.psm1'='6a51eee6e948755acc0bf177d1ef7078b4af4733fa0189927793679e7befad12'
    'DscResources/PshOrg_AccountAdminTemplateSetting/PshOrg_AccountAdminTemplateSetting.schema.mof'='f2a085be91bbcf58fa732d43310cbaa08094671abe119f01d1d53f67b02a2331'
    'DscResources/PshOrg_AdminTemplateSetting/PshOrg_AdminTemplateSetting.psm1'='8ee42454f5cdd23e64100611a05be0ac9cccba263a575eba497ba7fa5afe7070'
    'DscResources/PshOrg_AdminTemplateSetting/PshOrg_AdminTemplateSetting.schema.mof'='5e8c0bf82ba7376732aeb16eb0b08648168938faee9ff06ba28a4bcb4f733246'
    'LICENSE'='a8ad31b1c3f40dca5a84119351b8fa8ddc868edd77fad8a8ebf6d8f2d16fa4ae'
    'PolFileEditor.dll'='f4a33deebc499ae70e479ba75b6161cae9e1626d852af7a40b96c7d69207e607'
    'PolicyFileEditor.nuspec'='3e7e48b99238e2b977d4f3238ca99ba7bc497c53fb6e9296f2030720e24cb44d'
    'PolicyFileEditor.psd1'='e26456e3775665423051038358c25934dbe907b2ddce99cf558c5d708c4a3ce1'
    'PolicyFileEditor.psm1'='2bfd389a380d40500d76a9e9c0f8238e093727a748a6702297de4520767aa732'
    '[Content_Types].xml'='11b90ba057800c489a70a86167d7608f87b0b5d14a92343ba4f4c34781f73b96'
    '_rels/.rels'='f612e870f6795ba005e45f93dc77d03013911dfb64d3ce47b3fc0733e6d2587c'
    'en-US/about_RegistryValuesForAdminTemplates.Help.txt'='06f286bfa5d2dd9b16ad24c8dee8245948dd3f0b3033b65a5dcfacd851a83b5b'
    'package/services/metadata/core-properties/445e8411c5804e3690b6e21eed01e358.psmdcp'='ad5ce893115e275622393531920d6e484d7ae3f2fa53af92765c9246a21e1d00'
}
$result = [ordered]@{ Installed=$false; ActionsExecuted=$false; PolicyActivationRequested=$false; Files=@(); Tasks=@(); TrustedRoots=@(); LabControllerPolicyProbe=$false }

function Assert-NativeAMD64 {
    # Тот же native API, что в Prepare-ExamLab; x64-эмуляция на ARM64 не подходит.
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    $product = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
    if ($build -lt 19041 -or $product.ProductType -ne 'WinNT') { throw 'Нужен Windows client build19041 или новее.' }
    if (-not ('ExamLabNativePlatform' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ExamLabNativePlatform {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
}
'@
    }
    [UInt16]$processMachine = 0; [UInt16]$nativeMachine = 0
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        try { $detected = [ExamLabNativePlatform]::IsWow64Process2($currentProcess.Handle,[ref]$processMachine,[ref]$nativeMachine) }
        catch { throw 'Не удалось определить native architecture Windows через IsWow64Process2.' }
        if (-not $detected) { throw ('IsWow64Process2 не определил native architecture; Win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        if ($nativeMachine -ne 0x8664) { throw ('Нужна native AMD64 Windows; NativeMachine=0x{0:X4}' -f $nativeMachine) }
    } finally { $currentProcess.Dispose() }
}

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
    try { $configuration = $reader.ReadToEnd() | ConvertFrom-Json -DateKind String } finally { $reader.Dispose() }
    if ($configuration -isnot [pscustomobject] -or @($configuration.PSObject.Properties.Name | Where-Object {$_ -notin @('OrdinaryAccounts','Network')}).Count -or
        $configuration.PSObject.Properties.Name -notcontains 'OrdinaryAccounts' -or
        $configuration.OrdinaryAccounts -isnot [array] -or $configuration.OrdinaryAccounts.Count -eq 0) {
        throw 'pc.json: непустой OrdinaryAccounts и необязательный Network'
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
    if ($configuration.PSObject.Properties.Name -contains 'Network') {
        if ($null -eq $configuration.Network) { throw 'Явный Network:null недопустим; удалите необязательный раздел.' }
        Test-ExamNetworkConfig $configuration.Network
    }
    $hash
}

function Assert-ConfigurationRevision([string]$Path, [string]$Hash) {
    foreach ($name in @('usb.json','network-owned.json')) {
        $intentPath=Join-Path $Path $name
        if (Test-Path -LiteralPath $intentPath) {
            $intent=[IO.File]::ReadAllText($intentPath) | ConvertFrom-Json -DateKind String
            if ($intent.ConfigRevision -isnot [string] -or $intent.ConfigRevision -ne $Hash) {
                throw "Конфигурация компонента $name отличается: явная смена pc.json не выполняется установщиком"
            }
        }
    }
    $modePath = Join-Path $Path 'mode.json'
    if (Test-Path -LiteralPath $modePath) {
        $mode = Get-Content -LiteralPath $modePath -Raw | ConvertFrom-Json -DateKind String
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
        [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
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
        $staged = $To + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            $inputFile.Position = 0
            $outputFile = [IO.File]::Open($staged,'CreateNew','Write','None')
            try { $inputFile.CopyTo($outputFile); $outputFile.Flush($true) } finally { $outputFile.Dispose() }
            if ((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash -ne $hash) { throw "Не совпадает копия $To" }
            $backup = $null
            if ([IO.File]::Exists($To)) {
                $backup = $To + '.' + [Guid]::NewGuid().ToString('N') + '.previous'
                [IO.File]::Replace($staged, $To, $backup)
            } else { [IO.File]::Move($staged, $To) }
            $backupFiles[$To] = $backup
        } finally { [IO.File]::Delete($staged) }
    }
    if ((Get-FileHash -LiteralPath $To -Algorithm SHA256).Hash -ne $hash) { throw "Не совпадает копия $To" }
    [pscustomobject]@{ Name=[IO.Path]::GetFileName($To); SHA256=$hash; Changed=$changed; Path=$To }
}

function Copy-GeneratedSource([string]$Content, [string]$Target) {
    $source = Join-Path $state ('generated-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $sourceCount = $sources.Count
    try {
        [IO.File]::WriteAllText($source, $Content, [Text.UTF8Encoding]::new($false))
        Copy-Source $source $Target
    } finally {
        if ($sources.Count -gt $sourceCount) {
            $sources[$sources.Count - 1].Dispose()
            $sources.RemoveAt($sources.Count - 1)
        }
        [IO.File]::Delete($source)
    }
}

function Write-InstallReport {
    $json = $result | ConvertTo-Json -Depth 5
    if ($ReportPath) { $json | Set-Content -LiteralPath $ReportPath -Encoding UTF8 }
    if ($HumanOutput) { Write-Host "ExamLab installation report saved to $ReportPath" }
    else { Write-Output $json }
}

try {
    if (-not $SourceDirectory) { $SourceDirectory = Join-Path $PSScriptRoot '..\windows' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Нужен повышенный административный UAC token'
    }
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6') { throw 'Нужен native64 PowerShell 7' }
    Assert-NativeAMD64
    $machine = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($machine.PartOfDomain -or [int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 19041) {
        throw 'Нужна standalone Windows client build19041 или новее.'
    }
    $code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab'
    $state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
    if (-not $DeferPolling) {
        $maintenance = Open-ExamLabMaintenanceLock
        $pollWasEnabled = Suspend-ExamLabPolling
    }
    Assert-ExamLabInactive
    $ownership = Read-ExamLabOwnership
    # Старый активный цикл отказывается до создания каталогов/lock и изменения задач.
    Assert-NoLegacyState $state
    $powershell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
    foreach ($name in $codeFiles) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $SourceDirectory $name))
        if ($bytes.Length -lt 3 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191) { throw "$name должен иметь UTF-8 BOM для PS5.1" }
    }
    # Только pure schema validation из доверенного source payload; Apply не вызывается.
    Import-Module (Join-Path $SourceDirectory 'ExamNetwork.psm1') -Force
    Import-Module (Join-Path $SourceDirectory 'ExamLab.Controller.psm1') -Force
    $configurationHash = Get-ConfigurationHash $ConfigurationPath
    if ($TrustedRootCertificatePath.Count -ne $TrustedRootSha256.Count) { throw 'Передайте путь и проверенный SHA-256 для каждого сертификата.' }
    if ($TrustedRootCertificatePath.Count) {
        . (Join-Path $PSScriptRoot 'ExamLabRootTrust.ps1')
    }
    for ($index = 0; $index -lt $TrustedRootCertificatePath.Count; $index++) {
        $roots += Read-PinnedRoot $TrustedRootCertificatePath[$index] $TrustedRootSha256[$index]
    }
    $registration = $null
    if ($ControllerConfigurationPath) { $registration = Read-ControllerConfiguration $ControllerConfigurationPath }
    $fileTraceExam = ''
    if ($UsePublishedInstallers) {
        $fileTraceConfig = Get-Item -LiteralPath (Join-Path $SourceDirectory 'file-trace-exam.txt') -Force
        if ($fileTraceConfig -isnot [IO.FileInfo] -or $fileTraceConfig.Length -gt 64 -or
            ($fileTraceConfig.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Некорректная настройка файлового экзамена в HTTPS-поставке.'
        }
        $fileTraceExam = [IO.File]::ReadAllText($fileTraceConfig.FullName)
        if ($fileTraceExam -and $fileTraceExam -cnotmatch '\Afile-trace-[A-Za-z0-9._-]{1,53}\z') {
            throw 'В HTTPS-поставке ожидался точный идентификатор файлового экзамена.'
        }
    }
    # Готовый offline PFE3.0.1: фиксированные исходные 15 файлов и LICENSE.
    # Держим source handles до завершения доставки; runtime ничего не скачивает.
    if ($UsePublishedInstallers) {
        $pfeManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PolicyFileEditorPath 'PolicyFileEditor.psd1')
        if ($pfeManifest.ModuleVersion -ne '3.0.1' -or $pfeManifest.GUID -ne '110a2398-3053-4ffc-89d1-1b6a38a2dc86') {
            throw 'В поставке ожидается PolicyFileEditor 3.0.1.'
        }
    }
    foreach ($name in $pfeFiles.Keys) {
        $source=Join-Path $PolicyFileEditorPath $name
        $handle=[IO.File]::Open($source,'Open','Read','Read')
        $sources.Add($handle)
        if (-not $UsePublishedInstallers -and (Get-FileHash -InputStream $handle -Algorithm SHA256).Hash -ne $pfeFiles[$name]) {
            throw "Не совпадает PolicyFileEditor3.0.1: $name"
        }
    }
    $lgpoLock = [IO.File]::Open($LGPOPath,'Open','Read','Read')
    $sources.Add($lgpoLock)
    if (-not $UsePublishedInstallers -and (Get-FileHash -InputStream $lgpoLock -Algorithm SHA256).Hash -ne $lgpoSha256) { throw 'Не совпадает SHA256 LGPO3.0 из проверенного SCT' }
    $signature = Get-AuthenticodeSignature -LiteralPath $LGPOPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'LGPO.exe должен иметь действительную подпись Microsoft' }
    Assert-SafeDirectory $state
    $lock = [IO.File]::Open((Join-Path $state 'operation.lock'),'OpenOrCreate','ReadWrite','None')
    Assert-NoLegacyState $state
    Assert-ExamLabInactive
    Assert-ConfigurationRevision $state $configurationHash
    $registrationFile = Join-Path $state 'controller-registration.json'
    if (Test-Path -LiteralPath $registrationFile) {
        $installedRegistration = Read-ControllerConfiguration $registrationFile
        if ($registration -and ($registration.url -cne $installedRegistration.url -or $registration.deviceId -cne $installedRegistration.deviceId -or
            $registration.token -cne $installedRegistration.token)) {
            throw 'Данные зарегистрированного ПК изменились. Переезд выполняется отдельной административной операцией.'
        }
        $registration = $installedRegistration
    }
    $probeFile = Join-Path $state 'controller-policy-probe.enabled'
    if ($EnableLabControllerPolicyProbe -and -not $registration) { throw 'Стендовая проба требует регистрации контроллера.' }
    if ($fileTraceExam -and (-not $EnableLabControllerPolicyProbe -or -not $registration)) {
        throw 'Файловая проба требует включённой пилотной политики и регистрации контроллера.'
    }
    if ($registration) {
        $pc = [IO.File]::ReadAllText($ConfigurationPath) | ConvertFrom-Json -DateKind String
        $network = $pc.PSObject.Properties['Network']
        $endpoint = if ($network) { $network.Value.PSObject.Properties['ControllerEndpoint'] } else { $null }
        $url = [Uri]$registration.url
        if (($endpoint -and ($url.Host -cne $endpoint.Value.IP -or $url.Port -ne $endpoint.Value.Port)) -or
            ($EnableLabControllerPolicyProbe -and -not $endpoint)) {
            throw 'Для сетевой политики адрес и порт Windows ControllerEndpoint должны совпадать с HTTPS URL контроллера.'
        }
    }

    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $taskFolder = $scheduler.GetFolder('\')
    $existingTasks = @{}
    foreach ($name in $examLabTaskNames) {
        $pendingProtection = Test-ExamLabTaskNeedsProtection $ownership $name
        $task = Get-ExamLabTask $name -AllowPendingProtection:$pendingProtection
        if ($task) {
            if ($taskFolder.GetTask($name).GetInstances(0).Count -gt 0) { throw "Дождитесь завершения $name, затем повторите установку." }
            $existingTasks[$name] = $task
        }
    }
    $deliveryPending = $true
    Assert-SafeDirectory $code -Readable
    $files = @()
    foreach ($name in $codeFiles) { $files += Copy-Source (Join-Path $SourceDirectory $name) (Join-Path $code $name) }
    $files += Copy-Source (Join-Path $PSScriptRoot '..\tests\windows-fileio-light.ps1') (Join-Path $code 'windows-fileio-light.ps1')
    $files += Copy-Source (Join-Path $PSScriptRoot '..\tests\Export-ExamLabFileTrace.ps1') (Join-Path $code 'Export-ExamLabFileTrace.ps1')
    $files += Copy-GeneratedSource $fileTraceExam (Join-Path $code 'file-trace-exam.txt')
    $fileTraceLauncher = @'
@echo off
"%ProgramFiles%\PowerShell\7\pwsh.exe" -NoLogo -NoProfile -Command "$ErrorActionPreference='Stop'; $root=[Environment]::GetFolderPath('ProgramFiles'); $runtime=Join-Path $root 'PowerShell\7\pwsh.exe'; $script=Join-Path $root 'ExamLab\Export-ExamLabFileTrace.ps1'; $quoted=[string]::Concat([char]34,$script,[char]34); $process=Start-Process -Verb RunAs -FilePath $runtime -ArgumentList @('-NoLogo','-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',$quoted,'-OpenLatest') -PassThru -Wait; exit $process.ExitCode"
if errorlevel 1 pause
'@
    $launcherBytes = $fileTraceLauncher.Replace("`r`n", "`n").Replace("`n", "`r`n") + "`r`n"
    $files += Copy-GeneratedSource $launcherBytes (Join-Path $code 'Show-ExamLabFileTrace.cmd')
    foreach ($name in $maintenanceFiles) { $files += Copy-Source (Join-Path $PSScriptRoot $name) (Join-Path $code $name) }
    if ($UsePublishedInstallers) { $lgpoSha256 = $null }
    $files += Copy-Source $LGPOPath (Join-Path $code 'LGPO.exe') $lgpoSha256
    $files += Copy-Source $ConfigurationPath (Join-Path $state 'pc.json') $configurationHash
    $pfeTarget=Join-Path $code 'PolicyFileEditor\3.0.1'
    Assert-SafeDirectory (Join-Path $code 'PolicyFileEditor') -Readable
    Assert-SafeDirectory $pfeTarget -Readable
    foreach ($name in $pfeFiles.Keys) {
        $target=Join-Path $pfeTarget $name
        # Все уровни — фиксированные пути готового dependency package.
        $relative=Split-Path -Parent $name
        $current=$pfeTarget
        foreach ($segment in @($relative -split '[\\/]' | Where-Object {$_})) {
            $current=Join-Path $current $segment
            Assert-SafeDirectory $current -Readable
        }
        $expectedHash = if (-not $UsePublishedInstallers) { $pfeFiles[$name] }
        $files += Copy-Source (Join-Path $PolicyFileEditorPath $name) $target $expectedHash
    }
    $result.Files=$files
    if ($roots.Count) { $result.TrustedRoots = @(Install-PinnedRoots $roots) }
    if ($registration -and -not (Test-Path -LiteralPath $registrationFile)) { Write-ControllerJson $registrationFile $registration }
    if ($EnableLabControllerPolicyProbe) {
        Write-ControllerJson $probeFile $true
        $result.LabControllerPolicyProbe=$true
    } elseif (Test-Path -LiteralPath $probeFile) { Remove-Item -LiteralPath $probeFile }
    $tasks = @()
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    foreach ($action in $actions) {
        $wrapper = Join-Path $code ('task-'+$action+'.ps1')
        $log = Join-Path $state ($action+'.log')
        $body = @'
#requires -Version 7.6
$ErrorActionPreference='Stop'
try {
    $global:LASTEXITCODE=0
    & '__ENTRY__' -Action __ACTION__ *> '__LOG__'
    exit $LASTEXITCODE
} catch { $_ | Out-File -LiteralPath '__LOG__' -Encoding UTF8 -Append; exit 1 }
'@
        $body = $body.Replace('__ENTRY__',(Join-Path $code 'exam-lab.ps1').Replace("'","''")).Replace('__ACTION__',$action).Replace('__LOG__',$log.Replace("'","''"))
        $wrapperSource = Join-Path $state ('wrapper-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        $sourceCount = $sources.Count
        try {
            [IO.File]::WriteAllText($wrapperSource, $body, (New-Object Text.UTF8Encoding($true)))
            $files += Copy-Source $wrapperSource $wrapper
        } finally {
            # Copy-Source keeps payload handles open until the package verification ends.
            if ($sources.Count -gt $sourceCount) {
                $sources[$sources.Count - 1].Dispose()
                $sources.RemoveAt($sources.Count - 1)
            }
            [IO.File]::Delete($wrapperSource)
        }
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$wrapper+'"')
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Disable
        $name = 'ExamLab-Local-'+$action
        if (-not $existingTasks.ContainsKey($name)) {
            Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $taskAction -Principal $principal -Settings $settings -Description 'ExamLab: локальный экспериментальный пилот' | Out-Null
        }
        if (-not $existingTasks.ContainsKey($name) -or (Test-ExamLabTaskNeedsProtection $ownership $name)) {
            $taskFolder.GetTask($name).SetSecurityDescriptor($examLabTaskDacl, 0x10)
        }
        $tasks += $name
        $result.Tasks=$tasks
    }
    if ($registration) {
        $entry = Join-Path $code 'exam-lab.ps1'
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$entry+'" -Action poll')
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Disable
        if (-not $existingTasks.ContainsKey($pollTask)) {
            Register-ScheduledTask -TaskName $pollTask -TaskPath '\' -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'ExamLab: исходящий опрос контроллера при запуске Windows' | Out-Null
        }
        if (-not $existingTasks.ContainsKey($pollTask) -or (Test-ExamLabTaskNeedsProtection $ownership $pollTask)) {
            $taskFolder.GetTask($pollTask).SetSecurityDescriptor($examLabTaskDacl, 0x10)
        }
        $tasks += $pollTask
    }
    Assert-SafeDirectory $code -Readable
    Assert-SafeDirectory $state
    foreach ($name in $tasks) {
        Confirm-ExamLabTaskProtection $ownership $name
        $task = Get-ExamLabTask $name
        if ($name -eq $pollTask -and $DeferPolling) { continue }
        if ($task.State -eq 'Disabled') { Enable-ScheduledTask -InputObject $task | Out-Null }
    }
    $deliveryPending = $false
    foreach ($backup in $backupFiles.Values) { if ($backup) { [IO.File]::Delete($backup) } }
    $result.Files=$files; $result.Tasks=$tasks; $result.Installed=$true
    Write-InstallReport
} catch {
    $failure = $_
    if ($deliveryPending) {
        foreach ($target in $backupFiles.Keys) {
            try {
                $backup = $backupFiles[$target]
                if ($backup) { [IO.File]::Replace($backup, $target, [NullString]::Value) }
                else { [IO.File]::Delete($target) }
            } catch { Write-Warning "Не восстановлен файл ${target}. Резервная копия: $($backupFiles[$target])." }
        }
        # A previous normal task was never disabled or replaced.
        if ($existingTasks -and -not $existingTasks.ContainsKey('ExamLab-Local-normal')) {
            try { Disable-ScheduledTask -TaskName 'ExamLab-Local-normal' -TaskPath '\' -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
    }
    $result.Error=$failure.Exception.Message
    try { Write-InstallReport }
    finally { Write-Error $failure -ErrorAction Continue }
    exit 1
}
finally {
    if ($lock) { $lock.Dispose() }
    if ($maintenance) {
        try {
            if ($pollWasEnabled) { Start-ExamLabPolling }
        } finally { $maintenance.Dispose() }
    }
    foreach ($source in $sources) { $source.Dispose() }
    foreach ($root in $roots) { $root.Dispose() }
}
