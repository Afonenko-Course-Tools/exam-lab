#requires -Version 5.1
<#
.SYNOPSIS
Устанавливает защищённые файлы и фиксированные SYSTEM-задачи локального пилота.
.DESCRIPTION
Устанавливается на существующую standalone Windows x64. Действия модуля не запускаются.
LGPO.exe передаётся отдельно из официального Microsoft Security Compliance Toolkit.
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
    [switch]$EnableLabControllerPolicyProbe
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$lock = $null
$deliveryPending = $false
$sources = [Collections.Generic.List[object]]::new()
$actions = @('prepare','check','exam','normal')
$legacyActions = @('enable','finish')
$codeFiles = @('ExamLab.psm1','exam-lab.ps1','ExamLab.Usb.psm1','ExamNetwork.psm1','ExamLab.Controller.psm1')
$pollTask = 'ExamLab-Controller-Poll'
$taskNames = @($actions + $legacyActions | ForEach-Object { 'ExamLab-Local-'+$_ }) + @($pollTask)
$roots = @()
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
    try { $configuration = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
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
            $intent=[IO.File]::ReadAllText($intentPath) | ConvertFrom-Json
            if ($intent.ConfigRevision -isnot [string] -or $intent.ConfigRevision -ne $Hash) {
                throw "Конфигурация компонента $name отличается: явная смена pc.json не выполняется установщиком"
            }
        }
    }
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

function Get-CertificateSha256([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-','') }
    finally { $algorithm.Dispose() }
}

function Read-PinnedRoot([string]$Path,[string]$Expected) {
    if ($Expected -notmatch '\A[0-9A-Fa-f]{64}\z') { throw 'Для каждого корневого сертификата требуется проверенный SHA-256.' }
    $file = Get-Item -LiteralPath $Path
    if ($file -isnot [IO.FileInfo] -or $file.Length -gt 16384) { throw 'Ожидался один публичный корневой сертификат DER.' }
    $data = [IO.File]::ReadAllBytes($file.FullName)
    if ((Get-CertificateSha256 $data) -ine $Expected) { throw 'Отпечаток файла корневого сертификата отличается от проверенного SHA-256.' }
    $x509 = [Security.Cryptography.X509Certificates.X509Certificate2]
    if ($x509::GetCertContentType($data) -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) { throw 'Ожидался один публичный сертификат DER.' }
    $certificate = $x509::new($data)
    try {
        $constraints = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        $keyUsage = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        $now = Get-Date
        if ($certificate.HasPrivateKey -or (Get-CertificateSha256 $certificate.RawData) -ine $Expected -or
            [Convert]::ToBase64String($certificate.SubjectName.RawData) -cne [Convert]::ToBase64String($certificate.IssuerName.RawData) -or
            $constraints.Count -ne 1 -or -not $constraints[0].CertificateAuthority -or
            ($keyUsage.Count -and -not ($keyUsage[0].KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign)) -or
            $certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
            throw 'Сертификат должен быть действующим публичным корнем CA с разрешением подписывать сертификаты.'
        }
        return $certificate
    } catch { $certificate.Dispose(); throw }
}

function Install-PinnedRoots([Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates) {
    if (-not $Certificates.Count) { return }
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        foreach ($certificate in $Certificates) {
            $hash = Get-CertificateSha256 $certificate.RawData
            $matches = @($store.Certificates.Find('FindByThumbprint',$certificate.Thumbprint,$false))
            if (@($matches | Where-Object { (Get-CertificateSha256 $_.RawData) -cne $hash }).Count) { throw 'В Windows Root найден конфликт отпечатка сертификата.' }
            if (-not $matches.Count) { $store.Add($certificate) }
            $readback = @($store.Certificates.Find('FindByThumbprint',$certificate.Thumbprint,$false) |
                Where-Object { (Get-CertificateSha256 $_.RawData) -ceq $hash })
            if (-not $readback.Count) { throw 'Корневой сертификат отсутствует при повторном чтении Windows Root.' }
            [pscustomobject]@{ Subject=$certificate.Subject; SHA256=$hash; Added=(-not $matches.Count) }
        }
    } finally { $store.Dispose() }
}

try {
    if (-not $SourceDirectory) { $SourceDirectory = Join-Path $PSScriptRoot '..\windows' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Нужен повышенный административный UAC token'
    }
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Нужен native64 Windows PowerShell5.1' }
    Assert-NativeAMD64
    $machine = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($machine.PartOfDomain -or [int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 19041) {
        throw 'Нужна standalone Windows client build19041 или новее.'
    }
    $code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab'
    $state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
    # Старый активный цикл отказывается до создания каталогов/lock и изменения задач.
    Assert-NoLegacyState $state
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    foreach ($name in $codeFiles) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $SourceDirectory $name))
        if ($bytes.Length -lt 3 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191) { throw "$name должен иметь UTF-8 BOM для PS5.1" }
    }
    # Только pure schema validation из доверенного source payload; Apply не вызывается.
    Import-Module (Join-Path $SourceDirectory 'ExamNetwork.psm1') -Force
    Import-Module (Join-Path $SourceDirectory 'ExamLab.Controller.psm1') -Force
    $configurationHash = Get-ConfigurationHash $ConfigurationPath
    if ($TrustedRootCertificatePath.Count -ne $TrustedRootSha256.Count) { throw 'Передайте путь и проверенный SHA-256 для каждого сертификата.' }
    for ($index = 0; $index -lt $TrustedRootCertificatePath.Count; $index++) {
        $roots += Read-PinnedRoot $TrustedRootCertificatePath[$index] $TrustedRootSha256[$index]
    }
    $registration = $null
    if ($ControllerConfigurationPath) { $registration = Read-ControllerConfiguration $ControllerConfigurationPath }
    # Готовый offline PFE3.0.1: фиксированные исходные 15 файлов и LICENSE.
    # Держим source handles до завершения доставки; runtime ничего не скачивает.
    foreach ($name in $pfeFiles.Keys) {
        $source=Join-Path $PolicyFileEditorPath $name
        $handle=[IO.File]::Open($source,'Open','Read','Read')
        $sources.Add($handle)
        if ((Get-FileHash -InputStream $handle -Algorithm SHA256).Hash -ne $pfeFiles[$name]) {
            throw "Не совпадает PolicyFileEditor3.0.1: $name"
        }
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
    $registrationFile = Join-Path $state 'controller-registration.json'
    if (Test-Path -LiteralPath $registrationFile) {
        $installedRegistration = Read-ControllerConfiguration $registrationFile
        if ($registration -and ($registration.url -cne $installedRegistration.url -or $registration.deviceId -cne $installedRegistration.deviceId)) {
            throw 'URL или идентификатор зарегистрированного ПК изменились. Переезд выполняется отдельной административной операцией.'
        }
        if (-not $registration) { $registration = $installedRegistration }
    }
    $probeFile = Join-Path $state 'controller-policy-probe.enabled'
    if ($EnableLabControllerPolicyProbe -and -not $registration) { throw 'Стендовая проба требует регистрации контроллера.' }
    if ($registration) {
        $pc = [IO.File]::ReadAllText($ConfigurationPath) | ConvertFrom-Json
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
    $deliveryPending = $true
    foreach ($name in $taskNames) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskName $name | Out-Null
            if ($name -eq $pollTask -and $taskFolder.GetTask($name).GetInstances(0).Count -gt 0) {
                # Под operation.lock опрос сейчас не может менять политики.
                Stop-ScheduledTask -TaskName $name
            }
        }
    }
    foreach ($name in $taskNames) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task -and $taskFolder.GetTask($name).GetInstances(0).Count -gt 0) {
            throw "Дождитесь завершения $name. Задачи оставлены Disabled, повторите установку."
        }
    }
    Assert-SafeDirectory $code -Readable
    $files = @()
    foreach ($name in $codeFiles) { $files += Copy-Source (Join-Path $SourceDirectory $name) (Join-Path $code $name) }
    $files += Copy-Source $LGPOPath (Join-Path $code 'LGPO.exe') '0c97f29543418b30340c4ff5d930d31e6196dd59c2cc74b6b890fa7b90c910c7'
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
        $files += Copy-Source (Join-Path $PolicyFileEditorPath $name) $target $pfeFiles[$name]
    }
    $result.Files=$files
    $result.TrustedRoots = @(Install-PinnedRoots $roots)
    if ($registration -and $ControllerConfigurationPath) { Write-ControllerJson $registrationFile $registration }
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
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Disable
        $name = 'ExamLab-Local-'+$action
        Register-ScheduledTask -TaskName $name -Action $taskAction -Principal $principal -Settings $settings -Description 'ExamLab: локальный экспериментальный пилот' -Force | Out-Null
        $taskFolder.GetTask($name).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
        $tasks += $name
        $result.Tasks=$tasks
    }
    if ($registration) {
        $entry = Join-Path $code 'exam-lab.ps1'
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$entry+'" -Action poll')
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Disable
        Register-ScheduledTask -TaskName $pollTask -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'ExamLab: исходящий опрос контроллера при запуске Windows' -Force | Out-Null
        $taskFolder.GetTask($pollTask).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
        $tasks += $pollTask
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
        foreach ($name in $taskNames) {
            try { Disable-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
    }
    $result.Error=$failure.Exception.Message
    $result | ConvertTo-Json -Depth 5
    Write-Error $failure -ErrorAction Continue
    exit 1
}
finally {
    if ($lock) { $lock.Dispose() }
    foreach ($source in $sources) { $source.Dispose() }
    foreach ($root in $roots) { $root.Dispose() }
}
