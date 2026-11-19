#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:CodeRoot = Join-Path $env:ProgramFiles 'ExamLab'
$script:DataRoot = Join-Path $env:ProgramData 'ExamLab'
$script:ConfigFile = Join-Path $script:DataRoot 'pc.json'
$script:ModeFile = Join-Path $script:DataRoot 'mode.json'
$script:ControllerConfigurationFile = Join-Path $script:DataRoot 'controller-registration.json'
$script:ControllerStateFile = Join-Path $script:DataRoot 'controller-state.json'
$script:ControllerHealthFile = Join-Path $script:DataRoot 'controller-health.json'
$script:ControllerProbeOptIn = Join-Path $script:DataRoot 'controller-policy-probe.enabled'
$script:ControllerProbeStatusFile = Join-Path $script:DataRoot 'controller-policy-probe.json'
Import-Module (Join-Path $PSScriptRoot 'ExamLab.Controller.psm1')
$script:Namespace = 'root\cimv2\mdm\dmmap'
$script:LoadedSourceHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash

function Test-ExistingFile {
    param([string]$Path)
    try { $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return $false }
    if ($item -isnot [IO.FileInfo]) { throw "Ожидался файл: $Path" }
    return $true
}

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

function Assert-Host {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or
        -not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw 'Нужна Windows x64 и штатный Windows PowerShell 5.1 x64.'
    }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        throw 'Запустите фиксированное задание ExamLab из повышенного административного сеанса.'
    }
    if ((Test-ExistingFile (Join-Path $script:DataRoot 'state.json'))) {
        throw 'Обнаружен state.json прежнего прототипа. Миграция и старый finish не выполняются.'
    }
    Assert-NativeAMD64
    $machine=Get-CimInstance Win32_ComputerSystem
    $os=Get-CimInstance Win32_OperatingSystem
    if ([int]$os.BuildNumber -lt 19041 -or [int]$os.ProductType -ne 1) { throw 'Нужна Windows client build19041 или новее.' }
    if ($machine.PartOfDomain) { throw 'Доменная политика пока не поддерживается.' }
}

function Assert-SafePath {
    param([string]$Path, [switch]$Readable)
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $Path" }
    $trusted=@('S-1-5-18','S-1-5-32-544') + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
    $acl=Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw "Чужой владелец: $Path" }
    $mutation=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trusted) { continue }
        # CREATOR OWNER заменяется доверенным создателем дочернего объекта.
        # Остальные InheritOnly ACE проверяем: они дадут доступ новым mode/tmp.
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if (-not $Readable -or ($rule.FileSystemRights -band $mutation)) { throw "Небезопасный доступ: $Path" }
    }
}

function Test-DeclaredConfig {
    param($Config)
    if ($Config -isnot [pscustomobject] -or @($Config.PSObject.Properties.Name | Where-Object {$_ -notin @('OrdinaryAccounts','Network')}).Count -or
        $Config.PSObject.Properties.Name -notcontains 'OrdinaryAccounts' -or $Config.OrdinaryAccounts -isnot [Array] -or @($Config.OrdinaryAccounts).Count -eq 0) {
        throw 'pc.json: непустой OrdinaryAccounts и необязательный Network.'
    }
    $sids=@{}; $names=@{}
    foreach ($account in @($Config.OrdinaryAccounts)) {
        if (@($account.PSObject.Properties.Name).Count -ne 2 -or
            $account.PSObject.Properties.Name -notcontains 'Sid' -or $account.PSObject.Properties.Name -notcontains 'Name' -or
            $account.Sid -isnot [string] -or $account.Name -isnot [string] -or
            $account.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or
            [string]::IsNullOrWhiteSpace($account.Name) -or $account.Name.Trim() -cne $account.Name -or $account.Name -match '[\\/\x00-\x1f]' -or
            $sids.ContainsKey($account.Sid) -or $names.ContainsKey($account.Name)) { throw 'Неверный или повторный Sid/Name в OrdinaryAccounts.' }
        $sids[$account.Sid]=$true; $names[$account.Name]=$true
    }
    if ($Config.PSObject.Properties.Name -contains 'Network') {
        if ($null -eq $Config.Network) { throw 'Явный Network:null недопустим; удалите необязательный раздел.' }
        Test-ExamNetworkConfig $Config.Network
    }
    return $Config
}

function Test-LiveRoster {
    param($Config, [object[]]$LocalAccounts, [switch]$AllowDrift)
    $missing=@(); $renamed=@()
    foreach ($account in @($Config.OrdinaryAccounts)) {
        $actual=@($LocalAccounts | Where-Object {$_.SID.Value -ceq $account.Sid})
        if ($actual.Count -eq 0) {
            $missing += [pscustomobject]@{Sid=$account.Sid; DeclaredName=$account.Name}
        } elseif ($actual[0].Name -cne $account.Name) {
            $renamed += [pscustomobject]@{Sid=$account.Sid; DeclaredName=$account.Name; ActualName=$actual[0].Name}
        }
    }
    # Происхождение новых SID не угадывается; roster не дополняется автоматически.
    $declared=@($Config.OrdinaryAccounts | ForEach-Object {$_.Sid})
    $unlisted=@($LocalAccounts | Where-Object { [int]($_.SID.Value.Split('-')[-1]) -ge 1000 -and $_.SID.Value -notin $declared } |
        ForEach-Object {[pscustomobject]@{Sid=$_.SID.Value; Name=$_.Name}})
    $unconfirmed=($missing.Count -gt 0 -or $renamed.Count -gt 0 -or $unlisted.Count -gt 0)
    if ($unconfirmed -and -not $AllowDrift) { throw 'Локальный roster изменён: отсутствует SID, изменено имя или есть неописанный SID. Нужна отдельная административная проверка; список не расширяется автоматически.' }
    [pscustomobject]@{IdentityUnconfirmed=$unconfirmed; MissingAccounts=$missing; RenamedAccounts=$renamed; UnlistedAccounts=$unlisted}
}

function Read-Context {
    param([switch]$AllowRosterDriftOnlyForNormal)
    Assert-Host
    if ($PSScriptRoot -ne $script:CodeRoot -or
        (Get-FileHash -LiteralPath (Join-Path $script:CodeRoot 'ExamLab.psm1') -Algorithm SHA256).Hash -cne $script:LoadedSourceHash) {
        throw 'Код не установлен либо изменился после загрузки; запустите новое задание.'
    }
    Assert-SafePath $script:CodeRoot -Readable
    Assert-SafePath $script:DataRoot
    foreach ($file in @('ExamLab.psm1','exam-lab.ps1','ExamLab.Usb.psm1','ExamNetwork.psm1','ExamLab.Controller.psm1','LGPO.exe')) { Assert-SafePath (Join-Path $script:CodeRoot $file) -Readable }
    Import-Module (Join-Path $script:CodeRoot 'ExamLab.Usb.psm1') -Force
    Import-Module (Join-Path $script:CodeRoot 'ExamNetwork.psm1') -Force
    Assert-SafePath $script:ConfigFile
    $config=Test-DeclaredConfig ([IO.File]::ReadAllText($script:ConfigFile) | ConvertFrom-Json)
    $revision=(Get-FileHash -LiteralPath $script:ConfigFile -Algorithm SHA256).Hash
    $metadata=$null
    if ((Test-ExistingFile $script:ModeFile)) {
        Assert-SafePath $script:ModeFile
        $metadata=[IO.File]::ReadAllText($script:ModeFile) | ConvertFrom-Json
        if (@($metadata.PSObject.Properties.Name).Count -ne 3 -or
            $metadata.PSObject.Properties.Name -notcontains 'Prepared' -or $metadata.Prepared -isnot [bool] -or
            $metadata.PSObject.Properties.Name -notcontains 'Revision' -or $metadata.Revision -cne $revision -or
            $metadata.PSObject.Properties.Name -notcontains 'LastCompletedMode' -or
            $metadata.LastCompletedMode -notin @($null,'normal','exam')) { throw 'Конфигурация/metadata изменена. Нужна отдельная административная подготовка, не runtime roster update.' }
    }
    # Ошибка чтения SAM остаётся отказом; только успешная enumeration даёт drift.
    $localAccounts=@(Get-LocalUser -ErrorAction Stop)
    $roster=Test-LiveRoster $config $localAccounts -AllowDrift:$AllowRosterDriftOnlyForNormal
    $lgpo=Join-Path $script:CodeRoot 'LGPO.exe'
    if ((Get-FileHash -LiteralPath $lgpo -Algorithm SHA256).Hash -ne '0C97F29543418B30340C4FF5D930D31E6196DD59C2CC74B6B890FA7B90C910C7') { throw 'Неизвестный LGPO.exe.' }
    $signature=Get-AuthenticodeSignature -LiteralPath $lgpo
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Подпись Microsoft LGPO не подтверждена.' }
    [pscustomobject]@{
        Config=$config; Revision=$revision; Metadata=$metadata; LGPO=$lgpo
        IdentityUnconfirmed=$roster.IdentityUnconfirmed
        MissingAccounts=$roster.MissingAccounts; RenamedAccounts=$roster.RenamedAccounts; UnlistedAccounts=$roster.UnlistedAccounts
    }
}

function Get-SharedPCState {
    try {
        $instances=@(Get-CimInstance -Namespace $script:Namespace -ClassName MDM_SharedPC)
        if ($instances.Count -ne 1) { return [pscustomobject]@{ State='Unknown'; Count=$instances.Count; Instance=$null; Reason="MDM_SharedPC instances=$($instances.Count)" } }
        [pscustomobject]@{ State='Observed'; Count=1; Instance=$instances[0]; Reason=$null }
    } catch { [pscustomobject]@{ State='Unknown'; Count=$null; Instance=$null; Reason=$_.Exception.Message } }
}

function Get-ComponentStatus {
    param($Context)
    $network=$null
    if ($Context.Config.PSObject.Properties.Name -contains 'Network') { $network=$Context.Config.Network }
    [pscustomobject]@{
        Usb=(Get-ExamLabUsbStatus -ConfigRevision $Context.Revision)
        Network=(Get-ExamNetworkStatus -Config $network -ConfigRevision $Context.Revision)
    }
}

function Test-SharedPCTarget {
    param($Shared)
    if ($Shared.State -ne 'Observed') { return $false }
    $i=$Shared.Instance
    return ($i.EnableSharedPCMode -eq $true -and $i.EnableAccountManager -eq $true -and
        [int]$i.AccountModel -eq 2 -and $null -ne $i.DeletionPolicy -and [int]$i.DeletionPolicy -eq 0 -and
        $i.SetEduPolicies -eq $false -and $i.SetPowerPolicies -eq $false -and $i.RestrictLocalStorage -eq $false)
}

function Test-SharedPCUnset {
    param($Settings)
    foreach ($name in @('EnableSharedPCMode','EnableAccountManager','AccountModel','DeletionPolicy',
        'SetEduPolicies','SetPowerPolicies','RestrictLocalStorage')) {
        if ($null -ne $Settings.$name) { return $false }
    }
    return $true
}

function Get-Status {
    param($Context)
    $shared=Get-SharedPCState
    $settings=$null
    if ($shared.State -eq 'Observed' -and $shared.Count -eq 1) {
        # Текущее наблюдение для check; null не заменяется CSP default/false.
        $settings=[ordered]@{}
        foreach ($name in @('EnableSharedPCMode','EnableAccountManager','AccountModel','DeletionPolicy',
            'SetEduPolicies','SetPowerPolicies','RestrictLocalStorage')) {
            $settings[$name]=$shared.Instance.$name
        }
        $settings=[pscustomobject]$settings
    }
    $components=Get-ComponentStatus $Context
    # Единственный USB scanner принадлежит компоненту: он различает own и foreign.
    $conflicts=@($components.Usb.Conflicts)+@($components.Network.Blockers)
    $sourceNormal=($components.Usb.State -in @('NotConfigured','Normal') -and $components.Network.SourceNormal -and
        $components.Usb.NormalAllowed -and $components.Network.NormalAllowed -and $conflicts.Count -eq 0)
    $exemptions=@(foreach ($account in @($Context.Config.OrdinaryAccounts)) {
        $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC\Exemptions\'+$account.Sid)
        $exists=$null -ne $key; if ($key) { $key.Dispose() }
        [pscustomobject]@{ Sid=$account.Sid; Name=$account.Name; Exempt=$exists }
    })
    $configured=(Test-SharedPCTarget $shared) -and @($exemptions | Where-Object {-not $_.Exempt}).Count -eq 0
    [pscustomobject]@{
        Prepared=($null -ne $Context.Metadata -and $Context.Metadata.Prepared -and $configured)
        LastCompletedMode=if ($Context.Metadata) { $Context.Metadata.LastCompletedMode } else { $null }
        EffectiveMode=if ($Context.Metadata -and $Context.Metadata.Prepared -and $configured -and $conflicts.Count -eq 0 -and $sourceNormal -and -not $components.Usb.EffectiveReadbackPending -and -not $Context.IdentityUnconfirmed) { 'normal' } else { 'Unconfirmed' }
        IdentityUnconfirmed=$Context.IdentityUnconfirmed
        MissingAccounts=$Context.MissingAccounts; RenamedAccounts=$Context.RenamedAccounts; UnlistedAccounts=$Context.UnlistedAccounts
        IdentityWarning=if ($Context.IdentityUnconfirmed) { 'Локальный roster изменён: проверьте MissingAccounts, RenamedAccounts и UnlistedAccounts. Ordinary roster не изменён; normal снимает только собственные ограничения.' } else { $null }
        Components=$components; OwnSourceNormal=$sourceNormal; Conflicts=$conflicts
        SourceMode=if ($sourceNormal) {'normal'} else {'Unconfirmed'}
        SharedPCState=$shared.State; SharedPCReason=$shared.Reason; SharedPCSettings=$settings; SharedPCTargetMatches=$configured
        OrdinaryAccounts=$exemptions; Revision=$Context.Revision
        FullReady=$false; FilesystemSupported=$false; NetworkSupported=$false; GuestLifecycleValidated=$false; OrdinaryScenariosVerified=$false
        Blockers=@('Структурное ограничение файлового доступа Guest ещё не испытано; абсолютная home-only гарантия не заявляется.','Guest network isolation не принята.','Immediate Guest cleanup и обычные занятия после permanent SharedPC не приняты.')
    }
}

function Write-Metadata {
    param($Context, [bool]$Prepared, $LastCompletedMode)
    # Только собственная metadata, никаких прежних настроек Windows.
    $temporary=Join-Path $script:DataRoot ('mode-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    try {
        @{Prepared=$Prepared; Revision=$Context.Revision; LastCompletedMode=$LastCompletedMode} |
            ConvertTo-Json -Compress | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $script:ModeFile -Force
    } finally { if ([IO.File]::Exists($temporary)) { Remove-Item -LiteralPath $temporary } }
}

function Get-ExamLabStatus { Get-Status (Read-Context) }

function Get-PreparationContext {
    $context=Read-Context
    $status=Get-Status $context
    if ($status.Conflicts.Count) { throw ($status.Conflicts -join '; ') }
    if ($context.Metadata -and $context.Metadata.Prepared) {
        if (-not $status.Prepared) { throw 'Permanent SharedPC/exemptions изменены; чужие настройки не исправляются.' }
        return [pscustomobject]@{Context=$context; Status=$status; Shared=$null; AlreadyPrepared=$true}
    }
    $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
    if (@(Get-CimInstance Win32_UserProfile | Where-Object {$_.Loaded -and -not $_.Special -and $_.SID -notin $admins}).Count) {
        throw 'Выйдите из всех неадминистративных профилей перед prepare.'
    }
    $shared=Get-SharedPCState
    if ($shared.State -ne 'Observed' -or $shared.Count -ne 1) { throw "SharedPC Unknown: нужен существующий SYSTEM MDM instance; $($shared.Reason)" }
    if (-not $context.Metadata) {
        # Нельзя перекрывать чужую machine GPO даже во время однократной подготовки.
        $machinePol=Join-Path $env:windir 'System32\GroupPolicy\Machine\Registry.pol'
        if ([IO.File]::Exists($machinePol) -and (New-Object IO.FileInfo($machinePol)).Length -gt 8) {
            throw 'Существующая machine Registry.pol требует адресного разбора до SharedPC prepare.'
        }
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC\NodeValues',
            'SOFTWARE\Microsoft\PolicyManager\current\device\SharedPC')) {
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($node)
            if ($key) {
                try { if ($key.ValueCount -or $key.SubKeyCount) { throw "SharedPC уже управляется другим источником: $node" } }
                finally { $key.Dispose() }
            }
        }
        if (-not (Test-SharedPCUnset $shared.Instance)) {
            throw 'До первой подготовки все семь SharedPC полей должны быть unset/null; configured values требуют отдельного разбора.'
        }
        foreach ($account in @($context.Config.OrdinaryAccounts)) {
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC\Exemptions\'+$account.Sid)
            if ($key) { $key.Dispose(); throw "Exemption уже существует без нашего владения: $($account.Sid)" }
        }
    }
    foreach ($parentPath in @('SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC\Exemptions')) {
    $parent=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentPath)
    if ($parent) {
        try {
            $acl=$parent.GetAccessControl()
            $trusted=@('S-1-5-18','S-1-5-32-544')+$admins
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Чужой owner SharedPC parent.' }
            $writes=[Security.AccessControl.RegistryRights]::SetValue -bor [Security.AccessControl.RegistryRights]::CreateSubKey -bor [Security.AccessControl.RegistryRights]::Delete -bor
                [Security.AccessControl.RegistryRights]::ChangePermissions -bor [Security.AccessControl.RegistryRights]::TakeOwnership
            foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                # Новый Exemption SID создаётся SYSTEM; literal foreign InheritOnly
                # write всё равно запрещён, поскольку станет действующим на child.
                if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
                    ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
                if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and ($rule.RegistryRights -band $writes)) {
                    throw 'SharedPC parent доступен для чужой записи; ACL не исправляется.'
                }
            }
        } finally { $parent.Dispose() }
    }
    }
    if ($context.Metadata -and $shared.State -eq 'Observed' -and
        ($shared.Instance.SetEduPolicies -or $shared.Instance.SetPowerPolicies -or $shared.Instance.RestrictLocalStorage -or
         [int]$shared.Instance.AccountModel -notin @(0,2) -or [int]$shared.Instance.DeletionPolicy -notin @(0,1))) {
        throw 'Partial prepare конфликтует с выбранной декларацией; чужие значения не исправляются.'
    }
    return [pscustomobject]@{Context=$context; Status=$status; Shared=$shared; AlreadyPrepared=$false}
}

function Initialize-ExamLab {
    $preflight=Get-PreparationContext
    if ($preflight.AlreadyPrepared) { return $preflight.Status }
    # Первая проверка не считается актуальной после ожидания общего installer lock.
    $lockPath=Join-Path $script:DataRoot 'operation.lock'
    if ((Test-ExistingFile $lockPath)) { Assert-SafePath $lockPath }
    $lock=[IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')
    try {
        $preflight=Get-PreparationContext
        if ($preflight.AlreadyPrepared) { return $preflight.Status }
        $context=$preflight.Context; $shared=$preflight.Shared
        Write-Metadata $context $false $null
        foreach ($account in @($context.Config.OrdinaryAccounts)) {
            $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC\Exemptions\'+$account.Sid)
            $key.Dispose()
        }
        $instance=$shared.Instance
        # Только выбранная подготовка; эти настройки не переключаются normal/exam.
        $instance | Set-CimInstance -Property @{
            AccountModel=2; DeletionPolicy=0; EnableAccountManager=$true
            SetEduPolicies=$false; SetPowerPolicies=$false; RestrictLocalStorage=$false
        } | Out-Null
        $instance=Get-CimInstance -Namespace $script:Namespace -ClassName MDM_SharedPC
        if (@($instance).Count -ne 1) { throw 'SharedPC instance после настройки Unknown; partial prepare сохранён.' }
        $instance | Set-CimInstance -Property @{EnableSharedPCMode=$true} | Out-Null
        $readback=Get-Status $context
        if (-not $readback.SharedPCTargetMatches -or $readback.Conflicts.Count) { throw 'SharedPC/exemptions readback не подтверждён; partial prepare без rollback.' }
        Write-Metadata $context $true 'normal'
        return Get-ExamLabStatus
    } finally { $lock.Dispose() }
}

function Assert-ExamLabExamReady {
    throw 'Экзамен заблокирован до native-проверки структурного файлового ограничения и сети. Windows не изменена.'
}

function Invoke-ExamLabNormalUnderLock {
    param($Context,[IO.FileStream]$Lock)
    $components=Get-ComponentStatus $context
    $blockers=@($components.Usb.NormalBlockers)+@($components.Network.Blockers)
    if (-not $components.Usb.NormalAllowed -or -not $components.Network.NormalAllowed) {
        throw ('normal не применён: component preflight: '+($blockers -join '; '))
    }
    $network=$null
    if ($context.Config.PSObject.Properties.Name -contains 'Network') { $network=$context.Config.Network }
    # Все preflight завершены; фиксированные setters повторяют свои проверки.
    # При последующем отказе нет общего успеха/rollback; own intent сохраняется.
    $usb=$null; $net=$null; $phase='Usb'
    try {
        $usb=Invoke-ExamLabUsbModeUnderLock -Mode normal -ConfigRevision $context.Revision -OperationLock $lock
        $phase='Network'
        $net=Invoke-ExamNetworkUnderLock -Action Normal -Config $network -ConfigRevision $context.Revision -OperationLock $lock
    } catch {
        $partial=[pscustomobject]@{Completed=$false;FailedComponent=$phase;Usb=$usb;Network=$net;Error=$_.Exception.Message}
        throw ('normal не завершён; частичный результат без rollback: '+($partial | ConvertTo-Json -Depth 6 -Compress))
    }
    $status=Get-Status $context
    if (-not $status.OwnSourceNormal) {
        $incomplete=[pscustomobject]@{Completed=$false;Usb=$usb;Network=$net;FinalComponents=$status.Components;Conflicts=$status.Conflicts}
        throw ('normal source readback не подтверждён; без rollback: '+($incomplete | ConvertTo-Json -Depth 6 -Compress))
    }
    $status | Add-Member -NotePropertyName Normal -NotePropertyValue ([pscustomobject]@{
        SourceCleanupCompleted=$status.OwnSourceNormal
        Usb=$usb; Network=$net
        EffectiveReadbackPending=$true
        Reason='Сняты только собственные source entries; USB effective readback требует входа пользователя. SharedPC не выключается.'
    })
    return $status
}

function Invoke-ExamLabControllerPolicyProbe {
    param($Assignment,[IO.FileStream]$Lock)
    $probe = [pscustomobject]@{
        Revision=$Assignment.revision; ExamId=$Assignment.examId; FullReady=$false
        PreflightStartedUtc=(Get-ControllerUtc); MachineApplyStartedUtc=$null
        UsbSourceReadbackUtc=$null; NetworkReadbackUtc=$null; MachinePoliciesReadyUtc=$null
        FailedPhase=$null; Error=$null
    }
    $phase = 'Preflight'
    try {
        Assert-SafePath $script:ControllerProbeOptIn
        $context = Read-Context
        $status = Get-Status $context
        $network = $context.Config.PSObject.Properties['Network']
        $endpoint = if ($network) { $network.Value.PSObject.Properties['ControllerEndpoint'] } else { $null }
        $registration = Read-ControllerConfiguration $script:ControllerConfigurationFile
        $url = [Uri]$registration.url
        if (-not $status.Prepared -or -not $endpoint -or -not $endpoint.Value -or
            $endpoint.Value.IP -cne $url.Host -or $endpoint.Value.Port -ne $url.Port) {
            throw 'Проба требует подтверждённой Shared PC и одинакового сетевого и регистрационного адреса контроллера.'
        }
        $netBefore = Get-ExamNetworkStatus -Config $network.Value -ConfigRevision $context.Revision -CheckApplyHost
        $usbBefore = $status.Components.Usb
        if (-not $usbBefore.ExamAllowed -or $netBefore.ApplyBlockers.Count -or (-not $netBefore.ApplyAllowed -and -not $netBefore.EffectiveApplied)) {
            throw ('Предварительные проверки USB/сети: ' + ((@($usbBefore.ExamBlockers) + @($netBefore.ApplyBlockers) + @($netBefore.EffectiveBlockers)) -join ' | '))
        }
        $probe.MachineApplyStartedUtc = Get-ControllerUtc
        Write-ControllerJson $script:ControllerProbeStatusFile $probe
        $phase = 'Usb'
        $usb = Invoke-ExamLabUsbModeUnderLock -Mode exam -ConfigRevision $context.Revision -OperationLock $Lock
        if ($usb.State -cne 'Applied' -or $usb.OwnSourceEntries -ne 1 -or $usb.Conflicts.Count) { throw 'USB source readback не подтверждён.' }
        $probe.UsbSourceReadbackUtc = Get-ControllerUtc
        $phase = 'Network'
        $net = Invoke-ExamNetworkUnderLock -Action Apply -Config $network.Value -ConfigRevision $context.Revision -OperationLock $Lock
        if (-not $net.EffectiveApplied) { throw 'Network ActiveStore readback не подтверждён.' }
        $probe.NetworkReadbackUtc = Get-ControllerUtc
        $probe.MachinePoliciesReadyUtc = $probe.NetworkReadbackUtc
    } catch {
        $probe.FailedPhase = $phase
        $probe.Error = $_.Exception.Message
    }
    Write-ControllerJson $script:ControllerProbeStatusFile $probe
    return $probe
}

function Set-ExamLabMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('exam','normal')][string]$Mode,
        $ControllerAssignment,
        $LocalGeneration
    )
    $remote = $null -ne $ControllerAssignment
    # Локальный exam отказывает до config, lock и любых изменений Windows.
    if (-not $remote -and $Mode -eq 'exam') { Assert-ExamLabExamReady }
    if (-not $remote) { $null=Read-Context -AllowRosterDriftOnlyForNormal }
    else { Assert-Host }
    $lockPath = Join-Path $script:DataRoot 'operation.lock'
    if ((Test-ExistingFile $lockPath)) { Assert-SafePath $lockPath }
    $lock = [IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')
    try {
        $controller = $null
        if ($remote) {
            $controller = Read-ControllerState $script:ControllerStateFile
            if ($controller.LocalGeneration -cne $LocalGeneration) { return }
            $change = Compare-ControllerAssignment $ControllerAssignment $controller.Assignment
            if ($change -ceq 'repeat' -and $controller.Result -and
                ($controller.Result.outcome -cne 'error' -or $controller.Result.reason -ceq 'machine-apply-failed')) { return }
            if ($change -ceq 'new') {
                $controller.Assignment = $ControllerAssignment
                $controller.Result = $null
                if ($controller.AwaitingBaseline) {
                    if ($Mode -ceq 'exam') { $controller.StoppedExamId = $ControllerAssignment.examId }
                    $controller.AwaitingBaseline = $false
                }
                # Записываем принятое назначение до возможного изменения Windows.
                Write-ControllerJson $script:ControllerStateFile $controller
            }
            if ($Mode -ceq 'exam') {
                if ($controller.StoppedExamId -ceq $ControllerAssignment.examId) {
                    if ($controller.LocalNormal -and $controller.LocalNormal.SourceCleanupCompleted) {
                        $reason = if ($controller.LocalNormal.BaselineUnknown) { 'local-normal-baseline-unknown' } else { 'local-normal' }
                        Set-ControllerResult $controller 'overridden' $reason $false
                    } else {
                        Set-ControllerResult $controller 'error' 'local-normal-incomplete' $false
                    }
                } elseif (Test-ExistingFile $script:ControllerProbeOptIn) {
                    $probe = Invoke-ExamLabControllerPolicyProbe $ControllerAssignment $lock
                    if ($probe.MachinePoliciesReadyUtc) {
                        Set-ControllerResult $controller 'source-applied' 'machine-policies-only' $false
                    } elseif ($probe.FailedPhase -ceq 'Preflight') {
                        Set-ControllerResult $controller 'blocked' 'machine-preflight-failed' $false
                    } else {
                        Set-ControllerResult $controller 'error' 'machine-apply-failed' $false
                    }
                } else {
                    Set-ControllerResult $controller 'blocked' 'full-not-ready' $false
                }
                Write-ControllerJson $script:ControllerStateFile $controller
                return
            }
        } elseif (Test-ExistingFile $script:ControllerConfigurationFile) {
            # Ошибка чтения состояния останавливает опрос, но оставляет доступным
            # локальное восстановление Windows.
            try { $controller = Read-ControllerState $script:ControllerStateFile }
            catch { Write-Warning 'Состояние контроллера недоступно. Локальный normal продолжает восстановление.' }
            if ($controller) {
                $controller.LocalGeneration = [Guid]::NewGuid().ToString('N')
                if (-not $controller.Assignment) { $controller.AwaitingBaseline = $true }
                elseif ($controller.Assignment.mode -ceq 'exam') {
                    $controller.StoppedExamId = $controller.Assignment.examId
                    Set-ControllerResult $controller 'error' 'local-normal-incomplete' $false
                }
                $controller.LocalNormal = [pscustomobject]@{
                    SourceCleanupCompleted=$false; EffectiveMode='Unconfirmed'; ObservedUtc=(Get-ControllerUtc)
                    BaselineUnknown=$controller.AwaitingBaseline
                }
                Write-ControllerJson $script:ControllerStateFile $controller
            }
        }

        try {
            $context=Read-Context -AllowRosterDriftOnlyForNormal
            $status = Invoke-ExamLabNormalUnderLock $context $lock
        } catch {
            if ($remote) {
                Set-ControllerResult $controller 'error' 'local-action-failed' $false
                Write-ControllerJson $script:ControllerStateFile $controller
            }
            throw
        }
        if ($remote) {
            if ($status.EffectiveMode -ceq 'normal') {
                Set-ControllerResult $controller 'applied' '' $status.FullReady
            } else {
                Set-ControllerResult $controller 'source-applied' 'effective-readback-pending' $status.FullReady
            }
        } elseif ($controller) {
            $controller.LocalNormal = [pscustomobject]@{
                SourceCleanupCompleted=$status.Normal.SourceCleanupCompleted
                EffectiveMode=$status.EffectiveMode
                ObservedUtc=(Get-ControllerUtc)
                BaselineUnknown=$controller.AwaitingBaseline
            }
            if ($controller.StoppedExamId -and $controller.Assignment.mode -ceq 'exam') {
                Set-ControllerResult $controller 'overridden' 'local-normal' $status.FullReady
            }
        }
        if ($controller) { Write-ControllerJson $script:ControllerStateFile $controller }
        return $status
    } finally { $lock.Dispose() }
}

function Invoke-ExamLabControllerLoop {
    Assert-Host
    if ($PSScriptRoot -ne $script:CodeRoot) { throw 'Запустите установленную задачу опроса.' }
    Assert-SafePath $script:DataRoot
    Assert-SafePath $script:ControllerConfigurationFile
    $configuration = Read-ControllerConfiguration $script:ControllerConfigurationFile
    if (Test-ExistingFile $script:ControllerStateFile) { Assert-SafePath $script:ControllerStateFile }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    $bootUtc = $boot.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'",[Globalization.CultureInfo]::InvariantCulture)
    $health = [pscustomobject]@{
        BootUtc=$bootUtc; FirstAttemptUtc=$null; LastAttemptUtc=$null
        FirstValidContactUtc=$null; LastValidContactUtc=$null; Status='Starting'; Reason=$null
    }
    if (Test-ExistingFile $script:ControllerHealthFile) {
        Assert-SafePath $script:ControllerHealthFile
        $previous = [IO.File]::ReadAllText($script:ControllerHealthFile) | ConvertFrom-Json
        if ([DateTime]$previous.BootUtc -eq [DateTime]$bootUtc) {
            $health.FirstAttemptUtc = $previous.FirstAttemptUtc
            $health.FirstValidContactUtc = $previous.FirstValidContactUtc
            $health.LastValidContactUtc = $previous.LastValidContactUtc
        }
    }
    $client = New-ExamLabHttpClient
    try {
        while ($true) {
            $health.LastAttemptUtc = Get-ControllerUtc
            if (-not $health.FirstAttemptUtc) { $health.FirstAttemptUtc = $health.LastAttemptUtc }
            Write-ControllerJson $script:ControllerHealthFile $health
            try {
                $snapshot = Read-ControllerState $script:ControllerStateFile
            } catch {
                $health.Status='LocalError'
                $health.Reason='controller-state-unreadable'
                Write-ControllerJson $script:ControllerHealthFile $health
                Start-Sleep -Seconds 15
                continue
            }
            try {
                $assignment = Invoke-ControllerRequest $client $configuration $snapshot.Result
                $null = Compare-ControllerAssignment $assignment $snapshot.Assignment
                $health.LastValidContactUtc = Get-ControllerUtc
                if (-not $health.FirstValidContactUtc) { $health.FirstValidContactUtc = $health.LastValidContactUtc }
                $health.Status='Connected'
                $health.Reason=$null
                Write-ControllerJson $script:ControllerHealthFile $health
                try {
                    $null = Set-ExamLabMode -Mode $assignment.mode -ControllerAssignment $assignment -LocalGeneration $snapshot.LocalGeneration
                } catch {
                    $health.Status='LocalError'
                    $health.Reason='controller-action-delayed-or-failed'
                    Write-ControllerJson $script:ControllerHealthFile $health
                }
            } catch {
                $health.Status = if ($_.Exception.Message -ceq 'controller-unreachable') { 'Unavailable' } else { 'Rejected' }
                $health.Reason = $_.Exception.Message
                Write-ControllerJson $script:ControllerHealthFile $health
            }
            Start-Sleep -Seconds 15
        }
    } finally { $client.Dispose() }
}

Export-ModuleMember -Function Get-ExamLabStatus,Initialize-ExamLab,Set-ExamLabMode,Invoke-ExamLabControllerLoop
