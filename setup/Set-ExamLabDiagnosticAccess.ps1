#Requires -Version 5.1
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Создаёт временную конечную точку WinRM для чтения диагностики ExamLab на стенде.
.DESCRIPTION
Запускается локальным администратором в одноразовой Windows VM до первого
обращения за регистрацией ExamLab. Использует уже работающий WinRM с шифрованием
и входящим правилом для одного IPv4-адреса оператора. При включении перезапускает
WinRM, чтобы новая конечная точка вступила в силу. Выполняйте это из локального
административного сеанса. Пароль вводится в закрытом виде.
Отдельная учётная запись работает через конечную точку ExamLab-Diagnostics.
Доступная ей команда Get-ExamLabDiagnosticSnapshot читает задачи и события.
Закройте сеанс диагностики и выполните Disable до регистрации ExamLab.
.EXAMPLE
.\Set-ExamLabDiagnosticAccess.ps1 -Action Enable -SourceIPv4 10.0.2.2
.EXAMPLE
.\Set-ExamLabDiagnosticAccess.ps1 -Action Disable
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Enable', 'Disable')][string]$Action,
    [ipaddress]$SourceIPv4,
    [ValidateRange(1, 6)][int]$Hours = 2,
    [securestring]$Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }

$endpointName = 'ExamLab-Diagnostics'
$accountName = 'exam-lab-diag'
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$directory = Join-Path $programFiles 'ExamLabDiagnosticAccess'
$ownerFile = Join-Path $directory 'owner.txt'
$configurationFile = Join-Path $directory 'ExamLab-Diagnostics.pssc'

function Get-DiagnosticEndpoint {
    Get-PSSessionConfiguration -ErrorAction Stop | Where-Object Name -eq $endpointName
}

function Get-DiagnosticAccount {
    Get-LocalUser -ErrorAction Stop | Where-Object Name -eq $accountName
}

function Assert-DiagnosticPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Diagnostic path is a reparse point: $Path"
    }
}

function Assert-ScopedWinRM {
    if (-not $SourceIPv4 -or $SourceIPv4.AddressFamily -ne 'InterNetwork' -or
        $SourceIPv4.Equals([ipaddress]::Any) -or $SourceIPv4.Equals([ipaddress]::Broadcast)) {
        throw 'Specify one unicast IPv4 address as seen by the VM.'
    }
    if ((Get-Service WinRM).Status -ne 'Running') {
        throw 'Start the existing VM WinRM transport before enabling diagnostic access.'
    }
    if ((Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value -ne 'false' -or
        (Get-Item WSMan:\localhost\Service\Auth\Basic).Value -ne 'false' -or
        (Get-Item WSMan:\localhost\Service\Auth\Negotiate).Value -ne 'true') {
        throw 'WinRM must require encryption, disable Basic and allow Negotiate.'
    }
    $ports = @(foreach ($listener in Get-ChildItem WSMan:\localhost\Listener) {
        $settings = @{}
        foreach ($setting in Get-ChildItem -LiteralPath $listener.PSPath) {
            $settings[$setting.Name] = $setting.Value
        }
        if ($settings.Enabled -eq 'true') { [int]$settings.Port }
    })
    if ($ports.Count -ne 1) { throw 'Expected one active WinRM listener on the VM.' }
    $port = $ports[0]

    $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore
    if ($profiles | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -eq 'Allow' }) {
        throw 'Windows Firewall must be enabled and block unsolicited traffic.'
    }

    $foundScope = $false
    $address = $SourceIPv4.ToString()
    $hostProcess = Join-Path $env:SystemRoot 'System32\svchost.exe'
    foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow) {
        $portFilter = $rule | Get-NetFirewallPortFilter
        if ($portFilter.Protocol -notin 'TCP', '6', 'Any') { continue }
        $portsMatching = @($portFilter.LocalPort | Where-Object {
            $_ -eq 'Any' -or $_ -eq [string]$port -or
                ($_ -match '\A([0-9]+)-([0-9]+)\z' -and [int]$Matches[1] -le $port -and [int]$Matches[2] -ge $port)
        })
        if (-not $portsMatching.Count) { continue }
        if (($rule | Get-NetFirewallServiceFilter).Service -notin 'Any', 'WinRM') { continue }
        $program = [Environment]::ExpandEnvironmentVariables(($rule | Get-NetFirewallApplicationFilter).Program)
        if ($program -notin 'Any', 'System', $hostProcess) { continue }

        $remotes = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
        if (-not $remotes.Count -or @($remotes | Where-Object { $_ -notin $address, "$address/32" }).Count) {
            throw "Firewall rule '$($rule.Name)' could permit WinRM from another source."
        }
        if ($rule.Profile -eq 'Any' -and $portFilter.LocalPort -eq [string]$port) { $foundScope = $true }
    }
    if (-not $foundScope) {
        throw "No active firewall rule for TCP $port and source $address in every profile."
    }
    return $port
}

function Remove-DiagnosticAccess {
    if (-not (Test-Path -LiteralPath $directory)) {
        if ((Get-DiagnosticAccount) -or (Get-DiagnosticEndpoint)) {
            throw 'An existing diagnostic account or endpoint has no ExamLab ownership record.'
        }
        return
    }

    Assert-DiagnosticPath $directory
    Assert-DiagnosticPath $ownerFile
    $owner = [IO.File]::ReadAllText($ownerFile)
    if ($owner -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Invalid diagnostic access ownership record.' }
    $account = Get-DiagnosticAccount
    if ($account -and $account.Description -cne "ExamLabDiag:$owner") {
        throw 'The local account is not owned by this diagnostic access script.'
    }

    $leaseFile = Join-Path $directory "$owner.lease"
    if (Test-Path -LiteralPath $leaseFile) { Assert-DiagnosticPath $leaseFile }
    [IO.File]::Delete($leaseFile)
    if ($account -and $account.Enabled) { Disable-LocalUser -SID $account.SID }

    $existing = Get-DiagnosticEndpoint
    if ($existing) {
        Assert-DiagnosticPath $configurationFile
        $activePath = [string]$existing.ConfigFilePath
        if (-not $activePath) { throw 'The registered endpoint has no ExamLab configuration file.' }
        Assert-DiagnosticPath $activePath
        if ((Get-FileHash -LiteralPath $activePath).Hash -cne (Get-FileHash -LiteralPath $configurationFile).Hash) {
            throw 'The registered endpoint configuration differs from the ExamLab file.'
        }
        Unregister-PSSessionConfiguration -Name $endpointName -Force -NoServiceRestart
    }
    if ($account) { Remove-LocalUser -SID $account.SID }
    if (Test-Path -LiteralPath $configurationFile) { Assert-DiagnosticPath $configurationFile }
    [IO.File]::Delete($configurationFile)
    if (Get-ChildItem -LiteralPath $directory -Force | Where-Object Name -ne 'owner.txt') {
        throw 'Diagnostic access was removed; review unexpected files in its directory.'
    }
    [IO.File]::Delete($ownerFile)
    [IO.Directory]::Delete($directory)
}

$mutex = [Threading.Mutex]::new($false, 'Global\ExamLabDiagnosticAccess')
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another diagnostic access operation is in progress.' }

    if ($Action -eq 'Disable') {
        Remove-DiagnosticAccess
        [pscustomobject]@{ Endpoint = $endpointName; Enabled = $false }
        return
    }

    $machine = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($machine.PartOfDomain -or $os.ProductType -ne 1) {
        throw 'This endpoint is intended for a standalone Windows client VM.'
    }
    $commonData = [Environment]::GetFolderPath('CommonApplicationData')
    if ((Test-Path -LiteralPath (Join-Path $commonData 'ExamLab\controller-registration.json')) -or
        (Test-Path -LiteralPath (Join-Path $programFiles 'ExamLabSetupReports\Enrollment\enrollment.json'))) {
        throw 'Use the temporary diagnostic account before preparing ExamLab registration on this VM.'
    }
    $port = Assert-ScopedWinRM
    if ((Test-Path -LiteralPath $directory) -or (Get-DiagnosticAccount) -or (Get-DiagnosticEndpoint)) {
        throw 'The diagnostic access names or directory already exist. Review or disable the previous access first.'
    }
    if (-not $Password) { $Password = Read-Host 'Temporary diagnostic account password' -AsSecureString }
    if (-not $Password -or $Password.Length -lt 16 -or $Password.Length -gt 127) {
        throw 'Use a temporary password from 16 to 127 characters.'
    }
    $expires = [DateTime]::UtcNow.AddHours($Hours)
    $ownerGuid = [Guid]::NewGuid()
    $owner = $ownerGuid.ToString('N')
    $leaseName = "$owner.lease"
    $leaseFile = Join-Path $directory $leaseName

    $null = [IO.Directory]::CreateDirectory($directory)
    try {
        $acl = Get-Acl -LiteralPath $directory
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $identity = [Security.Principal.SecurityIdentifier]::new($sid)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.SetAccessRule($rule)
        }
        Set-Acl -LiteralPath $directory -AclObject $acl
        [IO.File]::WriteAllText($ownerFile, $owner)
    } catch {
        if (-not [IO.File]::Exists($ownerFile)) { [IO.Directory]::Delete($directory) }
        throw
    }

    try {
        $account = New-LocalUser -Name $accountName -FullName 'ExamLab Diagnostics' -Description "ExamLabDiag:$owner" `
            -Password $Password -AccountExpires $expires.ToLocalTime() -UserMayNotChangePassword -Disabled

        $snapshot = @{
            Name = 'Get-ExamLabDiagnosticSnapshot'
            ScriptBlock = {
                param([ValidateSet('Task','Events')][string]$Section = 'Task')

                $programFiles = [Environment]::GetFolderPath('ProgramFiles')
                $lease = Join-Path (Join-Path $programFiles 'ExamLabDiagnosticAccess') $ExamLabDiagnosticLeaseName
                if (-not [IO.File]::Exists($lease) -or
                    [DateTime]::ParseExact([IO.File]::ReadAllText($lease), 'o',
                        [Globalization.CultureInfo]::InvariantCulture, 'RoundtripKind') -le [DateTime]::UtcNow) {
                    throw 'Diagnostic access has expired or been revoked.'
                }

                if ($Section -eq 'Task') {
                    $scheduler = New-Object -ComObject 'Schedule.Service'
                    $scheduler.Connect()
                    foreach ($task in $scheduler.GetFolder('\').GetTasks(1)) {
                        if ($task.Name -like 'ExamLab-*') {
                            [pscustomobject]@{
                                Name = $task.Name
                                State = [int]$task.State
                                LastTaskResult = $task.LastTaskResult
                                Xml = $task.Xml
                                Dacl = $task.GetSecurityDescriptor(4)
                            }
                        }
                    }
                    return
                }

                $since = [DateTime]::UtcNow.AddHours(-2)
                foreach ($target in @(
                    @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = $since }
                    @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $since }
                )) {
                    Get-WinEvent -FilterHashtable $target -MaxEvents 100 -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.LogName -eq 'Application' -or
                                ($_.Properties | Where-Object { $_.Value -is [string] -and $_.Value -like '\ExamLab-*' })
                        } | ForEach-Object { $_.ToXml() }
                }
            }
        }
        New-PSSessionConfigurationFile -Path $configurationFile -Guid $ownerGuid -SessionType RestrictedRemoteServer `
            -LanguageMode NoLanguage -RunAsVirtualAccount -FunctionDefinitions $snapshot -VisibleFunctions $snapshot.Name `
            -VariableDefinitions @{ Name = 'ExamLabDiagnosticLeaseName'; Value = $leaseName }
        if (-not (Test-PSSessionConfigurationFile -Path $configurationFile)) {
            throw 'Windows rejected the diagnostic session configuration.'
        }
        $sid = $account.SID.Value
        $options = New-PSTransportOption -IdleTimeoutSec 300 -MaxIdleTimeoutSec 600 -MaxSessionsPerUser 2
        Register-PSSessionConfiguration -Name $endpointName -Path $configurationFile -Force -TransportOption $options `
            -SecurityDescriptorSddl "O:BAG:BAD:P(A;;GX;;;$sid)" | Out-Null
        [IO.File]::WriteAllText($leaseFile, $expires.ToString('o', [Globalization.CultureInfo]::InvariantCulture))
        Enable-LocalUser -SID $account.SID
    } catch {
        $failure = $_
        try { Remove-DiagnosticAccess }
        catch { Write-Warning "Diagnostic access cleanup requires Disable: $($_.Exception.Message)" }
        throw $failure
    }

    [pscustomobject]@{
        Endpoint = $endpointName
        Enabled = $true
        Account = "$env:COMPUTERNAME\$accountName"
        SourceIPv4 = $SourceIPv4.ToString()
        Port = $port
        ExpiresUtc = $expires.ToString('o')
    }
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
