#requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Disable', 'Enable', 'Uninstall')][string]$Action)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if ($PSVersionTable.PSEdition -ne 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'Open PowerShell 7 x64.'
}
$code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab'
$core = Join-Path $code 'ExamLabMaintenance.Core.ps1'
if ($PSScriptRoot -ine $code) { throw 'Run the installed ExamLab maintenance entry point.' }
foreach ($path in $code, $PSCommandPath, $core) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Unexpected reparse point: $path."
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $powershell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
    $process = Start-Process -FilePath $powershell -Verb RunAs -Wait -PassThru -ArgumentList (
        '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Action {1}' -f $PSCommandPath, $Action)
    exit $process.ExitCode
}

. $core
Assert-ExamLabProtectedPath $examLabCodePath -Readable
Assert-ExamLabProtectedPath $PSCommandPath -Readable
Assert-ExamLabProtectedPath $core -Readable

function Assert-ExamLabNormalReport($Report) {
    if ($Report.OwnSourceNormal -ne $true -or $Report.Normal.SourceCleanupCompleted -ne $true -or
        $Report.Conflicts.Count -or $Report.Normal.Collection.Errors.Count) {
        throw 'ExamLab normal was not verified. See the latest normal.log.'
    }
}

function Set-ExamLabTasksEnabled([bool]$Enabled) {
    foreach ($name in $examLabTaskNames) {
        # The local emergency normal task remains available even when polling is disabled.
        if ($name -eq 'ExamLab-Local-normal' -or ($Enabled -and $name -eq $examLabPollTask)) { continue }
        $task = Get-ExamLabTask $name
        if (-not $task) {
            if ($Enabled) { throw "Required task $name is missing." }
            continue
        }
        if ($Enabled -and $task.State -eq 'Disabled') {
            Enable-ScheduledTask -InputObject $task | Out-Null
        } elseif (-not $Enabled -and $task.State -ne 'Disabled') {
            Disable-ScheduledTask -InputObject $task | Out-Null
            if ($task.State -in @('Running', 'Queued')) { Stop-ScheduledTask -InputObject $task }
        }
    }
}

function Remove-ExamLabTree($Ownership, [string]$Path, [switch]$RetainMaintenance) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $tree = $Ownership.Trees.PSObject.Properties[$Path]
    if (-not (Test-ExamLabOwnedResource $Ownership $Path) -or -not $tree) {
        Write-Warning "Retaining $Path because ownership is unconfirmed."
        return
    }
    $items = @(Get-ExamLabProtectedTreeItems $Path | Sort-Object FullName -Descending)
    foreach ($item in $items) {
        if ($RetainMaintenance -and $item -is [IO.FileInfo] -and $item.DirectoryName -ieq $Path -and
            $item.Name -in @('ExamLabMaintenance.ps1', 'ExamLabMaintenance.Core.ps1')) { continue }
        $record = $tree.Value.PSObject.Properties[$item.FullName.Substring($Path.Length + 1)]
        if (-not $record) {
            Write-Warning "Retaining unrecorded resource $($item.FullName)."
            continue
        }
        if ($item.PSIsContainer) {
            if ($record.Value -ceq 'Directory' -and -not @(Get-ChildItem -LiteralPath $item.FullName -Force).Count) {
                [IO.Directory]::Delete($item.FullName)
            }
        } elseif ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ceq $record.Value) {
            Remove-Item -LiteralPath $item.FullName -Force
        } else { Write-Warning "Retaining changed file $($item.FullName)." }
    }
    if (-not @(Get-ChildItem -LiteralPath $Path -Force).Count) { [IO.Directory]::Delete($Path) }
}

function Remove-ExamLabRecordedFile($Ownership, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $record = $Ownership.Trees.PSObject.Properties[$Path]
    if ((Test-ExamLabOwnedResource $Ownership $Path) -and $record -and $item -is [IO.FileInfo] -and
        -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $record.Value) {
        [IO.File]::Delete($Path)
    } else { Write-Warning "Retaining changed or reused file $Path." }
}

function Remove-ExamLabRegistrationState($Ownership) {
    $registrationPath = Join-Path $examLabStatePath 'controller-registration.json'
    if (-not (Test-Path -LiteralPath $registrationPath)) { return }
    Assert-ExamLabProtectedPath $examLabStatePath
    Assert-ExamLabProtectedPath $registrationPath
    $proof = $Ownership.Trees.PSObject.Properties[$registrationPath]
    if (-not (Test-ExamLabOwnedResource $Ownership $registrationPath) -or -not $proof -or
        (Get-Item -LiteralPath $registrationPath -Force) -isnot [IO.FileInfo] -or
        (Get-FileHash -LiteralPath $registrationPath -Algorithm SHA256).Hash -cne $proof.Value) {
        Write-Warning 'Retaining the local registration and controller state because ownership is unconfirmed.'
        return
    }

    $locks = [Collections.Generic.List[IO.FileStream]]::new()
    try {
        foreach ($name in 'operation.lock','file-trace-worker.lock') {
            $path = Join-Path $examLabStatePath $name
            if (Test-Path -LiteralPath $path) {
                Assert-ExamLabProtectedPath $path
                $locks.Add([IO.File]::Open($path, 'Open', 'ReadWrite', 'None'))
            }
        }
        try {
            $registration = Read-ExamLabProtectedJson $registrationPath
            if ($registration.deviceId -isnot [string] -or $registration.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z') {
                throw 'registration'
            }
            $files = @(foreach ($name in 'controller-state.json','controller-health.json','controller-policy-probe.json','file-trace-attempt.json') {
                $path = Join-Path $examLabStatePath $name
                try { $item = Get-Item -LiteralPath $path -Force }
                catch [Management.Automation.ItemNotFoundException] { continue }
                Assert-ExamLabProtectedPath $path
                if ($item -isnot [IO.FileInfo]) { throw 'file type' }
                if ($name -eq 'controller-state.json') {
                    $state = Read-ExamLabProtectedJson $path
                    if (-not $state.PSObject.Properties['Assignment'] -or
                        ($null -ne $state.Assignment -and $state.Assignment.deviceId -cne $registration.deviceId)) {
                        throw 'controller state'
                    }
                } elseif ($name -eq 'file-trace-attempt.json' -and
                    (Read-ExamLabProtectedJson $path).deviceId -cne $registration.deviceId) {
                    throw 'trace state'
                }
                $item
            })
        } catch { throw 'The protected controller or file trace state could not be matched to the installed ExamLab registration.' }
        foreach ($file in $files) { [IO.File]::Delete($file.FullName) }
        # Сохраняем доказательство владения до удаления последней записи состояния.
        Remove-ExamLabRecordedFile $Ownership $registrationPath
    } catch {
        throw "ExamLab local uninstall is incomplete because local registration state could not be removed. $($_.Exception.Message)"
    } finally { foreach ($lock in $locks) { $lock.Dispose() } }
}

function Remove-ExamLabEnrollmentSecrets {
    $directory = Join-Path $examLabReportsPath 'Enrollment'
    try {
        try { $item = Get-Item -LiteralPath $directory -Force }
        catch [Management.Automation.ItemNotFoundException] { return }
        Assert-ExamLabProtectedPath $examLabReportsPath
        Assert-ExamLabProtectedPath $directory
        if ($item -isnot [IO.DirectoryInfo]) { throw 'Expected the protected ExamLab enrollment directory.' }

        # Только штатные входные файлы и их временные копии от атомарной записи.
        $files = @(Get-ChildItem -LiteralPath $directory -Force | Where-Object {
            $_.Name -match '\A(?:enrollment\.json|pc\.json|registration\.json|wazuh\.key)(?:\.[0-9a-f]{32}\.tmp)?\z'
        } | Sort-Object { $_.Name -eq 'enrollment.json' })
        foreach ($file in $files) {
            if ($file -isnot [IO.FileInfo]) { throw "Expected an ExamLab enrollment file at $($file.FullName)." }
            Assert-ExamLabProtectedPath $file.FullName
        }
        foreach ($file in $files) { [IO.File]::Delete($file.FullName) }
    } catch {
        throw "ExamLab local uninstall is incomplete because enrollment data could not be removed from $directory. $($_.Exception.Message)"
    }
}

$maintenance = Open-ExamLabMaintenanceLock
try {
    $ownership = Read-ExamLabOwnership
    if (-not $ownership.Version) { throw 'ExamLab has no verified local installation.' }
    Assert-ExamLabArp $ownership
    if ($ownership.Removing -and $Action -ne 'Uninstall') { throw 'Finish the previous local uninstall first.' }
    foreach ($name in $examLabTaskNames) { $null = Get-ExamLabTask $name }
    $pollWasEnabled = Suspend-ExamLabPolling
    if (-not $ownership.Removing) {
        try {
            Assert-ExamLabNormalReport (Invoke-ExamLabSystemTask 'normal')
            Assert-ExamLabInactive
        } catch {
            if ($pollWasEnabled -and -not $ownership.Disabled) { Start-ExamLabPolling }
            throw
        }
    }

    if ($Action -eq 'Enable') {
        Set-ExamLabTasksEnabled $true
        $ownership.Disabled = $false
        Complete-ExamLabInstallation $ownership $ownership.Version
        Write-Host 'ExamLab polling is enabled.'
        return
    }

    $ownership.Disabled = $true
    $ownership.Removing = $Action -eq 'Uninstall'
    Save-ExamLabOwnership $ownership
    if (Test-Path -LiteralPath $examLabFinalReport) {
        Assert-ExamLabProtectedPath $examLabFinalReport
        [IO.File]::Delete($examLabFinalReport)
    }
    Set-ExamLabTasksEnabled $false
    if ($Action -eq 'Disable') {
        Write-Host 'ExamLab polling and exam tasks are disabled. The local normal task is available.'
        return
    }

    $wazuhMarker = 'HKLM:\SOFTWARE\ExamLabWazuhPilot'
    if (Test-Path -LiteralPath $wazuhMarker) {
        $wazuhFolder = Join-Path $examLabProgramFiles 'ExamLabWazuh'
        $wazuhScript = Join-Path $wazuhFolder 'Install-ExamLabWazuh.ps1'
        Assert-ExamLabProtectedPath $wazuhFolder -Readable
        Assert-ExamLabProtectedPath $wazuhScript -Readable
        $hash = Get-ItemPropertyValue -LiteralPath $wazuhMarker -Name 'SourceSha256'
        if ((Get-FileHash -LiteralPath $wazuhScript -Algorithm SHA256).Hash -cne $hash) { throw 'The installed Wazuh runner differs from its ownership record.' }
        $PSNativeCommandUseErrorActionPreference = $false
        & $examLabPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wazuhScript -Action Uninstall
        if ($LASTEXITCODE -ne 0) { throw "Local Wazuh removal failed with exit code $LASTEXITCODE." }
    }

    $alertKey = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ExamLab-Alert'
    foreach ($resource in @($alertKey, 'ExamLab-Alert event source')) {
        $path = if ($resource -eq $alertKey) { $alertKey } else { $sourceKey }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $mutable = if ($resource -eq $alertKey) { @('Status') } else { @() }
        $record = $ownership.Trees.PSObject.Properties[$resource]
        if ((Test-ExamLabOwnedResource $ownership $resource) -and $record -and
            (Get-ExamLabRegistryFingerprint $path $mutable) -ceq $record.Value) {
            if ($resource -eq $alertKey) { Remove-Item -LiteralPath $alertKey }
            else {
                Add-Type -AssemblyName System.Diagnostics.EventLog
                [Diagnostics.EventLog]::DeleteEventSource('ExamLab-Alert')
            }
        } else { Write-Warning "Retaining changed or reused registration $path." }
    }
    foreach ($name in 'ExamLab - Moodle.lnk', 'ExamLab - IDEA.lnk') {
        Remove-ExamLabRecordedFile $ownership (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $name)
    }
    $cache = Join-Path $examLabProgramFiles 'ExamLabGradleCache'
    foreach ($name in 'ExamLabAlert', 'ExamLabBrowser', 'ExamLabIdea', 'ExamLabGradleCache') {
        if ($name -ceq 'ExamLabGradleCache' -and [Environment]::GetEnvironmentVariable('GRADLE_RO_DEP_CACHE', 'Machine') -ceq $cache) {
            Write-Warning 'Retaining the Gradle cache because the reused machine environment still references it.'
            continue
        }
        Remove-ExamLabTree $ownership (Join-Path $examLabProgramFiles $name)
    }

    . (Join-Path $examLabCodePath 'ExamLabRootTrust.ps1')
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        foreach ($certificate in $store.Certificates) {
            $record = $ownership.Roots.PSObject.Properties[(Get-CertificateSha256 $certificate.RawData)]
            if ($record -and $record.Value -ceq 'Created') { $store.Remove($certificate) }
        }
    } finally { $store.Dispose() }

    $reusedTask = $false
    foreach ($name in $examLabTaskNames | Sort-Object { $_ -eq 'ExamLab-Local-normal' }) {
        $task = Get-ExamLabTask $name
        if (-not $task) { continue }
        if (Test-ExamLabOwnedResource $ownership $name) {
            Unregister-ScheduledTask -InputObject $task -Confirm:$false
        } else {
            $reusedTask = $true
            Write-Warning "Retaining task $name because it existed before this installation."
        }
    }
    # Остальные компоненты уже сняты. До удаления точки входа оставляем возможность безопасного повтора.
    Remove-ExamLabRegistrationState $ownership
    Remove-ExamLabEnrollmentSecrets
    $ownedArp = Test-ExamLabOwnedResource $ownership $examLabArpKey
    if ($ownedArp) {
        if (Test-Path -LiteralPath $examLabArpKey) { Remove-Item -LiteralPath $examLabArpKey }
    } else { Write-Warning 'Retaining the reused ExamLab app entry.' }
    if (-not $reusedTask -and $ownedArp) {
        Remove-ExamLabTree $ownership $examLabCodePath -RetainMaintenance
    }
    $ownership.Version = $null
    $ownership.Roots = [pscustomobject]@{}
    $ownership.Disabled = $false
    $ownership.Removing = $false
    # Retain proofs for leftover resources. A later install must not claim those left deliberately.
    Save-ExamLabOwnership $ownership
    if (-not $reusedTask -and $ownedArp) {
        Remove-ExamLabTree $ownership $examLabCodePath
    } else { Write-Warning 'Retaining the code needed by existing tasks or the app entry.' }
    Write-Host 'ExamLab removal completed. Shared PC preparation and local records are retained.'
} finally { $maintenance.Dispose() }
