# Shared by the trusted bootstrap and the installed local maintenance entry point.
$examLabProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
$examLabCodePath = Join-Path $examLabProgramFiles 'ExamLab'
$examLabStatePath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
$examLabReportsPath = Join-Path $examLabProgramFiles 'ExamLabSetupReports'
$examLabFinalReport = Join-Path $examLabReportsPath 'install-final.json'
$examLabOwnershipPath = Join-Path $examLabReportsPath 'ownership.json'
$examLabInstallChangesPath = Join-Path $examLabReportsPath 'installation-pending.json'
$examLabPowerShell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
$examLabPollTask = 'ExamLab-Controller-Poll'
$examLabTaskNames = @('ExamLab-Local-prepare', 'ExamLab-Local-check', 'ExamLab-Local-exam', 'ExamLab-Local-normal', $examLabPollTask)
$examLabArpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ExamLab'
$examLabTaskDacl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
# BEGIN EXAMLAB BOOTSTRAP PRIVATE PATHS
$script:examLabTrustedSids = $null

function Get-ExamLabTrustedSids {
    if (-not $script:examLabTrustedSids) {
        $script:examLabTrustedSids = @('S-1-5-18', 'S-1-5-32-544') + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    }
    $script:examLabTrustedSids
}

function Assert-ExamLabProtectedPath([string]$Path, [switch]$Readable) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $Path." }
    $admins = Get-ExamLabTrustedSids
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $admins) {
        throw "Unexpected owner: $Path."
    }
    $writes = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $admins) { continue }
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($Readable -and $rule.IsInherited -and
            $rule.IdentityReference.Value -eq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { continue }
        if (-not $Readable -or ($rule.FileSystemRights -band $writes)) { throw "Unsafe access: $Path." }
    }
}

function New-ExamLabPrivateDirectory([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($value in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = [Security.Principal.SecurityIdentifier]::new($value)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { [void][IO.Directory]::CreateDirectory($Path, $acl) }
    else { [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path) }
}
# END EXAMLAB BOOTSTRAP PRIVATE PATHS

function Write-ExamLabMaintenanceJson([string]$Path, $Value, [switch]$InstallChange) {
    $track = $InstallChange -and (Test-Path -LiteralPath $examLabInstallChangesPath)
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    if ($track) { Save-ExamLabInstallTemporaryFile $temporary $false }
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 10 -Compress))
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ($track) {
            Set-ExamLabInstallFile $temporary $Path
        } elseif ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { [IO.File]::Delete($temporary) }
}

function Read-ExamLabProtectedJson([string]$Path) {
    Assert-ExamLabProtectedPath $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', [IO.FileShare]::Read -bor [IO.FileShare]::Delete)
    try {
        if ($stream.Length -gt 4MB) { throw "Unexpected JSON size: $Path." }
        $reader = [IO.StreamReader]::new($stream)
        try { $reader.ReadToEnd() | ConvertFrom-Json -DateKind String } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Test-ExamLabStoppedAssignment($State) {
    if ($State -isnot [pscustomobject] -or -not $State.PSObject.Properties['Assignment']) { return $false }
    if ($null -eq $State.Assignment) { return $true }
    if ($State.Assignment.mode -ceq 'normal') { return $true }
    if ($State.Assignment.mode -cne 'exam') { return $false }
    if ($State.PSObject.Properties['Result'] -and $State.Result -and $State.Result.reason -ceq 'local-normal-collection-stop-failed') { return $false }
    return ($State.Assignment.examId -is [string] -and $State.Assignment.examId -and
        $State.StoppedExamId -ceq $State.Assignment.examId -and $State.LocalNormal -and
        $State.LocalNormal.SourceCleanupCompleted -is [bool] -and $State.LocalNormal.SourceCleanupCompleted -and
        $State.LocalNormal.BaselineUnknown -is [bool] -and -not $State.LocalNormal.BaselineUnknown)
}

function Assert-ExamLabInactive {
    if (-not (Test-Path -LiteralPath $examLabStatePath)) { return }
    Assert-ExamLabProtectedPath $examLabStatePath
    foreach ($name in 'state.json', 'network-owned.json') {
        if (Test-Path -LiteralPath (Join-Path $examLabStatePath $name)) {
            throw 'ExamLab maintenance requires local normal and no unfinished policy changes.'
        }
    }
    $usbPath = Join-Path $examLabStatePath 'usb.json'
    if ((Test-Path -LiteralPath $usbPath) -and (Read-ExamLabProtectedJson $usbPath).State -cne 'Normal') {
        throw 'ExamLab maintenance requires local normal and no unfinished USB change.'
    }
    $modePath = Join-Path $examLabStatePath 'mode.json'
    if (Test-Path -LiteralPath $modePath) {
        $mode = Read-ExamLabProtectedJson $modePath
        if (-not $mode -or $mode.LastCompletedMode -cnotin @($null, 'normal')) {
            throw 'ExamLab maintenance requires local normal.'
        }
    }
    $controllerPath = Join-Path $examLabStatePath 'controller-state.json'
    if ((Test-Path -LiteralPath $controllerPath) -and
        -not (Test-ExamLabStoppedAssignment (Read-ExamLabProtectedJson $controllerPath))) {
        throw 'An exam is still assigned. Finish it with local normal before maintenance.'
    }
}

function Open-ExamLabMaintenanceLock {
    if (-not (Test-Path -LiteralPath $examLabInstallChangesPath)) { Assert-ExamLabInactive }
    if (-not (Test-Path -LiteralPath $examLabReportsPath)) { New-ExamLabPrivateDirectory $examLabReportsPath }
    Assert-ExamLabProtectedPath $examLabReportsPath
    $path = Join-Path $examLabReportsPath 'maintenance.lock'
    if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
    try { [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'Another ExamLab installation or maintenance action is running.' }
}

function Get-ExamLabTaskDefinition([string]$Name) {
    if ($Name -cnotin $examLabTaskNames) { throw "Unexpected task name: $Name." }
    $poll = $Name -ceq $examLabPollTask
    $arguments = if ($poll) {
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action poll' -f (Join-Path $examLabCodePath 'exam-lab.ps1')
    } else {
        '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $examLabCodePath ('task-' + $Name.Substring('ExamLab-Local-'.Length) + '.ps1'))
    }
    $trigger = if ($poll) {
        [ordered]@{
            Type = 8; Enabled = $true; StartBoundary = ''; EndBoundary = ''; Delay = 'PT0S'
            ExecutionTimeLimit = 'P3D'; Interval = 'PT0S'; Duration = 'PT0S'; StopAtDurationEnd = $false
        }
    }
    [ordered]@{
        Actions = @([ordered]@{ Type = 0; Path = $examLabPowerShell; Arguments = $arguments; WorkingDirectory = '' })
        Principal = [ordered]@{ UserId = 'S-1-5-18'; GroupId = ''; LogonType = 5; RunLevel = 1 }
        Triggers = @($trigger | Where-Object { $null -ne $_ })
        Settings = [ordered]@{
            ExecutionTimeLimit = $(if ($poll) { 'PT0S' } else { 'PT10M' })
            MultipleInstances = 2; DisallowStartIfOnBatteries = $false; StopIfGoingOnBatteries = $false
            RestartCount = $(if ($poll) { 3 } else { 0 })
            RestartInterval = $(if ($poll) { 'PT1M' } else { 'PT0S' })
            AllowDemandStart = $true; AllowHardTerminate = $true; StartWhenAvailable = $false
            RunOnlyIfIdle = $false; RunOnlyIfNetworkAvailable = $false; WakeToRun = $false
            Hidden = $false; DeleteExpiredTaskAfter = 'PT0S'; Priority = 7
        }
        Dacl = $examLabTaskDacl
    }
}

function Get-ExamLabTaskFolder {
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\')
}

function Get-ExamLabRegisteredTask([string]$Name, $Folder = (Get-ExamLabTaskFolder)) {
    try { $Folder.GetTask($Name) }
    catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.HResult -ne -2147024894) { throw } # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
    }
}

function ConvertTo-ExamLabTaskDuration([string]$Value, [string]$Default = 'PT0S') {
    if (-not $Value) { return $Default }
    [Xml.XmlConvert]::ToString([Xml.XmlConvert]::ToTimeSpan($Value))
}

function ConvertTo-ExamLabTaskDacl([string]$Value) {
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Value)
    $rules = @(foreach ($ace in $descriptor.DiscretionaryAcl) {
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        [Convert]::ToHexString($bytes)
    })
    [ordered]@{
        Protected = [bool]($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        CanonicalRules = @($rules | Sort-Object)
    }
}

function Compare-ExamLabTaskFields([string]$Field, $Expected, $Actual) {
    if ($Expected -is [Collections.IDictionary] -and $Actual -is [Collections.IDictionary]) {
        foreach ($key in $Expected.Keys) { Compare-ExamLabTaskFields "$Field.$key" $Expected[$key] $Actual[$key] }
    } elseif ($Expected -is [array] -and $Actual -is [array] -and $Expected.Count -eq $Actual.Count) {
        for ($index = 0; $index -lt $Expected.Count; $index++) {
            Compare-ExamLabTaskFields "$Field[$index]" $Expected[$index] $Actual[$index]
        }
    } elseif ($Field -eq 'Task.Actions[0].Path' -and $Expected -ieq $Actual) {
        return
    } elseif ($Expected -is [array] -or $Actual -is [array] -or $Expected -cne $Actual) {
        [pscustomobject]@{ Field = $Field; Expected = $Expected; Actual = $Actual }
    }
}

function Get-ExamLabTaskCheck([string[]]$Names = $examLabTaskNames) {
    $folder = Get-ExamLabTaskFolder
    $ownership = Read-ExamLabOwnership
    foreach ($name in $Names) {
        $expected = Get-ExamLabTaskDefinition $name
        $registered = Get-ExamLabRegisteredTask $name $folder
        $actual = $null
        $enabled = $false
        $state = $null
        $source = $null
        $owned = $false
        $differences = @()
        if ($registered) {
            $definition = $registered.Definition
            $principal = $definition.Principal
            $user = [string]$principal.UserId
            if ($user -and $user -notmatch '^S-\d') {
                try { $user = [Security.Principal.NTAccount]::new($user).Translate([Security.Principal.SecurityIdentifier]).Value }
                catch [Security.Principal.IdentityNotMappedException] { }
            }
            $settings = [ordered]@{}
            foreach ($key in $expected.Settings.Keys) {
                $value = $definition.Settings.$key
                $settings[$key] = if ($expected.Settings[$key] -is [string]) {
                    ConvertTo-ExamLabTaskDuration $value
                } else { $value }
            }
            $actual = [ordered]@{
                Actions = @(for ($index = 1; $index -le $definition.Actions.Count; $index++) {
                    $action = $definition.Actions.Item($index)
                    $fields = [ordered]@{ Type = [int]$action.Type }
                    if ($action.Type -eq 0) {
                        foreach ($key in 'Path', 'Arguments', 'WorkingDirectory') { $fields[$key] = [string]$action.$key }
                    }
                    $fields
                })
                Principal = [ordered]@{
                    UserId = $user; GroupId = [string]$principal.GroupId
                    LogonType = [int]$principal.LogonType; RunLevel = [int]$principal.RunLevel
                }
                Triggers = @(for ($index = 1; $index -le $definition.Triggers.Count; $index++) {
                    $trigger = $definition.Triggers.Item($index)
                    $fields = [ordered]@{
                        Type = [int]$trigger.Type; Enabled = [bool]$trigger.Enabled
                        StartBoundary = [string]$trigger.StartBoundary; EndBoundary = [string]$trigger.EndBoundary
                        ExecutionTimeLimit = ConvertTo-ExamLabTaskDuration $trigger.ExecutionTimeLimit 'P3D'
                        Interval = ConvertTo-ExamLabTaskDuration $trigger.Repetition.Interval
                        Duration = ConvertTo-ExamLabTaskDuration $trigger.Repetition.Duration
                        StopAtDurationEnd = [bool]$trigger.Repetition.StopAtDurationEnd
                    }
                    if ($trigger.Type -eq 8) { $fields.Delay = ConvertTo-ExamLabTaskDuration $trigger.Delay }
                    $fields
                })
                Settings = $settings
                Dacl = [string]$registered.GetSecurityDescriptor(4) # DACL_SECURITY_INFORMATION
            }
            $expectedDacl = ConvertTo-ExamLabTaskDacl $expected.Dacl
            $actualDacl = ConvertTo-ExamLabTaskDacl $actual.Dacl
            $differences = @(foreach ($section in 'Actions', 'Principal', 'Triggers', 'Settings') {
                Compare-ExamLabTaskFields "Task.$section" $expected[$section] $actual[$section]
            })
            if (@(Compare-ExamLabTaskFields 'Task.Dacl' $expectedDacl $actualDacl).Count) {
                $differences += [pscustomobject]@{ Field = 'Task.Dacl'; Expected = $expected.Dacl; Actual = $actual.Dacl }
            }
            $enabled = [bool]$registered.Enabled
            $state = [int]$registered.State
            $source = [string]$definition.RegistrationInfo.Source
            $proof = $ownership.TasksVerified.PSObject.Properties[$name]
            if ($proof -and (Test-ExamLabOwnedResource $ownership $name)) {
                $owned = ($proof.Value -is [string] -and $proof.Value -ceq $source) -or
                    ($proof.Value -is [bool] -and $proof.Value -and -not $source)
            }
        }
        [pscustomobject]@{
            Name = $name; Exists = [bool]$registered; Owned = $owned; Enabled = $enabled; State = $state
            Source = $source; Expected = $expected; Actual = $actual; Differences = $differences
        }
    }
}

function Assert-ExamLabTaskCheck($Check, [switch]$RequireOwnership) {
    if ($Check.Differences.Count) {
        throw "Scheduled task $($Check.Name) differs in $($Check.Differences.Field -join ', ')."
    }
    if ($Check.Exists -and $RequireOwnership -and -not $Check.Owned) {
        throw "Scheduled task $($Check.Name) has unconfirmed ownership."
    }
}

function Get-ExamLabTask([string]$Name, [switch]$RequireOwnership) {
    $check = Get-ExamLabTaskCheck $Name
    Assert-ExamLabTaskCheck $check -RequireOwnership:$RequireOwnership
    if ($check.Exists) { Get-ScheduledTask -TaskName $Name -TaskPath '\' }
}

function New-ExamLabScheduledTask([string]$Name, [string]$Source) {
    $expected = Get-ExamLabTaskDefinition $Name
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $definition = $scheduler.NewTask(0)
    $definition.RegistrationInfo.Source = $Source
    $definition.RegistrationInfo.Description = 'ExamLab'
    foreach ($key in 'UserId', 'LogonType', 'RunLevel') { $definition.Principal.$key = $expected.Principal[$key] }
    foreach ($item in $expected.Actions) {
        $action = $definition.Actions.Create($item.Type)
        foreach ($key in 'Path', 'Arguments', 'WorkingDirectory') { $action.$key = $item[$key] }
    }
    foreach ($item in $expected.Triggers) {
        $trigger = $definition.Triggers.Create($item.Type)
        $trigger.Enabled = $item.Enabled
        # Empty boundaries, zero delay/repetition and the default execution limit are the scheduler defaults.
    }
    foreach ($key in $expected.Settings.Keys) {
        if ($key -eq 'DeleteExpiredTaskAfter' -or ($key -eq 'RestartInterval' -and -not $expected.Settings.RestartCount)) { continue }
        $definition.Settings.$key = $expected.Settings[$key]
    }
    $definition.Settings.Enabled = $false
    # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE. Existing tasks are never overwritten here.
    $null = $scheduler.GetFolder('\').RegisterTaskDefinition($Name, $definition, 0x12,
        $expected.Principal.UserId, $null, $expected.Principal.LogonType, $expected.Dacl)
}

function Suspend-ExamLabPolling {
    $operation = $null
    try {
        if (Test-Path -LiteralPath $examLabStatePath) {
            Assert-ExamLabProtectedPath $examLabStatePath
            $path = Join-Path $examLabStatePath 'operation.lock'
            if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
            $operation = [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None')
        }
        Assert-ExamLabInactive
        $check = Get-ExamLabTaskCheck $examLabPollTask
        Assert-ExamLabTaskCheck $check -RequireOwnership
        $task = if ($check.Exists) { Get-ScheduledTask -TaskName $examLabPollTask -TaskPath '\' }
        if (-not $task) { return $false }
        $wasEnabled = $task.State -ne 'Disabled'
        try {
            if ($wasEnabled) {
                Save-ExamLabTaskEnabledChange $check
                Disable-ScheduledTask -InputObject $task | Out-Null
            }
            $scheduler = New-Object -ComObject Schedule.Service
            $scheduler.Connect()
            $registered = $scheduler.GetFolder('\').GetTask($examLabPollTask)
            if ($registered.GetInstances(0).Count -gt 0) { Stop-ScheduledTask -InputObject $task }
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while ($registered.GetInstances(0).Count -gt 0) {
                if ($timer.Elapsed.TotalSeconds -ge 5) { throw 'The poll task could not be stopped.' }
                Start-Sleep -Milliseconds 100
            }
            return $wasEnabled
        } catch {
            if ($wasEnabled) { Enable-ScheduledTask -InputObject $task | Out-Null }
            throw
        }
    } finally { if ($operation) { $operation.Dispose() } }
}

function Start-ExamLabPolling {
    $task = Get-ExamLabTask $examLabPollTask -RequireOwnership
    if (-not $task) { throw 'The ExamLab poll task is missing.' }
    if ($task.State -eq 'Disabled') { $task = Enable-ScheduledTask -InputObject $task }
    if ($task.State -ne 'Running') { Start-ScheduledTask -InputObject $task }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ((Get-ExamLabTask $examLabPollTask).State -eq 'Running') { return }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 10)
    throw 'The ExamLab poll task did not start.'
}

function Invoke-ExamLabSystemTask([string]$Action, [int]$TimeoutSeconds = 120) {
    $taskName = 'ExamLab-Local-' + $Action
    $task = Get-ExamLabTask $taskName -RequireOwnership
    if (-not $task -or $task.State -ne 'Ready') { throw "$taskName is not ready." }
    $reportPath = Join-Path $examLabStatePath ($Action + '.log')
    $previousReport = [IO.File]::GetLastWriteTimeUtc($reportPath)
    $previousRun = (Get-ScheduledTaskInfo -InputObject $task).LastRunTime
    if ($previousRun -ge (Get-Date).AddSeconds(-1)) { Start-Sleep -Seconds 2 }
    Start-ScheduledTask -InputObject $task
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 500
        $task = Get-ExamLabTask $taskName
        $result = Get-ScheduledTaskInfo -InputObject $task
        if ($task.State -eq 'Ready' -and $result.LastRunTime -gt $previousRun -and $result.LastTaskResult -ne 0x41301) {
            if ($result.LastTaskResult -ne 0) { throw "$taskName failed with result $($result.LastTaskResult). See $reportPath." }
            if ([IO.File]::GetLastWriteTimeUtc($reportPath) -gt $previousReport) {
                return (Read-ExamLabProtectedJson $reportPath)
            }
        }
    } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw "Timed out waiting for $taskName. See $reportPath."
}

function Read-ExamLabOwnership {
    if (Test-Path -LiteralPath $examLabOwnershipPath) {
        $state = Read-ExamLabProtectedJson $examLabOwnershipPath
        if (-not $state -or $state.Schema -ne 1 -or $state.Disabled -isnot [bool] -or
            $state.Resources -isnot [pscustomobject] -or $state.Trees -isnot [pscustomobject] -or
            $state.Roots -isnot [pscustomobject] -or $state.TasksVerified -isnot [pscustomobject]) { throw 'Invalid ExamLab ownership record.' }
        return $state
    }
    [pscustomobject]@{
        Schema = 1; Disabled = $false; Version = $null; RebootBootUtc = $null; Removing = $false
        Resources = [pscustomobject]@{}; Trees = [pscustomobject]@{}; Roots = [pscustomobject]@{}; TasksVerified = [pscustomobject]@{}
    }
}

function Save-ExamLabOwnership($Ownership) {
    Write-ExamLabMaintenanceJson $examLabOwnershipPath $Ownership -InstallChange
}

function Register-ExamLabResource($Ownership, [string]$Name, [bool]$Exists) {
    $record = $Ownership.Resources.PSObject.Properties[$Name]
    if (-not $record -or (-not $Exists -and $record.Value -cne 'Created')) {
        $kind = if ($Exists) { 'Reused' } else { 'Created' }
        Add-Member -InputObject $Ownership.Resources -NotePropertyName $Name -NotePropertyValue $kind -Force
        Save-ExamLabOwnership $Ownership
    }
    if (-not $Exists -and ($Ownership.Trees.PSObject.Properties[$Name] -or $Ownership.TasksVerified.PSObject.Properties[$Name])) {
        $Ownership.Trees.PSObject.Properties.Remove($Name)
        $Ownership.TasksVerified.PSObject.Properties.Remove($Name)
        Save-ExamLabOwnership $Ownership
    }
}

function Test-ExamLabOwnedResource($Ownership, [string]$Name) {
    $record = $Ownership.Resources.PSObject.Properties[$Name]
    return ($record -and $record.Value -ceq 'Created')
}

function Open-ExamLabInstallWorkerLock {
    Assert-ExamLabProtectedPath $examLabReportsPath
    $path = Join-Path $examLabReportsPath 'installation-worker.lock'
    if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
    try { [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'An ExamLab local installation worker is still running.' }
}

function Read-ExamLabInstallChanges {
    if (-not (Test-Path -LiteralPath $examLabInstallChangesPath)) { return }
    $journal = Read-ExamLabProtectedJson $examLabInstallChangesPath
    if ($journal.Schema -ne 1 -or $journal.Id -cnotmatch '\A[0-9a-f]{32}\z' -or
        $journal.Committed -isnot [bool] -or $journal.Changes -isnot [array]) {
        throw 'Invalid pending ExamLab installation record.'
    }
    $journal
}

function Start-ExamLabInstallChanges {
    if (Read-ExamLabInstallChanges) { throw 'Recover the previous ExamLab installation before applying changes.' }
    Write-ExamLabMaintenanceJson $examLabInstallChangesPath ([ordered]@{
        Schema = 1; Id = [Guid]::NewGuid().ToString('N'); Committed = $false; Changes = @()
    })
}

function Add-ExamLabInstallChange($Change) {
    $journal = Read-ExamLabInstallChanges
    if (-not $journal -or $journal.Committed) { throw 'No open ExamLab installation attempt.' }
    $journal.Changes += $Change
    Write-ExamLabMaintenanceJson $examLabInstallChangesPath $journal
}

function Add-ExamLabInstallResidual([string]$Target, [string]$Reason) {
    Add-ExamLabInstallChange ([ordered]@{ Kind = 'Residual'; Target = $Target; Reason = $Reason })
}

function Save-ExamLabInstallTemporaryFile([string]$Path, [bool]$Readable) {
    if (Test-Path -LiteralPath $Path) { throw "A temporary installation file already exists at $Path." }
    Add-ExamLabInstallChange ([ordered]@{ Kind = 'TemporaryFile'; Target = $Path; Readable = $Readable })
}

function Remove-ExamLabInstallTemporaryFile($Change) {
    if (-not (Test-Path -LiteralPath $Change.Target)) { return }
    Assert-ExamLabProtectedPath $Change.Target -Readable:$Change.Readable
    if (-not [IO.File]::Exists($Change.Target)) { throw "Expected a temporary file at $($Change.Target)." }
    [IO.File]::Delete($Change.Target)
}

function Get-ExamLabProtectedFileHash([string]$Path, [bool]$Readable) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Assert-ExamLabProtectedPath $Path -Readable:$Readable
    if (-not [IO.File]::Exists($Path)) { throw "Expected a protected file at $Path." }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Set-ExamLabInstallFile([string]$Staged, [string]$Target, [switch]$Readable) {
    $prior = Get-ExamLabProtectedFileHash $Target $Readable
    $next = Get-ExamLabProtectedFileHash $Staged $Readable
    if (-not $next) { throw "Missing staged installation file $Staged." }
    if ($prior -ceq $next) { return }
    $backup = $Target + '.' + [Guid]::NewGuid().ToString('N') + '.previous'
    Add-ExamLabInstallChange ([ordered]@{
        Kind = 'File'; Target = $Target; Staged = $Staged; Backup = $backup
        Prior = $prior; Applied = $next; Readable = [bool]$Readable
    })
    if ($prior) { [IO.File]::Replace($Staged, $Target, $backup) }
    else { [IO.File]::Move($Staged, $Target) }
}

function Remove-ExamLabInstallFile([string]$Target) {
    $prior = Get-ExamLabProtectedFileHash $Target $false
    if (-not $prior) { return }
    $backup = $Target + '.' + [Guid]::NewGuid().ToString('N') + '.previous'
    Add-ExamLabInstallChange ([ordered]@{
        Kind = 'File'; Target = $Target; Staged = $null; Backup = $backup
        Prior = $prior; Applied = $null; Readable = $false
    })
    [IO.File]::Move($Target, $backup)
}

function Save-ExamLabTaskEnabledChange($Check) {
    if (-not (Test-Path -LiteralPath $examLabInstallChangesPath)) { return }
    if (-not $Check.Owned) { throw "Cannot change an unconfirmed task: $($Check.Name)." }
    Add-ExamLabInstallChange ([ordered]@{
        Kind = 'TaskEnabled'; Target = $Check.Name; Source = $Check.Source; Prior = $Check.Enabled
    })
}

function Add-ExamLabInstallTask([string]$Name) {
    $journal = Read-ExamLabInstallChanges
    if (-not $journal) { throw 'No open ExamLab installation attempt.' }
    $source = 'ExamLab/' + $journal.Id
    Add-ExamLabInstallChange ([ordered]@{ Kind = 'TaskCreated'; Target = $Name; Source = $source })
    New-ExamLabScheduledTask $Name $source
    $source
}

function Remove-ExamLabInstallFileStaging($Change) {
    foreach ($entry in @(@{ Path = $Change.Staged; Hash = $Change.Applied }, @{ Path = $Change.Backup; Hash = $Change.Prior })) {
        if (-not $entry.Path) { continue }
        $hash = Get-ExamLabProtectedFileHash $entry.Path $Change.Readable
        if (-not $hash) { continue }
        if ($hash -cne $entry.Hash) { throw "File changed during installation: $($entry.Path)." }
        [IO.File]::Delete($entry.Path)
    }
}

function Undo-ExamLabInstallChange($Change) {
    switch ($Change.Kind) {
        'TemporaryFile' { Remove-ExamLabInstallTemporaryFile $Change }
        'File' {
            $current = Get-ExamLabProtectedFileHash $Change.Target $Change.Readable
            if ($current -cne $Change.Prior) {
                if ($current -cne $Change.Applied) { throw "File changed during installation: $($Change.Target)." }
                if ($Change.Prior) {
                    $backup = Get-ExamLabProtectedFileHash $Change.Backup $Change.Readable
                    if ($backup -cne $Change.Prior) { throw "The previous file version cannot be verified: $($Change.Target)." }
                    if ($current) { [IO.File]::Replace($Change.Backup, $Change.Target, [NullString]::Value) }
                    else { [IO.File]::Move($Change.Backup, $Change.Target) }
                } else { [IO.File]::Delete($Change.Target) }
            }
            Remove-ExamLabInstallFileStaging $Change
        }
        'TaskCreated' {
            $check = Get-ExamLabTaskCheck $Change.Target
            if (-not $check.Exists) { return }
            if ($check.Source -cne $Change.Source) { throw "Scheduled task ownership changed: $($Change.Target)." }
            Assert-ExamLabTaskCheck $check
            $folder = Get-ExamLabTaskFolder
            $task = Get-ExamLabRegisteredTask $Change.Target $folder
            $task.Enabled = $false
            if ($task.GetInstances(0).Count) { $task.Stop(0) }
            if ($task.GetInstances(0).Count) { throw "Scheduled task is still running: $($Change.Target)." }
            $folder.DeleteTask($Change.Target, 0)
        }
        'TaskEnabled' {
            $check = Get-ExamLabTaskCheck $Change.Target
            Assert-ExamLabTaskCheck $check -RequireOwnership
            if (-not $check.Exists -or $check.Source -cne $Change.Source) {
                throw "Scheduled task ownership changed: $($Change.Target)."
            }
            $task = Get-ExamLabRegisteredTask $Change.Target
            if ($check.Enabled -ne $Change.Prior) { $task.Enabled = $Change.Prior }
            if (-not $Change.Prior -and $task.GetInstances(0).Count) { $task.Stop(0) }
            elseif ($Change.Prior -and $Change.Target -ceq $examLabPollTask) { Start-ExamLabPolling }
        }
        'Directory' {
            if (-not (Test-Path -LiteralPath $Change.Target)) { return }
            Assert-ExamLabProtectedPath $Change.Target -Readable
            if (-not [IO.Directory]::Exists($Change.Target) -or @(Get-ChildItem -LiteralPath $Change.Target -Force).Count) {
                throw "The installation directory is no longer empty: $($Change.Target)."
            }
            [IO.Directory]::Delete($Change.Target)
        }
        'Arp' { Undo-ExamLabArpChange $Change }
        'Root' {
            $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
                foreach ($certificate in $store.Certificates.Find('FindByThumbprint', $Change.Target, $false)) {
                    $sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData))
                    if ($sha256 -cne $Change.Sha256) { throw "Certificate with changed content: $($Change.Target)." }
                    $store.Remove($certificate)
                }
            } finally { $store.Dispose() }
        }
        default { throw "Unknown ExamLab installation change: $($Change.Kind)." }
    }
}

function Undo-ExamLabInstallChanges {
    $journal = Read-ExamLabInstallChanges
    if (-not $journal) { return }
    $results = [Collections.Generic.List[object]]::new()
    $operation = $null
    $worker = Open-ExamLabInstallWorkerLock
    try {
        if (-not $journal.Committed -and (Test-Path -LiteralPath $examLabStatePath)) {
            Assert-ExamLabProtectedPath $examLabStatePath
            $path = Join-Path $examLabStatePath 'operation.lock'
            if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
            $operation = [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None')
            Assert-ExamLabInactive
        }
        while ($journal.Changes.Count) {
            $count = $journal.Changes.Count
            $change = $journal.Changes[$count - 1]
            try {
                if ($journal.Committed) {
                    if ($change.Kind -ceq 'File') { Remove-ExamLabInstallFileStaging $change }
                    elseif ($change.Kind -ceq 'TemporaryFile') { Remove-ExamLabInstallTemporaryFile $change }
                } elseif ($change.Kind -ceq 'Residual') {
                    $results.Add([pscustomobject]@{
                        Kind = $change.Kind; Target = $change.Target; Status = 'ReviewRequired'; Reason = $change.Reason
                    })
                } else {
                    Undo-ExamLabInstallChange $change
                    $results.Add([pscustomobject]@{ Kind = $change.Kind; Target = $change.Target; Status = 'RolledBack' })
                }
                $journal.Changes = @($journal.Changes | Select-Object -First ($count - 1))
                Write-ExamLabMaintenanceJson $examLabInstallChangesPath $journal
            } catch {
                $results.Add([pscustomobject]@{
                    Kind = $change.Kind; Target = $change.Target; Status = 'Conflict'; Error = $_.Exception.Message
                })
                break
            }
        }
        if (-not $journal.Changes.Count -and -not @($results | Where-Object Status -eq 'Conflict').Count) {
            [IO.File]::Delete($examLabInstallChangesPath)
        }
    } finally {
        if ($operation) { $operation.Dispose() }
        $worker.Dispose()
    }
    $results
}

function Invoke-ExamLabInstallRecovery {
    $results = @(Undo-ExamLabInstallChanges)
    $results
    if (@($results | Where-Object Status -eq 'Conflict').Count) {
        throw "The previous ExamLab installation has unresolved changes. See $examLabInstallChangesPath."
    }
    Assert-ExamLabInactive
}

function Complete-ExamLabInstallChanges {
    $journal = Read-ExamLabInstallChanges
    if (-not $journal) { return }
    $journal.Committed = $true
    Write-ExamLabMaintenanceJson $examLabInstallChangesPath $journal
    $cleanup = @(Undo-ExamLabInstallChanges)
    foreach ($item in $cleanup) { Write-Warning "Installation backup cleanup deferred for $($item.Target): $($item.Error)" }
}

function Get-ExamLabArpCommand {
    '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" -Action Uninstall' -f $examLabPowerShell, (Join-Path $examLabCodePath 'ExamLabMaintenance.ps1')
}

function Assert-ExamLabArp($Ownership) {
    if (-not (Test-Path -LiteralPath $examLabArpKey)) { return }
    $values = Get-ItemProperty -LiteralPath $examLabArpKey
    $pending = $Ownership -and (Test-ExamLabOwnedResource $Ownership $examLabArpKey)
    foreach ($expected in @{ DisplayName = 'ExamLab'; UninstallString = (Get-ExamLabArpCommand) }.GetEnumerator()) {
        $actual = $values.PSObject.Properties[$expected.Key]
        if (($actual -and $actual.Value -cne $expected.Value) -or (-not $actual -and -not $pending)) {
            throw 'A different ExamLab uninstall entry exists.'
        }
    }
    $key = Get-Item -LiteralPath $examLabArpKey
    try { $acl = [Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($key) }
    finally { $key.Dispose() }
    $admins = Get-ExamLabTrustedSids
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $admins) {
        throw 'Unexpected owner of the ExamLab uninstall entry.'
    }
    $writeRights = [Security.AccessControl.RegistryRights]::SetValue -bor [Security.AccessControl.RegistryRights]::CreateSubKey -bor
        [Security.AccessControl.RegistryRights]::Delete -bor [Security.AccessControl.RegistryRights]::ChangePermissions -bor
        [Security.AccessControl.RegistryRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $admins -and ($rule.RegistryRights -band $writeRights)) {
            throw 'Unsafe access to the ExamLab uninstall entry.'
        }
    }
}

function Get-ExamLabArpTrackedValues([string[]]$Names) {
    if (-not (Test-Path -LiteralPath $examLabArpKey)) { return }
    $key = Get-Item -LiteralPath $examLabArpKey
    try {
        $present = $key.GetValueNames()
        $values = [ordered]@{}
        foreach ($name in $Names) {
            $values[$name] = if ($name -in $present) {
                [ordered]@{
                    Kind = [string]$key.GetValueKind($name)
                    Data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                }
            }
        }
        [pscustomobject]$values
    } finally { $key.Dispose() }
}

function Undo-ExamLabArpChange($Change) {
    $names = @($Change.Applied.PSObject.Properties.Name)
    $current = Get-ExamLabArpTrackedValues $names
    if (-not $current) {
        if ($Change.Prior) { throw 'The previously present ExamLab app entry disappeared.' }
        return
    }
    Assert-ExamLabArp (Read-ExamLabOwnership)
    if (-not $Change.Prior -and
        (-not $current.InstallAttemptId -or $current.InstallAttemptId.Data -cne $Change.Applied.InstallAttemptId)) {
        throw 'Ownership of the incomplete ExamLab app entry could not be verified.'
    }
    $same = @{}
    foreach ($name in $names) {
        $actual = $current.PSObject.Properties[$name].Value
        $prior = if ($Change.Prior) { $Change.Prior.PSObject.Properties[$name].Value }
        $applied = $Change.Applied.PSObject.Properties[$name].Value
        $same[$name] = ($prior | ConvertTo-Json -Compress) -ceq ($actual | ConvertTo-Json -Compress)
        $appliedKind = if ($applied -is [string]) { 'String' } else { 'DWord' }
        if (-not $same[$name] -and (-not $actual -or $actual.Kind -cne $appliedKind -or $actual.Data -cne $applied)) {
            throw "The ExamLab app entry changed during installation: $name."
        }
    }
    $key = Get-Item -LiteralPath $examLabArpKey
    try {
        if (-not $Change.Prior) {
            if ($key.SubKeyCount -or @($key.GetValueNames() | Where-Object { $_ -notin $names }).Count) {
                throw 'The incomplete ExamLab app entry contains unrecorded properties.'
            }
        } else {
            foreach ($name in $names) {
                if ($same[$name]) { continue }
                $prior = $Change.Prior.PSObject.Properties[$name].Value
                if ($prior) {
                    $type = [Microsoft.Win32.RegistryValueKind]$prior.Kind
                    $data = switch ($type) {
                        'Binary' { ,([byte[]]$prior.Data) }
                        'MultiString' { ,([string[]]$prior.Data) }
                        'DWord' { [int]$prior.Data }
                        'QWord' { [long]$prior.Data }
                        default { $prior.Data }
                    }
                    $key.SetValue($name, $data, $type)
                } else { $key.DeleteValue($name, $false) }
            }
        }
    } finally { $key.Dispose() }
    if (-not $Change.Prior) { Remove-Item -LiteralPath $examLabArpKey }
}

function Publish-ExamLabInstallation($Ownership, [string]$Version) {
    Assert-ExamLabArp $Ownership
    $journal = Read-ExamLabInstallChanges
    $values = [ordered]@{
        UninstallString = Get-ExamLabArpCommand; DisplayName = 'ExamLab'; DisplayVersion = $Version
        InstallLocation = $examLabCodePath; NoModify = 1; NoRepair = 1
    }
    $exists = Test-Path -LiteralPath $examLabArpKey
    if ($journal) {
        if ($exists -and -not (Test-ExamLabOwnedResource $Ownership $examLabArpKey)) {
            throw 'The existing ExamLab app entry has unconfirmed ownership.'
        }
        $values.InstallAttemptId = $journal.Id
        $prior = Get-ExamLabArpTrackedValues @($values.Keys)
        Register-ExamLabResource $Ownership $examLabArpKey $exists
        Add-ExamLabInstallChange ([ordered]@{ Kind = 'Arp'; Target = $examLabArpKey; Prior = $prior; Applied = $values })
    }
    $parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $true)
    try {
        $acl = [Security.AccessControl.RegistrySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($value in 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545') {
            $sid = [Security.Principal.SecurityIdentifier]::new($value)
            $rights = if ($value -eq 'S-1-5-32-545') { 'ReadKey' } else { 'FullControl' }
            $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid, $rights, 'Allow'))
        }
        $key = $parent.CreateSubKey('ExamLab', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $acl)
        try {
            if ($journal) { $key.SetValue('InstallAttemptId', $journal.Id) }
            foreach ($name in $values.Keys) {
                if ($name -ne 'InstallAttemptId') { $key.SetValue($name, $values[$name]) }
            }
        } finally { $key.Dispose() }
    } finally { $parent.Dispose() }
    Assert-ExamLabArp $Ownership
    $Ownership.Version = $Version
    Save-ExamLabOwnership $Ownership
    $completedUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    Write-ExamLabMaintenanceJson $examLabFinalReport ([ordered]@{ version = $Version; completedUtc = $completedUtc }) -InstallChange
}

function Set-ExamLabRootTrust($Ownership, $Certificates, [switch]$BootstrapAddedFirstRoot, [switch]$PassThru) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        $bootstrapRoot = if ($BootstrapAddedFirstRoot) { $Certificates[0].Thumbprint }
        foreach ($certificate in $Certificates) {
            $sha256 = Get-CertificateSha256 $certificate.RawData
            $present = @($store.Certificates.Find('FindByThumbprint', $certificate.Thumbprint, $false))
            if (@($present | Where-Object { (Get-CertificateSha256 $_.RawData) -cne $sha256 }).Count) {
                throw 'An existing root certificate conflicts with this release.'
            }
            $bootstrapCreated = $bootstrapRoot -and $certificate.Thumbprint -ceq $bootstrapRoot
            if ($bootstrapCreated -and -not $present.Count) { throw 'The verified bootstrap root is absent.' }
            if (-not $Ownership.Roots.PSObject.Properties[$sha256]) {
                $kind = if ($present.Count -and -not $bootstrapCreated) { 'Reused' } else { 'Created' }
                Add-Member -InputObject $Ownership.Roots -NotePropertyName $sha256 -NotePropertyValue $kind
                Save-ExamLabOwnership $Ownership
            }
            if (-not $present.Count) {
                if (Test-Path -LiteralPath $examLabInstallChangesPath) {
                    Add-ExamLabInstallChange ([ordered]@{ Kind = 'Root'; Target = $certificate.Thumbprint; Sha256 = $sha256 })
                }
                $store.Add($certificate)
            }
            $verified = @($store.Certificates.Find('FindByThumbprint', $certificate.Thumbprint, $false) |
                Where-Object { (Get-CertificateSha256 $_.RawData) -ceq $sha256 })
            if (-not $verified.Count) { throw 'Windows Root store readback failed.' }
            if ($PassThru) {
                [pscustomobject]@{ Subject = $certificate.Subject; Added = (-not $present.Count); SHA256 = $sha256 }
            } else { Write-Host "ExamLab verified root certificate: $sha256" }
        }
    } finally { $store.Dispose() }
}

function Get-ExamLabProtectedTreeItems([string]$Path) {
    Assert-ExamLabProtectedPath $Path -Readable
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
        Assert-ExamLabProtectedPath $item.FullName -Readable
        $item
        if ($item.PSIsContainer) { Get-ExamLabProtectedTreeItems $item.FullName }
    }
}

function Save-ExamLabOwnedTree($Ownership, [string]$Path, [string[]]$VerifiedFiles) {
    if (-not (Test-ExamLabOwnedResource $Ownership $Path) -or -not (Test-Path -LiteralPath $Path)) { return }
    $previous = $Ownership.Trees.PSObject.Properties[$Path]
    $verifiedOnly = $PSBoundParameters.ContainsKey('VerifiedFiles')
    $hashes = [ordered]@{}
    foreach ($item in Get-ExamLabProtectedTreeItems $Path) {
        $name = $item.FullName.Substring($Path.Length + 1)
        $prior = if ($previous) { $previous.Value.PSObject.Properties[$name] } else { $null }
        $listed = $item.FullName -in $VerifiedFiles -or ($item.PSIsContainer -and
            @($VerifiedFiles | Where-Object { $_.StartsWith($item.FullName + '\', [StringComparison]::OrdinalIgnoreCase) }).Count)
        if ($prior -and -not $listed) {
            $hashes[$name] = $prior.Value
        } elseif ($listed -or (-not $previous -and -not $verifiedOnly)) {
            $hashes[$name] = if ($item.PSIsContainer) { 'Directory' } else { (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
        }
    }
    Add-Member -InputObject $Ownership.Trees -NotePropertyName $Path -NotePropertyValue ([pscustomobject]$hashes) -Force
    Save-ExamLabOwnership $Ownership
}

function Save-ExamLabOwnedFile($Ownership, [string]$Path) {
    if (-not (Test-ExamLabOwnedResource $Ownership $Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "File is a reparse point: $Path." }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $record = $Ownership.Trees.PSObject.Properties[$Path]
    if (-not $record -or $record.Value -cne $hash) {
        Add-Member -InputObject $Ownership.Trees -NotePropertyName $Path -NotePropertyValue $hash -Force
        Save-ExamLabOwnership $Ownership
    }
}

function Complete-ExamLabInstallation($Ownership, [string]$Version) {
    $path = Join-Path $examLabStatePath 'operation.lock'
    if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
    $operation = [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        Assert-ExamLabInactive
        try {
            $check = Get-ExamLabTaskCheck $examLabPollTask
            Assert-ExamLabTaskCheck $check -RequireOwnership
            if ($check.Exists -and -not $check.Enabled) { Save-ExamLabTaskEnabledChange $check }
            Start-ExamLabPolling
            Publish-ExamLabInstallation $Ownership $Version
        } catch {
            $task = Get-ExamLabTask $examLabPollTask -RequireOwnership
            if ($task -and $task.State -ne 'Disabled') {
                Disable-ScheduledTask -InputObject $task | Out-Null
                Stop-ScheduledTask -InputObject $task
            }
            throw
        }
    } finally { $operation.Dispose() }
}

function Copy-ExamLabFileAtomically([string]$Source, [string]$Target) {
    $temporary = $Target + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Copy($Source, $temporary)
        if ([IO.File]::Exists($Target)) { [IO.File]::Replace($temporary, $Target, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Target) }
    } finally { [IO.File]::Delete($temporary) }
}

function Get-ExamLabRegistryFingerprint([string]$Path, [string[]]$MutableNames) {
    $key = Get-Item -LiteralPath $Path
    try {
        $values = [ordered]@{}
        foreach ($name in $key.GetValueNames() | Sort-Object) {
            if ($name -in $MutableNames) { continue }
            $values[$name] = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor
            [Security.AccessControl.AccessControlSections]::Access
        $acl = ([Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($key, $sections)).GetSecurityDescriptorSddlForm($sections)
        $data = [Text.Encoding]::UTF8.GetBytes(([ordered]@{
            acl = $acl; names = $values; subKeys = @($key.GetSubKeyNames() | Sort-Object)
        } | ConvertTo-Json -Compress -Depth 6))
    } finally { $key.Dispose() }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($algorithm.ComputeHash($data)).Replace('-', '') }
    finally { $algorithm.Dispose() }
}

function Save-ExamLabAlertRegistration($Ownership) {
    $alertKey = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\ExamLab-Alert'
    foreach ($resource in @($alertKey, 'ExamLab-Alert event source')) {
        if (-not (Test-ExamLabOwnedResource $Ownership $resource) -or $Ownership.Trees.PSObject.Properties[$resource]) { continue }
        $path = if ($resource -eq $alertKey) { $alertKey } else { $sourceKey }
        $mutable = if ($resource -eq $alertKey) { @('Status') } else { @() }
        Add-Member -InputObject $Ownership.Trees -NotePropertyName $resource -NotePropertyValue (Get-ExamLabRegistryFingerprint $path $mutable)
    }
    Save-ExamLabOwnership $Ownership
}
