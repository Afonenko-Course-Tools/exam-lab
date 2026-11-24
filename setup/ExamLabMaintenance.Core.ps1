# Shared by the trusted bootstrap and the installed local maintenance entry point.
$examLabProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
$examLabCodePath = Join-Path $examLabProgramFiles 'ExamLab'
$examLabStatePath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
$examLabReportsPath = Join-Path $examLabProgramFiles 'ExamLabSetupReports'
$examLabFinalReport = Join-Path $examLabReportsPath 'install-final.json'
$examLabOwnershipPath = Join-Path $examLabReportsPath 'ownership.json'
$examLabPowerShell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
$examLabPollTask = 'ExamLab-Controller-Poll'
$examLabTaskNames = @('ExamLab-Local-prepare', 'ExamLab-Local-check', 'ExamLab-Local-exam', 'ExamLab-Local-normal', $examLabPollTask)
$examLabArpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ExamLab'
$examLabTaskDacl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
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
    [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
}

function Write-ExamLabMaintenanceJson([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 10 -Compress))
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
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
    Assert-ExamLabInactive
    if (-not (Test-Path -LiteralPath $examLabReportsPath)) { New-ExamLabPrivateDirectory $examLabReportsPath }
    Assert-ExamLabProtectedPath $examLabReportsPath
    $path = Join-Path $examLabReportsPath 'maintenance.lock'
    if (Test-Path -LiteralPath $path) { Assert-ExamLabProtectedPath $path }
    try { [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'Another ExamLab installation or maintenance action is running.' }
}

function Get-ExamLabTask([string]$Name, [switch]$AllowPendingProtection) {
    if ($Name -notin $examLabTaskNames) { throw "Unexpected task name: $Name." }
    $task = Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction SilentlyContinue
    if (-not $task) { return }
    $arguments = if ($Name -ceq $examLabPollTask) {
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action poll' -f (Join-Path $examLabCodePath 'exam-lab.ps1')
    } else {
        '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $examLabCodePath ('task-' + $Name.Substring(14) + '.ps1'))
    }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1 -or $actions[0].Execute -ine $examLabPowerShell -or $actions[0].Arguments -cne $arguments -or
        $actions[0].WorkingDirectory -or $task.Principal.UserId -inotmatch '^(S-1-5-18|(?:NT AUTHORITY\\)?SYSTEM)$' -or
        $task.Principal.RunLevel -ne 'Highest' -or $task.Principal.LogonType -ne 'ServiceAccount') {
        throw "A scheduled task named $Name has a different definition."
    }
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $registered = $scheduler.GetFolder('\').GetTask($Name)
    $dacl = [Security.AccessControl.CommonSecurityDescriptor]::new($false, $false, $registered.GetSecurityDescriptor(4))
    $expectedDacl = [Security.AccessControl.CommonSecurityDescriptor]::new($false, $false, $examLabTaskDacl)
    $protected = ($dacl.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    $matches = $protected -and $dacl.DiscretionaryAcl.Count -eq $expectedDacl.DiscretionaryAcl.Count
    $sids = @()
    foreach ($ace in $dacl.DiscretionaryAcl) {
        $matches = $matches -and ($ace -is [Security.AccessControl.CommonAce]) -and
            ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed) -and
            ($ace.SecurityIdentifier.Value -in @('S-1-5-18', 'S-1-5-32-544')) -and
            ($ace.AccessMask -eq $expectedDacl.DiscretionaryAcl[0].AccessMask) -and $ace.AceFlags -eq 'None'
        if ($ace -is [Security.AccessControl.CommonAce]) { $sids += $ace.SecurityIdentifier.Value }
    }
    if ((-not $AllowPendingProtection -or $task.State -ne 'Disabled') -and (-not $matches -or $sids -notcontains 'S-1-5-18' -or $sids -notcontains 'S-1-5-32-544')) {
        throw "A scheduled task named $Name has different security."
    }
    $task
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
        $record = Read-ExamLabOwnership
        $task = Get-ExamLabTask $examLabPollTask -AllowPendingProtection:(Test-ExamLabTaskNeedsProtection $record $examLabPollTask)
        if (-not $task) { return $false }
        $wasEnabled = $task.State -ne 'Disabled'
        try {
            if ($wasEnabled) { Disable-ScheduledTask -InputObject $task | Out-Null }
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
    $task = Get-ExamLabTask $examLabPollTask
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
    $task = Get-ExamLabTask $taskName
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
    Write-ExamLabMaintenanceJson $examLabOwnershipPath $Ownership
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

function Test-ExamLabTaskNeedsProtection($Ownership, [string]$Name) {
    return ((Test-ExamLabOwnedResource $Ownership $Name) -and -not $Ownership.TasksVerified.PSObject.Properties[$Name])
}

function Confirm-ExamLabTaskProtection($Ownership, [string]$Name) {
    $null = Get-ExamLabTask $Name
    if (Test-ExamLabTaskNeedsProtection $Ownership $Name) {
        Add-Member -InputObject $Ownership.TasksVerified -NotePropertyName $Name -NotePropertyValue $true
        Save-ExamLabOwnership $Ownership
    }
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

function Publish-ExamLabInstallation($Ownership, [string]$Version) {
    Assert-ExamLabArp $Ownership
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
            $key.SetValue('UninstallString', (Get-ExamLabArpCommand))
            $key.SetValue('DisplayName', 'ExamLab')
            $key.SetValue('DisplayVersion', $Version)
            $key.SetValue('InstallLocation', $examLabCodePath)
            $key.SetValue('NoModify', 1)
            $key.SetValue('NoRepair', 1)
        } finally { $key.Dispose() }
    } finally { $parent.Dispose() }
    Assert-ExamLabArp $Ownership
    $Ownership.Version = $Version
    Save-ExamLabOwnership $Ownership
    $completedUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    Write-ExamLabMaintenanceJson $examLabFinalReport ([ordered]@{ version = $Version; completedUtc = $completedUtc })
}

function Set-ExamLabRootTrust($Ownership, $Certificates, [switch]$BootstrapAddedFirstRoot) {
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
            if (-not $present.Count) { $store.Add($certificate) }
            $verified = @($store.Certificates.Find('FindByThumbprint', $certificate.Thumbprint, $false) |
                Where-Object { (Get-CertificateSha256 $_.RawData) -ceq $sha256 })
            if (-not $verified.Count) { throw 'Windows Root store readback failed.' }
            Write-Host "ExamLab verified root certificate: $sha256"
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
    $hashes = [ordered]@{}
    foreach ($item in Get-ExamLabProtectedTreeItems $Path) {
        $name = $item.FullName.Substring($Path.Length + 1)
        $prior = if ($previous) { $previous.Value.PSObject.Properties[$name] } else { $null }
        if ($prior -and $item.FullName -notin $VerifiedFiles) {
            $hashes[$name] = $prior.Value
        } elseif (-not $previous -or $item.FullName -in $VerifiedFiles) {
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
    if (-not $Ownership.Trees.PSObject.Properties[$Path]) {
        Add-Member -InputObject $Ownership.Trees -NotePropertyName $Path -NotePropertyValue $hash
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
            Start-ExamLabPolling
            Publish-ExamLabInstallation $Ownership $Version
        } catch {
            $task = Get-ExamLabTask $examLabPollTask
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
