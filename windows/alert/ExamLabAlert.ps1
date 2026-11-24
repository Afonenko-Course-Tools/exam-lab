#requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Initialize','Arm','ControlProbe','Signal','SignalFromAudit','Receive','GetControllerAlert','Acknowledge','AcknowledgeRemote','Disarm')]
    [string]$Action,
    [string]$GuestSid,
    [int]$GuestSessionId,
    [guid]$RunId,
    [long]$AuditRecordId,
    [long]$AuditBaseline,
    [string]$CanaryPath,
    [string]$GuestLogonId,
    [switch]$ForController,
    [switch]$ResumeInitialize,
    [switch]$AsJson,
    [guid]$AcknowledgementId,
    [string]$Owner,
    [int]$Revision,
    [string]$BootUtc,
    [string]$OpaqueGuestSessionId,
    [string]$ExpiresUtc
)

$ErrorActionPreference = 'Stop'
$base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabAlert'
$registrySubkey = 'SOFTWARE\ExamLabAlertPilot'
$registryPath = "HKLM:\$registrySubkey"
$source = 'ExamLab-Alert'
$signalEventId = 6101
Add-Type -AssemblyName System.Diagnostics.EventLog
$powerShell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'

if (-not [Environment]::Is64BitProcess -or $PSScriptRoot -ne $base) {
    throw 'Запустите 64-битный PowerShell 7 с установленным сценарием ExamLabAlert.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($Action -in 'Receive','GetControllerAlert','AcknowledgeRemote','ControlProbe' -or ($Action -eq 'Arm' -and $ForController)) {
    if (-not $identity.IsSystem) { throw 'Для этого действия нужен токен SYSTEM.' }
} elseif (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Нужен повышенный токен администратора Windows.'
}
if ($Action -eq 'Initialize') {
    $private = Join-Path $base 'Private'
    $hasPrivate = Test-Path -LiteralPath $private
    $hasStatus = Test-Path -LiteralPath $registryPath
    $hasSource = [Diagnostics.EventLog]::SourceExists($source)
    if (-not $ResumeInitialize -and ($hasPrivate -or $hasStatus -or $hasSource)) {
        throw 'Область или источник пробы уже существует. Проверьте владение предыдущей установкой.'
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $statusAcl = [Security.AccessControl.RegistrySecurity]::new()
    $statusAcl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in 'S-1-5-18', 'S-1-5-32-544') {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        $statusAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    foreach ($sidValue in 'S-1-5-32-545', 'S-1-5-32-546') {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $statusAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid, 'ReadKey', 'Allow'))
    }
    function Assert-InitializationAcl($Actual, $Expected) {
        $sidType = [Security.Principal.SecurityIdentifier]
        $rightsProperty = if ($Actual -is [Security.AccessControl.RegistrySecurity]) { 'RegistryRights' } else { 'FileSystemRights' }
        $owner = $Actual.GetOwner($sidType).Value
        $trusted = @('S-1-5-18', 'S-1-5-32-544') + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
        $rules = @($Actual.GetAccessRules($true, $true, $sidType))
        $expectedRules = @($Expected.GetAccessRules($true, $true, $sidType))
        if ($owner -cnotin $trusted -or -not $Actual.AreAccessRulesProtected -or $rules.Count -ne $expectedRules.Count) {
            throw 'Права области пробы отличаются от установленного набора.'
        }
        foreach ($rule in $rules) {
            if (-not ($expectedRules | Where-Object {
                $_.IdentityReference.Value -ceq $rule.IdentityReference.Value -and
                $_.AccessControlType -eq $rule.AccessControlType -and
                $_.InheritanceFlags -eq $rule.InheritanceFlags -and $_.PropagationFlags -eq $rule.PropagationFlags -and
                $_.$rightsProperty -eq $rule.$rightsProperty
            })) { throw 'Права области пробы отличаются от установленного набора.' }
        }
    }
    if ($hasPrivate) {
        $item = Get-Item -LiteralPath $private -Force
        if (-not $item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Закрытый каталог пробы отличается от собственного каталога.'
        }
        Assert-InitializationAcl (Get-Acl -LiteralPath $private) $acl
    }
    if ($hasStatus) {
        $statusKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registrySubkey)
        if (-not $statusKey) { throw 'Не удалось прочитать существующий ключ статуса пробы.' }
        try { Assert-InitializationAcl ([Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($statusKey)) $statusAcl }
        finally { $statusKey.Dispose() }
    }
    if ($hasSource -and [Diagnostics.EventLog]::LogNameFromSourceName($source, '.') -cne 'Application') {
        throw 'Одноимённый источник зарегистрирован в другом журнале.'
    }
    if (-not $hasPrivate) { [IO.FileSystemAclExtensions]::CreateDirectory($acl, $private) | Out-Null }
    if (-not $hasStatus) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
            $registrySubkey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $statusAcl)
        $key.Dispose()
    }
    if (-not $hasSource) { [Diagnostics.EventLog]::CreateEventSource($source, 'Application') }
    return
}

if ($Action -eq 'Receive') {
    $message = [Console]::ReadLine()
    if (-not $message -or $message.Length -gt 65536) { throw 'Неверный формат Wazuh Active Response.' }
    $request = ConvertFrom-Json -DateKind String -InputObject $message
    $eventInfo = $request.parameters.alert.data.win.system
    $recordId = 0L
    if ($request.version -ne 1 -or $request.command -cne 'add' -or
        $request.parameters.alert.rule.id -ne '110610' -or
        $eventInfo.providerName -cne $source -or $eventInfo.channel -cne 'Application' -or
        $eventInfo.eventID -ne $signalEventId -or
        -not [long]::TryParse([string]$eventInfo.eventRecordID, [ref]$recordId) -or $recordId -le 0) {
        return
    }
}

function Save-State($Value) {
    Set-ItemProperty -LiteralPath $registryPath -Name Status -Value ($Value | ConvertTo-Json -Compress -Depth 3)
}

function ConvertFrom-AlertState([string]$Json) {
    if (-not $Json) { return }
    $value = ConvertFrom-Json -DateKind String -InputObject $Json
    if ($null -eq $value) { return }
    foreach ($name in 'Revision','BootUtc','OpaqueGuestSessionId','AuthenticationId','SecurityReadRecordId',
        'SignalIssued','Reason','ShownUtc','AcknowledgementId','AcknowledgementAcceptedUtc','ScreenClosedUtc','LastAcknowledgement') {
        if (-not $value.PSObject.Properties[$name]) {
            Add-Member -InputObject $value -NotePropertyName $name -NotePropertyValue $null
        }
    }
    $value
}

function Get-Acknowledgement($Value) {
    if ($null -eq $Value) { return }
    if (-not $Value.AcknowledgedUtc) { return $Value.LastAcknowledgement }
    $Value | Select-Object RunId, GuestSid, SessionId, Revision, BootUtc, OpaqueGuestSessionId,
        AcknowledgedUtc, AcknowledgedBy, AcknowledgedBySid, AcknowledgementId, ScreenClosedUtc
}

function Get-AlertUtc([DateTime]$Utc = [DateTime]::UtcNow) {
    $Utc.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-AlertGuestBinding {
    $examLab = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLab\ExamLab.psm1'
    Import-Module $examLab -Scope Local -ErrorAction Stop
    Get-ExamLabControllerGuestBinding
}

function Test-AlertGuestBinding($State, $Binding) {
    return ($null -ne $Binding -and $State.Revision -eq $Binding.Revision -and
        $State.BootUtc -ceq $Binding.BootUtc -and $State.OpaqueGuestSessionId -ceq $Binding.GuestSessionId -and
        $State.GuestSid -ceq $Binding.GuestSid -and $State.SessionId -eq $Binding.SessionId -and
        $State.AuthenticationId -eq $Binding.AuthenticationId)
}

function Update-AlertShown($State) {
    if ($State.ShownUtc -or $State.Phase -cne 'Pending') { return }
    $shown = $null
    $rights = [Security.AccessControl.EventWaitHandleRights]'Synchronize, ReadPermissions'
    try {
        if ([Threading.EventWaitHandleAcl]::TryOpenExisting("Global\ExamLab-Alert-Shown-$($State.RunId)", $rights, [ref]$shown) -and
            ([Threading.ThreadingAclExtensions]::GetAccessControl($shown)).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $State.GuestSid -and
            $shown.WaitOne(0)) {
            $task = Find-AlertScreen (Get-AlertTaskFolder) $State.RunId
            if ($task -and $task.GetInstances(0).Count -gt 0) {
                $State.ShownUtc = Get-AlertUtc
                Save-State $State
            }
        }
    } catch [UnauthorizedAccessException] {
        # Объект без ожидаемых прав не подтверждает показ.
    } finally { if ($shown) { $shown.Dispose() } }
}

function Get-ControllerAlert($State, [switch]$AsJson) {
    $phase = if ($State.Phase -ceq 'Acknowledged') { 'acknowledged' } elseif ($State.ShownUtc) { 'shown' } else { 'received' }
    $result = [pscustomobject]@{
        alertId = $State.RunId
        revision = $State.Revision
        bootUtc = $State.BootUtc
        guestSessionId = $State.OpaqueGuestSessionId
        reason = $State.Reason
        phase = $phase
        receivedUtc = $State.ReceivedUtc
        shownUtc = $State.ShownUtc
        acknowledgedUtc = $State.AcknowledgedUtc
        acknowledgedBy = $State.AcknowledgedBy
        acknowledgementId = $State.AcknowledgementId
    }
    if ($AsJson) { $result | ConvertTo-Json -Depth 3 -Compress } else { $result }
}

function Start-Acknowledgement($State, [string]$Name, $Sid, $Id, [DateTimeOffset]$Expiry = [DateTimeOffset]::MaxValue) {
    if ($State.Revision) { Update-AlertShown $State }
    $accepted = [DateTimeOffset]::UtcNow
    if ($accepted -ge $Expiry) { throw 'Срок удалённого подтверждения истёк.' }
    $State.Phase = 'Closing'
    $State.AcknowledgedBy = $Name
    $State.AcknowledgedBySid = $Sid
    $State | Add-Member -NotePropertyName AcknowledgementId -NotePropertyValue $Id -Force
    $State | Add-Member -NotePropertyName AcknowledgementAcceptedUtc -NotePropertyValue (Get-AlertUtc $accepted.UtcDateTime) -Force
    Save-State $State
    Complete-Acknowledgement $State
}

function Complete-Acknowledgement($State) {
    Remove-AlertScreen $State
    $State.Phase = 'Acknowledged'
    $closed = Get-AlertUtc
    $State.AcknowledgedUtc = if ($State.AcknowledgementAcceptedUtc) { $State.AcknowledgementAcceptedUtc } else { $closed }
    $State | Add-Member -NotePropertyName ScreenClosedUtc -NotePropertyValue $closed -Force
    $State | Add-Member -NotePropertyName LastAcknowledgement -NotePropertyValue (Get-Acknowledgement $State) -Force
    Save-State $State
}

function Test-GuestDesktop([string]$Sid, [int]$SessionId) {
    $explorers = Get-CimInstance Win32_Process -Filter "Name='explorer.exe' AND SessionId=$SessionId"
    $desktop = $explorers | Where-Object {
        (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $Sid
    } | Select-Object -First 1
    return $null -ne $desktop
}

function Get-AlertTaskFolder {
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\')
}

function Find-AlertScreen($Folder, [string]$Id) {
    $name = "ExamLab-Alert-Pilot-$Id"
    foreach ($candidate in $Folder.GetTasks(1)) {
        if ($candidate.Name -ceq $name) { return $candidate }
    }
}

function Register-AlertScreen($State) {
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -Disable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $screen = Join-Path $base 'Show-ExamLabAlert.ps1'
    $arguments = '-NoLogo -NoProfile -NonInteractive -STA -WindowStyle Hidden -ExecutionPolicy Bypass ' +
        ('-File "{0}" -RunId {1} -GuestSid {2} -GuestSessionId {3}' -f $screen, $State.RunId, $State.GuestSid, $State.SessionId)
    $action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $base
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $State.GuestSid -LogonType Interactive -RunLevel Limited
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
    $name = "ExamLab-Alert-Pilot-$($State.RunId)"
    Register-ScheduledTask -TaskName $name -Action $action -Principal $taskPrincipal `
        -Settings $settings -Trigger $trigger -Description 'ExamLab: экран текущего Guest' | Out-Null
    try {
        (Get-AlertTaskFolder).GetTask($name).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)', 16)
        Enable-ScheduledTask -TaskName $name | Out-Null
    } catch {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        throw
    }
}

function Remove-AlertScreen($State) {
    $folder = Get-AlertTaskFolder
    $task = Find-AlertScreen $folder $State.RunId
    if ($task) {
        $task.Enabled = $false
        if ($task.GetInstances(0).Count -gt 0) {
            try { $task.Stop(0) } catch { if ($task.GetInstances(0).Count -gt 0) { throw } }
            $deadline = [DateTime]::UtcNow.AddSeconds(2)
            while ($task.GetInstances(0).Count -gt 0) {
                if ([DateTime]::UtcNow -ge $deadline) { throw 'Процесс задачи экрана ещё работает.' }
                Start-Sleep -Milliseconds 100
            }
        }
        $folder.DeleteTask($task.Name, 0)
    }
    if (Find-AlertScreen $folder $State.RunId) { throw 'Задача экрана сохранилась после снятия.' }
}

$lockPath = Join-Path $base 'Private\writer.lock'
$lock = $null
$deadline = [Datetime]::UtcNow.AddSeconds(5)
while ($null -eq $lock) {
    try {
        $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    } catch [IO.IOException] {
        if ([Datetime]::UtcNow -ge $deadline) { throw }
        Start-Sleep -Milliseconds 100
    }
}

try {
    $key = Get-Item -LiteralPath $registryPath
    try { $json = $key.GetValue('Status') } finally { $key.Dispose() }
    $state = ConvertFrom-AlertState $json
    switch ($Action) {
        { $_ -in 'Arm','ControlProbe' } {
            $binding = $null
            if ($ForController -or $Action -ceq 'ControlProbe') {
                $binding = Get-AlertGuestBinding
                if (-not $binding) { throw 'Нет текущего Guest в действующем назначении экзамена.' }
                if ($Action -ceq 'ControlProbe') {
                    $GuestSid = $binding.GuestSid
                    $GuestSessionId = $binding.SessionId
                }
                if ($GuestSid -cne $binding.GuestSid -or $GuestSessionId -ne $binding.SessionId) {
                    throw 'Запрошенный Guest не совпадает с текущим входом.'
                }
            }
            if ($state -and $state.Phase -cne 'Disarmed') { throw 'Сначала завершите предыдущую пробу.' }
            $sid = [Security.Principal.SecurityIdentifier]::new($GuestSid)
            if (-not $sid.IsAccountSid() -or $GuestSessionId -le 0) {
                throw 'Укажите SID и номер интерактивного сеанса тестового Guest.'
            }
            if (-not (Test-GuestDesktop $sid.Value $GuestSessionId)) {
                throw 'Explorer указанного пользователя и сеанса не найден.'
            }
            $lastAcknowledgement = Get-Acknowledgement $state
            $state = [pscustomobject]@{
                RunId = [guid]::NewGuid().ToString('D')
                Phase = 'Armed'
                ArmedUtc = [DateTimeOffset]::UtcNow.ToString('o')
                GuestSid = $sid.Value
                SessionId = $GuestSessionId
                Revision = $null
                BootUtc = $null
                OpaqueGuestSessionId = $null
                AuthenticationId = $null
                EventRecordId = 0L
                SecurityReadRecordId = $null
                SignalIssued = $false
                EventUtc = $null
                Reason = $null
                ReceivedUtc = $null
                ShownUtc = $null
                AcknowledgedUtc = $null
                AcknowledgedBy = $null
                AcknowledgedBySid = $null
                AcknowledgementId = $null
                LastAcknowledgement = $lastAcknowledgement
                DisarmedUtc = $null
            }
            if ($binding) {
                $state.Revision = $binding.Revision
                $state.BootUtc = $binding.BootUtc
                $state.OpaqueGuestSessionId = $binding.GuestSessionId
                $state.AuthenticationId = $binding.AuthenticationId
            }
            Register-AlertScreen $state
            try { Save-State $state } catch {
                Remove-AlertScreen $state
                throw
            }
        }
        { $_ -in 'Signal','SignalFromAudit','ControlProbe' } {
            if ($null -eq $state -or $state.Phase -ne 'Armed' -or
                $state.EventRecordId -ne 0 -or $state.SecurityReadRecordId -or $state.SignalIssued) {
                throw 'Ожидается одна новая проба в фазе Armed.'
            }
            if (-not (Test-GuestDesktop $state.GuestSid $state.SessionId)) {
                throw 'Сеанс Guest для контрольного события больше не открыт.'
            }
            if ($state.Revision -and (-not $identity.IsSystem -or -not (Test-AlertGuestBinding $state (Get-AlertGuestBinding)))) {
                throw 'Сеанс Guest или назначение изменились после подготовки сигнала.'
            }
            $reason = 'control-signal'
            if ($Action -eq 'SignalFromAudit') {
                if ($state.RunId -ne $RunId.ToString('D') -or -not $state.ArmedUtc -or $AuditBaseline -le 0 -or
                    $AuditRecordId -le $AuditBaseline -or $GuestLogonId -notmatch '^0x[0-9a-f]+$' -or
                    $CanaryPath -notmatch '^[A-Z]:\\') {
                    throw 'Укажите текущий запуск, полный путь, журнал до пробы, новую запись и идентификатор входа Guest.'
                }
                $audit = Get-WinEvent -LogName Security -FilterXPath (
                    "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4663 and EventRecordID=$AuditRecordId]]"
                ) -MaxEvents 1
                . (Join-Path $PSScriptRoot 'Test-ExamLabFileReadAudit.ps1')
                if (-not (Test-ExamLabFileReadAudit -EventXml ([xml]$audit.ToXml()) -Path $CanaryPath -Sid $state.GuestSid -LogonId $GuestLogonId -ArmedUtc ([DateTimeOffset]$state.ArmedUtc) -NowUtc ([DateTimeOffset]::UtcNow))) {
                    throw 'Запись Security не подтверждает недавнее чтение контрольного файла текущим Guest.'
                }
                $state | Add-Member -NotePropertyName SecurityReadRecordId -NotePropertyValue $AuditRecordId -Force
                $reason = 'canary-read'
            }
            # Сбой чтения после записи события не разрешает вторую запись в этом запуске.
            $state | Add-Member -NotePropertyName SignalIssued -NotePropertyValue $true -Force
            Save-State $state
            $nonce = [guid]::NewGuid().ToString('D')
            [Diagnostics.EventLog]::WriteEntry($source, $nonce, 'Warning', $signalEventId)
            $filter = "*[System[Provider[@Name='$source'] and EventID=$signalEventId]]"
            $event = Get-WinEvent -LogName Application -FilterXPath $filter -MaxEvents 20 |
                Where-Object { $nonce -cin $_.Properties.Value } |
                Select-Object -Last 1
            if (-not $event) { throw 'Контрольная запись не найдена в Windows Event Log.' }
            $state.EventRecordId = [long]$event.RecordId
            $state.EventUtc = $event.TimeCreated.ToUniversalTime().ToString('o')
            $state | Add-Member -NotePropertyName Reason -NotePropertyValue $reason -Force
            Save-State $state
        }
        'Receive' {
            if ($null -eq $state -or $state.Phase -ne 'Armed' -or $state.EventRecordId -ne $recordId) { return }
            $utcNow = [DateTimeOffset]::UtcNow
            $age = $utcNow - [DateTimeOffset]::Parse($state.EventUtc, [Globalization.CultureInfo]::InvariantCulture)
            if ($age.TotalSeconds -gt 120 -or $age.TotalSeconds -lt -5) { return }
            if (-not (Test-GuestDesktop $state.GuestSid $state.SessionId)) { return }
            if ($state.Revision -and -not (Test-AlertGuestBinding $state (Get-AlertGuestBinding))) { return }
            $state.Phase = 'Pending'
            $state.ReceivedUtc = Get-AlertUtc
            Save-State $state
            # TASK_RUN_USE_SESSION_ID | TASK_RUN_USER_SID. При ошибке немедленного запуска
            # задача повторит попытку по своему минутному расписанию.
            $task = (Get-AlertTaskFolder).GetTask("ExamLab-Alert-Pilot-$($state.RunId)")
            $task.RunEx($null, 12, $state.SessionId, $state.GuestSid) | Out-Null
        }
        'GetControllerAlert' {
            if ($null -eq $state -or -not $state.Revision) { return }
            if ($state.Phase -ceq 'Closing') { Complete-Acknowledgement $state }
            if ($state.Phase -ceq 'Acknowledged' -or ($state.Phase -ceq 'Disarmed' -and $state.AcknowledgedUtc)) {
                $state.Phase = 'Acknowledged'
                Get-ControllerAlert $state -AsJson:$AsJson
                return
            }
            if ($state.Phase -cne 'Pending' -or -not (Test-AlertGuestBinding $state (Get-AlertGuestBinding))) { return }
            Update-AlertShown $state
            Get-ControllerAlert $state -AsJson:$AsJson
        }
        'AcknowledgeRemote' {
            if ($null -eq $state -or -not $state.Revision -or $state.RunId -cne $RunId.ToString('D') -or
                $state.Revision -ne $Revision -or $state.BootUtc -cne $BootUtc -or
                $state.OpaqueGuestSessionId -cne $OpaqueGuestSessionId -or
                $AcknowledgementId -eq [guid]::Empty -or $Owner -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
                -not (Test-AlertGuestBinding $state (Get-AlertGuestBinding))) {
                throw 'Удалённое подтверждение не совпадает с текущим Guest и тревогой.'
            }
            $id = $AcknowledgementId.ToString('D')
            if ($state.Phase -cin 'Closing','Acknowledged' -and $state.AcknowledgementId -ceq $id -and $state.AcknowledgedBy -ceq $Owner) {
                if ($state.Phase -ceq 'Closing') { Complete-Acknowledgement $state }
                Get-ControllerAlert $state
                return
            }
            $expiry = [DateTimeOffset]::MinValue
            if ($state.Phase -cne 'Pending' -or -not [DateTimeOffset]::TryParseExact($ExpiresUtc,
                "yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$expiry) -or $expiry -le [DateTimeOffset]::UtcNow) {
                throw 'Нет ожидающей тревоги или срок удалённого подтверждения истёк.'
            }
            Start-Acknowledgement $state $Owner $null $id $expiry
            Get-ControllerAlert $state
        }
        'Acknowledge' {
            if ($null -eq $state -or $state.Phase -ne 'Pending' -or $state.RunId -ne $RunId.ToString('D') -or
                [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $state.SessionId -or
                -not (Test-GuestDesktop $state.GuestSid $state.SessionId)) {
                throw 'Нет ожидающей тревоги этого запуска в текущем сеансе.'
            }
            Start-Acknowledgement $state $identity.Name $identity.User.Value $null
        }
        'Disarm' {
            if ($null -eq $state) { return }
            if ($state.Phase -ne 'Disarmed') {
                $state.Phase = 'Disarmed'
                $state.DisarmedUtc = [DateTimeOffset]::UtcNow.ToString('o')
                Save-State $state
            }
            Remove-AlertScreen $state
        }
    }
} finally {
    $lock.Dispose()
}
