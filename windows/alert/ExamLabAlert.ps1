[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Initialize','Arm','Signal','Receive','Acknowledge','Disarm')]
    [string]$Action,
    [string]$GuestSid,
    [int]$GuestSessionId,
    [guid]$RunId
)

$ErrorActionPreference = 'Stop'
$base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabAlert'
$registrySubkey = 'SOFTWARE\ExamLabAlertPilot'
$registryPath = "HKLM:\$registrySubkey"
$source = 'ExamLab-Alert'
$signalEventId = 6101
$powerShell = Join-Path $PSHOME 'powershell.exe'

if (-not [Environment]::Is64BitProcess -or $PSScriptRoot -ne $base) {
    throw 'Запустите 64-битный Windows PowerShell с установленным сценарием ExamLabAlert.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($Action -eq 'Receive') {
    if (-not $identity.IsSystem) { throw 'Для приёма требуется локальная служба Wazuh с токеном SYSTEM.' }
} elseif (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Нужен повышенный токен администратора Windows.'
}
if ($Action -eq 'Initialize') {
    $private = Join-Path $base 'Private'
    if ((Test-Path -LiteralPath $private) -or (Test-Path -LiteralPath $registryPath)) {
        throw 'Область пробы уже существует. Проверьте предыдущее состояние.'
    }
    if ([Diagnostics.EventLog]::SourceExists($source)) {
        throw 'Источник журнала уже существует. Проверьте предыдущую установку.'
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
    [IO.Directory]::CreateDirectory($private, $acl) | Out-Null
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($registrySubkey, 'ReadWriteSubTree', $statusAcl)
    $key.Dispose()
    New-EventLog -LogName Application -Source $source
    return
}

if ($Action -eq 'Receive') {
    $message = [Console]::ReadLine()
    if (-not $message -or $message.Length -gt 65536) { throw 'Неверный формат Wazuh Active Response.' }
    $request = ConvertFrom-Json -InputObject $message
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
    Set-ItemProperty -LiteralPath $registryPath -Name Status -Value ($Value | ConvertTo-Json -Compress)
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
    $name = "ExamLab-Alert-Pilot-$($State.RunId)"
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) { $task | Unregister-ScheduledTask -Confirm:$false }
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
    $state = if ($json) { ConvertFrom-Json -InputObject $json }
    switch ($Action) {
        'Arm' {
            if ($state -and $state.Phase -ne 'Disarmed') { throw 'Сначала завершите предыдущую пробу.' }
            $sid = [Security.Principal.SecurityIdentifier]::new($GuestSid)
            if (-not $sid.IsAccountSid() -or $GuestSessionId -le 0) {
                throw 'Укажите SID и номер интерактивного сеанса тестового Guest.'
            }
            if (-not (Test-GuestDesktop $sid.Value $GuestSessionId)) {
                throw 'Explorer указанного пользователя и сеанса не найден.'
            }
            $state = [ordered]@{
                RunId = [guid]::NewGuid().ToString('D')
                Phase = 'Armed'
                GuestSid = $sid.Value
                SessionId = $GuestSessionId
                EventRecordId = 0L
                EventUtc = $null
                ReceivedUtc = $null
                AcknowledgedUtc = $null
                AcknowledgedBy = $null
                AcknowledgedBySid = $null
                DisarmedUtc = $null
            }
            Register-AlertScreen $state
            try { Save-State $state } catch {
                Remove-AlertScreen $state
                throw
            }
        }
        'Signal' {
            if ($null -eq $state -or $state.Phase -ne 'Armed' -or $state.EventRecordId -ne 0) {
                throw 'Ожидается одна новая проба в фазе Armed.'
            }
            if (-not (Test-GuestDesktop $state.GuestSid $state.SessionId)) {
                throw 'Сеанс Guest для контрольного события больше не открыт.'
            }
            $nonce = [guid]::NewGuid().ToString('D')
            Write-EventLog -LogName Application -Source $source -EventId $signalEventId -EntryType Warning -Message $nonce
            $filter = "*[System[Provider[@Name='$source'] and EventID=$signalEventId]]"
            $event = Get-WinEvent -LogName Application -FilterXPath $filter -MaxEvents 20 |
                Where-Object { $nonce -cin $_.Properties.Value } |
                Select-Object -Last 1
            if (-not $event) { throw 'Контрольная запись не найдена в Windows Event Log.' }
            $state.EventRecordId = [long]$event.RecordId
            $state.EventUtc = $event.TimeCreated.ToUniversalTime().ToString('o')
            Save-State $state
        }
        'Receive' {
            if ($null -eq $state -or $state.Phase -ne 'Armed' -or $state.EventRecordId -ne $recordId) { return }
            $utcNow = [DateTimeOffset]::UtcNow
            $age = $utcNow - [DateTimeOffset]::Parse($state.EventUtc, [Globalization.CultureInfo]::InvariantCulture)
            if ($age.TotalSeconds -gt 120 -or $age.TotalSeconds -lt -5) { return }
            if (-not (Test-GuestDesktop $state.GuestSid $state.SessionId)) { return }
            $state.Phase = 'Pending'
            $state.ReceivedUtc = $utcNow.ToString('o')
            Save-State $state
            # TASK_RUN_USE_SESSION_ID | TASK_RUN_USER_SID. При ошибке немедленного запуска
            # задача повторит попытку по своему минутному расписанию.
            $task = (Get-AlertTaskFolder).GetTask("ExamLab-Alert-Pilot-$($state.RunId)")
            $task.RunEx($null, 12, $state.SessionId, $state.GuestSid) | Out-Null
        }
        'Acknowledge' {
            if ($null -eq $state -or $state.Phase -ne 'Pending' -or $state.RunId -ne $RunId.ToString('D') -or
                [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $state.SessionId -or
                -not (Test-GuestDesktop $state.GuestSid $state.SessionId)) {
                throw 'Нет ожидающей тревоги этого запуска в текущем сеансе.'
            }
            $state.Phase = 'Acknowledged'
            $state.AcknowledgedUtc = [DateTimeOffset]::UtcNow.ToString('o')
            $state.AcknowledgedBy = $identity.Name
            $state.AcknowledgedBySid = $identity.User.Value
            Save-State $state
            Remove-AlertScreen $state
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
