$script:FileTraceAuthorization = Join-Path $script:CodeRoot 'file-trace-exam.txt'
$script:FileTraceAttempt = Join-Path $script:DataRoot 'file-trace-attempt.json'
$script:FileTraceLease = Join-Path $script:DataRoot 'file-trace-worker.lock'

function Test-ExamLabFileTraceAuthorization([string]$ExamId, [string]$Path) {
    if ($ExamId -cnotmatch '\Afile-trace-[A-Za-z0-9._-]{1,53}\z' -or
        -not (Test-ExistingFile $Path)) { return $false }
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.Length -eq 0) { return $false }
    if ($file.Length -gt 64) { throw 'Некорректная настройка файлового экзамена.' }
    Assert-SafePath $Path -Readable
    return [IO.File]::ReadAllText($Path) -ceq $ExamId
}

function Test-ExamLabFileTraceAssignment($State, $Attempt) {
    $assignment = $State.Assignment
    return ((Test-ControllerActiveExam $State) -and $State.LocalGeneration -ceq $Attempt.localGeneration -and
        $assignment.revision -eq $Attempt.revision -and
        $assignment.examId -cmatch '\Afile-trace-[A-Za-z0-9._-]+\z' -and $assignment.examId -ceq $Attempt.examId)
}

function Get-ExamLabFileTraceStopReason($Context) {
    try {
        $attempt = $Context.Attempt
        if (-not (Test-ExamLabFileTraceAuthorization $attempt.examId $Context.AuthorizationPath)) { return 'opt-out' }
        $state = Read-ControllerState $Context.StatePath $attempt.deviceId
        if (-not (Test-ExamLabFileTraceAssignment $state $attempt)) { return 'assignment-ended' }
        $current = Get-ControllerConsoleLogon
        if (-not $current -or
            (Get-ControllerGuestSessionId $Context.Token $attempt.bootUtc $current) -cne $attempt.guestSessionId) {
            return 'guest-changed'
        }
    } catch { return 'binding-unavailable' }
}

function Read-ExamLabFileTraceAttempt {
    if (-not (Test-ExistingFile $script:FileTraceAttempt)) { return }
    Assert-SafePath $script:FileTraceAttempt
    $stream = [IO.File]::Open($script:FileTraceAttempt, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        if ($stream.Length -gt 8KB) { throw 'Отметка пробы FileIO.light превышает допустимый размер.' }
        $reader = [IO.StreamReader]::new($stream)
        try { $reader.ReadToEnd() | ConvertFrom-Json -DateKind String }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Open-ExamLabFileTraceLease {
    if (Test-ExistingFile $script:FileTraceLease) { Assert-SafePath $script:FileTraceLease }
    try { [IO.File]::Open($script:FileTraceLease, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch {
        $failure = $_.Exception.GetBaseException()
        if ($failure -isnot [IO.IOException] -or ($failure.HResult -band 0xffff) -notin 32,33) { throw }
    }
}

function Stop-ExamLabOrphanedFileTrace([string]$BootUtc) {
    $previous = Read-ExamLabFileTraceAttempt
    if (-not $previous -or $previous.phase -cne 'running') { return }
    $lease = Open-ExamLabFileTraceLease
    if (-not $lease) { return }
    try {
        # Полученный lease означает, что worker уже не сможет начать или продолжить эту попытку.
        $attempt = Read-ExamLabFileTraceAttempt
        if (-not $attempt -or $attempt.phase -cne 'running') { return }
        if ($attempt.runId -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Некорректное имя экземпляра FileIO.light.' }
        if ($attempt.bootUtc -ceq $BootUtc) {
            $wpr = Join-Path ([Environment]::GetFolderPath('System')) 'wpr.exe'
            Start-Process -FilePath $wpr -ArgumentList ('-cancel -instancename ExamLabFileIO-' + $attempt.runId) -WindowStyle Hidden
        }
        $attempt.phase = 'cleanup-requested'
        Write-ControllerJson $script:FileTraceAttempt $attempt
    } finally { $lease.Dispose() }
}

function Invoke-ExamLabFileTraceAssignment($Assignment, $Configuration, $Snapshot, $Observation) {
    if ($Assignment.mode -cne 'exam' -or $Assignment.examId -cnotmatch '\Afile-trace-[A-Za-z0-9._-]+\z' -or
        -not (Test-ExamLabFileTraceAuthorization $Assignment.examId $script:FileTraceAuthorization)) { return }
    if (-not $Observation.Readiness -or -not $Observation.Readiness.machineReady -or
        $Observation.Readiness.revision -ne $Assignment.revision) { return }
    $lockPath = Join-Path $script:DataRoot 'operation.lock'
    Assert-SafePath $lockPath
    $lock = Open-ExamLabModeLock $lockPath
    try {
        $state = Read-ControllerState $script:ControllerStateFile $Assignment.deviceId
        if ($state.LocalGeneration -cne $Snapshot.LocalGeneration -or
            -not (Test-ControllerActiveExam $state) -or
            (Compare-ControllerAssignment $Assignment $state.Assignment) -cne 'repeat') { return }
        Stop-ExamLabOrphanedFileTrace $Observation.Readiness.bootUtc
        if (-not $Observation.Readiness.guestSessionId) { return }
        $lease = Open-ExamLabFileTraceLease
        if (-not $lease) { return }
        try {
            $last = Read-ExamLabFileTraceAttempt
            if ($last) {
                if ($last.deviceId -cne $Assignment.deviceId) { throw 'Отметка пробы относится к другой регистрации ПК.' }
                if ($last.revision -gt $Assignment.revision -or $last.phase -ceq 'running' -or
                    ($last.revision -eq $Assignment.revision -and $last.phase -cne 'pending')) { return }
            }
            $attempt = [pscustomobject]@{
                deviceId = $Assignment.deviceId
                revision = $Assignment.revision
                examId = $Assignment.examId
                guestSessionId = $Observation.Readiness.guestSessionId
                bootUtc = $Observation.Readiness.bootUtc
                localGeneration = $Snapshot.LocalGeneration
                runId = [guid]::NewGuid().ToString('N')
                phase = 'pending'
            }
            if (Get-ExamLabFileTraceStopReason @{
                Attempt=$attempt; Token=$Configuration.token
                AuthorizationPath=$script:FileTraceAuthorization; StatePath=$script:ControllerStateFile
            }) { return }
            $entry = Join-Path $script:CodeRoot 'exam-lab.ps1'
            Assert-SafePath $entry -Readable
            Assert-SafePath (Join-Path $script:CodeRoot 'windows-fileio-light.ps1') -Readable
            $pwsh = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
            if ($last -and $last.revision -eq $attempt.revision -and $last.examId -ceq $attempt.examId -and
                $last.bootUtc -ceq $attempt.bootUtc -and $last.guestSessionId -ceq $attempt.guestSessionId -and
                $last.localGeneration -ceq $attempt.localGeneration) {
                if ($last.runId -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Некорректное имя экземпляра FileIO.light.' }
                $attempt = $last
            } else {
                # Worker сверяет runId под тем же lease, прежде чем начать запись.
                Write-ControllerJson $script:FileTraceAttempt $attempt
            }
        } finally { $lease.Dispose() }
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action file-trace -TraceRunId {1}' -f $entry, $attempt.runId
        Start-Process -FilePath $pwsh -ArgumentList $arguments -WindowStyle Hidden
    } finally { $lock.Dispose() }
}

function Test-ExamLabFileTraceNormal($State, $Attempt) {
    if (-not $State -or -not $State.Assignment -or $State.Assignment.deviceId -cne $Attempt.deviceId) { return $false }
    if ($State.Assignment.mode -ceq 'exam') {
        return ($State.Assignment.revision -eq $Attempt.revision -and $State.Assignment.examId -ceq $Attempt.examId -and
            $State.LocalNormal -and $State.StoppedExamId -ceq $Attempt.examId -and
            $State.LocalNormal.SourceCleanupCompleted -eq $true -and -not $State.LocalNormal.BaselineUnknown -and
            $State.Result -and $State.Result.outcome -ceq 'overridden' -and
            $State.Result.reason -ceq 'local-normal-source-confirmed')
    }
    return ($State.Result -and $State.Assignment.mode -ceq 'normal' -and
        $State.Assignment.revision -gt $Attempt.revision -and $State.Result.revision -eq $State.Assignment.revision -and
        $State.Result.mode -ceq 'normal' -and
        ($State.Result.outcome -ceq 'applied' -or
            ($State.Result.outcome -ceq 'source-applied' -and $State.Result.reason -ceq 'effective-readback-pending')))
}

function Start-ExamLabFileTraceExport($State) {
    if (-not $State) { return }
    if (-not [IO.File]::Exists($script:FileTraceAttempt)) { return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { if (-not $identity.IsSystem) { return } } finally { $identity.Dispose() }
    $attempt = Read-ExamLabFileTraceAttempt
    if (-not $attempt -or $attempt.phase -cne 'finished' -or $attempt.PSObject.Properties['exportRequestedUtc'] -or
        -not (Test-ExamLabFileTraceNormal $State $attempt)) { return }
    $lease = Open-ExamLabFileTraceLease
    if (-not $lease) { return }
    try {
        $attempt = Read-ExamLabFileTraceAttempt
        if (-not $attempt -or $attempt.phase -cne 'finished' -or $attempt.PSObject.Properties['exportRequestedUtc'] -or
            -not (Test-ExamLabFileTraceNormal $State $attempt) -or
            -not (Test-ExamLabFileTraceAuthorization $attempt.examId $script:FileTraceAuthorization)) { return }
        if ($attempt.runId -cnotmatch '\A[0-9a-f]{32}\z' -or
            ($attempt.revision -isnot [int] -and $attempt.revision -isnot [long]) -or
            $attempt.revision -lt 1 -or $attempt.revision -gt [int]::MaxValue) {
            throw 'Некорректная отметка экспорта FileIO.light.'
        }
        $exporter = Join-Path $script:CodeRoot 'Export-ExamLabFileTrace.ps1'
        Assert-SafePath $exporter -Readable
        $instance = 'ExamLabFileIO-' + $attempt.runId
        $reportsRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabSetupReports'
        $directory = Join-Path $reportsRoot $instance
        Assert-SafePath $reportsRoot
        Assert-SafePath $directory
        $stdout = Join-Path $directory 'export.json'
        $stderr = Join-Path $directory 'export-error.txt'
        if ((Test-Path -LiteralPath $stdout) -or (Test-Path -LiteralPath $stderr)) { throw 'Отчёт экспорта уже существует.' }
        $pwsh = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ExpectedComputerName "{1}" -TraceInstance {2} -Upload -ExamRevision {3} -Headless' -f
            $exporter, $env:COMPUTERNAME, $instance, $attempt.revision
        try {
            Start-Process -FilePath $pwsh -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        } catch {
            foreach ($path in @($stdout, $stderr)) {
                $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if ($file -is [IO.FileInfo] -and $file.Length -eq 0) {
                    Remove-Item -LiteralPath $file.FullName -ErrorAction SilentlyContinue
                }
            }
            throw
        }
        $attempt | Add-Member -NotePropertyName exportRequestedUtc -NotePropertyValue (Get-ControllerUtc)
        Write-ControllerJson $script:FileTraceAttempt $attempt
    } finally { $lease.Dispose() }
}

function Complete-ExamLabFileTraceNormal($State) {
    $attempt = Read-ExamLabFileTraceAttempt
    if (-not $attempt) { return }
    if ($attempt.phase -ceq 'running') {
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
        $bootUtc = $boot.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
        Stop-ExamLabOrphanedFileTrace $bootUtc
    } elseif ($attempt.phase -ceq 'finished') {
        Start-ExamLabFileTraceExport $State
    }
}

function Invoke-ExamLabFileTraceProbe([guid]$TraceRunId) {
    Assert-Host
    if ($PSScriptRoot -cne $script:CodeRoot -or $TraceRunId -eq [guid]::Empty) {
        throw 'Запустите установленную пробу ExamLab с отметкой попытки.'
    }
    Assert-SafePath $script:CodeRoot -Readable
    Assert-SafePath $script:DataRoot
    Assert-SafePath $script:ControllerConfigurationFile
    Assert-SafePath $script:ControllerStateFile
    $configuration = Read-ControllerConfiguration $script:ControllerConfigurationFile
    $lease = Open-ExamLabFileTraceLease
    if (-not $lease) { return }
    try {
        $attempt = Read-ExamLabFileTraceAttempt
        if (-not $attempt -or $attempt.phase -cne 'pending' -or
            $attempt.runId -cne $TraceRunId.ToString('N') -or $attempt.deviceId -cne $configuration.deviceId) { return }
        # Обратный вызов из сценария захвата использует его собственную область script:.
        $context = @{
            Attempt=$attempt; Token=$configuration.token
            AuthorizationPath=$script:FileTraceAuthorization; StatePath=$script:ControllerStateFile
        }
        if (Get-ExamLabFileTraceStopReason $context) { return }
        $guest = Get-ExamLabControllerGuestBinding
        if (-not $guest -or $guest.Revision -ne $attempt.revision -or $guest.BootUtc -cne $attempt.bootUtc -or
            $guest.GuestSessionId -cne $attempt.guestSessionId) { return }
        $capture = Join-Path $script:CodeRoot 'windows-fileio-light.ps1'
        Assert-SafePath $capture -Readable
        $attempt.phase = 'running'
        Write-ControllerJson $script:FileTraceAttempt $attempt
        $records = & $capture -ExpectedComputerName $env:COMPUTERNAME -Seconds 35 -RunId $TraceRunId `
            -StopWhen { param($Current) Get-ExamLabFileTraceStopReason $Current } -StopContext $context
        $completed = @($records | ConvertFrom-Json | Where-Object { $_.event -ceq 'completed' })
        $attempt.phase = if ($completed.Count -eq 1) { 'finished' } else { 'closed-without-trace' }
        Write-ControllerJson $script:FileTraceAttempt $attempt
    } finally { $lease.Dispose() }
    if ($attempt.phase -ceq 'finished') {
        # Штатный normal и завершение записи могут происходить в любом порядке.
        # После публикации закрытого ETL повторно читаем сохранённый результат normal.
        Start-ExamLabFileTraceExport (Read-ControllerState $script:ControllerStateFile $configuration.deviceId)
    }
}
