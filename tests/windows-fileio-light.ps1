#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [ValidateRange(10,45)][int]$Seconds = 35,
    [guid]$RunId = [guid]::NewGuid(),
    [scriptblock]$StopWhen,
    $StopContext
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Environment]::Is64BitProcess -or
    -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $env:COMPUTERNAME -ine $ExpectedComputerName) {
    throw 'Запустите повышенный PowerShell 7 на согласованной испытательной VM.'
}

$private = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabSetupReports'
$directory = Get-Item -LiteralPath $private -Force
for ($ancestor = $directory; $ancestor; $ancestor = $ancestor.Parent) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Путь трассы содержит перенаправление.' }
}
$acl = Get-Acl -LiteralPath $private
$trusted = @('S-1-5-18','S-1-5-32-544') + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
if (-not $directory.PSIsContainer -or -not $acl.AreAccessRulesProtected -or
    $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
    @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $trusted
    }).Count) {
    throw 'Трассу нужно сохранять в закрытом каталоге отчётов ExamLab.'
}
$disk = [IO.DriveInfo]::new($directory.Root.FullName)
if ($disk.AvailableFreeSpace -lt 2GB) { throw 'Для остановки WPR и записи ETL требуется минимум 2 ГиБ свободного места.' }

$wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
$instance = 'ExamLabFileIO-' + $RunId.ToString('N')
$output = Join-Path $private $instance
$recording = Join-Path $output 'recording'
[void](New-Item -ItemType Directory -Path $output)
[void](New-Item -ItemType Directory -Path $recording)
$etl = Join-Path $output 'fileio.etl'
$wprLog = Join-Path $output 'wpr.txt'
$metrics = Join-Path $output 'metrics.jsonl'

# Снимок доступной физической памяти без опроса WMI и фонового сборщика.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ExamLabFileIoMemory
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Size;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong Reserved;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);

    public static ulong AvailableBytes()
    {
        var status = new MemoryStatus { Size = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (!GlobalMemoryStatusEx(ref status))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return status.AvailablePhysical;
    }
}
'@

function Invoke-Wpr([string[]]$Arguments, [int]$TimeoutSeconds = 10) {
    $info = [Diagnostics.ProcessStartInfo]::new($wpr)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { }
            throw "Истекло время выполнения wpr $($Arguments[0])."
        }
        $lines = @(($stdout.GetAwaiter().GetResult(), $stderr.GetAwaiter().GetResult()) -split '\r?\n' |
            Where-Object { $_ })
        $lines | Tee-Object -FilePath $wprLog -Append | Out-Host
        if ($process.ExitCode -ne 0) { throw "wpr $($Arguments[0]) завершился кодом $($process.ExitCode)." }
        $lines
    } finally { $process.Dispose() }
}

function Wait-TraceTarget([long]$TargetMilliseconds) {
    while ($recordClock.ElapsedMilliseconds -lt $TargetMilliseconds) {
        if ($StopWhen) {
            $reason = & $StopWhen $StopContext
            if ($reason) { return $reason }
        }
        $remaining = [math]::Max(0, $TargetMilliseconds - $recordClock.ElapsedMilliseconds)
        $delay = if ($StopWhen) { [math]::Min(1000, $remaining) } else { $remaining }
        if ($delay) { Start-Sleep -Milliseconds $delay }
    }
}

function Write-TraceRecord([System.Collections.IDictionary]$Record) {
    $Record['schemaVersion'] = 1
    $Record['instance'] = $instance
    $line = $Record | ConvertTo-Json -Compress -Depth 7
    Add-Content -LiteralPath $metrics -Value $line -Encoding utf8
    $line
}

function Get-MemorySample([string]$Phase) {
    [pscustomobject]@{
        phase = $Phase
        utc = [DateTimeOffset]::UtcNow.ToString('o')
        availablePhysicalBytes = [ExamLabFileIoMemory]::AvailableBytes()
    }
}

function Get-WprLoss([string[]]$Lines) {
    $collectors = [Collections.Generic.List[object]]::new()
    $current = $null
    $dropped = $null
    $observedLoss = $false
    foreach ($line in $Lines) {
        if ($line -match '^\s*Dropped events?\s*:\s*([0-9]+)\s*$') {
            $dropped = [long]$Matches[1]
            $observedLoss = $observedLoss -or ($dropped -gt 0)
        } elseif ($line -match '^\s*Collector Name\s*:\s*(\S.*)$') {
            $current = [ordered]@{
                name = $Matches[1].Trim()
                eventsLost = $null
                buffersLost = $null
                logBuffersLost = $null
                realTimeBuffersLost = $null
            }
            $collectors.Add($current)
        } elseif ($current -and $line -match '^\s*(Events Lost|Buffers Lost|Log Buffers Lost|Real Time Buffers Lost)\s*:\s*([0-9]+)\s*$') {
            $field = switch ($Matches[1]) {
                'Events Lost' { 'eventsLost' }
                'Buffers Lost' { 'buffersLost' }
                'Log Buffers Lost' { 'logBuffersLost' }
                'Real Time Buffers Lost' { 'realTimeBuffersLost' }
            }
            $count = [long]$Matches[2]
            $current[$field] = $count
            $observedLoss = $observedLoss -or ($count -gt 0)
        }
    }
    $complete = $null -ne $dropped -and $collectors.Count -gt 0 -and
        @($collectors | Where-Object { $null -eq $_.eventsLost }).Count -eq 0
    [pscustomobject]@{
        source = 'wpr-status-before-stop'
        countersRecognized = $complete
        droppedEvents = $dropped
        hasObservedLoss = if ($observedLoss) { $true } elseif ($complete) { $false } else { $null }
        collectors = $collectors.ToArray()
    }
}

$startAttempted = $false
$phase = 'profile'
$memory = [Collections.Generic.List[object]]::new()
try {
    $null = Invoke-Wpr @('-profiledetails', 'FileIO.light', '-filemode')
    $memory.Add((Get-MemorySample 'before-start'))
    if ($StopWhen) {
        $stopReason = & $StopWhen $StopContext
        if ($stopReason) {
            Write-TraceRecord ([ordered]@{ event = 'skipped'; reason = $stopReason })
            return
        }
    }
    $phase = 'start'
    $startClock = [Diagnostics.Stopwatch]::StartNew()
    $startAttempted = $true
    $null = Invoke-Wpr @('-start', 'FileIO.light', '-filemode', '-recordtempto', $recording, '-instancename', $instance)
    $startClock.Stop()
    $recordClock = [Diagnostics.Stopwatch]::StartNew()
    $started = [DateTimeOffset]::UtcNow
    $memory.Add((Get-MemorySample 'after-start'))
    Write-TraceRecord ([ordered]@{
        event = 'started'
        profile = 'FileIO.light'
        mode = 'file'
        startedUtc = $started.ToString('o')
        targetSeconds = $Seconds
        startMilliseconds = $startClock.ElapsedMilliseconds
        directory = $output
    })

    $phase = 'record'
    Write-Host "Трасса запущена на $Seconds с. Выполните один короткий контрольный шаг в Guest."
    Write-Host "Команда ручной отмены: wpr -cancel -instancename $instance"
    $stopReason = Wait-TraceTarget ($Seconds * 500)
    if (-not $stopReason) {
        $memory.Add((Get-MemorySample 'mid-recording'))
        $stopReason = Wait-TraceTarget ($Seconds * 1000)
    }
    if (-not $stopReason) { $stopReason = 'timeout' }
    $recordWindowMilliseconds = $recordClock.ElapsedMilliseconds

    $phase = 'status'
    $status = @()
    if ($stopReason -ceq 'timeout') {
        try { $status = @(Invoke-Wpr @('-status', 'collectors', '-details', '-instancename', $instance) 3) }
        catch { Write-Warning $_.Exception.Message }
    }
    $loss = Get-WprLoss $status
    $memory.Add((Get-MemorySample 'before-stop'))

    $phase = 'stop'
    $stopRequested = [DateTimeOffset]::UtcNow
    $recordClock.Stop()
    $stopClock = [Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-Wpr @('-stop', $etl, 'ExamLab Guest FileIO.light', '-skipPdbGen', '-instancename', $instance) 90
    $startAttempted = $false
    $stopClock.Stop()
    $finished = [DateTimeOffset]::UtcNow
    $memory.Add((Get-MemorySample 'after-stop'))

    $phase = 'hash'
    $hashClock = [Diagnostics.Stopwatch]::StartNew()
    $length = (Get-Item -LiteralPath $etl).Length
    if ($length -le 0) { throw 'WPR сохранил пустой ETL.' }
    $hash = (Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash
    $hashClock.Stop()
    Write-TraceRecord ([ordered]@{
        event = 'completed'
        profile = 'FileIO.light'
        mode = 'file'
        startedUtc = $started.ToString('o')
        stopRequestedUtc = $stopRequested.ToString('o')
        finishedUtc = $finished.ToString('o')
        targetSeconds = $Seconds
        startMilliseconds = $startClock.ElapsedMilliseconds
        windowMilliseconds = $recordWindowMilliseconds
        stopReason = $stopReason
        beforeStopMilliseconds = $recordClock.ElapsedMilliseconds
        stopMilliseconds = $stopClock.ElapsedMilliseconds
        hashMilliseconds = $hashClock.ElapsedMilliseconds
        memorySamples = $memory.ToArray()
        loss = $loss
        tracePath = $etl
        bytes = $length
        sha256 = $hash
    })
} catch {
    Write-TraceRecord ([ordered]@{
        event = 'failed'
        phase = $phase
        utc = [DateTimeOffset]::UtcNow.ToString('o')
        memorySamples = $memory.ToArray()
        errorType = $_.Exception.GetType().FullName
    })
    throw
} finally {
    if ($startAttempted) {
        try {
            $null = Invoke-Wpr @('-cancel', '-instancename', $instance)
            Write-TraceRecord ([ordered]@{ event = 'cancelled'; utc = [DateTimeOffset]::UtcNow.ToString('o') })
        } catch {
            Write-TraceRecord ([ordered]@{
                event = 'cancel-failed'
                utc = [DateTimeOffset]::UtcNow.ToString('o')
                cancelCommand = "wpr -cancel -instancename $instance"
            })
            Write-Warning "Проверьте состояние именованного экземпляра: wpr -status -instancename $instance"
        }
    }
}
