function Collect-ExamLabDiagnostics {
    param([Parameter(Mandatory)][string]$DiagnosticDirectory)

    # The bootstrap owns the current attempt and creates this private directory.
    $report = Join-Path $DiagnosticDirectory 'report'
    $since = (Get-Item -LiteralPath $DiagnosticDirectory -ErrorAction Stop).CreationTimeUtc.AddMinutes(-1)
    $errors = Join-Path $report 'windows-collection-errors.log'

    function Write-CollectionError([string]$Source, [System.Management.Automation.ErrorRecord]$Failure) {
        @(
            "[$([DateTime]::UtcNow.ToString('o'))] $Source"
            ($Failure | Format-List * -Force | Out-String -Width 4096)
            $Failure.Exception.ToString()
        ) | Add-Content -LiteralPath $errors -Encoding UTF8
    }

    $summary = [ordered]@{
        CollectedUtc = [DateTime]::UtcNow.ToString('o')
        EventWindowStartUtc = $since.ToString('o')
        Windows = [Environment]::OSVersion.Version.ToString()
        ProcessIs64Bit = [Environment]::Is64BitProcess
        PowerShell = $PSVersionTable.PSVersion.ToString()
    }
    try {
        $summary.SystemDriveFreeBytes = ([IO.DriveInfo]::new($env:SystemDrive)).AvailableFreeSpace
        $summary.OperatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
            Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
        $summary.Services = @(Get-CimInstance Win32_Service -Filter "Name='WazuhSvc' OR Name='Schedule'" -ErrorAction Stop |
            Select-Object Name, DisplayName, State, StartMode, Status, ExitCode, ServiceSpecificExitCode, PathName)
    } catch { Write-CollectionError 'Windows summary' $_ }
    $summary | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $report 'windows-summary.json') -Encoding UTF8

    try {
        $scheduler = New-Object -ComObject 'Schedule.Service' -ErrorAction Stop
        $scheduler.Connect()
        $taskFolder = $scheduler.GetFolder('\')
        $definitions = foreach ($task in $taskFolder.GetTasks(1)) {
            if ($task.Name -notlike 'ExamLab-*') { continue }
            try {
                $definition = [ordered]@{
                    Name = $task.Name
                    Path = $task.Path
                    State = [int]$task.State
                    Enabled = $task.Enabled
                    LastRunTime = $task.LastRunTime.ToString('o')
                    LastTaskResult = $task.LastTaskResult
                    Xml = $task.Xml
                }
                try { $definition.SecurityDescriptor = $task.GetSecurityDescriptor(7) }
                catch { Write-CollectionError "Task security descriptor $($task.Path)" $_ }
                $definition
            } catch { Write-CollectionError "Task $($task.Path)" $_ }
        }
        ConvertTo-Json -InputObject @($definitions) -Depth 4 |
            Set-Content -LiteralPath (Join-Path $report 'windows-tasks.json') -Encoding UTF8
    } catch { Write-CollectionError 'Task Scheduler definitions' $_ }

    $targets = [ordered]@{
        'msi' = @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = $since }
        'service-control' = @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7023, 7024, 7031, 7034, 7040, 7045; StartTime = $since }
        'schannel' = @{ LogName = 'System'; ProviderName = 'Schannel'; StartTime = $since }
        'task-scheduler' = @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $since }
        'device-management' = @{ LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'; StartTime = $since }
    }
    foreach ($target in $targets.GetEnumerator()) {
        try {
            $xml = [IO.StreamWriter]::new((Join-Path $report ("windows-events-$($target.Key).xml")), $false)
            try {
                $xml.WriteLine('<Events>')
                Get-WinEvent -FilterHashtable $target.Value -Oldest -ErrorAction Stop | ForEach-Object {
                    $event = $_
                    try {
                        if ($target.Key -eq 'task-scheduler') {
                            $taskProperty = $event.Properties | Where-Object {
                                $_.Value -is [string] -and $_.Value -like '\ExamLab-*'
                            } | Select-Object -First 1
                            if (-not $taskProperty) { return }
                        }
                        $xml.WriteLine($event.ToXml())
                    } finally { $event.Dispose() }
                }
            } finally {
                $xml.WriteLine('</Events>')
                $xml.Dispose()
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') {
                Write-CollectionError "Windows event log $($target.Value.LogName)" $_
            }
        }
    }
}
