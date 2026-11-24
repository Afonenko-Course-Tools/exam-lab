function Collect-ExamLabDiagnostics {
    param([Parameter(Mandatory)][string]$DiagnosticDirectory)

    $report = Join-Path $DiagnosticDirectory 'report'
    $systemInfo = Join-Path $report 'windows-summary.txt'
    $since = (Get-Item -LiteralPath $DiagnosticDirectory).CreationTimeUtc.AddMinutes(-1)
    $created = [DateTime]::UtcNow
    @(
        "UTC: $($created.ToString('o'))"
        "Windows: $([Environment]::OSVersion.Version)"
        "64-bit process: $([Environment]::Is64BitProcess)"
        "PowerShell: $($PSVersionTable.PSVersion)"
        "System drive free bytes: $(([IO.DriveInfo]::new($env:SystemDrive)).AvailableFreeSpace)"
    ) | Set-Content -LiteralPath $systemInfo

    try {
        Get-Service -Name 'WazuhSvc','Schedule' -ErrorAction SilentlyContinue |
            Format-Table Name, Status, StartType -AutoSize |
            Out-String | Add-Content -LiteralPath $systemInfo
        $tasks = Get-ScheduledTask -TaskName 'ExamLab*' -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            $info = $task | Get-ScheduledTaskInfo
            "$($task.TaskName) $($task.State) lastRun=$($info.LastRunTime.ToString('o')) lastResult=$($info.LastTaskResult)" |
                Add-Content -LiteralPath $systemInfo
        }
    } catch {
        'Service or task inspection failed.' | Add-Content -LiteralPath $systemInfo
    }

    $targets = @(
        @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = $since }
        @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7023, 7024, 7031, 7034, 7045; StartTime = $since }
        @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $since }
        @{ LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'; Level = 1, 2, 3; StartTime = $since }
    )
    $events = foreach ($target in $targets) {
        Get-WinEvent -FilterHashtable $target -MaxEvents 40 -ErrorAction SilentlyContinue |
            Where-Object {
                if ($_.LogName -like '*TaskScheduler*') {
                    return @($_.Properties | Where-Object { $_.Value -is [string] -and $_.Value -match '^\\ExamLab' }).Count -gt 0
                }
                if ($_.ProviderName -eq 'Service Control Manager') {
                    return @($_.Properties | Where-Object { $_.Value -match 'Wazuh|ExamLab|Schedule' }).Count -gt 0
                }
                if ($_.ProviderName -eq 'MsiInstaller') {
                    return $_.Message -match 'PowerShell|Temurin|OpenJDK|Wazuh'
                }
                return $true
            } | Select-Object LogName, ProviderName, Id, RecordId, Level, TimeCreated
    }
    ConvertTo-Json -InputObject @($events) -Depth 3 |
        Set-Content -LiteralPath (Join-Path $report 'windows-events.json')
}
