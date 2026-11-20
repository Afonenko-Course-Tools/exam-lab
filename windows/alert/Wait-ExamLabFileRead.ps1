[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$RunId,
    [Parameter(Mandatory)][long]$AuditBaseline,
    [Parameter(Mandatory)][string]$CanaryPath,
    [Parameter(Mandatory)][string]$GuestLogonId,
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabAlert'
if ($PSScriptRoot -ne $base -or -not [Environment]::Is64BitProcess) {
    throw 'Run the installed script from 64-bit Windows PowerShell.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Windows administrator is required.'
}
if ($AuditBaseline -le 0 -or $GuestLogonId -notmatch '^0x[0-9a-f]+$' -or
    $CanaryPath -notmatch '^[A-Z]:\\') {
    throw 'Supply a Security log baseline, Guest logon ID and full local file path.'
}

. (Join-Path $base 'Test-ExamLabFileReadAudit.ps1')
$key = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
$clock = [Diagnostics.Stopwatch]::StartNew()
do {
    $state = Get-ItemPropertyValue -LiteralPath $key -Name Status | ConvertFrom-Json
    if ($state.RunId -ne $RunId.ToString('D') -or $state.Phase -ne 'Armed' -or
        -not $state.ArmedUtc -or $state.EventRecordId -ne 0 -or $state.SecurityReadRecordId) {
        throw 'The requested Guest alert is not armed for a new signal.'
    }
    $guestSid = [Security.Principal.SecurityIdentifier]::new([string]$state.GuestSid).Value
    $query = "*[System[EventID=4663 and EventRecordID > $AuditBaseline] and EventData[Data[@Name='SubjectUserSid']='$guestSid' and Data[@Name='SubjectLogonId']='$GuestLogonId']]"
    $events = try {
        Get-WinEvent -LogName Security -FilterXPath $query -Oldest
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
    }
    foreach ($event in $events) {
        if (Test-ExamLabFileReadAudit -EventXml ([xml]$event.ToXml()) -Path $CanaryPath -Sid $guestSid -LogonId $GuestLogonId -ArmedUtc ([DateTimeOffset]$state.ArmedUtc) -NowUtc ([DateTimeOffset]::UtcNow)) {
            & (Join-Path $base 'ExamLabAlert.ps1') -Action SignalFromAudit -RunId $RunId `
                -AuditBaseline $AuditBaseline -AuditRecordId $event.RecordId -CanaryPath $CanaryPath -GuestLogonId $GuestLogonId
            return
        }
    }
    Start-Sleep -Milliseconds 250
} while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds)
throw 'No new successful Guest read of the canary was recorded before timeout.'
