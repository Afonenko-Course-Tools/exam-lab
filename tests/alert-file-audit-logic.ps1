$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../windows/alert/Test-ExamLabFileReadAudit.ps1')
$now = [DateTimeOffset]::Parse('2026-11-19T12:01:00Z')
$xmlText = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4663</EventID>
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-11-19T12:00:50Z"/><Channel>Security</Channel></System>
<EventData><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\ExamLab\Canary.txt</Data>
<Data Name="SubjectUserSid">S-1-5-21-11-22-33-1001</Data><Data Name="SubjectLogonId">0x123ab</Data>
<Data Name="AccessMask">0x120089</Data></EventData>
</Event>
'@
$expected = @{ Path='C:\ExamLab\Canary.txt'; Sid='S-1-5-21-11-22-33-1001'; LogonId='0x123ab'; NowUtc=$now; ArmedUtc=$now.AddSeconds(-30) }
if (-not (Test-ExamLabFileReadAudit -EventXml ([xml]$xmlText) @expected)) { throw 'Expected matching read.' }
$changes = @(
    @('Canary.txt','Other.txt'), @('>File<','>Key<'), @('33-1001','33-1002'),
    @('0x123ab','0x123ac'), @('0x120089','0x120088'), @('>4663<','>4656<'),
    @('0x8020000000000000','0x8010000000000000'),
    @('12:00:50Z','11:58:59Z'), @('12:00:50Z','12:00:29Z'), @('12:00:50Z','12:01:01Z')
)
foreach ($change in $changes) {
    $modified = [xml]($xmlText.Replace($change[0], $change[1]))
    if (Test-ExamLabFileReadAudit -EventXml $modified @expected) {
        throw "Unexpected match after replacing $($change[0]) with $($change[1])."
    }
}
'File read audit logic passed'
