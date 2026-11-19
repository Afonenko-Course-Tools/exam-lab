function Test-ExamLabFileReadAudit {
    param(
        [xml]$EventXml,
        [string]$Path,
        [string]$Sid,
        [string]$LogonId,
        [DateTimeOffset]$ArmedUtc,
        [DateTimeOffset]$NowUtc
    )

    $system = $EventXml.Event.System
    if ($system.EventID -ne '4663' -or $system.Provider.Name -cne 'Microsoft-Windows-Security-Auditing' -or
        $system.Channel -cne 'Security' -or $system.Keywords -ne '0x8020000000000000') { return $false }

    $created = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$system.TimeCreated.SystemTime,
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$created)) {
        return $false
    }
    $age = ($NowUtc - $created).TotalSeconds
    if ($created -lt $ArmedUtc -or $age -lt 0 -or $age -gt 120) { return $false }

    $fields = @{}
    foreach ($field in $EventXml.Event.EventData.Data) { $fields[$field.Name] = $field.'#text' }
    return $fields.ObjectType -ceq 'File' -and $fields.ObjectName -eq $Path -and
        $fields.SubjectUserSid -eq $Sid -and $fields.SubjectLogonId -eq $LogonId -and
        $fields.AccessMask -match '^0x[0-9a-f]*[13579bdf]$'
}
