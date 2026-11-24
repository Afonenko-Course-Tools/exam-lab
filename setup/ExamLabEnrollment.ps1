# Используется только проверенным установщиком под общей блокировкой обслуживания.
function Assert-ExamLabEnrollmentRosterMatches([object[]]$Saved, [object[]]$Observed) {
    if ((ConvertTo-Json -InputObject $Saved -Compress) -cne (ConvertTo-Json -InputObject $Observed -Compress)) {
        throw 'The ordinary local Windows accounts differ from the saved ExamLab roster. Administrative review is required.'
    }
}

function Get-ExamLabEnrollmentRoster([object[]]$SavedOrdinaryAccounts = @(), [switch]$PreviouslyPrepared) {
    $users = @(Get-LocalUser -ErrorAction Stop)
    $setupAccountIssue = Get-ExamLabSetupAccountIssue -LocalAccounts $users
    if ($setupAccountIssue) { throw $setupAccountIssue }
    $roster = @(foreach ($user in $users) {
        $sid = $user.SID.Value
        if ($sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-(?<Rid>[0-9]+)\z') {
            throw 'Windows returned an unexpected local user SID.'
        }
        if ([long]$Matches.Rid -ge 1000) { [pscustomobject]@{ Sid = $sid; Name = $user.Name } }
    })
    $hasSavedRoster = $PSBoundParameters.ContainsKey('SavedOrdinaryAccounts')
    $guestArguments = @{
        LocalAccounts = $users
        OrdinaryAccounts = $SavedOrdinaryAccounts
        IdentifyOnly = -not $hasSavedRoster
    }
    if ($hasSavedRoster -and $PreviouslyPrepared) { $guestArguments.PreviouslyPrepared = $true }
    $guestEvidence = @(Get-ExamLabGuestRosterEvidence @guestArguments)
    if (-not $hasSavedRoster -and $guestEvidence.Count) {
        throw 'First ExamLab enrollment found an unlisted Shared PC account. Administrative review is required before enrollment.'
    }
    if ($hasSavedRoster) {
        $savedSids = @($SavedOrdinaryAccounts | ForEach-Object Sid)
        $excludedSids = @(foreach ($guest in $guestEvidence) {
            if ($guest.Sid -in $savedSids) { continue }
            if ($guest.VerifiedInactive -isnot [bool] -or -not $guest.VerifiedInactive) {
                throw "Shared PC account $($guest.Sid) could not be verified as inactive. Administrative review is required."
            }
            $guest.Sid
        })
        $roster = @($roster | Where-Object { $_.Sid -notin $excludedSids })
    }
    if (-not ($roster | Where-Object Name -ne 'defaultuser0')) {
        throw 'Windows has no ordinary local user accounts for ExamLab.'
    }
    $roster = @($roster | Sort-Object Sid)
    if ($hasSavedRoster) { Assert-ExamLabEnrollmentRosterMatches $SavedOrdinaryAccounts $roster }
    $roster
}

function Request-ExamLabEnrollment([uri]$EnrollmentUrl, [string]$Claim) {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    $client.MaxResponseContentBufferSize = 32768
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $EnrollmentUrl)
        try {
            $request.Content = [Net.Http.StringContent]::new(
                (@{ claim = $Claim } | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json')
            try { $response = $client.Send($request) }
            catch { throw 'ExamLab could not reach the enrollment server over HTTPS. Run the same launcher again.' }
            try {
                if ([int]$response.StatusCode -notin 200,201) {
                    $reason = $null
                    try {
                        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                        $reason = (ConvertFrom-Json -InputObject $body -NoEnumerate).error
                    } catch { }
                    $message = switch -Exact ($reason) {
                        'enrollment-closed' { 'No enrollment window is open for this PC.' }
                        'enrollment-expired' { 'The enrollment window has expired.' }
                        'enrollment-already-claimed' { 'The enrollment window has no places left for a new PC.' }
                        'diagnostic-enrollment-revoked' { 'The saved diagnostic registration was revoked.' }
                        'diagnostic-wazuh-unavailable' { 'The diagnostic server could not issue a Wazuh key. Run the same launcher again.' }
                    }
                    if ($message) { throw "ExamLab enrollment failed. $message" }
                    if ([int]$response.StatusCode -in 401,403) { throw 'ExamLab enrollment access was denied by the server.' }
                    throw "ExamLab enrollment server returned HTTP $([int]$response.StatusCode)."
                }
                try {
                    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    ConvertFrom-Json -InputObject $body -DateKind String -NoEnumerate
                } catch { throw 'ExamLab enrollment server returned invalid JSON.' }
            } finally { $response.Dispose() }
        } finally { $request.Dispose() }
    } finally { $client.Dispose() }
}

function Assert-ExamLabEnrollmentReceipt($Receipt, [string]$ControllerUrl) {
    try {
        if ($Receipt -isnot [pscustomobject] -or @($Receipt.PSObject.Properties).Count -ne 3 -or
            @($Receipt.PSObject.Properties.Name | Where-Object { $_ -cnotin 'network','registration','wazuhKey' }).Count -or
            $Receipt.network -isnot [pscustomobject] -or $Receipt.registration -isnot [pscustomobject] -or
            @($Receipt.registration.PSObject.Properties).Count -ne 3 -or
            @($Receipt.registration.PSObject.Properties.Name | Where-Object { $_ -cnotin 'url','deviceId','token' }).Count) {
            throw 'schema'
        }
        $registration = $Receipt.registration
        if ($registration.url -isnot [string] -or $registration.url -cne $ControllerUrl -or
            $registration.deviceId -isnot [string] -or $registration.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
            $registration.token -isnot [string] -or $registration.token -cnotmatch '\A[A-Za-z0-9_-]{43}\z' -or
            $Receipt.wazuhKey -isnot [string] -or $Receipt.wazuhKey.Length -gt 1024) { throw 'registration' }
        Test-ExamNetworkConfig $Receipt.network
        $url = [uri]$ControllerUrl
        if ($Receipt.network.ControllerEndpoint.IP -cne $url.Host -or
            $Receipt.network.ControllerEndpoint.Port -ne $url.Port -or $Receipt.network.WazuhEndpoint.Port -ne 1514) {
            throw 'network'
        }
        $key = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($Receipt.wazuhKey))
        if ($key -cnotmatch '\A[0-9]{3,8} [A-Za-z0-9_.-]+ [A-Za-z0-9.:/_-]+ [A-Fa-f0-9]{64}\z') { throw 'key' }
    } catch { throw 'ExamLab enrollment data does not match the registration, network or Wazuh contract.' }
}

function Test-ExamLabPreviouslyPreparedEnrollment($Record, [string]$ControllerUrl) {
    if ($null -eq $Record -or $null -eq $Record.receipt) { return $false }
    Assert-ExamLabEnrollmentReceipt $Record.receipt $ControllerUrl
    $modePath = Join-Path $examLabStatePath 'mode.json'
    $configurationPath = Join-Path $examLabStatePath 'pc.json'
    if (-not ([IO.File]::Exists($modePath) -and [IO.File]::Exists($configurationPath))) { return $false }
    try {
        Assert-ExamLabProtectedPath $examLabStatePath
        $mode = Read-ExamLabProtectedJson $modePath
        if ($mode -isnot [pscustomobject] -or @($mode.PSObject.Properties).Count -ne 3 -or
            @($mode.PSObject.Properties.Name | Where-Object { $_ -cnotin 'Prepared', 'Revision', 'LastCompletedMode' }).Count -or
            $mode.Prepared -isnot [bool] -or -not $mode.Prepared -or
            $mode.Revision -isnot [string] -or $mode.Revision -cnotmatch '\A[A-F0-9]{64}\z' -or
            $mode.LastCompletedMode -cnotin @($null, 'normal', 'exam')) { return $false }

        Assert-ExamLabProtectedPath $configurationPath
        # Пока читается JSON, тот же исходный файл остаётся доступен только для чтения.
        $configurationFile = [IO.File]::Open($configurationPath, 'Open', 'Read', 'Read')
        try {
            if ((Get-FileHash -InputStream $configurationFile -Algorithm SHA256).Hash -cne $mode.Revision) { return $false }
            $configuration = Read-ExamLabProtectedJson $configurationPath
            if ($configuration -isnot [pscustomobject] -or @($configuration.PSObject.Properties).Count -ne 2 -or
                @($configuration.PSObject.Properties.Name | Where-Object { $_ -cnotin 'OrdinaryAccounts', 'Network' }).Count -or
                $configuration.OrdinaryAccounts -isnot [array] -or $configuration.Network -isnot [pscustomobject]) { return $false }
            if ((ConvertTo-Json -InputObject $configuration.Network -Depth 10 -Compress) -cne
                (ConvertTo-Json -InputObject $Record.receipt.network -Depth 10 -Compress)) { return $false }
            Assert-ExamLabEnrollmentRosterMatches $Record.ordinaryAccounts $configuration.OrdinaryAccounts
            return $true
        } finally { $configurationFile.Dispose() }
    } catch { return $false }
}

function Write-ExamLabEnrollmentArtifact([string]$Path, [string]$Content) {
    if (Test-Path -LiteralPath $Path) {
        Assert-ExamLabProtectedPath $Path
        if ([IO.File]::ReadAllText($Path) -cne $Content) { throw 'Saved ExamLab enrollment input differs from its receipt.' }
        return
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Content)
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        [IO.File]::Move($temporary, $Path)
    } finally { [IO.File]::Delete($temporary) }
}

function Read-ExamLabEnrollmentRecord([string]$Directory, [string]$EnrollmentUrl) {
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    Assert-ExamLabProtectedPath $Directory
    $ledger = Join-Path $Directory 'enrollment.json'
    if (-not (Test-Path -LiteralPath $ledger)) { return }
    try {
        $record = Read-ExamLabProtectedJson $ledger
        if ($record.schema -ne 1 -or $record.enrollmentUrl -cne $EnrollmentUrl -or
            $record.claim -isnot [string] -or $record.claim -cnotmatch '\A[0-9a-f]{64}\z' -or
            $record.ordinaryAccounts -isnot [array] -or -not $record.ordinaryAccounts.Count -or
            -not $record.PSObject.Properties['receipt']) { throw 'ledger' }
        foreach ($account in $record.ordinaryAccounts) {
            if ($account -isnot [pscustomobject] -or @($account.PSObject.Properties).Count -ne 2 -or
                $account.Sid -isnot [string] -or $account.Sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z' -or
                $account.Name -isnot [string] -or -not $account.Name) { throw 'roster' }
        }
        return $record
    } catch { throw 'Saved ExamLab enrollment record is invalid or belongs to a different server.' }
}

function Get-ExamLabEnrollmentInputs([string]$Directory, [string]$EnrollmentUrl, [string]$ControllerUrl, [object[]]$Roster) {
    if (-not (Test-Path -LiteralPath $Directory)) { New-ExamLabPrivateDirectory $Directory }
    Assert-ExamLabProtectedPath $Directory
    $ledger = Join-Path $Directory 'enrollment.json'
    $installedRegistration = Join-Path $examLabStatePath 'controller-registration.json'
    $record = Read-ExamLabEnrollmentRecord $Directory $EnrollmentUrl
    if ($null -eq $record) {
        if (Test-Path -LiteralPath $installedRegistration) { throw 'ExamLab is already registered through a different installation route.' }
        foreach ($name in 'pc.json','registration.json','wazuh.key') {
            if (Test-Path -LiteralPath (Join-Path $Directory $name)) { throw 'ExamLab enrollment inputs exist without their receipt.' }
        }
        $record = [pscustomobject]@{
            schema = 1
            enrollmentUrl = $EnrollmentUrl
            claim = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
            ordinaryAccounts = $Roster
            receipt = $null
        }
        Write-ExamLabMaintenanceJson $ledger $record
    }
    Assert-ExamLabEnrollmentRosterMatches $record.ordinaryAccounts $Roster
    if ($null -eq $record.receipt) {
        if (Test-Path -LiteralPath $installedRegistration) { throw 'ExamLab enrollment and installed registration are inconsistent.' }
        $receipt = Request-ExamLabEnrollment $EnrollmentUrl $record.claim
        Assert-ExamLabEnrollmentReceipt $receipt $ControllerUrl
        $record.receipt = $receipt
        Write-ExamLabMaintenanceJson $ledger $record
    } else {
        Assert-ExamLabEnrollmentReceipt $record.receipt $ControllerUrl
    }
    if (Test-Path -LiteralPath $installedRegistration) {
        try {
            $installed = Read-ExamLabProtectedJson $installedRegistration
            $registered = $record.receipt.registration
            if ($installed.url -cne $registered.url -or $installed.deviceId -cne $registered.deviceId -or
                $installed.token -cne $registered.token) { throw 'registration' }
        } catch { throw 'The installed ExamLab registration differs from the saved enrollment receipt.' }
    }
    $paths = [pscustomobject]@{
        ComputerConfigPath = Join-Path $Directory 'pc.json'
        RegistrationPath = Join-Path $Directory 'registration.json'
        WazuhKeyPath = Join-Path $Directory 'wazuh.key'
        ManagerIPv4 = $record.receipt.network.WazuhEndpoint.IP
    }
    Write-ExamLabEnrollmentArtifact $paths.ComputerConfigPath (
        ConvertTo-Json -InputObject ([ordered]@{ OrdinaryAccounts = $record.ordinaryAccounts; Network = $record.receipt.network }) -Depth 10 -Compress)
    Write-ExamLabEnrollmentArtifact $paths.RegistrationPath (ConvertTo-Json -InputObject $record.receipt.registration -Compress)
    Write-ExamLabEnrollmentArtifact $paths.WazuhKeyPath $record.receipt.wazuhKey
    return $paths
}
