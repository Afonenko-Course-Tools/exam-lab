@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
set "EXAMLAB_LAUNCHER=%~f0"
set "EXAMLAB_ARG1=%~1"
set "EXAMLAB_ARG2=%~2"
set "EXAMLAB_ARG3=%~3"
set "EXAMLAB_ARG4=%~4"
set "NATIVE=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "NATIVE=%SystemRoot%\Sysnative"
"%NATIVE%\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { $launcherText = [IO.File]::ReadAllText($env:EXAMLAB_LAUNCHER); $script = ($launcherText -split '(?m)^:NativePowerShell\r?$', 2)[1]; . ([ScriptBlock]::Create($script)) } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }"
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="100" goto :Finish
exit /b 0
:Finish
if not defined EXAMLAB_NO_PAUSE pause
exit /b %RESULT%

@EARLY_CHECK_PAYLOAD@

:NativePowerShell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$arg1 = $env:EXAMLAB_ARG1
$action = if ($arg1) { $arg1 } else { 'Apply' }
$options = @($env:EXAMLAB_ARG2, $env:EXAMLAB_ARG3 | Where-Object { $_ })
if ($action -notin 'Check', 'Prefetch', 'Apply', 'Verify' -or $env:EXAMLAB_ARG4 -or
    @($options | Where-Object { $_ -notin '--offline', '--elevated' }).Count -or
    @($options | Select-Object -Unique).Count -ne $options.Count) {
    throw 'Usage: Start-ExamLab.cmd [Check|Prefetch|Apply|Verify] [--offline]'
}
$offline = $options -contains '--offline'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and $action -ne 'Check') {
    if ($options -contains '--elevated') { throw 'Run the verified Start-ExamLab.cmd as an administrator.' }
    $arguments = "$action --elevated"
    if ($offline) { $arguments += ' --offline' }
    Start-Process -FilePath $env:EXAMLAB_LAUNCHER -ArgumentList $arguments -Verb RunAs
    exit 100
}

@BOOTSTRAP_PRIVATE_PATHS@

$release = '@REVISION@'
$baseUrl = '@PREFETCH_BASE_URL@'
$toolPath = "exam-lab-$release/tools"
$controllerCa = [Convert]::FromBase64String('@CONTROLLER_CA_BASE64@')
$receiver = "$baseUrl/diagnostics @CONTROLLER_CA_SHA256@"
$runtime = @{ Name='@PWSH_FILE@'; SHA256='@PWSH_SHA256@'; Bytes=@PWSH_BYTES@; Tool=$true }
$installer = @{ Name='@INSTALLER_FILE@'; SHA256='@INSTALLER_SHA256@'; Bytes=@INSTALLER_BYTES@; Tool=$false }
$bundle = @{ Name='@BUNDLE_FILE@'; SHA256='@BUNDLE_SHA256@'; Bytes=@BUNDLE_BYTES@; Tool=$false }
$tools = @BOOTSTRAP_TOOLS@
foreach ($tool in $tools) { $tool.Tool = $true }
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$reports = Join-Path $programFiles 'ExamLabSetupReports'
$cache = Join-Path $reports 'Downloads'
$pwsh = Join-Path $programFiles 'PowerShell\7\pwsh.exe'
$sourceDirectory = [IO.Path]::GetDirectoryName($env:EXAMLAB_LAUNCHER)
$attempt = [Guid]::NewGuid().ToString('N')
$attemptParent = if ($admin) { $programFiles } else { [Environment]::GetFolderPath('LocalApplicationData') }
$work = Join-Path $attemptParent "ExamLabBootstrap-$attempt"
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Set-Location -LiteralPath ([Environment]::GetFolderPath('System'))
$report = Join-Path $work 'report'
$transcribing = $false
$lock = $null
$attemptLock = $null
$result = 1
$sharedCacheRead = $false
$transportStarted = $false

function Start-BootstrapTransport {
    if ($script:transportStarted) { return }
    $previousTemp = $env:TEMP
    $previousTmp = $env:TMP
    try {
        $env:TEMP = $env:TMP = $work
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public sealed class ExamLabBootstrapTransport : IDisposable {
    private readonly X509Certificate2 root;

    public ExamLabBootstrapTransport(byte[] certificate) {
        root = new X509Certificate2(certificate);
    }

    private bool ValidateServer(object sender, X509Certificate certificate, X509Chain supplied, SslPolicyErrors errors) {
        if (certificate == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0) return false;
        using (var leaf = new X509Certificate2(certificate))
        using (var chain = new X509Chain()) {
            chain.ChainPolicy.ExtraStore.Add(root);
            if (supplied != null)
                foreach (X509ChainElement element in supplied.ChainElements)
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
            if (!chain.Build(leaf) || chain.ChainElements.Count < 2) return false;
            foreach (var status in chain.ChainStatus)
                if ((status.Status & ~X509ChainStatusFlags.UntrustedRoot) != 0) return false;
            var anchor = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            return Convert.ToBase64String(anchor.RawData) == Convert.ToBase64String(root.RawData);
        }
    }

    public HttpWebRequest Request(string url) {
        var uri = new Uri(url);
        if (uri.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("HTTPS is required.");
        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.AllowAutoRedirect = false;
        request.Proxy = null;
        request.ServerCertificateValidationCallback = ValidateServer;
        request.Timeout = 30000;
        request.ReadWriteTimeout = 120000;
        return request;
    }

    public void Dispose() { root.Dispose(); }
}
'@
    } finally {
        $env:TEMP = $previousTemp
        $env:TMP = $previousTmp
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $script:transport = [ExamLabBootstrapTransport]::new($controllerCa)
    $script:transportStarted = $true
}

function Test-Artifact([string]$Path, $Artifact) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    (Get-Item -LiteralPath $Path -Force).Length -eq $Artifact.Bytes -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ieq $Artifact.SHA256
}

function Get-SuppliedArtifact($Artifact) {
    $folders = if ($Artifact.Tool) { 'tools', $toolPath.Replace('/', '\') } else { '.' }
    foreach ($folder in $folders) {
        $supplied = Join-Path (Join-Path $sourceDirectory $folder) $Artifact.Name
        if (Test-Path -LiteralPath $supplied -PathType Leaf) { return $supplied }
    }
}

function Receive-Artifact($Artifact, [string]$Partial) {
    Start-BootstrapTransport
    $relative = if ($Artifact.Tool) { "$toolPath/$($Artifact.Name)" } else { $Artifact.Name }
    $request = $transport.Request("$baseUrl/$relative")
    $offset = 0L
    if (Test-Path -LiteralPath $Partial) {
        Assert-ExamLabProtectedPath $Partial
        $offset = (Get-Item -LiteralPath $Partial -Force).Length
        if ($offset -ge $Artifact.Bytes) { $offset = 0L }
    }
    if ($offset) { $request.AddRange($offset) }
    $response = $null
    $source = $null
    $target = $null
    $activity = 'Downloading ' + $Artifact.Name
    try {
        try { $response = $request.GetResponse() }
        catch [Net.WebException] {
            if ($_.Exception.Response) {
                try {
                    if ($offset -and [int]$_.Exception.Response.StatusCode -eq 416) {
                        [IO.File]::Delete($Partial)
                        return Receive-Artifact $Artifact $Partial
                    }
                } finally { $_.Exception.Response.Dispose() }
            }
            throw
        }
        if ($response.StatusCode -eq [Net.HttpStatusCode]::OK) {
            $offset = 0L
        } elseif ($response.StatusCode -eq [Net.HttpStatusCode]::PartialContent -and $offset) {
            if ($response.Headers['Content-Range'] -cne "bytes $offset-$($Artifact.Bytes - 1)/$($Artifact.Bytes)") {
                throw "Unexpected Content-Range for $($Artifact.Name)."
            }
        } else { throw "Unexpected HTTP status $([int]$response.StatusCode) for $($Artifact.Name)." }
        if ($response.ContentLength -ge 0 -and $response.ContentLength -ne $Artifact.Bytes - $offset) {
            throw "Unexpected Content-Length for $($Artifact.Name)."
        }
        $mode = if ($offset) { [IO.FileMode]::Append } else { [IO.FileMode]::Create }
        $target = [IO.File]::Open($Partial, $mode, 'Write', 'None')
        $source = $response.GetResponseStream()
        $buffer = [byte[]]::new(256KB)
        $received = $offset
        $progress = [Diagnostics.Stopwatch]::StartNew()
        $lastDisplayed = -1L
        $lastLogged = -30L
        Write-Host "$activity ($offset / $($Artifact.Bytes) bytes)."
        while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($progress.Elapsed.TotalHours -ge 4) { throw 'The download exceeded four hours.' }
            $received += $read
            if ($received -gt $Artifact.Bytes) { throw "Unexpected extra bytes for $($Artifact.Name)." }
            $target.Write($buffer, 0, $read)
            $seconds = [long][Math]::Floor($progress.Elapsed.TotalSeconds)
            if ($seconds -ne $lastDisplayed) {
                Write-Progress -Activity $activity -Status "$received / $($Artifact.Bytes) bytes" `
                    -PercentComplete ([Math]::Floor(100.0 * $received / $Artifact.Bytes))
                $lastDisplayed = $seconds
            }
            if ($seconds -ge $lastLogged + 30) {
                Write-Host "$activity ($received / $($Artifact.Bytes) bytes)."
                $lastLogged = $seconds
            }
        }
        $target.Flush($true)
        if ($received -ne $Artifact.Bytes) { throw "Incomplete download: $received / $($Artifact.Bytes) bytes." }
        Write-Host "$activity ($received / $($Artifact.Bytes) bytes)."
    } finally {
        if ($target) { $target.Dispose() }
        if ($source) { $source.Dispose() }
        if ($response) { $response.Dispose() }
        Write-Progress -Activity $activity -Completed
    }
}

function Save-Artifact($Artifact) {
    $target = Join-Path $cache $Artifact.Name
    if (Test-Path -LiteralPath $target) {
        Assert-ExamLabProtectedPath $target
        if (Test-Artifact $target $Artifact) {
            Write-Host "Verified cache: $($Artifact.Name)."
            return
        }
    }
    $partial = "$target.$($Artifact.SHA256).partial"
    if (Test-Path -LiteralPath $partial) { Assert-ExamLabProtectedPath $partial }
    if (-not (Test-Artifact $partial $Artifact)) {
        $supplied = Get-SuppliedArtifact $Artifact
        if ($supplied) {
            [IO.File]::Copy($supplied, $partial, $true)
            Write-Host "Imported $($Artifact.Name) from the supplied directory."
        } elseif ($offline) {
            throw "The offline cache is missing $($Artifact.Name)."
        } else {
            Receive-Artifact $Artifact $partial
        }
    }
    if (-not (Test-Artifact $partial $Artifact)) {
        [IO.File]::Delete($partial)
        throw "Package size or SHA-256 does not match: $($Artifact.Name)."
    }
    if ([IO.File]::Exists($target)) { [IO.File]::Replace($partial, $target, [NullString]::Value) }
    else { [IO.File]::Move($partial, $target) }
}

function Complete-DiagnosticArchive([string]$Directory) {
    $archive = Join-Path $Directory 'diagnostics.zip'
    if ([IO.File]::Exists($archive)) { return }
    $temporary = "$archive.partial"
    if ($admin -and (Test-Path -LiteralPath $temporary)) { Assert-ExamLabProtectedPath $temporary }
    [IO.File]::Delete($temporary)
    try {
        [IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $Directory 'report'), $temporary)
        [IO.File]::Move($temporary, $archive)
    } finally { [IO.File]::Delete($temporary) }
}

function Complete-InterruptedDiagnostics([string]$Directory) {
    if ([IO.File]::Exists((Join-Path $Directory 'diagnostics.zip'))) { return }
    $startFile = Join-Path $Directory 'attempt-start.json'
    $receiverFile = Join-Path $Directory 'delivery-target.txt'
    $attemptLockPath = Join-Path $Directory 'attempt.lock'
    if (-not ([IO.File]::Exists($startFile) -and [IO.File]::Exists($receiverFile) -and
        [IO.File]::Exists($attemptLockPath))) { return }
    if ($admin) {
        foreach ($candidate in $startFile, $receiverFile, $attemptLockPath) { Assert-ExamLabProtectedPath $candidate }
    }
    if ([IO.File]::ReadAllText($receiverFile) -cne $receiver) { return }
    $previousLock = $null
    $childLock = $null
    try {
        try {
            $previousLock = [IO.File]::Open($attemptLockPath, 'Open', 'ReadWrite', 'None')
            $childLockPath = Join-Path $Directory 'child.lock'
            if ([IO.File]::Exists($childLockPath)) {
                if ($admin) { Assert-ExamLabProtectedPath $childLockPath }
                $childLock = [IO.File]::Open($childLockPath, 'Open', 'ReadWrite', 'None')
            }
        } catch [IO.IOException] { return }
        $previousReport = Join-Path $Directory 'report'
        if ($admin) { Assert-ExamLabProtectedPath $previousReport }
        $summary = Join-Path $previousReport 'attempt.json'
        if (-not [IO.File]::Exists($summary)) {
            $start = [IO.File]::ReadAllText($startFile) | ConvertFrom-Json
            [ordered]@{
                Attempt=$start.Attempt; Release=$start.Release; Action=$start.Action; StartedUtc=$start.StartedUtc
                Interrupted=$true; RecoveredUtc=[DateTime]::UtcNow
            } | ConvertTo-Json | Set-Content -LiteralPath $summary -Encoding UTF8
        }
        Complete-DiagnosticArchive $Directory
    } finally {
        if ($childLock) { $childLock.Dispose() }
        if ($previousLock) { $previousLock.Dispose() }
    }
}

function Send-Diagnostics([string]$Directory) {
    $archive = Join-Path $Directory 'diagnostics.zip'
    $receipt = Join-Path $Directory 'upload-result.json'
    $receiverFile = Join-Path $Directory 'delivery-target.txt'
    if ($offline -or -not (Test-Path -LiteralPath $archive -PathType Leaf) -or
        -not (Test-Path -LiteralPath $receiverFile -PathType Leaf)) { return }
    if ($admin) {
        Assert-ExamLabProtectedPath $archive
        Assert-ExamLabProtectedPath $receiverFile
    }
    if (-not $admin) {
        foreach ($candidate in $archive, $receiverFile) {
            if ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
        }
    }
    if ([IO.File]::ReadAllText($receiverFile) -cne $receiver) { return }
    if (Test-Path -LiteralPath $receipt -PathType Leaf) {
        if ($admin) { Assert-ExamLabProtectedPath $receipt }
        try {
            $saved = [IO.File]::ReadAllText($receipt) | ConvertFrom-Json
            if ($saved.reportId -cmatch '\A[0-9a-f]{32}\z') { return }
        } catch { Write-Warning "Invalid diagnostics receipt in $Directory. Retrying the same ZIP." }
    }
    Start-BootstrapTransport
    $request = $transport.Request("$baseUrl/diagnostics")
    $request.Method = 'POST'
    $request.ContentType = 'application/zip'
    $request.AllowWriteStreamBuffering = $false
    $request.ServicePoint.Expect100Continue = $false
    $request.ContentLength = (Get-Item -LiteralPath $archive -Force).Length
    $archiveStream = [IO.File]::Open($archive, 'Open', 'Read', 'Read')
    try {
        $output = $request.GetRequestStream()
        try { $archiveStream.CopyTo($output) } finally { $output.Dispose() }
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 201) { throw "Unexpected diagnostics status $([int]$response.StatusCode)." }
            $reader = [IO.StreamReader]::new($response.GetResponseStream())
            try {
                $content = $reader.ReadToEnd()
                $id = ($content | ConvertFrom-Json).reportId
                if ($id -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Missing diagnostics reportId.' }
            } finally { $reader.Dispose() }
        } finally { $response.Dispose() }
        $temporary = "$receipt.$([Guid]::NewGuid().ToString('N')).tmp"
        try {
            [IO.File]::WriteAllText($temporary, $content)
            if ([IO.File]::Exists($receipt)) { [IO.File]::Replace($temporary, $receipt, [NullString]::Value) }
            else { [IO.File]::Move($temporary, $receipt) }
        } finally { [IO.File]::Delete($temporary) }
        Write-Host "Diagnostics accepted: $id"
    } finally { $archiveStream.Dispose() }
}

function Invoke-EarlyCheck {
    $parts = [regex]::Matches($launcherText, '(?m)^rem EXAMLAB_EARLY_CHECK:([A-Za-z0-9+/=]+)\r?$')
    if (-not $parts.Count) { throw 'The verified launcher is missing the Check payload.' }
    $encoded = ($parts | ForEach-Object { $_.Groups[1].Value }) -join ''
    $checkScript = Join-Path $work 'Prepare-ExamLab.ps1'
    [IO.File]::WriteAllBytes($checkScript, [Convert]::FromBase64String($encoded))
    $checkReport = Join-Path $report 'early-check.json'
    $previousTemp = $env:TEMP
    $previousTmp = $env:TMP
    try {
        $env:TEMP = $env:TMP = $work
        $ErrorActionPreference = 'Continue'
        & (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $checkScript -Action Check -HumanOutput -ReportPath $checkReport 2>&1 |
            ForEach-Object { [string]$_ } | Tee-Object -FilePath (Join-Path $report 'early-check.log') | Out-Host
        $script:checkExit = $LASTEXITCODE
    } finally {
        $env:TEMP = $previousTemp
        $env:TMP = $previousTmp
    }
    if (-not (Test-Path -LiteralPath $checkReport -PathType Leaf)) { throw "Check returned $checkExit without a report." }
    Get-Content -LiteralPath $checkReport -Raw | ConvertFrom-Json
}

function Get-ReleasePlan($Check, [bool]$RuntimeReady) {
    $plannedFiles = @($Check.Plan.Packages | ForEach-Object { $_.File })
    $requiredTools = @('LGPO.zip', 'PolicyFileEditor-3.0.1.zip', 'wazuh-agent-4.14.10-1.msi',
        'gradle-9.8.2-bin.zip', 'gradle-exam-cache.zip') + $plannedFiles
    $artifacts = @($installer, $bundle)
    if (-not $RuntimeReady) { $artifacts += $runtime }
    foreach ($name in $requiredTools | Select-Object -Unique) {
        $tool = @($tools | Where-Object { $_.Name -ceq $name })
        if ($tool.Count -ne 1) { throw "No pinned release artifact for $name." }
        $artifacts += $tool[0]
    }
    $rows = foreach ($artifact in $artifacts) {
        $target = Join-Path $cache $artifact.Name
        $status = if (-not $sharedCacheRead) { 'UnknownWithoutElevation' }
            elseif (Test-Artifact $target $artifact) { 'Cached' }
            else { 'Missing' }
        $supplied = Get-SuppliedArtifact $artifact
        if ($status -ne 'Cached' -and $supplied) { $status = 'SuppliedUnverified' }
        [pscustomobject]@{ Name=$artifact.Name; Bytes=$artifact.Bytes; CacheStatus=$status }
    }
    $unverified = @($rows | Where-Object CacheStatus -ne 'Cached')
    $unknown = @($unverified | Where-Object CacheStatus -eq 'UnknownWithoutElevation')
    $missing = @($unverified | Where-Object CacheStatus -eq 'Missing')
    $missingBytes = if ($missing.Count) { [long](($missing | Measure-Object Bytes -Sum).Sum) } else { 0L }
    $upperBoundBytes = if ($unverified.Count) { [long](($unverified | Measure-Object Bytes -Sum).Sum) } else { 0L }
    $plan = [ordered]@{
        Release=$release; Attempt=$attempt; Action=$action; Elevated=$admin; Offline=$offline
        PowerShell7Ready=$RuntimeReady; Artifacts=@($rows); Transport='HTTPS; byte ranges tested during delivery'
        DownloadBytes=$(if (-not $unknown.Count) { $missingBytes })
        DownloadUpperBoundBytes=$upperBoundBytes
        CacheDriveFreeBytes=([IO.DriveInfo]::new([IO.Path]::GetPathRoot($programFiles))).AvailableFreeSpace
    }
    $plan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'release-plan.json') -Encoding UTF8
    Write-Host "PowerShell 7 ready: $RuntimeReady. Cache drive free bytes: $($plan.CacheDriveFreeBytes)."
    $rows | Format-Table Name, Bytes, CacheStatus -AutoSize | Out-Host
    Write-Host "Download upper bound: $($plan.DownloadUpperBoundBytes) bytes."
    return $artifacts
}

function Test-PowerShellRuntime {
    if (-not (Test-Path -LiteralPath $pwsh -PathType Leaf)) { return $false }
    if ($admin) {
        Assert-ExamLabProtectedPath ([IO.Path]::GetDirectoryName($pwsh)) -Readable
        Assert-ExamLabProtectedPath $pwsh -Readable
    }
    & $pwsh -NoLogo -NoProfile -NonInteractive -Command `
        'if ($PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion -lt [semver]"@PWSH_VERSION@" -or $PSVersionTable.PSVersion.PreReleaseLabel -or -not [Environment]::Is64BitProcess) { exit 1 }' | Out-Host
    return $LASTEXITCODE -eq 0
}

function Invoke-Bootstrap {
    $check = Invoke-EarlyCheck
    $bootCheck = [Collections.Generic.List[string]]::new()
    if ($check.Platform) {
        $platform = $check.Platform
        $domain = if ($null -eq $platform.PartOfDomain) { 'unknown' } else { $platform.PartOfDomain }
        Write-Host "Windows $($platform.Edition), build $($platform.Build). Domain member: $domain. Elevated: $admin."
        $platform.OptionalObservations | ForEach-Object { Write-Host "Check: $_" }
        if (-not $platform.ClientWindows -or [int]$platform.Build -lt 19041) {
            $bootCheck.Add('The pilot requires a Windows client, build 19041 or newer.')
        }
        if ($platform.PartOfDomain -eq $true) { $bootCheck.Add('The pilot requires a standalone Windows computer.') }
    }
    if ($check.Preflight) {
        $check.Preflight.Services | Format-Table Name, Status, StartValue -AutoSize | Out-Host
        foreach ($service in @($check.Preflight.Services | Where-Object StartValue -eq 4)) {
            $bootCheck.Add("The required Windows service $($service.Name) is disabled.")
        }
        if ($admin -and $check.Preflight.LocalMLGPO.Status -eq 'AbsentBindings') {
            $bootCheck.Add('Windows Local Group Policy components are absent.')
        }
    }
    $taskObservation = 'NotCheckedWithoutElevation'
    if ($admin) {
        try {
            $tasks = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop |
                Where-Object TaskName -in 'ExamLab-Local-prepare', 'ExamLab-Local-check', 'ExamLab-Local-exam',
                    'ExamLab-Local-normal', 'ExamLab-Controller-Poll' | Select-Object TaskName, State)
            $taskObservation = $tasks
            $tasks | Format-Table -AutoSize | Out-Host
        } catch { $taskObservation = "Unknown: $_" }
    }
    if ($check.Plan) {
        $check.Plan.Actions | Format-Table Name, Operation, ExistingVersion, ExistingPath, Destination -AutoSize | Out-Host
    }
    $check.Errors | ForEach-Object { Write-Host "Check: $_" }
    $bootCheck | ForEach-Object { Write-Host "Check: $_" }
    [ordered]@{ Blockers=$bootCheck.ToArray(); NativeCheckExit=$checkExit; InstalledTasks=$taskObservation } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $report 'pilot-preflight.json') -Encoding UTF8
    if ($action -ne 'Verify' -and ($checkExit -ne 0 -or $bootCheck.Count)) {
        Write-Host "Check report: $report"
        if ($checkExit -ne 0) { return $checkExit }
        return 2
    }
    $runtimeReady = Test-PowerShellRuntime
    if ($check.Plan) { $artifacts = @(Get-ReleasePlan $check $runtimeReady) }
    if ($action -eq 'Check') {
        Write-Host "Check report: $report"
        return 0
    }
    if ($action -ne 'Verify' -and -not $check.Plan) { throw 'Check returned no installation plan.' }
    if ($action -ne 'Verify') {
        foreach ($artifact in $artifacts) { Save-Artifact $artifact }
        if ($action -eq 'Prefetch') { return 0 }
    }
    if (-not $runtimeReady) {
        if ($action -eq 'Verify') { throw 'PowerShell 7 x64 for this release is unavailable.' }
        if (Test-Path -LiteralPath (Join-Path $programFiles 'ExamLab')) {
            throw 'The existing ExamLab installation requires local maintenance before changing its PowerShell runtime.'
        }
        $msi = Join-Path $cache $runtime.Name
        $log = Join-Path $report 'PowerShell-msi.log'
        $signature = Get-AuthenticodeSignature -LiteralPath $msi
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
            throw "The PowerShell MSI signature did not pass verification: $($signature.Status)."
        }
        Write-Host 'Installing PowerShell 7 x64.'
        $process = Start-Process -FilePath (Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe') `
            -ArgumentList "/i `"$msi`" /quiet /norestart USE_MU=0 ENABLE_MU=0 /L*v `"$log`"" -Wait -PassThru
        if ($process.ExitCode -ne 0) { return $process.ExitCode }
        if (-not (Test-PowerShellRuntime)) { throw 'The PowerShell 7 MSI ran, but the specified runtime did not pass verification.' }
    }
    $entry = Join-Path $cache $installer.Name
    Assert-ExamLabProtectedPath $entry
    $localEntry = Join-Path $work 'Install-ExamLab.ps1'
    [IO.File]::Copy($entry, $localEntry)
    if (-not (Test-Artifact $localEntry $installer)) { throw 'The cached installer failed SHA-256 verification.' }
    $env:EXAMLAB_DIAGNOSTICS_DIR = $work
    $env:PSModulePath = (Join-Path ([IO.Path]::GetDirectoryName($pwsh)) 'Modules') + ';' + (Join-Path $PSHOME 'Modules')
    $arguments = @('-Action', $action)
    if ($offline) { $arguments += '-Offline' }
    $ErrorActionPreference = 'Continue'
    & $pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $localEntry @arguments 2>&1 |
        ForEach-Object { [string]$_ } | Tee-Object -FilePath (Join-Path $report 'powershell-console.log') | Out-Host
    return $LASTEXITCODE
}

try {
    if ($admin) { New-ExamLabPrivateDirectory $work }
    else {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in $identity.User.Value, 'S-1-5-18', 'S-1-5-32-544') {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.Directory]::CreateDirectory($work, $acl)
    }
    [void][IO.Directory]::CreateDirectory($report)
    [IO.File]::WriteAllText((Join-Path $work 'delivery-target.txt'), $receiver)
    $attemptLock = [IO.File]::Open((Join-Path $work 'attempt.lock'), 'CreateNew', 'ReadWrite', 'None')
    [ordered]@{ Attempt=$attempt; Release=$release; Action=$action; StartedUtc=[DateTime]::UtcNow } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $work 'attempt-start.json') -Encoding UTF8
    Start-Transcript -LiteralPath (Join-Path $report 'bootstrap.log') | Out-Null
    $transcribing = $true
    Write-Host "ExamLab $release, $action, attempt $attempt"
    if ($admin) {
        if ($action -in 'Prefetch', 'Apply') {
            $lockPath = Join-Path $programFiles '.exam-lab-bootstrap.lock'
            if (Test-Path -LiteralPath $lockPath) { Assert-ExamLabProtectedPath $lockPath -Readable }
            $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
            if (-not (Test-Path -LiteralPath $reports)) { New-ExamLabPrivateDirectory $reports }
            Assert-ExamLabProtectedPath $reports
            if (-not (Test-Path -LiteralPath $cache)) { New-ExamLabPrivateDirectory $cache }
        }
        if (Test-Path -LiteralPath $reports) { Assert-ExamLabProtectedPath $reports }
        if (Test-Path -LiteralPath $cache) { Assert-ExamLabProtectedPath $cache }
        $sharedCacheRead = $true
    }
    $result = Invoke-Bootstrap
} catch {
    $failure = $_
    if (Test-Path -LiteralPath $report) {
        $failure | Format-List * -Force | Out-String -Width 360 |
            Set-Content -LiteralPath (Join-Path $report 'bootstrap-error.log') -Encoding UTF8
    }
    [Console]::Error.WriteLine($failure.ToString())
} finally {
    if (Test-Path -LiteralPath $report) {
        try {
            if (-not (Test-Path -LiteralPath (Join-Path $report 'powershell-transcript.log'))) {
                $eventLog = Join-Path ([Environment]::GetFolderPath('System')) 'wevtutil.exe'
                $ErrorActionPreference = 'Continue'
                & $eventLog qe Application "/q:*[System[Provider[@Name='MsiInstaller'] and TimeCreated[timediff(@SystemTime) <= 900000]]]" `
                    /rd:true /c:30 /f:xml /e:Events 2>&1 | Out-File -LiteralPath (Join-Path $report 'bootstrap-msi-events.xml') -Encoding UTF8
                & $eventLog qe System "/q:*[System[Provider[@Name='Schannel'] and TimeCreated[timediff(@SystemTime) <= 900000]]]" `
                    /rd:true /c:30 /f:xml /e:Events 2>&1 | Out-File -LiteralPath (Join-Path $report 'bootstrap-schannel-events.xml') -Encoding UTF8
                $ErrorActionPreference = 'Stop'
            }
        } catch { Write-Warning "Native Windows events unavailable: $_" }
        Write-Host "Attempt $attempt finished with exit $result."
        if ($transcribing) { try { Stop-Transcript | Out-Null } catch { Write-Warning $_ } }
        try {
            [ordered]@{ Attempt=$attempt; Release=$release; Action=$action; ExitCode=$result; EndedUtc=[DateTime]::UtcNow } |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'attempt.json') -Encoding UTF8
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            Complete-DiagnosticArchive $work
            $retryPrevious = -not $offline
            try { Send-Diagnostics $work }
            catch {
                Write-Warning "Diagnostic delivery is pending: $_"
                if ($_.Exception.InnerException -is [Net.WebException] -and -not $_.Exception.InnerException.Response) {
                    $retryPrevious = $false
                }
            }
            if ($retryPrevious) {
                $previous = Get-ChildItem -LiteralPath $attemptParent -Directory -Filter 'ExamLabBootstrap-*' |
                    Where-Object {
                        $_.Name -cmatch '^ExamLabBootstrap-[0-9a-f]{32}$' -and $_.FullName -ne $work -and
                            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
                    }
                foreach ($directory in $previous) {
                    try {
                        if ($admin) {
                            Assert-ExamLabProtectedPath $directory.FullName
                            Complete-InterruptedDiagnostics $directory.FullName
                        }
                        Send-Diagnostics $directory.FullName
                    } catch { Write-Warning "Diagnostic delivery is pending for $($directory.Name): $_" }
                }
            }
        } catch { Write-Warning "Diagnostic delivery is pending: $_" }
        Write-Host "Local diagnostics: $work"
    }
    if ($transportStarted) { $transport.Dispose() }
    if ($attemptLock) { $attemptLock.Dispose() }
    if ($lock) { $lock.Dispose() }
}
if ($result -eq 3010) { Write-Host 'Restart Windows, then run the same verified Start-ExamLab.cmd again.' }
exit $result
