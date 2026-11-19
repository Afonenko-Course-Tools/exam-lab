#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ControllerFields($Value, [string[]]$Names) {
    return ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq $Names.Count -and
        @($Names | Where-Object { $_ -cnotin $Value.PSObject.Properties.Name }).Count -eq 0)
}

function ConvertFrom-ControllerJson([string]$Json) {
    if ($PSVersionTable.PSVersion -ge [version]'7.5') {
        $value = ConvertFrom-Json -InputObject $Json -DateKind String
    } else {
        $value = ConvertFrom-Json -InputObject $Json
    }
    # Сохраняем внешний JSON-массив как массив, включая массив из одного объекта.
    if ($Json.TrimStart().StartsWith('[')) { return ,@($value) }
    return $value
}

function Read-ControllerConfiguration([string]$Path) {
    try {
        $file = Get-Item -LiteralPath $Path
        if ($file -isnot [IO.FileInfo] -or $file.Length -gt 4096) { throw 'Некорректный файл' }
        $configuration = ConvertFrom-ControllerJson ([IO.File]::ReadAllText($file.FullName))
        if (-not (Test-ControllerFields $configuration @('url','deviceId','token')) -or
            $configuration.deviceId -isnot [string] -or $configuration.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
            $configuration.token -isnot [string] -or $configuration.token -cnotmatch '\A[A-Za-z0-9._~-]{32,256}\z' -or
            $configuration.url -isnot [string] -or $configuration.url -cnotmatch '\Ahttps://[^/?#@\s\\]+/exam/v1/poll\z') {
            throw 'Некорректные поля'
        }
        $uri = [Uri]::new($configuration.url, [UriKind]::Absolute)
        if (-not $uri.IsWellFormedOriginalString() -or $uri.AbsolutePath -cne '/exam/v1/poll' -or
            $uri.HostNameType -notin @([UriHostNameType]::Dns, [UriHostNameType]::IPv4, [UriHostNameType]::IPv6)) {
            throw 'Некорректный URL'
        }
        return $configuration
    } catch {
        # Ошибка парсера конфигурации может включать фрагмент токена.
        throw 'Файл регистрации контроллера должен задавать https URL /exam/v1/poll, deviceId и отдельный Bearer token из административного комплекта.'
    }
}

function ConvertTo-ControllerAssignment([string]$Json, [string]$DeviceId) {
    try { $assignment = ConvertFrom-ControllerJson $Json }
    catch { throw 'invalid-assignment' }
    if (-not (Test-ControllerFields $assignment @('deviceId','revision','mode','examId')) -or
        $assignment.deviceId -isnot [string] -or $assignment.deviceId -cne $DeviceId -or
        ($assignment.revision -isnot [int] -and $assignment.revision -isnot [long]) -or
        $assignment.revision -lt 1 -or $assignment.revision -gt [int]::MaxValue -or
        $assignment.mode -isnot [string] -or $assignment.mode -cnotin @('normal','exam') -or
        ($assignment.mode -ceq 'normal' -and $null -ne $assignment.examId) -or
        ($assignment.mode -ceq 'exam' -and ($assignment.examId -isnot [string] -or $assignment.examId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z'))) {
        throw 'invalid-assignment'
    }
    return $assignment
}

function Get-ControllerUtc {
    [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Read-ControllerState([string]$Path) {
    if (-not [IO.File]::Exists($Path)) {
        return [pscustomobject]@{
            Assignment=$null; Result=$null; LastConfirmed=$null
            LocalGeneration=$null; StoppedExamId=$null; AwaitingBaseline=$false
            LocalNormal=$null
        }
    }
    $state = ConvertFrom-ControllerJson ([IO.File]::ReadAllText($Path))
    if (-not (Test-ControllerFields $state @('Assignment','Result','LastConfirmed','LocalGeneration','StoppedExamId','AwaitingBaseline','LocalNormal'))) {
        throw 'Повреждён controller-state.json'
    }
    return $state
}

function Write-ControllerJson([string]$Path, $Value) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $data = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress))
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            $stream.Write($data, 0, $data.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { [IO.File]::Delete($temporary) }
}

function Set-ControllerResult($State, [string]$Outcome, [string]$Reason, [bool]$FullReady) {
    $State.Result = [pscustomobject]@{
        revision = $State.Assignment.revision
        mode = $State.Assignment.mode
        examId = $State.Assignment.examId
        outcome = $Outcome
        reason = if ($Reason) { $Reason } else { $null }
        fullReady = $FullReady
        observedUtc = Get-ControllerUtc
    }
    if ($Outcome -ceq 'applied') { $State.LastConfirmed = $State.Result }
}

function Compare-ControllerAssignment($Incoming, $Previous) {
    if (-not $Previous -or $Incoming.revision -gt $Previous.revision) { return 'new' }
    if ($Incoming.revision -lt $Previous.revision) { throw 'stale-assignment' }
    if ($Incoming.mode -cne $Previous.mode -or $Incoming.examId -cne $Previous.examId) { throw 'conflicting-assignment' }
    return 'repeat'
}

function New-ExamLabHttpClient {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $handler.UseCookies = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(8)
    $client.MaxResponseContentBufferSize = 4096
    return $client
}

function Invoke-ControllerRequest($Client, $Configuration, $Result) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $Configuration.url)
    $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Configuration.token)
    $json = @{ deviceId=$Configuration.deviceId; result=$Result } | ConvertTo-Json -Depth 4 -Compress
    $request.Content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
    try {
        try { $response = $Client.SendAsync($request).GetAwaiter().GetResult() }
        catch { throw 'controller-unreachable' }
        try {
            if ([int]$response.StatusCode -ne 200) { throw ('http-' + [int]$response.StatusCode) }
            if (-not $response.Content.Headers.ContentType -or $response.Content.Headers.ContentType.MediaType -ine 'application/json') {
                throw 'invalid-assignment'
            }
            ConvertTo-ControllerAssignment ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult()) $Configuration.deviceId
        } finally { $response.Dispose() }
    } finally { $request.Dispose() }
}

Export-ModuleMember -Function Read-ControllerConfiguration,ConvertTo-ControllerAssignment,Get-ControllerUtc,
    Read-ControllerState,Write-ControllerJson,Set-ControllerResult,Compare-ControllerAssignment,
    New-ExamLabHttpClient,Invoke-ControllerRequest
