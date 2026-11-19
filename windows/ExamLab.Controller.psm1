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
            $configuration.token -isnot [string] -or $configuration.token -cnotmatch '\A[A-Za-z0-9_-]{43}\z' -or
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
    try {
        if (-not ('System.Runtime.Serialization.Json.JsonReaderWriterFactory' -as [type])) {
            Add-Type -AssemblyName System.Runtime.Serialization
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
        $quotas = [Xml.XmlDictionaryReaderQuotas]::new()
        $quotas.MaxDepth = 3
        $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes, $quotas)
        try {
            $document = [Xml.XmlDocument]::new()
            $document.Load($reader)
        } finally { $reader.Dispose() }
        $root = $document.DocumentElement
        if ($root.GetAttribute('type') -cne 'object' -or $root.ChildNodes.Count -ne 4) { throw 'invalid-assignment' }
        # Обычный ConvertFrom-Json теряет повторяющиеся ключи; сохраняем их для проверки.
        $fields = [Collections.Generic.Dictionary[string,Xml.XmlElement]]::new([StringComparer]::Ordinal)
        foreach ($node in $root.ChildNodes) { $fields.Add($node.Name, $node) }
        $mode = $fields['mode'].InnerText
        $examType = $fields['examId'].GetAttribute('type')
        $examId = $fields['examId'].InnerText
        $revision = 0
        $revNode = $fields['revision']
        if ($fields['deviceId'].GetAttribute('type') -cne 'string' -or $fields['deviceId'].InnerText -cne $DeviceId -or
            $revNode.GetAttribute('type') -cne 'number' -or $revNode.InnerText -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
            -not [int]::TryParse($revNode.InnerText, [ref]$revision) -or
            $fields['mode'].GetAttribute('type') -cne 'string' -or $mode -cnotin @('normal','exam') -or
            ($mode -ceq 'normal' -and $examType -cne 'null') -or
            ($mode -ceq 'exam' -and ($examType -cne 'string' -or $examId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z'))) {
            throw 'invalid-assignment'
        }
        return [pscustomobject]@{
            deviceId=$DeviceId; revision=$revision; mode=$mode
            examId=if ($examType -ceq 'string') { $examId } else { $null }
        }
    } catch { throw 'invalid-assignment' }
}

function Get-ControllerUtc {
    [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Test-ControllerResult($Result) {
    return ((Test-ControllerFields $Result @('revision','mode','examId','outcome','reason','fullReady','observedUtc')) -and
        ($Result.revision -is [int] -or $Result.revision -is [long]) -and $Result.revision -ge 1 -and $Result.revision -le [int]::MaxValue -and
        $Result.mode -is [string] -and $Result.mode -cin @('exam','normal') -and
        (($Result.mode -ceq 'normal' -and $null -eq $Result.examId) -or
            ($Result.mode -ceq 'exam' -and $Result.examId -is [string] -and $Result.examId -cmatch '\A[A-Za-z0-9._-]{1,64}\z')) -and
        $Result.outcome -is [string] -and $Result.outcome -cin @('applied','source-applied','blocked','error','overridden') -and
        (($Result.outcome -ceq 'applied' -and $null -eq $Result.reason) -or
            ($Result.outcome -cne 'applied' -and $Result.reason -is [string] -and $Result.reason -cmatch '\A[a-z0-9-]{1,64}\z')) -and
        ($Result.outcome -cne 'overridden' -or $Result.mode -ceq 'exam') -and
        $Result.fullReady -is [bool] -and ($Result.outcome -ceq 'applied' -or -not $Result.fullReady) -and
        ($Result.outcome -cne 'applied' -or $Result.mode -ceq 'normal' -or $Result.fullReady) -and
        $Result.observedUtc -is [string] -and $Result.observedUtc -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\z')
}

function Read-ControllerState([string]$Path, [string]$DeviceId) {
    try { $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{
            Assignment=$null; Result=$null; LastConfirmed=$null
            LocalGeneration=$null; StoppedExamId=$null; AwaitingBaseline=$false
            LocalNormal=$null
        }
    }
    if ($file -isnot [IO.FileInfo] -or $file.Length -gt 8192) { throw 'Повреждён controller-state.json' }
    # Читатель держит прежний файл открытым и не мешает атомарной замене.
    $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', [IO.FileShare]::Read -bor [IO.FileShare]::Delete)
    try {
        $reader = [IO.StreamReader]::new($stream)
        try { $json = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $state = ConvertFrom-ControllerJson $json
    if (-not (Test-ControllerFields $state @('Assignment','Result','LastConfirmed','LocalGeneration','StoppedExamId','AwaitingBaseline','LocalNormal')) -or
        $state.AwaitingBaseline -isnot [bool] -or
        ($null -ne $state.LocalGeneration -and ($state.LocalGeneration -isnot [string] -or $state.LocalGeneration -cnotmatch '\A[a-f0-9]{32}\z')) -or
        ($null -ne $state.StoppedExamId -and ($state.StoppedExamId -isnot [string] -or $state.StoppedExamId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z'))) {
        throw 'Повреждён controller-state.json'
    }
    if ($null -ne $state.Assignment) {
        if (-not (Test-ControllerFields $state.Assignment @('deviceId','revision','mode','examId')) -or
            $state.Assignment.deviceId -isnot [string] -or $state.Assignment.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z') { throw 'Повреждён controller-state.json' }
        if (-not $DeviceId) { $DeviceId = $state.Assignment.deviceId }
        $state.Assignment = ConvertTo-ControllerAssignment ($state.Assignment | ConvertTo-Json -Compress) $DeviceId
    }
    if (($null -ne $state.Result -and (-not (Test-ControllerResult $state.Result) -or -not $state.Assignment -or
            $state.Result.revision -ne $state.Assignment.revision -or $state.Result.mode -cne $state.Assignment.mode -or
            $state.Result.examId -cne $state.Assignment.examId)) -or
        ($null -ne $state.LastConfirmed -and (-not (Test-ControllerResult $state.LastConfirmed) -or
            $state.LastConfirmed.outcome -cne 'applied' -or -not $state.Assignment -or $state.LastConfirmed.revision -gt $state.Assignment.revision)) -or
        ($null -ne $state.LocalNormal -and (-not (Test-ControllerFields $state.LocalNormal @('SourceCleanupCompleted','EffectiveMode','ObservedUtc','BaselineUnknown')) -or
            $state.LocalNormal.SourceCleanupCompleted -isnot [bool] -or $state.LocalNormal.BaselineUnknown -isnot [bool] -or
            $state.LocalNormal.EffectiveMode -isnot [string] -or $state.LocalNormal.EffectiveMode -cnotin @('normal','Unconfirmed')))) {
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
    $request.Headers.ConnectionClose = $true
    $json = @{ deviceId=$Configuration.deviceId; result=$Result } | ConvertTo-Json -Depth 4 -Compress
    $request.Content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
    try {
        try { $response = $Client.SendAsync($request).GetAwaiter().GetResult() }
        catch {
            $failure = $_.Exception
            while ($failure) {
                if ($failure -is [Security.Authentication.AuthenticationException] -or
                    ($failure -is [Net.WebException] -and $failure.Status -in @('TrustFailure','SecureChannelFailure'))) {
                    throw 'tls-failed'
                }
                $failure = $failure.InnerException
            }
            throw 'controller-unreachable'
        }
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
