#requires -Version 7.6
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ControllerFields($Value, [string[]]$Names) {
    return ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq $Names.Count -and
        @($Names | Where-Object { $_ -cnotin $Value.PSObject.Properties.Name }).Count -eq 0)
}

function ConvertFrom-ControllerJson([string]$Json) {
    $value = ConvertFrom-Json -InputObject $Json -DateKind String
    # Сохраняем внешний JSON-массив как массив, включая массив из одного объекта.
    if ($Json.TrimStart().StartsWith('[')) { return ,@($value) }
    return $value
}

function Read-ControllerObjectFields($Root, [string[]]$Names, [string[]]$OptionalNames) {
    if ($Root.GetAttribute('type') -cne 'object') { throw 'invalid-object' }
    # Обычный ConvertFrom-Json теряет повторяющиеся ключи.
    $fields = [Collections.Generic.Dictionary[string,Xml.XmlElement]]::new([StringComparer]::Ordinal)
    foreach ($node in $Root.ChildNodes) {
        if ($node.Name -cnotin $Names -and $node.Name -cnotin $OptionalNames) { throw 'invalid-object' }
        $fields.Add($node.Name, $node)
    }
    foreach ($name in $Names) {
        if (-not $fields.ContainsKey($name)) { throw 'invalid-object' }
    }
    return ,$fields
}

function Read-ControllerFlatFields([string]$Json, [string[]]$Names, [string[]]$OptionalNames) {
    # JSON reader .NET допускает запятую после последнего свойства.
    # Контракт принимает плоский объект только с объявленными свойствами.
    if ($Json -cmatch ',[ \t\r\n]*}(?=[ \t\r\n]*(?:[,}]|\z))') { throw 'invalid-object' }
    if (-not ('System.Runtime.Serialization.Json.JsonReaderWriterFactory' -as [type])) {
        Add-Type -AssemblyName System.Runtime.Serialization
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $quotas = [Xml.XmlDictionaryReaderQuotas]::new()
    $quotas.MaxDepth = 4
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes, $quotas)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.Load($reader)
    } finally { $reader.Dispose() }
    Read-ControllerObjectFields $document.DocumentElement $Names $OptionalNames
}

function Read-ControllerConfiguration([string]$Path) {
    try {
        $file = Get-Item -LiteralPath $Path
        if ($file -isnot [IO.FileInfo] -or $file.Length -gt 4096) { throw 'Некорректный файл' }
        $names = @('url','deviceId','token')
        $fields = Read-ControllerFlatFields ([IO.File]::ReadAllText($file.FullName)) $names
        foreach ($name in $names) {
            if ($fields[$name].GetAttribute('type') -cne 'string') { throw 'Некорректный тип поля' }
        }
        $configuration = [pscustomobject]@{
            url=$fields['url'].InnerText
            deviceId=$fields['deviceId'].InnerText
            token=$fields['token'].InnerText
        }
        if ($configuration.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
            $configuration.token -cnotmatch '\A[A-Za-z0-9_-]{43}\z' -or
            $configuration.url -cnotmatch '\Ahttps://[^/?#@\s\\]+/exam/v1/poll\z') {
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

function ConvertFrom-ControllerAssignmentFields($fields, [string]$DeviceId) {
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
}

function ConvertTo-ControllerAssignment([string]$Json, [string]$DeviceId) {
    try { ConvertFrom-ControllerAssignmentFields (Read-ControllerFlatFields $Json @('deviceId','revision','mode','examId')) $DeviceId }
    catch { throw 'invalid-assignment' }
}

function ConvertFrom-ControllerResponse([string]$Json, [string]$DeviceId) {
    try {
        $fields = Read-ControllerFlatFields $Json @('deviceId','revision','mode','examId') @('alertAcknowledgement')
        $assignment = ConvertFrom-ControllerAssignmentFields $fields $DeviceId
        $response = [pscustomobject]@{ Assignment=$assignment; AlertAcknowledgement=$null }
        if (-not $fields.ContainsKey('alertAcknowledgement')) { return $response }
        $names = @('acknowledgementId','alertId','revision','bootUtc','guestSessionId','owner','expiresUtc')
        $ack = Read-ControllerObjectFields $fields['alertAcknowledgement'] $names
        $result = [ordered]@{}
        foreach ($name in $names) {
            if ($name -ceq 'revision') {
                if ($ack[$name].GetAttribute('type') -cne 'number' -or $ack[$name].InnerText -cne [string]$assignment.revision) {
                    throw 'invalid-alert-command'
                }
                $result[$name] = $assignment.revision
            } else {
                if ($ack[$name].GetAttribute('type') -cne 'string') { throw 'invalid-alert-command' }
                $result[$name] = $ack[$name].InnerText
            }
        }
        $guid = '\A[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\z'
        $timestamp = "yyyy-MM-ddTHH:mm:ss.fff'Z'"
        $culture = [Globalization.CultureInfo]::InvariantCulture
        $dateStyle = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        $boot = [DateTime]::ParseExact($result.bootUtc, $timestamp, $culture, $dateStyle)
        $expires = [DateTime]::ParseExact($result.expiresUtc, $timestamp, $culture, $dateStyle)
        if ($assignment.mode -cne 'exam' -or $result.acknowledgementId -cnotmatch $guid -or $result.alertId -cnotmatch $guid -or
            $result.guestSessionId -cnotmatch '\A[a-f0-9]{64}\z' -or $result.owner -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
            $expires -le $boot -or $expires -gt [DateTime]::UtcNow.AddSeconds(95)) { throw 'invalid-alert-command' }
        $response.AlertAcknowledgement = [pscustomobject]$result
        return $response
    } catch { throw 'invalid-assignment' }
}

function Get-ControllerUtc {
    [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-ControllerInstallReport {
    # Итоговый отчёт устанавливается атомарно в защищённый каталог Program Files.
    try {
        $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabSetupReports'
        $directory = Get-Item -LiteralPath $root -Force
        $file = Get-Item -LiteralPath (Join-Path $root 'install-final.json') -Force
        if ($directory -isnot [IO.DirectoryInfo] -or $file -isnot [IO.FileInfo] -or
            ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 4096) { return }
        $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', [IO.FileShare]::Read -bor [IO.FileShare]::Delete)
        try {
            if ($stream.Length -gt 4096) { return }
            $reader = [IO.StreamReader]::new($stream)
            try { $json = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $fields = Read-ControllerFlatFields $json @('version','completedUtc')
        $version = $fields['version'].InnerText
        $completed = $fields['completedUtc'].InnerText
        if ($fields['version'].GetAttribute('type') -cne 'string' -or
            $fields['completedUtc'].GetAttribute('type') -cne 'string' -or
            $version -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}\z' -or
            $completed -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)\z') { return }
        $culture = [Globalization.CultureInfo]::InvariantCulture
        $date = [DateTimeOffset]::Parse($completed, $culture)
        return [pscustomobject]@{version=$version; completedUtc=$date.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", $culture)}
    } catch { return }
}

function Initialize-ControllerConsoleApi {
    if (-not ('ExamLabConsoleLogon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public sealed class ExamLabConsoleLogon {
    private const int WTSSessionInfoEx = 25;
    private const int WTSActive = 0;
    private const int WTS_SESSIONSTATE_UNLOCK = 1;
    private const int WTSUserName = 5;
    private const int WTSListen = 6;
    private const int TokenStatistics = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionEntry {
        public uint SessionId;
        public IntPtr StationName;
        public int State;
    }

    // Prefix of x64 WTSINFOEXW. Data is aligned to 8 bytes (LARGE_INTEGER members).
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    private struct SessionInfo {
        [FieldOffset(0)] public uint Level;
        [FieldOffset(8)] public uint SessionId;
        [FieldOffset(12)] public int State;
        [FieldOffset(16)] public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStats {
        public long TokenId;
        public long AuthenticationId;
        public long ExpirationTime;
        public int TokenType, ImpersonationLevel;
        public uint DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
        public long ModifiedId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int info,
        out IntPtr buffer, out uint bytes);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("wtsapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint session, out SafeAccessTokenHandle token);
    [DllImport("wtsapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, uint reserved, uint version,
        out IntPtr entries, out uint count);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int info,
        out TokenStats stats, int size, out int returnedSize);

    public string Sid { get; private set; }
    public uint SessionId { get; private set; }
    public long AuthenticationId { get; private set; }

    private static bool IsActive(uint session) {
        IntPtr buffer;
        uint bytes;
        bool ok = WTSQuerySessionInformationW(IntPtr.Zero, session, WTSSessionInfoEx, out buffer, out bytes);
        try {
            if (!ok || buffer == IntPtr.Zero || bytes < Marshal.SizeOf(typeof(SessionInfo))) return false;
            SessionInfo info = (SessionInfo)Marshal.PtrToStructure(buffer, typeof(SessionInfo));
            return info.Level == 1 && info.SessionId == session && info.State == WTSActive &&
                info.Flags == WTS_SESSIONSTATE_UNLOCK && WTSGetActiveConsoleSessionId() == session;
        } finally {
            if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
        }
    }

    public static ExamLabConsoleLogon Read() {
        uint session = WTSGetActiveConsoleSessionId();
        if (session == 0 || session == UInt32.MaxValue || !IsActive(session)) return null;

        SafeAccessTokenHandle token;
        bool ok = WTSQueryUserToken(session, out token);
        using (token) {
            if (!ok || token == null || token.IsInvalid) return null;
            TokenStats stats;
            int size = Marshal.SizeOf(typeof(TokenStats));
            int returned;
            if (!GetTokenInformation(token, TokenStatistics, out stats, size, out returned) ||
                returned != size || stats.AuthenticationId == 0) return null;

            using (WindowsIdentity identity = new WindowsIdentity(token.DangerousGetHandle())) {
                if (identity.User == null || !identity.User.IsAccountSid() || identity.Groups == null) return null;
                SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                if (identity.Groups.Contains(administrators) || !IsActive(session)) return null;
                return new ExamLabConsoleLogon { Sid = identity.User.Value, SessionId = session,
                    AuthenticationId = stats.AuthenticationId };
            }
        }
    }

    // Учитываем заблокированные и отключенные интерактивные сеансы наряду с активным.
    public static bool HasNoGuestSession() {
        return HasNoGuestSession(null, null);
    }

    public static bool HasNoGuestSession(ExamLabConsoleLogon allowedGuest, string allowedName) {
        IntPtr entries;
        uint count;
        bool ok = WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out entries, out count);
        try {
            if (!ok || entries == IntPtr.Zero || count == 0 || count > 4096) return false;
            bool seenAllowedGuest = false;
            int entrySize = Marshal.SizeOf(typeof(SessionEntry));
            for (int i = 0; i < count; i++) {
                SessionEntry entry = (SessionEntry)Marshal.PtrToStructure(IntPtr.Add(entries, i * entrySize), typeof(SessionEntry));
                if (entry.SessionId == 0 || entry.State == WTSListen) continue;
                IntPtr buffer;
                uint bytes;
                ok = WTSQuerySessionInformationW(IntPtr.Zero, entry.SessionId, WTSUserName, out buffer, out bytes);
                try {
                    if (!ok || buffer == IntPtr.Zero || bytes < 2 || bytes > 1024 || bytes % 2 != 0) return false;
                    string user = Marshal.PtrToStringUni(buffer, (int)bytes / 2 - 1);
                    if (user.StartsWith("shpctac", StringComparison.OrdinalIgnoreCase)) {
                        if (allowedGuest == null || seenAllowedGuest || entry.SessionId != allowedGuest.SessionId ||
                            entry.State != WTSActive || !String.Equals(user, allowedName, StringComparison.Ordinal)) return false;
                        ExamLabConsoleLogon current = Read();
                        if (current == null || current.SessionId != allowedGuest.SessionId ||
                            !String.Equals(current.Sid, allowedGuest.Sid, StringComparison.Ordinal) ||
                            current.AuthenticationId != allowedGuest.AuthenticationId) return false;
                        seenAllowedGuest = true;
                    }
                } finally {
                    if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
                }
            }
            return allowedGuest == null || seenAllowedGuest;
        } finally {
            if (entries != IntPtr.Zero) WTSFreeMemory(entries);
        }
    }
}
'@
    }
}

function Get-ControllerConsoleLogon {
    Initialize-ControllerConsoleApi
    return [ExamLabConsoleLogon]::Read()
}

function Test-ControllerNoGuestSession($ObservedGuest, [string]$ObservedGuestName) {
    try {
        Initialize-ControllerConsoleApi
        if ($ObservedGuest) { return [ExamLabConsoleLogon]::HasNoGuestSession($ObservedGuest, $ObservedGuestName) }
        return [ExamLabConsoleLogon]::HasNoGuestSession()
    } catch { return $false }
}

function Get-ControllerGuestSessionId([string]$Token, [string]$BootUtc, $Logon) {
    $data = [string]::Format([Globalization.CultureInfo]::InvariantCulture,
        'exam-lab:guest:v1:{0}:{1}:{2}:{3}', $BootUtc, $Logon.Sid, $Logon.SessionId, $Logon.AuthenticationId)
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::ASCII.GetBytes($Token))
    try {
        return [BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($data))).Replace('-', '').ToLowerInvariant()
    } finally { $hmac.Dispose() }
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

function Test-ControllerActiveExam($State) {
    $assignment = $State.Assignment
    $result = $State.Result
    return ($assignment -and $result -and $assignment.mode -ceq 'exam' -and
        $result.revision -eq $assignment.revision -and $result.mode -ceq 'exam' -and
        $result.examId -ceq $assignment.examId -and $State.StoppedExamId -cne $assignment.examId -and
        $result.outcome -ceq 'source-applied' -and $result.reason -ceq 'machine-policies-only')
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

function Invoke-ControllerRequest {
    param($Client, $Configuration, $Result, $Readiness, $ClientReport, [switch]$ResponseEnvelope)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $Configuration.url)
    $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Configuration.token)
    $request.Headers.ConnectionClose = $true
    $payload = @{ deviceId=$Configuration.deviceId; result=$Result }
    if ($Readiness) { $payload.readiness = $Readiness }
    if ($ClientReport) { $payload.client = $ClientReport }
    $json = $payload | ConvertTo-Json -Depth 4 -Compress
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
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($ResponseEnvelope) { ConvertFrom-ControllerResponse $body $Configuration.deviceId }
            else { ConvertTo-ControllerAssignment $body $Configuration.deviceId }
        } finally { $response.Dispose() }
    } finally { $request.Dispose() }
}

Export-ModuleMember -Function Read-ControllerConfiguration,ConvertTo-ControllerAssignment,Get-ControllerUtc,
    Read-ControllerState,Write-ControllerJson,Set-ControllerResult,Compare-ControllerAssignment,Test-ControllerActiveExam,
    New-ExamLabHttpClient,Invoke-ControllerRequest,Get-ControllerConsoleLogon,Get-ControllerGuestSessionId,
    Get-ControllerInstallReport,Test-ControllerNoGuestSession,ConvertFrom-ControllerResponse
