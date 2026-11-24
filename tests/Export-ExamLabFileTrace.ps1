#Requires -Version 7.6
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Local')]
    [Parameter(Mandatory, ParameterSetName = 'Upload')]
    [Parameter(ParameterSetName = 'Latest')]
    [string]$ExpectedComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory, ParameterSetName = 'Local')]
    [Parameter(Mandatory, ParameterSetName = 'Upload')]
    [ValidatePattern('\AExamLabFileIO-[0-9a-f]{32}\z', Options = 'None')][string]$TraceInstance,
    [Parameter(Mandatory, ParameterSetName = 'Upload')][switch]$Upload,
    [Parameter(Mandatory, ParameterSetName = 'Upload')][ValidateRange(1, 2147483647)][int]$ExamRevision,
    [Parameter(ParameterSetName = 'Upload')][switch]$Headless,
    [Parameter(Mandatory, ParameterSetName = 'Latest')][switch]$OpenLatest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or -not [Environment]::Is64BitProcess -or $env:COMPUTERNAME -ine $ExpectedComputerName) {
    throw 'Запустите повышенный PowerShell 7 x64 на согласованной испытательной машине.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$operator = $identity.User.Value
$system = 'S-1-5-18'
$administrators = 'S-1-5-32-544'
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    ($operator -eq $system) -ne $Headless.IsPresent) {
    throw 'Нужен повышенный токен администратора. Для SYSTEM укажите -Headless.'
}
if ($Headless) { $WarningPreference = 'SilentlyContinue' }
$localAdmins = @($system, $administrators, $operator) + @(
    Get-LocalGroupMember -SID $administrators | ForEach-Object { $_.SID.Value }
)
$programFiles = [Environment]::GetFolderPath('ProgramFiles')

function Assert-TraceAccess(
    [IO.FileSystemInfo]$Item,
    [string[]]$Allowed,
    [switch]$Root,
    [switch]$Readable
) {
    for ($part = $Item; $part; $part = if ($part -is [IO.FileInfo]) { $part.Directory } else { $part.Parent }) {
        if ($part.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "В пути есть перенаправление: $($part.FullName)"
        }
    }
    $acl = Get-Acl -LiteralPath $Item.FullName
    if (($Root -and -not $acl.AreAccessRulesProtected) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $Allowed) {
        throw "Небезопасный владелец или DACL: $($Item.FullName)"
    }
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $Allowed) { continue }
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if (-not $Readable -or ($rule.FileSystemRights -band $write)) {
            throw "Небезопасный доступ: $($Item.FullName)"
        }
    }
}

function New-TraceExportDirectory([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system, $administrators, $operator) | Select-Object -Unique) {
        $rights = if ($sid -in @($system, $administrators)) { 'FullControl' } else { 'ReadAndExecute' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), $rights, 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    [IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
}

function Write-TraceZip([IO.FileInfo[]]$Files, [string]$Destination, [IO.FileInfo]$PreparedZip) {
    # Режим Create пишет записи потоково и автоматически использует ZIP64 при необходимости.
    $temporary = $Destination + '.' + [Guid]::NewGuid().ToString('N') + '.part'
    try {
        $target = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try {
            if ($PreparedZip) {
                $source = [IO.File]::OpenRead($PreparedZip.FullName)
                try { $source.CopyTo($target) }
                finally { $source.Dispose() }
            } else {
                $archive = [IO.Compression.ZipArchive]::new($target, 'Create', $true)
                try {
                    foreach ($file in $Files) {
                        $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                            $archive, $file.FullName, $file.Name, 'Fastest')
                    }
                } finally { $archive.Dispose() }
            }
            $target.Flush($true)
        } finally { $target.Dispose() }
        [IO.File]::Move($temporary, $Destination)
    } finally { [IO.File]::Delete($temporary) }
}

function Find-TraceEthernetRoute([Net.IPAddress]$Address) {
    # ВМ может выдавать эмулированный PCI-адаптер за физический.
    # HypervisorPresent может быть установлен и на физическом Windows с VBS.
    $machine = Get-CimInstance -ClassName Win32_ComputerSystem -Property Manufacturer, Model
    $virtualMachine = 'QEMU|VirtualBox|Virtual Machine|Virtual PC|VMware|\bKVM\b|\bXen\b|Parallels|bhyve|Bochs|Virtual Platform|' +
        'Amazon EC2|Google Compute Engine|OpenStack|oVirt|RHEV|HVM domU|innotek'
    if (-not $machine -or [string]::IsNullOrWhiteSpace($machine.Manufacturer) -or [string]::IsNullOrWhiteSpace($machine.Model) -or
        "$($machine.Manufacturer) $($machine.Model)" -match $virtualMachine) {
        return
    }

    $find = @{
        Namespace = 'root/StandardCimv2'
        ClassName = 'MSFT_NetRoute'
        MethodName = 'Find'
        Arguments = @{ RemoteIPAddress = $Address.ToString() }
    }
    $found = Invoke-CimMethod @find
    if ($found.ReturnValue -ne 0) { return }
    $source = @($found.CmdletOutput | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' })
    $routes = @($found.CmdletOutput | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' })
    if ($source.Count -ne 1 -or $routes.Count -ne 1 -or $source[0].InterfaceIndex -ne $routes[0].InterfaceIndex) { return }
    $index = [int]$routes[0].InterfaceIndex
    if ($index -le 0 -or $index -ge 0x1000000) { return }
    $adapters = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter -Filter "InterfaceIndex=$index")
    if ($adapters.Count -ne 1) { return }
    $adapter = $adapters[0]
    if ($adapter.HardwareInterface -ne $true -or $adapter.Virtual -ne $false -or
        $adapter.NdisPhysicalMedium -ne 14 -or $adapter.InterfaceOperationalStatus -ne 1 -or
        $adapter.MediaConnectState -ne 1) { return }
    $local = [Net.IPAddress]::Parse($source[0].IPAddress)
    if ($local.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($local) -or $local.Equals([Net.IPAddress]::Any)) { return }
    [pscustomobject]@{ Index = $index; Source = $local }
}

function Initialize-TraceNative {
    if ('ExamLabFileTraceNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public static class ExamLabFileTraceNative
{
    // Winsock IP_UNICAST_IF constrains IPv4 egress even if the preferred route changes.
    private const SocketOptionName IpUnicastInterface = (SocketOptionName)31;

    public static SocketsHttpHandler WiredHandler(IPAddress local, IPAddress remote, int port, int index)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (context, cancellation) =>
            {
                if (context.DnsEndPoint.Port != port || context.DnsEndPoint.Host != remote.ToString())
                    throw new InvalidOperationException("Unexpected HTTPS destination.");

                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, IpUnicastInterface, IPAddress.HostToNetworkOrder(index));
                    socket.Bind(new IPEndPoint(local, 0));
                    await socket.ConnectAsync(new IPEndPoint(remote, port), cancellation).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
    }

    [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int processId);

    public static int DesktopProcessId()
    {
        var shell = GetShellWindow();
        return shell != IntPtr.Zero && GetWindowThreadProcessId(shell, out int id) != 0 ? id : 0;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHParseDisplayName(string name, IntPtr context, out IntPtr item, uint flags, IntPtr attributes);

    [DllImport("shell32.dll")]
    private static extern int SHOpenFolderAndSelectItems(IntPtr folder, uint count, IntPtr items, uint flags);

    [DllImport("ole32.dll")] private static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();

    public static void RevealArchive(string path)
    {
        int initialized = CoInitializeEx(IntPtr.Zero, 2);
        if (initialized < 0 && initialized != unchecked((int)0x80010106))
            Marshal.ThrowExceptionForHR(initialized);
        try
        {
            Marshal.ThrowExceptionForHR(SHParseDisplayName(path, IntPtr.Zero, out IntPtr item, 0, IntPtr.Zero));
            try { Marshal.ThrowExceptionForHR(SHOpenFolderAndSelectItems(item, 0, IntPtr.Zero, 0)); }
            finally { Marshal.FreeCoTaskMem(item); }
        }
        finally
        {
            if (initialized >= 0)
                CoUninitialize();
        }
    }
}
'@
}

function Show-TraceInOperatorExplorer([string]$Archive, [string]$Sid) {
    if ($Headless -or -not [Environment]::UserInteractive) { return $false }
    $session = (Get-Process -Id $PID).SessionId
    if ($session -eq 0) { return $false }
    Initialize-TraceNative
    $explorerProcessId = [ExamLabFileTraceNative]::DesktopProcessId()
    if ($explorerProcessId -le 0) { return $false }
    $shell = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$explorerProcessId"
    if (-not $shell -or $shell.SessionId -ne $session -or
        $shell.ExecutablePath -ine (Join-Path ([Environment]::GetFolderPath('Windows')) 'explorer.exe')) { return $false }
    $owner = Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid
    if ($owner.ReturnValue -ne 0 -or $owner.Sid -cne $Sid -or
        [ExamLabFileTraceNative]::DesktopProcessId() -ne $explorerProcessId) { return $false }
    [ExamLabFileTraceNative]::RevealArchive($Archive)
    $true
}

function Send-TraceArchive($Registration, [Uri]$Controller, $Route, [Net.IPAddress]$Address, [IO.Stream]$Stream, [string]$Sha) {
    Initialize-TraceNative
    $endpoint = [Uri]::new($Controller, '/exam/v1/file-trace')
    $handler = [ExamLabFileTraceNative]::WiredHandler($Route.Source, $Address, $Controller.Port, $Route.Index)
    $client = [Net.Http.HttpClient]::new($handler)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $endpoint)
    try {
        $client.Timeout = [TimeSpan]::FromMinutes(60)
        $client.MaxResponseContentBufferSize = 4096
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Registration.token)
        $request.Headers.Add('X-ExamLab-Device', $Registration.deviceId)
        $request.Headers.Add('X-ExamLab-Revision', $ExamRevision.ToString([Globalization.CultureInfo]::InvariantCulture))
        $request.Headers.Add('X-ExamLab-Trace-Sha256', $Sha)
        $request.Content = [Net.Http.StreamContent]::new($Stream, 65536)
        $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/zip')
        $request.Content.Headers.ContentLength = $Stream.Length
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -notin @(200, 201)) { throw "Сервер отклонил трассу (HTTP $([int]$response.StatusCode))." }
            if ($response.Content.Headers.ContentType.MediaType -ine 'application/json') {
                throw 'Сервер не подтвердил приём трассы в JSON.'
            }
            $receipt = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
            if ($receipt.reportId -isnot [string] -or $receipt.reportId -cnotmatch '\A[A-Za-z0-9._-]{1,128}\z') {
                throw 'Сервер не выдал допустимый идентификатор трассы.'
            }
            $receipt.reportId
        } finally { $response.Dispose() }
    } finally {
        $request.Dispose()
        $client.Dispose()
    }
}

function Get-ProtectedTraceContext {
    $code = Get-Item -LiteralPath (Join-Path $programFiles 'ExamLab') -Force
    $state = Get-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab') -Force
    if ($code -isnot [IO.DirectoryInfo] -or $state -isnot [IO.DirectoryInfo]) { throw 'Некорректная установка ExamLab.' }
    Assert-TraceAccess $code $localAdmins -Readable
    Assert-TraceAccess $state $localAdmins -Root
    $modules = foreach ($name in 'ExamLab.Controller.psm1', 'ExamLab.psm1') {
        $module = Get-Item -LiteralPath (Join-Path $code.FullName $name) -Force
        if ($module -isnot [IO.FileInfo]) { throw 'Некорректный модуль ExamLab.' }
        Assert-TraceAccess $module $localAdmins -Readable
        $module.FullName
    }
    [pscustomobject]@{ State = $state; Modules = @($modules) }
}

function Read-TraceAttempt([IO.DirectoryInfo]$State) {
    $attemptFile = Get-Item -LiteralPath (Join-Path $State.FullName 'file-trace-attempt.json') -Force
    if ($attemptFile -isnot [IO.FileInfo] -or $attemptFile.Length -gt 8192) { throw 'Некорректная запись запуска трассы.' }
    Assert-TraceAccess $attemptFile $localAdmins
    $attempt = Get-Content -LiteralPath $attemptFile.FullName -Raw | ConvertFrom-Json -DateKind String
    if ($attempt -isnot [pscustomobject] -or $attempt.runId -isnot [string] -or
        $attempt.runId -cnotmatch '\A[0-9a-f]{32}\z' -or $attempt.deviceId -isnot [string] -or
        $attempt.deviceId -cnotmatch '\A[A-Za-z0-9._-]{1,64}\z' -or
        ($attempt.revision -isnot [int] -and $attempt.revision -isnot [long]) -or
        $attempt.revision -lt 1 -or $attempt.revision -gt [int]::MaxValue -or $attempt.examId -isnot [string] -or
        $attempt.examId -cnotmatch '\Afile-trace-[A-Za-z0-9._-]{1,53}\z' -or $attempt.phase -cne 'finished') {
        throw 'Запись запуска не подтверждает завершённую файловую пробу.'
    }
    $attempt
}

function Assert-TraceAssignment([IO.DirectoryInfo]$State, $Attempt, [string]$DeviceId, [string]$RunId, [int]$Revision) {
    if ($Attempt.runId -cne $RunId -or $Attempt.deviceId -cne $DeviceId -or $Attempt.revision -ne $Revision) {
        throw 'Запись запуска не подтверждает устройство, трассу и ревизию.'
    }
    $controllerState = Get-Item -LiteralPath (Join-Path $State.FullName 'controller-state.json') -Force
    if ($controllerState -isnot [IO.FileInfo]) { throw 'Не найдено состояние контроллера.' }
    Assert-TraceAccess $controllerState $localAdmins
    $local = Read-ControllerState $controllerState.FullName $DeviceId
    if (-not (Test-ExamLabFileTraceNormal $local $Attempt)) { throw 'Для получения трассы сначала подтвердите normal.' }
}

if ($OpenLatest) {
    $context = Get-ProtectedTraceContext
    foreach ($modulePath in $context.Modules) { Import-Module $modulePath -Scope Local }
    $latest = Read-TraceAttempt $context.State
    Assert-TraceAssignment $context.State $latest $latest.deviceId $latest.runId $latest.revision
    $TraceInstance = 'ExamLabFileIO-' + $latest.runId
}

$reportsPath = Join-Path $programFiles 'ExamLabSetupReports'
$sourceRoot = Get-Item -LiteralPath $reportsPath -Force
$traceDirectory = Get-Item -LiteralPath (Join-Path $reportsPath $TraceInstance) -Force
if ($sourceRoot -isnot [IO.DirectoryInfo] -or $traceDirectory -isnot [IO.DirectoryInfo]) {
    throw 'Нужен закрытый каталог завершённой пробы FileIO.light.'
}
Assert-TraceAccess $sourceRoot $localAdmins -Root
Assert-TraceAccess $traceDirectory $localAdmins
$files = foreach ($name in 'fileio.etl', 'metrics.jsonl', 'wpr.txt') {
    $file = Get-Item -LiteralPath (Join-Path $traceDirectory.FullName $name) -Force
    if ($file -isnot [IO.FileInfo] -or $file.Length -le 0) { throw "Нет завершённого файла трассы: $name" }
    Assert-TraceAccess $file $localAdmins
    $file
}
$metricFile = $files | Where-Object Name -eq 'metrics.jsonl'
if ($metricFile.Length -gt 1MB) { throw 'Неожиданный размер метрик пробы.' }
$completed = Get-Content -LiteralPath $metricFile.FullName -Tail 1 | ConvertFrom-Json
$etl = $files | Where-Object Name -eq 'fileio.etl'
if ($completed.event -cne 'completed' -or $completed.instance -cne $TraceInstance -or
    $completed.schemaVersion -ne 1 -or $completed.profile -cne 'FileIO.light' -or
    $completed.mode -cne 'file' -or $completed.bytes -ne $etl.Length -or
    $completed.sha256 -cnotmatch '\A[0-9A-Fa-f]{64}\z') {
    throw 'Метрики не подтверждают завершённую запись FileIO.light.'
}

$runId = $TraceInstance.Substring('ExamLabFileIO-'.Length)
$directory = Join-Path $programFiles "ExamLabFileTraceExport-$runId-$operator"
if (-not (Test-Path -LiteralPath $directory)) {
    $null = New-TraceExportDirectory $directory
}
$output = Get-Item -LiteralPath $directory -Force
if ($output -isnot [IO.DirectoryInfo]) { throw 'Путь экспорта не является каталогом.' }
$exportReaders = @($system, $administrators, $operator)
Assert-TraceAccess $output $exportReaders -Root
$readerRule = (Get-Acl -LiteralPath $directory).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference.Value -ceq $operator -and $_.AccessControlType -eq 'Allow' }
if (-not $readerRule) { throw 'Этот каталог экспорта принадлежит другому оператору.' }

$zip = Join-Path $directory 'file-trace.zip'
if (-not (Test-Path -LiteralPath $zip)) {
    $preparedZip = $null
    if ($OpenLatest) {
        $systemDirectory = Join-Path $programFiles "ExamLabFileTraceExport-$runId-$system"
        $systemZipPath = Join-Path $systemDirectory 'file-trace.zip'
        if (Test-Path -LiteralPath $systemZipPath) {
            $systemOutput = Get-Item -LiteralPath $systemDirectory -Force
            $preparedZip = Get-Item -LiteralPath $systemZipPath -Force
            if ($systemOutput -isnot [IO.DirectoryInfo] -or $preparedZip -isnot [IO.FileInfo] -or $preparedZip.Length -le 0) {
                throw 'Некорректный архив фонового экспорта.'
            }
            Assert-TraceAccess $systemOutput @($system, $administrators) -Root
            Assert-TraceAccess $preparedZip @($system, $administrators)
        }
    }
    Write-TraceZip $files $zip $preparedZip
}
$zipFile = Get-Item -LiteralPath $zip -Force
if ($zipFile -isnot [IO.FileInfo] -or $zipFile.Length -le 0) { throw 'Экспорт не создал действительный ZIP.' }
Assert-TraceAccess $zipFile $exportReaders

$stream = [IO.File]::Open($zipFile.FullName, 'Open', 'Read', 'Read')
$sha = $null
$reportId = $null
$outcome = 'local-only'
$failureStage = $null
$index = $null
try {
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    $stream.Position = 0
    if ($Upload) {
        try {
            $failureStage = 'registration'
            $context = Get-ProtectedTraceContext
            foreach ($modulePath in $context.Modules) { Import-Module $modulePath -Scope Local }
            $registration = Get-Item -LiteralPath (Join-Path $context.State.FullName 'controller-registration.json') -Force
            if ($registration -isnot [IO.FileInfo]) { throw 'Не найден файл регистрации.' }
            Assert-TraceAccess $registration $localAdmins
            $registered = Read-ControllerConfiguration $registration.FullName
            $failureStage = 'assignment'
            $attempt = Read-TraceAttempt $context.State
            Assert-TraceAssignment $context.State $attempt $registered.deviceId $runId $ExamRevision
            $controller = [Uri]::new($registered.url)
            $failureStage = 'route'
            $route = $null
            if ($controller.HostNameType -eq [UriHostNameType]::IPv4) {
                $destination = [Net.IPAddress]::Parse($controller.Host)
                try { $route = Find-TraceEthernetRoute $destination }
                catch { }
            }
            if ($route) {
                $index = $route.Index
                $failureStage = 'send'
                $reportId = Send-TraceArchive $registered $controller $route $destination $stream $sha
                $outcome = 'uploaded'
                $failureStage = $null
            } else {
                $outcome = 'no-verified-ethernet'
                Write-Warning 'Архив сохранён локально. Проводной маршрут до контроллера не подтверждён.'
            }
        } catch {
            $outcome = 'upload-failed'
            Write-Warning 'Отправка не подтверждена. Архив сохранён локально и доступен для явного повтора.'
        }
    }
} finally { $stream.Dispose() }

$explorerOpened = $false
if ($outcome -ne 'uploaded') {
    try { $explorerOpened = Show-TraceInOperatorExplorer $zipFile.FullName $operator }
    catch { Write-Warning 'Не удалось открыть папку экспорта в рабочем столе администратора.' }
}
[pscustomobject]@{
    outcome = $outcome
    failureStage = $failureStage
    archive = $zipFile.FullName
    bytes = $zipFile.Length
    sha256 = $sha
    reportId = $reportId
    interfaceIndex = $index
    explorerOpened = $explorerOpened
} | ConvertTo-Json -Compress
