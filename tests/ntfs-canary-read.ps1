#requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('read','deny')][string]$Expected,
    [Parameter(Mandatory)][string[]]$Paths,
    [Parameter(Mandatory)][string]$JavaPath,
    [Parameter(Mandatory)][string]$ProbeClassPath,
    [string]$ExpectedSid,
    [switch]$CheckMutationRights
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$whoami = Join-Path ([Environment]::SystemDirectory) 'whoami.exe'
$nativeGroups = @(& $whoami /groups /fo csv /nh)
if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать группы токена.' }
$groups = @($nativeGroups | ConvertFrom-Csv -Header Name,Type,Sid,Attributes)
$groupSids = @($groups | ForEach-Object { $_.Sid } | Sort-Object)
if (-not $groupSids.Count -or @($groupSids | Where-Object { $_ -notmatch '^S-\d+(-\d+)+$' }).Count) {
    throw 'Формат групп токена не распознан.'
}
if ($sessionId -eq 0 -or 'S-1-5-32-544' -in $groupSids -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    ($ExpectedSid -and $identity.User.Value -ne $ExpectedSid)) {
    throw 'Ожидался настоящий интерактивный сеанс указанной стандартной учётки.'
}

if ($CheckMutationRights -and -not ('ExamLabNtfsRights' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ExamLabNtfsRights {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        System.IntPtr security, uint disposition, uint flags, System.IntPtr template);
    public static int OpenResult(string path, uint access) {
        using (var file = CreateFile(path, access, 7, System.IntPtr.Zero, 3, 0x02000000, System.IntPtr.Zero)) {
            return file.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@
}

$success = $true
$results = foreach ($path in $Paths) {
    if ($path -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($path) -ne $path) {
        throw "Нужен точный абсолютный путь: $path"
    }
    $dotnet = $null
    try {
        $bytes = [IO.File]::ReadAllBytes($path)
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
        $dotnet = @{Outcome='read'; Hash=$hash}
    } catch {
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [UnauthorizedAccessException] -and $cause.HResult -eq -2147024891) {
            $dotnet = @{Outcome='deny'; Error='0x80070005'}
        } else { $dotnet = @{Outcome='error'; Error=$cause.Message} }
    }
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $JavaPath -cp $ProbeClassPath WindowsProbe file $path $Expected 2>&1)
        $javaExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $java = ($output | Out-String).Trim()
    $javaOk = $false
    if ($Expected -eq 'read' -and $dotnet.Outcome -eq 'read') {
        $javaOk = $java -match "^READ bytes=\d+ sha256=$($dotnet.Hash)$"
    } elseif ($Expected -eq 'deny') { $javaOk = $java -ceq "ACCESS_DENIED $path" }
    $rights = @()
    if ($CheckMutationRights) {
        foreach ($specific in ([ordered]@{WriteData=2; Delete=0x10000; WriteDac=0x40000; WriteOwner=0x80000}).GetEnumerator()) {
            $rights += [pscustomobject]@{Path=$path; Right=$specific.Key; Result=[ExamLabNtfsRights]::OpenResult($path,$specific.Value)}
        }
        for ($parent=[IO.Path]::GetDirectoryName($path); $parent; $parent=[IO.Path]::GetDirectoryName($parent)) {
            $rights += [pscustomobject]@{Path=$parent; Right='DeleteChild'; Result=[ExamLabNtfsRights]::OpenResult($parent,0x40)}
            if ($parent -ne [IO.Path]::GetPathRoot($parent)) {
                $rights += [pscustomobject]@{Path=$parent; Right='Delete'; Result=[ExamLabNtfsRights]::OpenResult($parent,0x10000)}
            }
        }
    }
    $pass = ($dotnet.Outcome -eq $Expected -and $javaExit -eq 0 -and $javaOk -and
        @($rights | Where-Object { $_.Result -ne 5 }).Count -eq 0)
    if (-not $pass) { $success = $false }
    [pscustomobject]@{Path=$path; Expected=$Expected; DotNet=$dotnet; JavaExit=$javaExit; Java=$java; Rights=$rights; Pass=$pass}
}
[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Sid=$identity.User.Value; Profile=$env:USERPROFILE;
    Session=$sessionId; Groups=$groups; Pass=$success; Files=@($results)} | ConvertTo-Json -Depth 8
if (-not $success) { exit 1 }
