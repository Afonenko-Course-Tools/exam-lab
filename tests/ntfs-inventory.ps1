#requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateRange(20,400)][int]$MaxEntriesPerArea = 120,
    [string[]]$KnownOtherProfileFiles = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$whoami = Join-Path ([Environment]::SystemDirectory) 'whoami.exe'
$groups = @(& $whoami /groups /fo csv /nh)
if ($LASTEXITCODE -ne 0 -or $session -eq 0 -or -not $groups.Count -or
    ($groups -match '"S-1-5-32-544"').Count -gt 0) {
    throw 'Запустите из интерактивного сеанса стандартного Shared PC Guest.'
}
if (-not ('ExamLabInventoryAccess' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ExamLabInventoryAccess {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        System.IntPtr security, uint disposition, uint flags, System.IntPtr template);
    public static int Check(string path, uint access) {
        using (var file = CreateFile(path, access, 7, System.IntPtr.Zero, 3, 0x02200000, System.IntPtr.Zero)) {
            return file.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@
}

function Test-PlainLocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFullPath($Path) -ne $Path) { return $false }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if ($drive.DriveType -ne 'Fixed') { return $false }
    try {
        for ($current=$Path; $current; $current=[IO.Path]::GetDirectoryName($current)) {
            if ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
    } catch { return $false }
    return $true
}

function New-AccessCounts {
    [ordered]@{Allowed=0; Denied=0; Other=0}
}

function Add-AccessResult($Counts, [string]$Path, [uint32]$Access) {
    switch ([ExamLabInventoryAccess]::Check($Path,$Access)) {
        0 { $Counts.Allowed++ }
        5 { $Counts.Denied++ }
        default { $Counts.Other++ }
    }
}

function Measure-Area([string]$Name, [string[]]$Roots, [int]$Depth) {
    $result = [ordered]@{Area=$Name; Roots=$Roots.Count; SkippedRoots=0; Entries=0; Files=0; Directories=0;
        SkippedReparse=0; ListingDenied=0; ListingError=0; LimitReached=$false;
        RootList=(New-AccessCounts); RootDeleteChild=(New-AccessCounts); RootDelete=(New-AccessCounts);
        RootWriteDac=(New-AccessCounts); FileReadData=(New-AccessCounts)}
    $pending = [Collections.Generic.Queue[object]]::new()
    foreach ($path in $Roots) {
        if (-not (Test-PlainLocalPath $path)) { $result.SkippedRoots++; continue }
        if (-not [IO.Directory]::Exists($path)) { $result.SkippedRoots++; continue }
        Add-AccessResult $result.RootList $path 1
        Add-AccessResult $result.RootDeleteChild $path 0x40
        Add-AccessResult $result.RootDelete $path 0x10000
        Add-AccessResult $result.RootWriteDac $path 0x40000
        $pending.Enqueue([pscustomobject]@{Path=$path; Depth=0})
    }
    while ($pending.Count -gt 0 -and $result.Entries -lt $MaxEntriesPerArea) {
        $next = $pending.Dequeue()
        if (-not (Test-PlainLocalPath $next.Path)) { $result.SkippedReparse++; continue }
        $iterator = $null
        try {
            $iterator = [IO.DirectoryInfo]::new($next.Path).EnumerateFileSystemInfos().GetEnumerator()
            while ($result.Entries -lt $MaxEntriesPerArea -and $iterator.MoveNext()) {
                $entry = $iterator.Current
                $result.Entries++
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $result.SkippedReparse++; continue }
                if ($entry -is [IO.DirectoryInfo]) {
                    $result.Directories++
                    if ($next.Depth -lt $Depth) {
                        $pending.Enqueue([pscustomobject]@{Path=$entry.FullName; Depth=($next.Depth+1)})
                    }
                } else {
                    $result.Files++
                    Add-AccessResult $result.FileReadData $entry.FullName 1
                }
            }
        } catch {
            if ($_.Exception.GetBaseException() -is [UnauthorizedAccessException]) { $result.ListingDenied++ }
            else { $result.ListingError++ }
        } finally { if ($null -ne $iterator) { $iterator.Dispose() } }
    }
    $result.LimitReached = ($result.Entries -ge $MaxEntriesPerArea)
    return [pscustomobject]$result
}

$systemRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$commonDocuments = [Environment]::GetFolderPath('CommonDocuments')
$profileDiscovery = 'Observed'
$otherProfiles = @()
try {
    $otherProfiles = @(Get-CimInstance Win32_UserProfile | Where-Object {
        -not $_.Special -and $_.SID -ne $identity.User.Value -and $_.LocalPath -and $_.LocalPath -ne $env:USERPROFILE
    } | ForEach-Object { $_.LocalPath })
} catch { $profileDiscovery = 'Unavailable' }
$knownSystemRoots = @($env:SystemRoot,[Environment]::GetFolderPath('ProgramFiles'),
    [Environment]::GetFolderPath('ProgramFilesX86'),[IO.Path]::GetDirectoryName($env:USERPROFILE),$programData)
$otherRootDiscovery = 'Observed'
$otherSystemDirectories = @()
try {
    $otherSystemDirectories = @([IO.Directory]::EnumerateDirectories($systemRoot) |
        Where-Object { $_ -notin $knownSystemRoots } | Select-Object -First $MaxEntriesPerArea)
} catch { $otherRootDiscovery = 'Unavailable' }
$fixed = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Name -ne $systemRoot })
$otherNtfs = @($fixed | Where-Object { $_.IsReady -and $_.DriveFormat -eq 'NTFS' } | ForEach-Object { $_.Name })
$foreignMarkers = New-AccessCounts
$foreignMarkersSkipped = 0
foreach ($path in $KnownOtherProfileFiles) {
    $inOtherProfile = @($otherProfiles | Where-Object {
        $path.StartsWith($_.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if ($inOtherProfile -and (Test-PlainLocalPath $path)) { Add-AccessResult $foreignMarkers $path 1 }
    else { $foreignMarkersSkipped++ }
}
$areas = @(
    Measure-Area 'SystemDriveRoot' @($systemRoot) 0
    Measure-Area 'OtherSystemDriveDirectories' $otherSystemDirectories 1
    Measure-Area 'OtherProfiles' $otherProfiles 1
    Measure-Area 'PublicRoot' @($env:PUBLIC) 1
    Measure-Area 'CommonDocuments' @($commonDocuments) 1
    Measure-Area 'ProgramData' @($programData) 1
    Measure-Area 'OtherFixedNtfs' $otherNtfs 1
)
[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Session=$session; ProfileDiscovery=$profileDiscovery;
    OtherSystemRootDiscovery=$otherRootDiscovery; OtherFixed=$fixed.Count; MaxEntriesPerArea=$MaxEntriesPerArea; ExactOtherProfileReadData=$foreignMarkers;
    ExactOtherProfileFilesSkipped=$foreignMarkersSkipped; Areas=$areas} | ConvertTo-Json -Depth 6
