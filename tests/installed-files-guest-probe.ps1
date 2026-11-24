#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExpectedComputerName)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not [Environment]::Is64BitProcess -or -not [Environment]::UserInteractive -or $sessionId -le 0 -or
    $env:COMPUTERNAME -ine $ExpectedComputerName -or $env:USERNAME -cnotmatch '^shpctac[0-9a-f]{5}$' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите пробу без повышения из настоящего Shared PC Guest испытательной Windows VM.'
}

if (-not ('ExamLabGuestFileAccess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class ExamLabGuestFileAccess {
    private const uint ShareReadWriteDelete = 0x7, OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    public static int Check(string path, uint access, bool directory) {
        using (SafeFileHandle handle = CreateFile(path, access, ShareReadWriteDelete, IntPtr.Zero,
            OpenExisting, directory ? BackupSemantics : 0, IntPtr.Zero)) {
            return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@
}

function Test-NativeAccess([string]$Path, [string]$Operation, [uint32]$Rights, [switch]$Directory) {
    $code = [ExamLabGuestFileAccess]::Check($Path, $Rights, [bool]$Directory)
    $outcome = if ($code -eq 0) { 'Allowed' } elseif ($code -eq 5) { 'Denied' } else { 'Unknown' }
    [pscustomobject]@{
        path=$Path; operation=$Operation; win32Code=$code
        outcome=$outcome
    }
}

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
$fileTargets = @(
    (Join-Path $programFiles 'ExamLab\exam-lab.ps1'),
    (Join-Path $programFiles 'ExamLab\ExamLab.psm1'),
    (Join-Path $programFiles 'ExamLabAlert\ExamLabAlert.ps1'),
    (Join-Path $programFiles 'ExamLabAlert\Show-ExamLabAlert.ps1'),
    (Join-Path $programFiles 'ExamLabIdea\Install-ExamLabIdea.ps1'),
    (Join-Path $programFilesX86 'ossec-agent\active-response\bin\exam-lab-alert.cmd')
)
$parentTargets = @($fileTargets | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique)
$parentTargets += (Join-Path $programFilesX86 'ossec-agent\active-response'),
    (Join-Path $programFilesX86 'ossec-agent'), $programFiles, $programFilesX86
$observations = @(
    foreach ($path in $fileTargets) {
        Test-NativeAccess $path 'ReadData' 0x0001
        Test-NativeAccess $path 'WriteData' 0x0002
        Test-NativeAccess $path 'AppendData' 0x0004
        Test-NativeAccess $path 'DeleteOrRenameSource' 0x10000
    }
    foreach ($directory in $parentTargets) {
        Test-NativeAccess $directory 'AddFileOrRenameDestination' 0x0002 -Directory
        Test-NativeAccess $directory 'AddSubdirectory' 0x0004 -Directory
        Test-NativeAccess $directory 'DeleteChild' 0x0040 -Directory
        Test-NativeAccess $directory 'DeleteOrRenameDirectory' 0x10000 -Directory
    }
)

$workspace = Join-Path $env:LOCALAPPDATA ('ExamLab-FileProbe-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $workspace)
$file = Join-Path $workspace 'one.txt'
$renamed = Join-Path $workspace 'two.txt'
try {
    [IO.File]::WriteAllText($file, 'ExamLab synthetic Guest file')
    [IO.File]::Move($file, $renamed)
    $knownContent = [IO.File]::ReadAllText($renamed) -ceq 'ExamLab synthetic Guest file'
    [IO.File]::Delete($renamed)
    $workspacePassed = $knownContent -and -not [IO.File]::Exists($renamed)
} finally {
    [IO.File]::Delete($file)
    [IO.File]::Delete($renamed)
    [IO.Directory]::Delete($workspace)
}

[pscustomobject]@{
    utc=[DateTimeOffset]::UtcNow.ToString('o'); guestSid=$identity.User.Value; sessionId=$sessionId
    workspacePassed=$workspacePassed; observations=$observations
}
