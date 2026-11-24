@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
set "EXAMLAB_LAUNCHER=%~f0"
set "NATIVE=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "NATIVE=%SystemRoot%\Sysnative"
"%NATIVE%\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { $source = [IO.File]::ReadAllText($env:EXAMLAB_LAUNCHER); . ([ScriptBlock]::Create(($source -split '(?m)^:NativePowerShell\r?$', 2)[1])) } catch { [Console]::Error.WriteLine('ExamLab Check: ' + $_.Exception.Message); exit 1 }"
set "RESULT=%ERRORLEVEL%"
if not defined EXAMLAB_NO_PAUSE pause
exit /b %RESULT%

:NativePowerShell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$url = [Uri]'@CHECK_SCRIPT_URL@'
$size = @CHECK_SCRIPT_BYTES@
$expected = '@CHECK_SCRIPT_SHA256@'
$directory = [IO.Path]::GetDirectoryName($env:EXAMLAB_LAUNCHER)
$local = [IO.Path]::Combine($directory, [IO.Path]::GetFileName($url.AbsolutePath))
$data = [byte[]]::new($size)
$inputStream = $null
$response = $null
try {
    if ([IO.File]::Exists($local)) {
        $inputStream = [IO.File]::OpenRead($local)
    } else {
        $request = [Net.HttpWebRequest][Net.WebRequest]::Create($url)
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.Timeout = $request.ReadWriteTimeout = 15000
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -ne $size) {
            throw 'Unexpected Check script response.'
        }
        $inputStream = $response.GetResponseStream()
    }
    $offset = 0
    while ($offset -lt $size) {
        $count = $inputStream.Read($data, $offset, $size - $offset)
        if (-not $count) { break }
        $offset += $count
    }
    if ($offset -ne $size -or $inputStream.ReadByte() -ne -1) {
        throw 'Unexpected Check script size.'
    }
} finally {
    if ($inputStream) { $inputStream.Dispose() }
    if ($response) { $response.Dispose() }
}
$sha256 = [Security.Cryptography.SHA256]::Create()
try { $actual = [BitConverter]::ToString($sha256.ComputeHash($data)).Replace('-', '') }
finally { $sha256.Dispose() }
if ($actual -ine $expected) { throw 'Check script SHA-256 mismatch.' }
$launcherText = [Text.Encoding]::UTF8.GetString($data).TrimStart([char]0xFEFF)
. ([scriptblock]::Create($launcherText))
