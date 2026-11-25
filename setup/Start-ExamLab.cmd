@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
set "EXAMLAB_LAUNCHER=%~f0"
@BOOTSTRAP_ARGUMENTS@
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
@INVENTORY_PAYLOAD@

:NativePowerShell
@NATIVE_SCRIPT@
