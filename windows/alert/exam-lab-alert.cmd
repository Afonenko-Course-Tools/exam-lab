@echo off
setlocal
set "powershell=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "powershell=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
set "installRoot=%ProgramW6432%"
if not defined installRoot set "installRoot=%ProgramFiles%"
"%powershell%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%installRoot%\ExamLabAlert\ExamLabAlert.ps1" -Action Receive
exit /b %ERRORLEVEL%
