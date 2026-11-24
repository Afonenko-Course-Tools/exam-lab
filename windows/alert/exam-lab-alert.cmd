@echo off
setlocal
set "installRoot=%ProgramW6432%"
if not defined installRoot set "installRoot=%ProgramFiles%"
"%installRoot%\PowerShell\7\pwsh.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%installRoot%\ExamLabAlert\ExamLabAlert.ps1" -Action Receive
exit /b %ERRORLEVEL%
