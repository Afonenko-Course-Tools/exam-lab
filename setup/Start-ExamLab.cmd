@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
set "EXAMLAB_LAUNCHER=%~f0"
set "NATIVE=%SystemRoot%\System32"
if /I not "%PROCESSOR_ARCHITECTURE%"=="AMD64" goto :Unsupported
"%NATIVE%\fltmc.exe" >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto :Elevate

cd /d "%NATIVE%"
set "CURL=%NATIVE%\curl.exe"
set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
set "CA_PIN=@CONTROLLER_CA_SHA256@"
set "CA_THUMB=@CONTROLLER_CA_THUMBPRINT@"
set "CA_PENDING=%ProgramFiles%\.exam-lab-controller-%CA_PIN%.pending"
set "STARTED="
call :Run 9>"%ProgramFiles%\.exam-lab-bootstrap.lock"
set "RESULT=%ERRORLEVEL%"
if not defined STARTED (
    echo Cannot start ExamLab. Another installation may already be running.
    set "RESULT=1"
)
goto :Finish

:Elevate
if /I "%~1"=="--elevated" goto :ManualElevation
set "ELEVATION_SCRIPT=%TEMP%\ExamLab-runas-%RANDOM%-%RANDOM%.vbs"
> "%ELEVATION_SCRIPT%" echo Set shell = CreateObject("Shell.Application")
>> "%ELEVATION_SCRIPT%" echo shell.ShellExecute WScript.Arguments.Item(0), "--elevated", "", "runas", 1
"%NATIVE%\cscript.exe" //nologo //E:VBScript "%ELEVATION_SCRIPT%" "%EXAMLAB_LAUNCHER%"
set "RESULT=%ERRORLEVEL%"
del /q "%ELEVATION_SCRIPT%" >nul 2>&1
if not "%RESULT%"=="0" goto :ManualElevation
exit /b 0

:ManualElevation
echo Right-click the verified Start-ExamLab.cmd and select Run as administrator.
set "RESULT=1"
goto :Finish

:Unsupported
echo ExamLab requires native Windows x64.
set "RESULT=1"

:Finish
if not defined EXAMLAB_NO_PAUSE pause
exit /b %RESULT%

:Run
set "STARTED=1"
set "EXAMLAB_BOOTSTRAP_CA_ADDED="
set "CURL_TLS_FLAGS="
set "EXAMLAB_DIAGNOSTICS_DIR=%ProgramFiles%\ExamLabBootstrap-%RANDOM%-%RANDOM%"
set "WORK=%EXAMLAB_DIAGNOSTICS_DIR%"
set "REPORT=%WORK%\report"
set "LOG=%REPORT%\bootstrap.log"
md "%WORK%" || exit /b 1
"%NATIVE%\icacls.exe" "%WORK%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
if not "%ERRORLEVEL%"=="0" (
    rd "%WORK%" >nul 2>&1
    exit /b 1
)
md "%REPORT%" || exit /b 1

> "%LOG%" echo ExamLab release @REVISION@ - %DATE% %TIME%
>> "%LOG%" ver
>> "%LOG%" echo Native architecture: %PROCESSOR_ARCHITECTURE%
for %%V in (EditionID DisplayVersion CurrentBuildNumber UBR) do (
    "%NATIVE%\reg.exe" query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v %%V >> "%LOG%" 2>&1
)
if exist "%CURL%" "%CURL%" -q --version >> "%LOG%" 2>&1
call :Install
set "RESULT=%ERRORLEVEL%"
>> "%LOG%" echo Result: %RESULT%; phase: %PHASE%; %DATE% %TIME%

if "%RESULT%"=="0" goto :Success
if "%RESULT%"=="3010" goto :Restart
echo ExamLab failed during %PHASE% ^(exit %RESULT%^).
call :Upload
call :FinishTrust
call :RemovePayloads
echo Local diagnostics: "%WORK%"
exit /b %RESULT%

:Restart
call :FinishTrust
call :RemovePayloads
echo Restart Windows, then run the same verified Start-ExamLab.cmd again.
echo Local diagnostics: "%WORK%"
exit /b 3010

:Success
call :FinishTrust
rd /s /q "%WORK%" >nul 2>&1
exit /b 0

:Install
call :Step "controller CA verification"
@CONTROLLER_CA_PEM@
"%NATIVE%\certutil.exe" -f -decode "%WORK%\controller-ca.pem" "%WORK%\controller-ca.cer" >> "%LOG%" 2>&1
if not "%ERRORLEVEL%"=="0" exit /b 1
call :VerifyHash "%WORK%\controller-ca.cer" "%CA_PIN%"
if not "%ERRORLEVEL%"=="0" exit /b 1
set "CA_PRESENT="
"%NATIVE%\certutil.exe" -store Root "%CA_THUMB%" >> "%LOG%" 2>&1
if "%ERRORLEVEL%"=="0" set "CA_PRESENT=1"

call :Step "PowerShell 7 check"
set "RUNTIME_READY="
call :CheckPowerShell
if "%ERRORLEVEL%"=="0" set "RUNTIME_READY=1"
if exist "%ProgramFiles%\ExamLab" (
    if not defined CA_PRESENT goto :PrerequisiteRepair
    if not defined RUNTIME_READY goto :PrerequisiteRepair
)

call :Step "controller CA installation"
if defined CA_PRESENT goto :ControllerTrusted
call :AddControllerTrust
if not "%ERRORLEVEL%"=="0" exit /b 1
:ControllerTrusted
if exist "%ProgramFiles%\ExamLab" (
    del /q "%CA_PENDING%" >nul 2>&1
) else (
    if exist "%CA_PENDING%" set "EXAMLAB_BOOTSTRAP_CA_ADDED=1"
)
call :ConfigureCurl

if defined RUNTIME_READY goto :Installer
call :Step "PowerShell 7 download"
call :Download "@PWSH_URL@" "%WORK%\PowerShell.msi"
if not "%ERRORLEVEL%"=="0" exit /b 1
call :Step "PowerShell 7 MSI verification"
call :VerifyHash "%WORK%\PowerShell.msi" "@PWSH_SHA256@"
if not "%ERRORLEVEL%"=="0" exit /b 1

call :Step "PowerShell 7 MSI installation"
"%NATIVE%\msiexec.exe" /i "%WORK%\PowerShell.msi" /quiet /norestart USE_MU=0 ENABLE_MU=0 /L*v "%WORK%\PowerShell-msi.log"
set "MSI_RESULT=%ERRORLEVEL%"
>> "%LOG%" echo MSI exit code: %MSI_RESULT%
if not "%MSI_RESULT%"=="0" exit /b %MSI_RESULT%
call :CheckPowerShell
if not "%ERRORLEVEL%"=="0" exit /b 1

:Installer
call :Step "ExamLab installer download"
call :Download "@INSTALLER_URL@" "%WORK%\Install-ExamLab.ps1"
if not "%ERRORLEVEL%"=="0" exit /b 1
call :Step "ExamLab installer verification"
call :VerifyHash "%WORK%\Install-ExamLab.ps1" "@INSTALLER_SHA256@"
if not "%ERRORLEVEL%"=="0" exit /b 1
call :Step "ExamLab installer"
"%PWSH%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%WORK%\Install-ExamLab.ps1"
exit /b %ERRORLEVEL%

:PrerequisiteRepair
>> "%LOG%" echo An existing ExamLab installation is missing a trusted prerequisite. Local maintenance is required.
echo Existing ExamLab installation needs local maintenance before prerequisites can change.
exit /b 1

:CheckPowerShell
if not exist "%PWSH%" exit /b 1
"%PWSH%" -NoLogo -NoProfile -NonInteractive -Command "if ($PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion -lt [semver]'@PWSH_VERSION@' -or $PSVersionTable.PSVersion.PreReleaseLabel -or -not [Environment]::Is64BitProcess) { exit 1 }; $PSVersionTable.PSVersion.ToString()" >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%

:AddControllerTrust
> "%CA_PENDING%" echo %CA_PIN%
if not "%ERRORLEVEL%"=="0" exit /b 1
set "EXAMLAB_BOOTSTRAP_CA_ADDED=1"
"%NATIVE%\certutil.exe" -f -addstore Root "%WORK%\controller-ca.cer" >> "%LOG%" 2>&1
if not "%ERRORLEVEL%"=="0" exit /b 1
"%NATIVE%\certutil.exe" -store Root "%CA_THUMB%" >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%

:VerifyHash
"%NATIVE%\certutil.exe" -hashfile "%~1" SHA256 > "%WORK%\artifact-hash.txt" 2>&1
if not "%ERRORLEVEL%"=="0" exit /b 1
type "%WORK%\artifact-hash.txt" >> "%LOG%"
"%NATIVE%\findstr.exe" /I /X /L /C:"%~2" "%WORK%\artifact-hash.txt" >nul
exit /b %ERRORLEVEL%

:ConfigureCurl
"%CURL%" -q --ssl-revoke-best-effort --version >nul 2>&1
if not errorlevel 1 (
    set "CURL_TLS_FLAGS=--ssl-revoke-best-effort --cacert "%WORK%\controller-ca.pem""
    exit /b 0
)
rem WinSSL 7.55.1 uses the Windows root store and cannot use a custom CA file.
rem The private pilot CA has no revocation endpoint. Keep chain and hostname checks.
set "CURL_TLS_FLAGS=--ssl-no-revoke"
>> "%LOG%" echo HTTPS: legacy Windows curl, native certificate store.
exit /b 0

:Download
"%CURL%" -q --proto "=https" --noproxy "*" --tlsv1.2@CURL_RESOLVE@ %CURL_TLS_FLAGS% --fail --silent --show-error --connect-timeout 8 --max-time 180 --output "%~2" "%~1" >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%

:Step
set "PHASE=%~1"
echo [%TIME%] %PHASE%
>> "%LOG%" echo [%TIME%] %PHASE%
exit /b 0

:Upload
if not "%PHASE%"=="ExamLab installer" call :CollectNative
if exist "%WORK%\PowerShell-msi.log" "%NATIVE%\findstr.exe" /I /L /C:"Return value 3" /C:"MainEngineThread is returning" "%WORK%\PowerShell-msi.log" > "%REPORT%\msi-summary.log"
"%NATIVE%\tar.exe" -a -cf "%WORK%\diagnostics.zip" -C "%WORK%" report > "%WORK%\archive.log" 2>&1
if not "%ERRORLEVEL%"=="0" exit /b 0
if not defined CURL_TLS_FLAGS exit /b 0
for %%F in ("%WORK%\diagnostics.zip") do if %%~zF GTR 8388608 (
    echo Diagnostic ZIP is larger than 8 MiB. It is available locally.
    exit /b 0
)
"%CURL%" -q --proto "=https" --noproxy "*" --tlsv1.2@CURL_RESOLVE@ %CURL_TLS_FLAGS% --fail --silent --show-error --connect-timeout 4 --max-time 12 --header "Content-Type: application/zip" --header "Expect:" --data-binary "@%WORK%\diagnostics.zip" --output "%WORK%\upload-result.json" "@DIAGNOSTICS_URL@" >> "%LOG%" 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo Diagnostic upload unavailable. The ZIP is available locally.
    exit /b 0
)
echo Diagnostic upload response:
type "%WORK%\upload-result.json"
exit /b 0

:CollectNative
"%NATIVE%\wevtutil.exe" qe Application /q:"*[System[Provider[@Name='MsiInstaller'] and TimeCreated[timediff(@SystemTime) <= 900000]]]" /rd:true /c:12 /f:xml > "%WORK%\msi-events.xml" 2>> "%LOG%"
"%NATIVE%\wevtutil.exe" qe System /q:"*[System[Provider[@Name='Schannel'] and TimeCreated[timediff(@SystemTime) <= 900000]]]" /rd:true /c:12 /f:xml > "%WORK%\schannel-events.xml" 2>> "%LOG%"
exit /b 0

:FinishTrust
if not defined EXAMLAB_BOOTSTRAP_CA_ADDED exit /b 0
if exist "%WORK%\bootstrap-ca-managed" goto :ClearTrustPending
"%NATIVE%\certutil.exe" -store Root "%CA_THUMB%" >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto :ClearTrustPending
"%NATIVE%\certutil.exe" -delstore Root "%CA_THUMB%" >> "%LOG%" 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo Controller CA rollback failed. See the local bootstrap log.
    exit /b 1
)
:ClearTrustPending
del /q "%CA_PENDING%" >nul 2>&1
exit /b 0

:RemovePayloads
del /q "%WORK%\PowerShell.msi" "%WORK%\Install-ExamLab.ps1" "%WORK%\controller-ca.pem" "%WORK%\controller-ca.cer" "%WORK%\artifact-hash.txt" >nul 2>&1
exit /b 0
