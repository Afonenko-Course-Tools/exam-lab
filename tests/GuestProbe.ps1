#requires -Version 7.6
# Наблюдение настоящего уже вошедшего Guest. Не меняет policy/ACL/registry.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Guid]$RunId,
    [Parameter(Mandatory)][string]$ExpectedSid,
    [Parameter(Mandatory)][string]$UsbPath,
    [Parameter(Mandatory)][string]$JavaPath,
    [Parameter(Mandatory)][string]$ProbeClassPath,
    [ValidateSet('read','deny')][string]$ExpectedUsb='deny'
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
$result=[ordered]@{RunId=[string]$RunId;Sid=$identity.User.Value;IsAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);Usb=$null;Fatal=$null}
try {
    if($result.Sid -ne $ExpectedSid -or $result.IsAdmin){throw 'Не совпал настоящий nonadmin SID.'}
    $output=@(& $JavaPath -cp $ProbeClassPath WindowsProbe file $UsbPath $ExpectedUsb 2>&1)
    $code=$LASTEXITCODE; $text=($output|Out-String).Trim()
    $result.Usb=@{Path=$UsbPath;Expected=$ExpectedUsb;Exit=$code;Output=$text}
    if($code -ne 0){throw 'Java probe завершился ошибкой; отсутствующий путь не считается deny.'}
    if($ExpectedUsb -eq 'deny' -and $text -ne ('ACCESS_DENIED '+$UsbPath)){throw 'Нет явного AccessDeniedException.'}
    if($ExpectedUsb -eq 'read' -and $text -notmatch '^READ bytes=\d+ sha256=[a-f0-9]{64}$'){throw 'Нет read/hash результата.'}
} catch {$result.Fatal=$_.Exception.ToString()}
$result|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $env:TEMP ('exam-lab-guest-probe-'+$RunId+'.json')) -Encoding UTF8
if($result.Fatal){exit 1}
