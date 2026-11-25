#Requires -Version 7.6
# Проверка маршрутизации вызовов. WPR, Win32 и экспорт на Windows не испытываются.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:CodeRoot = $PSScriptRoot
$script:DataRoot = $PSScriptRoot
$script:ControllerStateFile = 'unused'
Import-Module (Join-Path $PSScriptRoot '../windows/ExamLab.Controller.psm1')
. (Join-Path $PSScriptRoot '../windows/trace/ExamLab.FileTrace.ps1')

function Test-ExistingFile([string]$Path) { [IO.File]::Exists($Path) }
function Assert-SafePath([string]$Path, [switch]$Readable) {}
function Get-ControllerConsoleLogon {
    [pscustomobject]@{ Sid='S-1-5-21-1-2-3-1111'; SessionId=3; AuthenticationId=12345 }
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-trace-binding-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixture
try {
    $callbackFile = Join-Path $fixture 'Capture.ps1'
    @'
param([scriptblock]$StopWhen, $StopContext)
Set-StrictMode -Version Latest
& $StopWhen $StopContext
'@ | Set-Content -LiteralPath $callbackFile
    $context = @{
        Token='test-token'
        AuthorizationPath=(Join-Path $fixture 'file-trace-exam.txt')
        StatePath=(Join-Path $fixture 'controller-state.json')
        Attempt=[pscustomobject]@{
            deviceId='test-device'; revision=3; examId='file-trace-test'
            bootUtc='2026-11-24T10:00:00.000Z'; localGeneration=$null
            guestSessionId=$null
        }
    }
    $attempt = $context.Attempt
    $attempt.guestSessionId = Get-ControllerGuestSessionId $context.Token $attempt.bootUtc (Get-ControllerConsoleLogon)
    [IO.File]::WriteAllText($context.AuthorizationPath, $attempt.examId)
    $state = [pscustomobject]@{
        Assignment=[pscustomobject]@{ deviceId=$attempt.deviceId; revision=3; mode='exam'; examId=$attempt.examId }
        Result=[pscustomobject]@{
            revision=3; mode='exam'; examId=$attempt.examId; outcome='source-applied'
            reason='machine-policies-only'; fullReady=$false; observedUtc='2026-11-24T10:01:00.000Z'
        }
        LastConfirmed=$null; LocalGeneration=$null; StoppedExamId=$null; AwaitingBaseline=$false; LocalNormal=$null
    }
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $context.StatePath
    $stopWhen = { param($Current) Get-ExamLabFileTraceStopReason $Current }
    $reason = & $callbackFile -StopWhen $stopWhen -StopContext $context
    if ($reason) { throw "Обратный вызов из сценария записи потерял действующий Guest: $reason" }
    $state.StoppedExamId = $attempt.examId
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $context.StatePath
    $reason = & $callbackFile -StopWhen $stopWhen -StopContext $context
    if ($reason -cne 'assignment-ended') { throw "Обратный вызов пропустил остановку назначения: $reason" }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
}

$script:authorizedExam = 'file-trace-selected'
$script:calls = [Collections.Generic.List[string]]::new()
function Test-ExamLabFileTraceAuthorization([string]$ExamId, [string]$Path) {
    $script:calls.Add('authorization')
    return $ExamId -ceq $script:authorizedExam
}
function Assert-SafePath([string]$Path) { throw "Неожиданный доступ к пути $Path." }

$guest = [pscustomobject]@{ machineReady = $true; revision = 1; guestSessionId = ('a' * 64) }
$observation = [pscustomobject]@{ Readiness = $guest }
$assignment = [pscustomobject]@{ mode = 'normal'; examId = $null; revision = 1 }
Invoke-ExamLabFileTraceAssignment $assignment $null $null $observation
$assignment.mode = 'exam'
$assignment.examId = 'regular-exam'
Invoke-ExamLabFileTraceAssignment $assignment $null $null $observation
if ($script:calls.Count) { throw 'Обычные назначения дошли до проверки разрешения трассы.' }

$assignment.examId = 'file-trace-other'
Invoke-ExamLabFileTraceAssignment $assignment $null $null $observation
$assignment.examId = $script:authorizedExam
$guest.revision = 2
Invoke-ExamLabFileTraceAssignment $assignment $null $null $observation
if (($script:calls -join ',') -cne 'authorization,authorization') {
    throw 'Решение о записи не проверило разрешение и текущую ревизию.'
}

$script:attempt = $null
$script:exportState = $null
function Read-ExamLabFileTraceAttempt { $script:attempt }
function Start-ExamLabFileTraceExport($State) {
    $script:calls.Add('export')
    $script:exportState = $State
}

$script:calls.Clear()
Complete-ExamLabFileTraceNormal $null
$script:attempt = [pscustomobject]@{ phase = 'pending' }
Complete-ExamLabFileTraceNormal $null
if ($script:calls.Count) { throw 'Normal начал экспорт до завершения записи.' }

$script:attempt.phase = 'finished'
$normal = [pscustomobject]@{ Result = 'normal-complete' }
Complete-ExamLabFileTraceNormal $normal
if (($script:calls -join ',') -cne 'export' -or $script:exportState -ne $normal) {
    throw 'Normal не передал своё состояние для экспорта завершённой трассы.'
}

'PASS: выбор назначения, привязка Guest из сценария записи и передача завершённой трассы на экспорт.'
