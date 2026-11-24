#Requires -Version 7.6
# Проверка маршрутизации вызовов. WPR, Win32 и экспорт на Windows не испытываются.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:CodeRoot = $PSScriptRoot
$script:DataRoot = $PSScriptRoot
$script:ControllerStateFile = 'unused'
Import-Module (Join-Path $PSScriptRoot '../windows/ExamLab.Controller.psm1')
. (Join-Path $PSScriptRoot '../windows/trace/ExamLab.FileTrace.ps1')

$script:authorizedExam = 'file-trace-selected'
$script:calls = [Collections.Generic.List[string]]::new()
function Test-ExamLabFileTraceAuthorization([string]$ExamId) {
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

'PASS: выбор назначения файловой записи и передача завершённой трассы на экспорт.'
