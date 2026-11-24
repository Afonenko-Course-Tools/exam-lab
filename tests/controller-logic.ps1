# Переносимая проверка формата и сохранённого состояния, без вызовов Windows API.
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\windows\ExamLab.Controller.psm1') -Force

function Assert-Rejected([string]$Name,[scriptblock]$Operation) {
    $rejected=$false
    try { & $Operation | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw "FAIL: $Name" }
    "PASS: $Name"
}

$exam='{"deviceId":"lab-01","revision":2,"mode":"exam","examId":"Run-A"}'
$assignment=ConvertTo-ControllerAssignment $exam 'lab-01'
$normal=ConvertTo-ControllerAssignment '{"deviceId":"lab-01","revision":3,"mode":"normal","examId":null}' 'lab-01'
if ($assignment.revision -ne 2 -or $assignment.examId -cne 'Run-A' -or $null -ne $normal.examId) { throw 'FAIL: корректные ответы' }
Assert-Rejected 'повторяющийся JSON-ключ' { ConvertTo-ControllerAssignment ($exam.Replace('"revision":2','"revision":1,"revision":2')) 'lab-01' }
Assert-Rejected 'запятая после последнего значения' { ConvertTo-ControllerAssignment ($exam.TrimEnd('}')+',}') 'lab-01' }
Assert-Rejected 'массив вместо объекта' { ConvertTo-ControllerAssignment "[$exam]" 'lab-01' }
Assert-Rejected 'другой регистр идентификатора ПК' { ConvertTo-ControllerAssignment $exam 'LAB-01' }
Assert-Rejected 'строка на месте целой ревизии' { ConvertTo-ControllerAssignment ($exam.Replace(':2,',':"2",')) 'lab-01' }
Assert-Rejected 'дробная ревизия' { ConvertTo-ControllerAssignment ($exam.Replace(':2,',':2.0,')) 'lab-01' }
Assert-Rejected 'слишком большая ревизия' { ConvertTo-ControllerAssignment ($exam.Replace(':2,',':2147483648,')) 'lab-01' }
Assert-Rejected 'неизвестное поле ответа' { ConvertTo-ControllerAssignment ($exam.Replace('"examId"','"script":"powershell","examId"')) 'lab-01' }
Assert-Rejected 'нижняя ревизия после нового назначения' { Compare-ControllerAssignment $assignment $normal }
Assert-Rejected 'другой examId на той же ревизии' {
    Compare-ControllerAssignment (ConvertTo-ControllerAssignment ($exam.Replace('Run-A','run-a')) 'lab-01') $assignment
}
if ((Compare-ControllerAssignment $assignment $assignment) -cne 'repeat' -or
    (Compare-ControllerAssignment $normal $assignment) -cne 'new') { throw 'FAIL: повтор и новая ревизия' }

$legacy = ConvertFrom-ControllerResponse $exam 'lab-01'
if ($legacy.Assignment.revision -ne 2 -or $legacy.AlertAcknowledgement) { throw 'FAIL: ответ прежнего контроллера' }
$expires = [DateTime]::UtcNow.AddSeconds(35).ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
$sessionHash = 'a' * 64
$ack = '{"alertId":"11111111-1111-4111-8111-111111111111","acknowledgementId":"22222222-2222-4222-8222-222222222222",' +
    '"revision":2,"bootUtc":"2026-11-19T14:00:00.123Z","guestSessionId":"' + $sessionHash +
    '","owner":"examowner","expiresUtc":"' + $expires + '"}'
$envelope = $exam.TrimEnd('}') + ',"alertAcknowledgement":' + $ack + '}'
$parsed = ConvertFrom-ControllerResponse $envelope 'lab-01'
if ($parsed.Assignment.mode -cne 'exam' -or $parsed.Assignment.PSObject.Properties['alertAcknowledgement'] -or
    $parsed.AlertAcknowledgement.guestSessionId -cne $sessionHash -or $parsed.AlertAcknowledgement.owner -cne 'examowner') {
    throw 'FAIL: отдельное типизированное снятие тревоги'
}
Assert-Rejected 'повтор поля владельца в снятии' {
    ConvertFrom-ControllerResponse ($envelope.Replace('"owner":', '"owner":"other", "owner":')) 'lab-01'
}
Assert-Rejected 'неизвестное поле команды снятия' {
    ConvertFrom-ControllerResponse ($envelope.Replace('"owner":', '"command":"script", "owner":')) 'lab-01'
}
Assert-Rejected 'назначение и снятие относятся к разным ревизиям' {
    ConvertFrom-ControllerResponse ($envelope.Replace('"revision":2,"bootUtc"', '"revision":3,"bootUtc"')) 'lab-01'
}
Assert-Rejected 'запятая в объекте команды снятия' {
    ConvertFrom-ControllerResponse ($envelope.Insert($envelope.Length - 2, ',')) 'lab-01'
}

$boot='2026-11-19T14:00:00.123Z'
$session=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=[uint32]1;AuthenticationId=[long]1234}
$token='a'*43
$id=Get-ControllerGuestSessionId $token $boot $session
if ($id -cnotmatch '\A[a-f0-9]{64}\z' -or $id -cne (Get-ControllerGuestSessionId $token $boot $session) -or
    $id -ceq (Get-ControllerGuestSessionId ('b'*43) $boot $session) -or
    $id -ceq (Get-ControllerGuestSessionId $token '2026-11-19T15:00:00.123Z' $session)) {
    throw 'FAIL: идентификатор Guest привязан к регистрации и загрузке'
}
$session.AuthenticationId=[long]1235
if ($id -ceq (Get-ControllerGuestSessionId $token $boot $session)) { throw 'FAIL: идентификатор повторился после смены входа' }
'PASS: непрозрачный идентификатор Guest меняется с регистрацией, загрузкой и входом'

$temporary=Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-controller-'+[Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $registration=Join-Path $temporary 'enrollment.json'
    $validRegistration='{"url":"https://controller.test:21650/exam/v1/poll","deviceId":"lab-01","token":"'+$token+'"}'
    [IO.File]::WriteAllText($registration,$validRegistration)
    if ((Read-ControllerConfiguration $registration).deviceId -cne 'lab-01') { throw 'FAIL: файл регистрации' }
    [IO.File]::WriteAllText($registration,$validRegistration.Replace('"url"','"url":"https://other.test/exam/v1/poll","url"'))
    Assert-Rejected 'двусмысленный адрес в приватной регистрации' { Read-ControllerConfiguration $registration }
    [IO.File]::WriteAllText($registration,($validRegistration.TrimEnd('}')+',}'))
    Assert-Rejected 'лишняя запятая в приватной регистрации' { Read-ControllerConfiguration $registration }
    $path=Join-Path $temporary 'controller-state.json'
    $state=Read-ControllerState $path
    if ($null -ne $state.Assignment -or $null -ne $state.Result) { throw 'FAIL: начальное состояние' }
    $state.Assignment=$assignment
    $state.LocalGeneration=[Guid]::NewGuid().ToString('N')
    $state.StoppedExamId=$assignment.examId
    $state.LocalNormal=[pscustomobject]@{SourceCleanupCompleted=$true;EffectiveMode='Unconfirmed';ObservedUtc=(Get-ControllerUtc);BaselineUnknown=$false}
    Set-ControllerResult $state 'overridden' 'local-normal' $false
    Write-ControllerJson $path $state
    Write-ControllerJson $path (Read-ControllerState $path 'lab-01')
    $result=Read-ControllerState $path 'lab-01'
    if ($result.LocalGeneration -cne $state.LocalGeneration -or $result.StoppedExamId -cne 'Run-A' -or
        $result.Result.outcome -cne 'overridden' -or $result.LastConfirmed) { throw 'FAIL: отмена после перечитывания' }
    'PASS: запись и замена сохраняют отмену, не подтверждая эффективный режим'
    Assert-Rejected 'состояние другого ПК' { Read-ControllerState $path 'lab-02' }
    $state.AwaitingBaseline='false'
    Write-ControllerJson $path $state
    Assert-Rejected 'некорректная форма предыдущего состояния' { Read-ControllerState $path 'lab-01' }
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
