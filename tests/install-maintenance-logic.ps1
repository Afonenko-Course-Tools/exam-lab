# Проверки алгоритма. PowerShell на Linux не подменяет испытание Windows.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$core = Join-Path $PSScriptRoot '..\setup\ExamLabMaintenance.Core.ps1'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($core, [ref]$null, [ref]$errors)
if ($errors.Count) { throw 'Ошибка синтаксиса ExamLabMaintenance.Core.ps1.' }
foreach ($functionName in 'Test-ExamLabStoppedAssignment','Write-ExamLabMaintenanceJson','Read-ExamLabProtectedJson') {
    $function = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true)
    . ([ScriptBlock]::Create($function.Extent.Text))
}

function Assert-Expected([bool]$Actual, [bool]$Expected, [string]$Case) {
    if ($Actual -ne $Expected) { throw "Неверный результат для $Case." }
}

$state = [pscustomobject]@{
    Assignment = $null
    Result = $null
    StoppedExamId = $null
    LocalNormal = $null
}
Assert-Expected (Test-ExamLabStoppedAssignment $null) $false 'пустого файла'
Assert-Expected (Test-ExamLabStoppedAssignment ([pscustomobject]@{})) $false 'неизвестной схемы'
Assert-Expected (Test-ExamLabStoppedAssignment $state) $true 'новой регистрации'
$state.Assignment = [pscustomobject]@{ mode = 'exam'; examId = 'current' }
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'назначенного экзамена'
$state.StoppedExamId = 'previous'
$state.LocalNormal = [pscustomobject]@{ SourceCleanupCompleted = $true; BaselineUnknown = $false }
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'предыдущего normal'
$state.StoppedExamId = 'current'
$state.LocalNormal.BaselineUnknown = $true
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'неизвестного назначения при normal'
$state.LocalNormal.BaselineUnknown = $false
$state.LocalNormal.SourceCleanupCompleted = 'true'
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'повреждённой отметки normal'
$state.LocalNormal.SourceCleanupCompleted = $true
Assert-Expected (Test-ExamLabStoppedAssignment $state) $true 'подтверждённого normal'
$state.Result = [pscustomobject]@{ reason = 'local-normal-collection-stop-failed' }
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'ошибки остановки сбора'
$state.Assignment.mode = 'normal'
Assert-Expected (Test-ExamLabStoppedAssignment $state) $true 'обычного назначения'
$state.Assignment.mode = 'unknown'
Assert-Expected (Test-ExamLabStoppedAssignment $state) $false 'неизвестного режима'

$path = Join-Path $PSScriptRoot '..\setup\Install-FromHttps.ps1.in'
$enrollment = Join-Path $PSScriptRoot '..\setup\ExamLabEnrollment.ps1'
$rendered = [IO.File]::ReadAllText($path).Replace('@MAINTENANCE_CORE@', [IO.File]::ReadAllText($core)).
    Replace('@ENROLLMENT_CORE@', [IO.File]::ReadAllText($enrollment)).Replace('@TOOLS_SHA256@', '@{}')
$null = [Management.Automation.Language.Parser]::ParseInput($rendered, [ref]$null, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
'PASS: защитный переход и синтаксис шаблона установки.'

# Имитируется обрыв после принятого запроса. Проверяется настоящий формат файлов,
# ACL и сеть Windows в этом тесте не используются.
. $enrollment
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-enroll-test-' + [guid]::NewGuid().ToString('N'))
$previousFiles = $env:ProgramFiles
$previousData = $env:ProgramData
try {
    [void][IO.Directory]::CreateDirectory($temporary)
    $env:ProgramFiles = $env:ProgramData = $temporary
    Import-Module (Join-Path $PSScriptRoot '..\windows\ExamNetwork.psm1') -Scope Local -Force
    function Assert-ExamLabProtectedPath([string]$Path) { if (-not (Test-Path -LiteralPath $Path)) { throw 'Путь отсутствует.' } }
    function New-ExamLabPrivateDirectory([string]$Path) { [void][IO.Directory]::CreateDirectory($Path) }
    function Get-LocalUser { $script:fakeUsers }
    function Get-ExamLabSetupAccountIssue([object[]]$LocalAccounts) {
        $script:checkedSetupUsers = $LocalAccounts
        return $script:setupAccountIssue
    }

    $ordinary = [pscustomobject]@{ Sid=[pscustomobject]@{ Value='S-1-5-21-1-2-3-1001' }; Name='Обычный пользователь'; Enabled=$false }
    $placeholder = [pscustomobject]@{ Sid=[pscustomobject]@{ Value='S-1-5-21-1-2-3-1002' }; Name='defaultuser0'; Enabled=$false }
    $script:fakeUsers = @($ordinary, $placeholder)
    $script:setupAccountIssue = 'Тестовый отказ Windows Setup для defaultuser0.'
    $blocked = $false
    try { $null = Get-ExamLabEnrollmentRoster } catch { $blocked = $_.Exception.Message -ceq $script:setupAccountIssue }
    Assert-Expected $blocked $true 'незавершённой подготовки Windows'
    Assert-Expected ($script:checkedSetupUsers.Count -eq 2) $true 'проверки текущего SAM'
    $script:setupAccountIssue = $null
    $script:fakeUsers = @($placeholder)
    $blocked = $false
    try { $null = Get-ExamLabEnrollmentRoster }
    catch { $blocked = $_.Exception.Message -ceq 'Windows has no ordinary local user accounts for ExamLab.' }
    Assert-Expected $blocked $true 'отсутствия обычной учётки при одном defaultuser0'
    $script:fakeUsers = @($ordinary, $placeholder)
    $roster = @(Get-ExamLabEnrollmentRoster)
    Assert-Expected ($roster.Count -eq 2 -and $roster[0].Name -ceq $ordinary.Name -and
        $roster[1].Name -ceq $placeholder.Name -and $roster[1].Sid -ceq $placeholder.Sid.Value) $true 'сохранения обеих отключённых учёток'

    $examLabStatePath = $temporary
    $stateDirectory = Join-Path $temporary 'Enrollment'
    $script:ledgerPath = Join-Path $stateDirectory 'enrollment.json'
    $script:postClaims = [Collections.Generic.List[string]]::new()
    $script:pollUrl = 'https://192.0.2.10:21650/exam/v1/poll'
    $enrollmentUrl = 'https://192.0.2.10:21650/install/enroll'
    function Request-ExamLabEnrollment($Url, [string]$Claim) {
        $persisted = Read-ExamLabProtectedJson $script:ledgerPath
        if ($persisted.claim -cne $Claim -or $Claim -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Claim должен быть сохранён до запроса.'
        }
        $script:postClaims.Add($Claim)
        if ($script:postClaims.Count -eq 1) { throw 'Имитированный обрыв ответа.' }
        [pscustomobject]@{
            network = [pscustomobject]@{
                ProxyEndpointIP='192.0.2.10'; ProxyEndpointPort=3128; TechnicalAccess=@()
                ControllerEndpoint=[pscustomobject]@{ IP='192.0.2.10'; Port=21650 }
                WazuhEndpoint=[pscustomobject]@{ IP='192.0.2.10'; Port=1514 }
            }
            registration = [pscustomobject]@{ url=$script:pollUrl; deviceId='fixture-seat'; token=('T' * 43) }
            wazuhKey = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('007 fixture-seat any ' + ('F' * 64))))
        }
    }
    $interrupted = $false
    try { $null = Get-ExamLabEnrollmentInputs $stateDirectory $enrollmentUrl $script:pollUrl $roster }
    catch { $interrupted = $_.Exception.Message -ceq 'Имитированный обрыв ответа.' }
    Assert-Expected $interrupted $true 'оборванного ответа'
    $resumed = Get-ExamLabEnrollmentInputs $stateDirectory $enrollmentUrl $script:pollUrl $roster
    $computerHash = (Get-FileHash -LiteralPath $resumed.ComputerConfigPath).Hash
    [IO.File]::Delete($resumed.RegistrationPath)
    $repeat = Get-ExamLabEnrollmentInputs $stateDirectory $enrollmentUrl $script:pollUrl $roster
    Assert-Expected ($script:postClaims.Count -eq 2 -and $script:postClaims[0] -ceq $script:postClaims[1]) $true 'повтора по тому же claim и локального повтора'
    Assert-Expected ((Test-Path -LiteralPath $repeat.RegistrationPath) -and
        (Get-FileHash -LiteralPath $repeat.ComputerConfigPath).Hash -ceq $computerHash) $true 'восстановления локального входного файла'
    $configuration = Read-ExamLabProtectedJson $repeat.ComputerConfigPath
    Assert-Expected ($configuration.OrdinaryAccounts.Count -eq 2 -and
        $configuration.OrdinaryAccounts[1].Sid -ceq $placeholder.Sid.Value) $true 'сохранения SID defaultuser0 в pc.json'
    $script:fakeUsers = @($ordinary)
    $changedRoster = @(Get-ExamLabEnrollmentRoster)
    $driftRejected = $false
    try { $null = Get-ExamLabEnrollmentInputs $stateDirectory $enrollmentUrl $script:pollUrl $changedRoster }
    catch { $driftRejected = $_.Exception.Message -like '*differ from the saved ExamLab roster*' }
    Assert-Expected $driftRejected $true 'административной проверки после исчезновения сохранённого SID'
    'PASS: переносимая логика регистрации и безопасного повтора ExamLab.'
} finally {
    $env:ProgramFiles = $previousFiles
    $env:ProgramData = $previousData
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
