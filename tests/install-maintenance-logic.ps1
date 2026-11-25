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

    # Подменяется только классификация Guest. Результат её использования и файлы регистрации настоящие.
    $script:verifiedInactiveGuestSids = @()
    $script:guestIdentifyOnly = $false
    $script:guestPreviouslyPrepared = $false
    function Get-ExamLabGuestRosterEvidence([object[]]$LocalAccounts, [object[]]$OrdinaryAccounts,
        [switch]$IdentifyOnly, [switch]$PreviouslyPrepared) {
        $script:guestIdentifyOnly = [bool]$IdentifyOnly
        $script:guestPreviouslyPrepared = [bool]$PreviouslyPrepared
        $declared = @($OrdinaryAccounts | ForEach-Object Sid)
        foreach ($candidate in $LocalAccounts) {
            if ($candidate.Name -like 'shpctac*' -and $candidate.Sid.Value -notin $declared) {
                [pscustomobject]@{
                    Sid=$candidate.Sid.Value
                    VerifiedInactive=(-not $IdentifyOnly -and $candidate.Sid.Value -in $script:verifiedInactiveGuestSids)
                }
            }
        }
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
    $guest1 = [pscustomobject]@{ Sid=[pscustomobject]@{ Value='S-1-5-21-1-2-3-1003' }; Name='shpctac012ab'; Enabled=$false }
    $guest2 = [pscustomobject]@{ Sid=[pscustomobject]@{ Value='S-1-5-21-1-2-3-1004' }; Name='shpctac012ac'; Enabled=$false }
    $script:fakeUsers = @($ordinary, $placeholder, $guest1)
    $script:verifiedInactiveGuestSids = @($guest1.Sid.Value)
    $firstGuestRejected = $false
    try { $null = Get-ExamLabEnrollmentRoster }
    catch { $firstGuestRejected = $_.Exception.Message -like '*First ExamLab enrollment*Shared PC account*' }
    Assert-Expected ($firstGuestRejected -and $script:guestIdentifyOnly -and -not $script:guestPreviouslyPrepared -and
        -not (Test-Path -LiteralPath $stateDirectory)) $true `
        'отказа первой регистрации при незакреплённом кандидате Guest без записи реестра регистрации'
    $script:fakeUsers = @($ordinary, $placeholder)
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
    $ledgerHash = (Get-FileHash -LiteralPath $script:ledgerPath).Hash
    $savedEnrollment = Read-ExamLabEnrollmentRecord $stateDirectory $enrollmentUrl
    Assert-Expected (Test-ExamLabPreviouslyPreparedEnrollment $savedEnrollment $script:pollUrl) $false 'отсутствия state proof'
    $installedConfiguration = Join-Path $examLabStatePath 'pc.json'
    $modePath = Join-Path $examLabStatePath 'mode.json'
    [IO.File]::Copy($repeat.ComputerConfigPath, $installedConfiguration)
    $metadata = [ordered]@{ Prepared=$true; Revision=('F' * 64); LastCompletedMode='normal' }
    Write-ExamLabMaintenanceJson $modePath $metadata
    Assert-Expected (Test-ExamLabPreviouslyPreparedEnrollment $savedEnrollment $script:pollUrl) $false 'несовпадающего SHA-256 pc.json'
    $metadata.Revision = $computerHash
    Write-ExamLabMaintenanceJson $modePath $metadata
    $previouslyPrepared = Test-ExamLabPreviouslyPreparedEnrollment $savedEnrollment $script:pollUrl
    Assert-Expected $previouslyPrepared $true 'валидного receipt и подтверждённого прежнего prepare'
    $metadata.LastCompletedMode = 'exam'
    Write-ExamLabMaintenanceJson $modePath $metadata
    Assert-Expected (Test-ExamLabPreviouslyPreparedEnrollment $savedEnrollment $script:pollUrl) $true 'прежнего prepare при сохранённом режиме exam'
    $metadata.LastCompletedMode = 'normal'
    Write-ExamLabMaintenanceJson $modePath $metadata
    $invalidReceipt = [pscustomobject]@{ receipt=$null; ordinaryAccounts=$savedEnrollment.ordinaryAccounts }
    Assert-Expected (Test-ExamLabPreviouslyPreparedEnrollment $invalidReceipt $script:pollUrl) $false 'отсутствия receipt'
    $modifiedConfig = Read-ExamLabProtectedJson $installedConfiguration
    $modifiedConfig.OrdinaryAccounts[0].Name = 'Чужой список'
    Write-ExamLabMaintenanceJson $installedConfiguration $modifiedConfig
    $metadata.Revision = (Get-FileHash -LiteralPath $installedConfiguration).Hash
    Write-ExamLabMaintenanceJson $modePath $metadata
    Assert-Expected (Test-ExamLabPreviouslyPreparedEnrollment $savedEnrollment $script:pollUrl) $false 'несовпадающего roster с правильным SHA-256'
    [IO.File]::Copy($repeat.ComputerConfigPath, $installedConfiguration, $true)
    $metadata.Revision = $computerHash
    Write-ExamLabMaintenanceJson $modePath $metadata
    $script:fakeUsers = @($ordinary, $placeholder, $guest1, $guest2)
    $script:verifiedInactiveGuestSids = @($guest1.Sid.Value, $guest2.Sid.Value)
    $verifiedRoster = @(Get-ExamLabEnrollmentRoster -SavedOrdinaryAccounts $savedEnrollment.ordinaryAccounts `
        -PreviouslyPrepared:$previouslyPrepared)
    $repeatWithGuests = Get-ExamLabEnrollmentInputs $stateDirectory $enrollmentUrl $script:pollUrl $verifiedRoster
    Assert-Expected (-not $script:guestIdentifyOnly -and $script:guestPreviouslyPrepared -and $verifiedRoster.Count -eq 2 -and
        $script:postClaims.Count -eq 2 -and (Get-FileHash -LiteralPath $script:ledgerPath).Hash -ceq $ledgerHash -and
        (Get-FileHash -LiteralPath $repeatWithGuests.ComputerConfigPath).Hash -ceq $computerHash) $true `
        'повтора с подтверждёнными Guest и сохранения реестра регистрации и pc.json'

    $script:verifiedInactiveGuestSids = @($guest1.Sid.Value)
    $unknownRejected = $false
    try { $null = Get-ExamLabEnrollmentRoster -SavedOrdinaryAccounts $savedEnrollment.ordinaryAccounts }
    catch { $unknownRejected = $_.Exception.Message -like '*1004*could not be verified as inactive*' }
    Assert-Expected $unknownRejected $true 'отказа при неподтверждённом Guest'

    $renamedOrdinary = [pscustomobject]@{ Sid=$ordinary.Sid; Name='Переименованный пользователь'; Enabled=$false }
    $script:fakeUsers = @($renamedOrdinary, $placeholder, $guest1)
    $renamedRejected = $false
    try { $null = Get-ExamLabEnrollmentRoster -SavedOrdinaryAccounts $savedEnrollment.ordinaryAccounts }
    catch { $renamedRejected = $_.Exception.Message -like '*differ from the saved ExamLab roster*' }
    Assert-Expected $renamedRejected $true 'отказа при переименованной обычной учётке до регистрации'
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
