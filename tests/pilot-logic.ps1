# Только переносимая валидация/ранний отказ. Windows API не подменяются.
$ErrorActionPreference='Stop'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-logic-'+[Guid]::NewGuid().ToString('N'))
$previousFiles=$env:ProgramFiles; $previousData=$env:ProgramData
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $env:ProgramFiles=$temporary; $env:ProgramData=$temporary
    $module=Import-Module (Join-Path $PSScriptRoot '..\windows\ExamLab.psm1') -Force -PassThru
    function Test-Config([string]$Name,[string]$Json,[bool]$Expected) {
        $passed=$false
        try { & $module {param($c) Test-DeclaredConfig $c} ($Json|ConvertFrom-Json) | Out-Null; $passed=$true } catch {}
        if ($passed -ne $Expected) { throw "FAIL $Name" }; "PASS $Name"
    }
    $valid='{"OrdinaryAccounts":[{"Sid":"S-1-5-21-1-2-3-1001","Name":"Обычный студент"}]}'
    Test-Config 'явный SID/Unicode name' $valid $true
    Test-Config 'нет списка' '{}' $false
    Test-Config 'пустой список' '{"OrdinaryAccounts":[]}' $false
    Test-Config 'scalar вместо списка' '{"OrdinaryAccounts":{"Sid":"S-1-5-21-1-2-3-1001","Name":"student"}}' $false
    Test-Config 'лишняя настройка' ($valid.Replace(']}','],"Firewall":true}')) $false
    Test-Config 'не локальный SID' ($valid.Replace('S-1-5-21-1-2-3-1001','S-1-5-18')) $false
    Test-Config 'пустое имя' ($valid.Replace('Обычный студент','')) $false
    Test-Config 'имя другого типа' ($valid.Replace('"Обычный студент"','123')) $false
    Test-Config 'лишнее поле account' ($valid.Replace('"Обычный студент"','"Обычный студент","Enabled":true')) $false
    Test-Config 'повтор SID' '{"OrdinaryAccounts":[{"Sid":"S-1-5-21-1-2-3-1001","Name":"a"},{"Sid":"S-1-5-21-1-2-3-1001","Name":"b"}]}' $false
    Test-Config 'повтор Windows name без учёта регистра' '{"OrdinaryAccounts":[{"Sid":"S-1-5-21-1-2-3-1001","Name":"a"},{"Sid":"S-1-5-21-1-2-3-1002","Name":"A"}]}' $false
    $unset=[pscustomobject]@{EnableSharedPCMode=$null;EnableAccountManager=$null;AccountModel=$null;DeletionPolicy=$null;SetEduPolicies=$null;SetPowerPolicies=$null;RestrictLocalStorage=$null}
    if (-not (& $module {param($s) Test-SharedPCUnset $s} $unset)) { throw 'FAIL all-null SharedPC должен быть unset.' }
    $unset.DeletionPolicy=0
    if (& $module {param($s) Test-SharedPCUnset $s} $unset) { throw 'FAIL configured DeletionPolicy=0 не является unset.' }
    $unset.DeletionPolicy=$null; $unset.EnableSharedPCMode=$false
    if (& $module {param($s) Test-SharedPCUnset $s} $unset) { throw 'FAIL configured EnableSharedPCMode=false не является unset.' }
    'PASS SharedPC unset: all-null принят, configured 0/false отклонены без default/coercion'
    $blocked=$false
    try { Set-ExamLabMode -Mode exam } catch { $blocked=$_.Exception.Message -like 'Экзамен заблокирован*' }
    if (-not $blocked -or @(Get-ChildItem -LiteralPath $temporary).Count) { throw 'FAIL exam должен отказать до platform/config/files.' }
    'PASS exam: ранний явный отказ до platform/config/files'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\windows\ExamLab.psm1'),[ref]$tokens,[ref]$errors)
    $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    $exceptions=@($ast.FindAll({param($n)
        $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Read-Context' -and
        @($n.CommandElements | Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'AllowUnlistedOnlyForNormal'}).Count -gt 0
    },$true))
    if ($exceptions.Count -ne 1) { throw 'FAIL unlisted SID exception должен иметь ровно один call site.' }
    $caller=$exceptions[0].Parent
    while ($caller -and $caller -isnot [Management.Automation.Language.FunctionDefinitionAst]) { $caller=$caller.Parent }
    if (-not $caller -or $caller.Name -ne 'Set-ExamLabMode') { throw 'FAIL prepare/check не могут обходить strict roster.' }
    'PASS roster exception: только normal route; exam проверен ранним отказом'
    foreach($name in @('netsh.exe','reg.exe','secedit.exe','Disable-NetFirewallRule','Set-NetFirewallProfile','Set-Acl','Save-Baseline','Restore-Baseline','New-CimInstance')) {
        if($name -in $commands){throw "FAIL global mutation/restore остался: $name"}
    }
    'PASS public module: global restore/FW/ACL reset/CSP root create calls отсутствуют'
    'Windows SharedPC/USB/filesystem/network НЕ испытывались.'
} finally {
    Remove-Module ExamLab -ErrorAction SilentlyContinue
    $env:ProgramFiles=$previousFiles; $env:ProgramData=$previousData
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
