# Только переносимая валидация/ранний отказ. Windows API не подменяются.
$ErrorActionPreference='Stop'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-logic-'+[Guid]::NewGuid().ToString('N'))
$previousFiles=$env:ProgramFiles; $previousData=$env:ProgramData
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $env:ProgramFiles=$temporary; $env:ProgramData=$temporary
    Import-Module (Join-Path $PSScriptRoot '..\windows\ExamNetwork.psm1') -Force
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
    $network=',"Network":{"ProxyEndpointIP":"192.0.2.10","ProxyEndpointPort":3128,"TechnicalAccess":[]}'
    $withNetwork=$valid.Substring(0,$valid.Length-1)+$network+'}'
    Test-Config 'optional Network literal IPv4/empty technical access' $withNetwork $true
    Test-Config 'Network hostname refused' ($withNetwork.Replace('192.0.2.10','proxy.example')) $false
    Test-Config 'Network loopback refused' ($withNetwork.Replace('192.0.2.10','127.0.0.1')) $false
    Test-Config 'Network shorthand IP refused' ($withNetwork.Replace('192.0.2.10','127.1')) $false
    Test-Config 'Network explicit null refused' ($valid.Substring(0,$valid.Length-1)+',"Network":null}') $false
    Test-Config 'Network port string refused' ($withNetwork.Replace(':3128',':"3128"')) $false
    Test-Config 'Network invalid port refused' ($withNetwork.Replace(':3128',':65536')) $false
    Test-Config 'TechnicalAccess explicit address/local port' ($withNetwork.Replace('[]','[{"RemoteIP":"192.0.2.20","LocalPort":5985}]')) $true
    Test-Config 'TechnicalAccess arbitrary direction refused' ($withNetwork.Replace('[]','[{"RemoteIP":"192.0.2.20","LocalPort":5985,"Direction":"Inbound"}]')) $false
    Test-Config 'TechnicalAccess duplicate refused' ($withNetwork.Replace('[]','[{"RemoteIP":"192.0.2.20","LocalPort":5985},{"RemoteIP":"192.0.2.20","LocalPort":5985}]')) $false
    # Чистые входные данные classifier, не подмена Get-LocalUser/Windows API.
    function New-AccountData([string]$Sid,[string]$Name) {
        [pscustomobject]@{SID=[pscustomobject]@{Value=$Sid}; Name=$Name}
    }
    $rosterConfig=$valid | ConvertFrom-Json
    $student=New-AccountData 'S-1-5-21-1-2-3-1001' 'Обычный студент'
    $builtin=New-AccountData 'S-1-5-21-1-2-3-500' 'Administrator'
    function Test-RosterCase([string]$Name,[object[]]$Actual,[int]$Missing,[int]$Renamed,[int]$Unlisted) {
        $before=@($rosterConfig,$Actual) | ConvertTo-Json -Depth 5 -Compress
        $result=& $module {param($c,$a) Test-LiveRoster $c $a -AllowDrift} $rosterConfig $Actual
        $drift=($Missing+$Renamed+$Unlisted) -gt 0
        if ($result.IdentityUnconfirmed -ne $drift -or @($result.MissingAccounts).Count -ne $Missing -or
            @($result.RenamedAccounts).Count -ne $Renamed -or @($result.UnlistedAccounts).Count -ne $Unlisted) { throw "FAIL normal roster: $Name" }
        foreach ($account in @($result.MissingAccounts)+@($result.RenamedAccounts)) {
            if ($account.Sid -cne $student.SID.Value -or $account.DeclaredName -cne $student.Name) { throw "FAIL declared identity: $Name" }
        }
        foreach ($account in @($result.RenamedAccounts)) {
            if ($account.ActualName -cne @($Actual | Where-Object {$_.SID.Value -ceq $student.SID.Value})[0].Name) { throw "FAIL renamed actual name: $Name" }
        }
        $rejected=$false
        try { & $module {param($c,$a) Test-LiveRoster $c $a} $rosterConfig $Actual | Out-Null }
        catch { if ($_.Exception.Message -notlike 'Локальный roster изменён*') { throw }; $rejected=$true }
        if ($rejected -ne $drift) { throw "FAIL strict roster: $Name" }
        if ((@($rosterConfig,$Actual) | ConvertTo-Json -Depth 5 -Compress) -cne $before) { throw "FAIL roster inputs changed: $Name" }
        "PASS pure roster strict/normal: $Name"
    }
    Test-RosterCase 'совпадающий SID/Name и builtin' @($student,$builtin) 0 0 0
    Test-RosterCase 'отсутствующий declared SID' @($builtin) 1 0 0
    Test-RosterCase 'переименование того же SID' @((New-AccountData $student.SID.Value 'new-name')) 0 1 0
    Test-RosterCase 'смена только регистра имени' @((New-AccountData $student.SID.Value 'обычный студент')) 0 1 0
    Test-RosterCase 'новый неописанный SID' @($student,(New-AccountData 'S-1-5-21-1-2-3-1002' 'new-user')) 0 0 1
    Test-RosterCase 'старое имя у нового SID не подменяет declared SID' @((New-AccountData 'S-1-5-21-1-2-3-1002' $student.Name)) 1 0 1
    Test-RosterCase 'успешно прочитанный пустой список' @() 1 0 0
    $unset=[pscustomobject]@{EnableSharedPCMode=$null;EnableAccountManager=$null;AccountModel=$null;DeletionPolicy=$null;SetEduPolicies=$null;SetPowerPolicies=$null;RestrictLocalStorage=$null}
    if (-not (& $module {param($s) Test-SharedPCUnset $s} $unset)) { throw 'FAIL all-null SharedPC должен быть unset.' }
    $unset.DeletionPolicy=0
    if (& $module {param($s) Test-SharedPCUnset $s} $unset) { throw 'FAIL configured DeletionPolicy=0 не является unset.' }
    $unset.DeletionPolicy=$null; $unset.EnableSharedPCMode=$false
    if (& $module {param($s) Test-SharedPCUnset $s} $unset) { throw 'FAIL configured EnableSharedPCMode=false не является unset.' }
    'PASS SharedPC unset: all-null принят, configured 0/false отклонены без default/coercion'
    $target=[pscustomobject]@{State='Observed';Instance=[pscustomobject]@{EnableSharedPCMode=$true;EnableAccountManager=$true;AccountModel=2;DeletionPolicy=0;SetEduPolicies=$false;SetPowerPolicies=$false;RestrictLocalStorage=$false}}
    if (-not (& $module {param($s) Test-SharedPCTarget $s} $target)) { throw 'FAIL explicit SharedPC target.' }
    $target.Instance.DeletionPolicy=$null
    if (& $module {param($s) Test-SharedPCTarget $s} $target) { throw 'FAIL target DeletionPolicy null не является выбранным0.' }
    'PASS SharedPC target: explicit0 принят, null не приводится к0'
    $missing=Join-Path $temporary 'missing.json'
    if (& $module {param($p) Test-ExistingFile $p} $missing) { throw 'FAIL missing file должен быть absent.' }
    $isDirectoryRejected=$false
    try { & $module {param($p) Test-ExistingFile $p} $temporary | Out-Null } catch { $isDirectoryRejected=$true }
    if (-not $isDirectoryRejected) { throw 'FAIL directory вместо файла должен отказать.' }
    'PASS safety file presence: absent только missing; directory отказан (ACL errors Windows не испытывались)'
    $blocked=$false
    try { Set-ExamLabMode -Mode exam } catch { $blocked=$_.Exception.Message -like 'Экзамен заблокирован*' }
    if (-not $blocked -or @(Get-ChildItem -LiteralPath $temporary).Count) { throw 'FAIL exam должен отказать до platform/config/files.' }
    'PASS exam: ранний явный отказ до platform/config/files'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\windows\ExamLab.psm1'),[ref]$tokens,[ref]$errors)
    $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    $exceptions=@($ast.FindAll({param($n)
        $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Read-Context' -and
        @($n.CommandElements | Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'AllowRosterDriftOnlyForNormal'}).Count -gt 0
    },$true))
    if ($exceptions.Count -ne 2) { throw 'FAIL roster drift exception должен иметь два вызова: до и после общего lock.' }
    foreach ($exception in $exceptions) {
    $caller=$exception.Parent
    while ($caller -and $caller -isnot [Management.Automation.Language.FunctionDefinitionAst]) { $caller=$caller.Parent }
    if (-not $caller -or $caller.Name -ne 'Set-ExamLabMode') { throw 'FAIL prepare/check не могут обходить strict roster.' }
    }
    'PASS roster exception: только normal route; exam проверен ранним отказом'
    foreach($name in @('netsh.exe','reg.exe','secedit.exe','Disable-NetFirewallRule','Set-NetFirewallProfile','Set-Acl','Save-Baseline','Restore-Baseline','New-CimInstance')) {
        if($name -in $commands){throw "FAIL global mutation/restore остался: $name"}
    }
    'PASS public module: global restore/FW/ACL reset/CSP root create calls отсутствуют'
    'Windows SharedPC/USB/filesystem/network НЕ испытывались.'
} finally {
    Remove-Module ExamLab -ErrorAction SilentlyContinue
    Remove-Module ExamNetwork -ErrorAction SilentlyContinue
    $env:ProgramFiles=$previousFiles; $env:ProgramData=$previousData
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
