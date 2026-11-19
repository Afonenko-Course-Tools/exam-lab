# Только переносимая валидация/ранний отказ. Windows API не подменяются.
$ErrorActionPreference='Stop'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-logic-'+[Guid]::NewGuid().ToString('N'))
$previousFiles=$env:ProgramFiles; $previousData=$env:ProgramData
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $env:ProgramFiles=$temporary; $env:ProgramData=$temporary
    $networkModule=Import-Module (Join-Path $PSScriptRoot '..\windows\ExamNetwork.psm1') -Force -PassThru
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
    $withDhcp=$withNetwork.Replace('"TechnicalAccess":[]','"TechnicalAccess":[],"DhcpServerIP":"192.0.2.30"')
    Test-Config 'Network with a unicast DHCP server' $withDhcp $true
    Test-Config 'Network broadcast DHCP server refused' ($withDhcp.Replace('192.0.2.30','255.255.255.255')) $false
    Test-Config 'Network hostname refused' ($withNetwork.Replace('192.0.2.10','proxy.example')) $false
    Test-Config 'Network loopback refused' ($withNetwork.Replace('192.0.2.10','127.0.0.1')) $false
    Test-Config 'Network shorthand IP refused' ($withNetwork.Replace('192.0.2.10','127.1')) $false
    Test-Config 'Network explicit null refused' ($valid.Substring(0,$valid.Length-1)+',"Network":null}') $false
    Test-Config 'Network port string refused' ($withNetwork.Replace(':3128',':"3128"')) $false
    Test-Config 'Network invalid port refused' ($withNetwork.Replace(':3128',':65536')) $false
    $controller='"ControllerEndpoint":{"IP":"192.0.2.10","Port":443}'
    $wazuh='"WazuhEndpoint":{"IP":"192.0.2.10","Port":1514}'
    $withServices=$withNetwork.Replace('"TechnicalAccess":[]',('"TechnicalAccess":[],'+$controller+','+$wazuh))
    Test-Config 'Network: один IP с тремя разными портами' $withServices $true
    Test-Config 'Network: необъявленное поле служебного адреса' ($withServices.Replace('"Port":443','"Port":443,"Program":"Any"')) $false
    Test-Config 'Network: служебный endpoint null' ($withServices.Replace($wazuh,'"WazuhEndpoint":null')) $false
    Test-Config 'Network: служебный endpoint без порта' ($withServices.Replace(',"Port":443','')) $false
    Test-Config 'Network: служебный endpoint с именем вместо IPv4' ($withServices.Replace('"IP":"192.0.2.10","Port":443','"IP":"controller.example","Port":443')) $false
    Test-Config 'Network: служебный endpoint с текстовым портом' ($withServices.Replace('"Port":1514','"Port":"1514"')) $false
    Test-Config 'Network: контроллер на открытом endpoint прокси' ($withServices.Replace('"Port":443','"Port":3128')) $false
    Test-Config 'Network: два служебных правила к одному endpoint' ($withServices.Replace('"Port":443','"Port":1514')) $false
    $serviceSpecs=@(& $networkModule {param($config) Get-NetSpecs $config} (($withServices | ConvertFrom-Json).Network))
    $proxySpec=$serviceSpecs | Where-Object Name -eq 'ExamLab.Network.Proxy.Out'
    $controllerSpec=$serviceSpecs | Where-Object Name -eq 'ExamLab.Network.Controller.Out'
    $wazuhSpec=$serviceSpecs | Where-Object Name -eq 'ExamLab.Network.Wazuh.Out'
    if ($serviceSpecs.Count -ne 3 -or $proxySpec.LocalUser -ne 'Any' -or
        $controllerSpec.LocalUser -cne 'D:(A;;CC;;;SY)' -or $controllerSpec.Program -notlike '*\WindowsPowerShell\v1.0\powershell.exe' -or
        $wazuhSpec.LocalUser -cne 'D:(A;;CC;;;SY)' -or $wazuhSpec.Program -notlike '*\ossec-agent\wazuh-agent.exe' -or $wazuhSpec.Service -ne 'Any' -or
        @($serviceSpecs | Where-Object {$_.Direction -ne 'Outbound' -or $_.Protocol -ne 'TCP' -or $_.RemoteAddress -ne '192.0.2.10'}).Count -or
        $controllerSpec.RemotePort -ne '443' -or $wazuhSpec.RemotePort -ne '1514') { throw 'FAIL точные исходящие правила контроллера и агента.' }
    'PASS Network: описание исходящих правил контроллера и Wazuh; фильтры Windows не испытывались.'
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
    # Source guards проверяются через AST, native observations Windows не подменяются.
    function Get-ParsedSource([string]$RelativePath) {
        $sourceTokens=$null; $sourceErrors=$null
        $sourceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $RelativePath),[ref]$sourceTokens,[ref]$sourceErrors)
        if ($sourceErrors.Count) { throw "FAIL parse $RelativePath" }
        $sourceAst
    }
    function Get-FunctionNode($SourceAst,[string]$Name) {
        $nodes=@($SourceAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true))
        if ($nodes.Count -ne 1) { throw "FAIL single function $Name" }
        $nodes[0]
    }
    function Get-CommandNodes($SourceAst,[string]$Name) {
        @($SourceAst.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Name},$true))
    }
    function Assert-CallBefore($SourceAst,[string]$Guard,[string[]]$Later) {
        $guardCalls=@(Get-CommandNodes $SourceAst $Guard)
        if ($guardCalls.Count -ne 1) { throw "FAIL one boundary call $Guard" }
        foreach ($name in $Later) {
            $laterCalls=@(Get-CommandNodes $SourceAst $name)
            if (-not $laterCalls.Count -or @($laterCalls | Where-Object {$_.Extent.StartOffset -lt $guardCalls[0].Extent.EndOffset}).Count) {
                throw "FAIL $Guard must precede $name"
            }
        }
    }
    $installAst=Get-ParsedSource '..\setup\Install-LocalPilot.ps1'
    $mainAst=Get-ParsedSource '..\windows\ExamLab.psm1'
    $netAst=Get-ParsedSource '..\windows\ExamNetwork.psm1'
    $nativeSource=$null
    foreach ($sourceAst in @($installAst,$mainAst,$netAst)) {
        if ($sourceAst.Extent.Text -match 'QEMU|KVM|Red Hat|ExamLab-TestVM') { throw 'FAIL runtime must not depend on VM identity.' }
        $guard=Get-FunctionNode $sourceAst 'Assert-NativeAMD64'
        if ($null -eq $nativeSource) { $nativeSource=$guard.Extent.Text }
        elseif ($nativeSource -cne $guard.Extent.Text) { throw 'FAIL native AMD64 guards must use the same reviewed API contract.' }
        if ($guard.Extent.Text -notmatch '\[UInt16\]\$nativeMachine' -or $guard.Extent.Text -notmatch '\[UInt16\]\$processMachine') { throw 'FAIL native outputs require UInt16.' }
        $nativeCalls=@($guard.FindAll({param($n)
            $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -eq 'IsWow64Process2'
        },$true))
        if ($nativeCalls.Count -ne 1) { throw 'FAIL exactly one native architecture observation.' }
        foreach ($condition in @('$build -lt 19041 -or $product.ProductType -ne ''WinNT''','-not $detected','$nativeMachine -ne 0x8664')) {
            $checks=@($guard.FindAll({param($n)
                $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -ceq $condition
            },$true))
            if ($checks.Count -ne 1 -or @($checks[0].Clauses[0].Item2.Statements | Where-Object {$_ -is [Management.Automation.Language.ThrowStatementAst]}).Count -ne 1) {
                throw "FAIL failclosed native branch: $condition"
            }
            if ($condition -like '$build*' -and $checks[0].Extent.EndOffset -gt $nativeCalls[0].Extent.StartOffset) { throw 'FAIL client/build floor must precede native API.' }
        }
        $nativeCatch=@($guard.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.CatchClauses.Count -gt 0},$true))
        if ($nativeCatch.Count -ne 1 -or @($nativeCatch[0].CatchClauses[0].Body.Statements | Where-Object {$_ -is [Management.Automation.Language.ThrowStatementAst]}).Count -ne 1) { throw 'FAIL native API exception must fail closed.' }
    }
    $entry=@($installAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
    if ($entry.Count -ne 1) { throw 'FAIL installer entry boundary.' }
    Assert-CallBefore $entry[0].Body 'Assert-NativeAMD64' @('Import-Module','Assert-SafeDirectory','Disable-ScheduledTask','Register-ScheduledTask')
    Assert-CallBefore (Get-FunctionNode $mainAst 'Assert-Host') 'Assert-NativeAMD64' @('Get-CimInstance')
    Assert-CallBefore (Get-FunctionNode $mainAst 'Read-Context') 'Assert-Host' @('Assert-SafePath','Import-Module','Get-LocalUser')
    Assert-CallBefore (Get-FunctionNode $netAst 'Read-NetContext') 'Assert-NativeAMD64' @('Assert-NetPath','Import-Module')
    foreach ($sourceAst in @($mainAst,$netAst)) {
        $topLevel=@($sourceAst.EndBlock.Statements | Where-Object {$_ -isnot [Management.Automation.Language.FunctionDefinitionAst]})
        foreach ($statement in $topLevel) {
            if (@(Get-CommandNodes $statement 'Assert-NativeAMD64').Count) { throw 'FAIL module import must remain pure.' }
        }
    }
    $applyHost=Get-FunctionNode $netAst 'Assert-NetApplyHost'
    foreach ($required in @('PartOfDomain','ProductType','19041','OMADM','dsregcmd.exe','AzureAdJoined','EnterpriseJoined','DomainJoined','WorkplaceJoined','MpsSvc','BFE')) {
        if (-not $applyHost.Extent.Text.Contains($required)) { throw "FAIL retained network host guard: $required" }
    }
    if ((Get-FunctionNode $mainAst 'Assert-Host').Extent.Text -notmatch 'S-1-5-18' -or
        $entry[0].Body.Extent.Text -notmatch 'IsInRole' -or $entry[0].Body.Extent.Text -notmatch 'PartOfDomain') { throw 'FAIL privilege/domain guards retained.' }
    'PASS source portability: native AMD64 failclosed/client floor/order, pure imports, no VM identity, retained privilege/MDM/domain guards; Windows API НЕ испытывались.'
    'Windows SharedPC/USB/filesystem/network НЕ испытывались.'
} finally {
    Remove-Module ExamLab -ErrorAction SilentlyContinue
    Remove-Module ExamNetwork -ErrorAction SilentlyContinue
    $env:ProgramFiles=$previousFiles; $env:ProgramData=$previousData
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
