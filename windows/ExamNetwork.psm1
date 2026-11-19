#requires -Version 5.1
# Экспериментальный компонент localhost GPO. HTTPS policy принадлежит серверному proxy.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:CodeRoot=Join-Path $env:ProgramFiles 'ExamLab'
$script:DataRoot=Join-Path $env:ProgramData 'ExamLab'
$script:MetaPath=Join-Path $script:DataRoot 'network-owned.json'
$script:LoadedHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$script:Profiles=@('Domain','Private','Public')
$script:Fields=[ordered]@{Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Block';AllowInboundRules='True';AllowLocalFirewallRules='False';AllowLocalIPsecRules='False'}
$script:Group='ExamLab Network v1'
$script:ControllerProgram='%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:WazuhProgram='%ProgramFiles(x86)%\ossec-agent\wazuh-agent.exe'
$script:SystemLocalUser='D:(A;;CC;;;SY)'

function Assert-NetEndpointIP($Value){
 $ip=$null
 if($Value -isnot [string] -or $Value -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or -not [Net.IPAddress]::TryParse($Value,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -cne $Value){throw 'Network требует literal IPv4.'}
 $b=$ip.GetAddressBytes()
 if($b[0] -in @(0,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)){throw 'Network endpoint должен быть unicast IPv4 вне loopback/link-local.'}
}
function Assert-NetEndpoint($IP,$Port){
 Assert-NetEndpointIP $IP
 if(($Port -isnot [int] -and $Port -isnot [long]) -or $Port -lt 1 -or $Port -gt 65535){throw 'Network требует целые порты 1..65535.'}
}
function Test-ExamNetworkConfig {
 [CmdletBinding()]param([AllowNull()]$Config)
 if($null -eq $Config){return}
 $names=@($Config.PSObject.Properties.Name)
 $required=@('ProxyEndpointIP','ProxyEndpointPort','TechnicalAccess')
 $services=@('ControllerEndpoint','WazuhEndpoint')
 $allowed=$required+@('DhcpServerIP')+$services
 if($Config -isnot [pscustomobject] -or @($required|Where-Object{$_ -notin $names}).Count -or @($names|Where-Object{$_ -notin $allowed}).Count){throw 'Network: нужны ProxyEndpointIP, ProxyEndpointPort, TechnicalAccess. Допустимы DhcpServerIP, ControllerEndpoint и WazuhEndpoint.'}
 if('DhcpServerIP' -in $names){Assert-NetEndpointIP $Config.DhcpServerIP}
 Assert-NetEndpoint $Config.ProxyEndpointIP $Config.ProxyEndpointPort
 $outbound=@(('{0}:{1}' -f $Config.ProxyEndpointIP,$Config.ProxyEndpointPort))
 foreach($name in $services){
  if($name -notin $names){continue}
  $endpoint=$Config.$name
  if($endpoint -isnot [pscustomobject] -or @($endpoint.PSObject.Properties).Count -ne 2 -or @($endpoint.PSObject.Properties.Name|Where-Object{$_ -notin @('IP','Port')}).Count){throw ('Network.'+$name+' допускает только IP и Port.')}
  Assert-NetEndpoint $endpoint.IP $endpoint.Port
  $pair='{0}:{1}' -f $endpoint.IP,$endpoint.Port
  if($pair -in $outbound){throw 'Все исходящие TCP endpoints Network должны различаться.'}
  $outbound+=$pair
 }
 if($Config.TechnicalAccess -isnot [array]){throw 'TechnicalAccess должен быть массивом, включая пустой.'}
 $seen=@{}
 foreach($a in $Config.TechnicalAccess){
  if($a -isnot [pscustomobject] -or @($a.PSObject.Properties).Count -ne 2 -or @($a.PSObject.Properties.Name|Where-Object{$_ -notin @('RemoteIP','LocalPort')}).Count){throw 'TechnicalAccess: только RemoteIP и LocalPort.'}
  Assert-NetEndpoint $a.RemoteIP $a.LocalPort
  $key=([string]$a.RemoteIP)+':'+([string]$a.LocalPort)
  if($seen.ContainsKey($key)){throw 'Повтор TechnicalAccess.'};$seen[$key]=$true
 }
}
function Test-NetPathPresent([string]$Path){
 try{$null=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;return $true}
 catch [System.Management.Automation.ItemNotFoundException]{return $false}
}
function Assert-NetPath([string]$Path,[switch]$Readable){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point в network paths.'}
 $acl=Get-Acl -LiteralPath $Path
 $trusted=@('S-1-5-18','S-1-5-32-544')+@(Get-LocalGroupMember -SID 'S-1-5-32-544'|ForEach-Object{$_.SID.Value})
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'Чужой owner network path.'}
 $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
 foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($ace.AccessControlType -ne 'Allow' -or $ace.IdentityReference.Value -in $trusted){continue}
  if($ace.IdentityReference.Value -eq 'S-1-3-0' -and ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)){continue}
  if(-not $Readable -or ($ace.FileSystemRights -band $write)){throw 'Network path доступен чужому SID.'}
 }
}
function Assert-NativeAMD64 {
    # Тот же native API, что в Prepare-ExamLab; x64-эмуляция на ARM64 не подходит.
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    $product = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
    if ($build -lt 19041 -or $product.ProductType -ne 'WinNT') { throw 'Нужен Windows client build19041 или новее.' }
    if (-not ('ExamLabNativePlatform' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ExamLabNativePlatform {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
}
'@
    }
    [UInt16]$processMachine = 0; [UInt16]$nativeMachine = 0
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        try { $detected = [ExamLabNativePlatform]::IsWow64Process2($currentProcess.Handle,[ref]$processMachine,[ref]$nativeMachine) }
        catch { throw 'Не удалось определить native architecture Windows через IsWow64Process2.' }
        if (-not $detected) { throw ('IsWow64Process2 не определил native architecture; Win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        if ($nativeMachine -ne 0x8664) { throw ('Нужна native AMD64 Windows; NativeMachine=0x{0:X4}' -f $nativeMachine) }
    } finally { $currentProcess.Dispose() }
}

function Read-NetContext($Config,[string]$Revision){
 Test-ExamNetworkConfig $Config
 if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Нужен Windows PowerShell 5.1 x64.'}
 $principal=New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Нужен повышенный административный токен.'}
 Assert-NativeAMD64
 if($PSScriptRoot -ine $script:CodeRoot -or (Get-FileHash -LiteralPath (Join-Path $script:CodeRoot 'ExamNetwork.psm1')).Hash -cne $script:LoadedHash){throw 'Network source не установлен либо изменился после загрузки.'}
 Assert-NetPath $script:CodeRoot -Readable;Assert-NetPath $script:DataRoot
 Assert-NetPath (Join-Path $script:CodeRoot 'ExamNetwork.psm1') -Readable
 $pc=Join-Path $script:DataRoot 'pc.json';Assert-NetPath $pc
 if($Revision -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -LiteralPath $pc).Hash -ine $Revision){throw 'Network ConfigRevision не совпала с pc.json.'}
 $current=[IO.File]::ReadAllText($pc)|ConvertFrom-Json
 $declared=$null;if($current.PSObject.Properties.Name -contains 'Network'){$declared=$current.Network}
 Test-ExamNetworkConfig $declared
 if(($Config|ConvertTo-Json -Depth 6 -Compress) -cne ($declared|ConvertTo-Json -Depth 6 -Compress)){throw 'Network должен поступать из текущего единственного pc.json.'}
 if((Test-NetPathPresent (Join-Path $script:DataRoot 'state.json'))){throw 'Старый state.json не поддерживается.'}
 Import-Module NetSecurity -ErrorAction Stop
 (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
}
function Get-NetSpecs($Config){
 if($null -eq $Config){return}
 [pscustomobject]@{Name='ExamLab.Network.Proxy.Out';Direction='Outbound';Protocol='TCP';RemoteAddress=$Config.ProxyEndpointIP;LocalPort='Any';RemotePort=[string]$Config.ProxyEndpointPort;Program='Any';Service='Any';LocalUser='Any'}
 $index=0
 foreach($a in $Config.TechnicalAccess){[pscustomobject]@{Name=('ExamLab.Network.Technical.'+$index+'.In');Direction='Inbound';Protocol='TCP';RemoteAddress=$a.RemoteIP;LocalPort=[string]$a.LocalPort;RemotePort='Any';Program='Any';Service='Any';LocalUser='Any'};$index++}
 if('DhcpServerIP' -in $Config.PSObject.Properties.Name){
  $client=Join-Path $env:SystemRoot 'System32\svchost.exe'
  [pscustomobject]@{Name='ExamLab.Network.Dhcp.Out';Direction='Outbound';Protocol='UDP';RemoteAddress=@($Config.DhcpServerIP,'255.255.255.255');LocalPort='68';RemotePort='67';Program=$client;Service='Dhcp';LocalUser='Any'}
  [pscustomobject]@{Name='ExamLab.Network.Dhcp.In';Direction='Inbound';Protocol='UDP';RemoteAddress=$Config.DhcpServerIP;LocalPort='68';RemotePort='67';Program=$client;Service='Dhcp';LocalUser='Any'}
 }
 if('ControllerEndpoint' -in $Config.PSObject.Properties.Name){
  [pscustomobject]@{Name='ExamLab.Network.Controller.Out';Direction='Outbound';Protocol='TCP';RemoteAddress=$Config.ControllerEndpoint.IP;LocalPort='Any';RemotePort=[string]$Config.ControllerEndpoint.Port;Program=$script:ControllerProgram;Service='Any';LocalUser=$script:SystemLocalUser}
 }
 if('WazuhEndpoint' -in $Config.PSObject.Properties.Name){
  [pscustomobject]@{Name='ExamLab.Network.Wazuh.Out';Direction='Outbound';Protocol='TCP';RemoteAddress=$Config.WazuhEndpoint.IP;LocalPort='Any';RemotePort=[string]$Config.WazuhEndpoint.Port;Program=$script:WazuhProgram;Service='Any';LocalUser=$script:SystemLocalUser}
 }
}
function Assert-NetApplyPrograms($Config){
 if('ControllerEndpoint' -in $Config.PSObject.Properties.Name){
  $controllerProgram=[Environment]::ExpandEnvironmentVariables($script:ControllerProgram)
  if(-not (Test-Path -LiteralPath $controllerProgram -PathType Leaf)){throw 'Не найден штатный Windows PowerShell для опроса контроллера.'}
 }
 if('WazuhEndpoint' -in $Config.PSObject.Properties.Name){
  $wazuhProgram=[Environment]::ExpandEnvironmentVariables($script:WazuhProgram)
  $agents=@(Get-CimInstance Win32_Service -Filter "Name = 'WazuhSvc'")
  if($agents.Count -ne 1 -or $agents[0].StartName -ine 'LocalSystem' -or
     [Environment]::ExpandEnvironmentVariables([string]$agents[0].PathName).Trim('"') -ine $wazuhProgram -or
     -not (Test-Path -LiteralPath $wazuhProgram -PathType Leaf)){
   throw 'Для WazuhEndpoint требуется WazuhSvc под LocalSystem со штатным путём к wazuh-agent.exe.'
  }
 }
}
function Assert-NetApplyAddress($Config){
 if('DhcpServerIP' -notin $Config.PSObject.Properties.Name){
  $manual=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.PrefixOrigin -eq 'Manual' -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)'})
  if($manual.Count -ne 1){throw 'Apply без DhcpServerIP требует единственный static Manual/Preferred IPv4.'}
  return
 }
 $addresses=@(Find-NetRoute -RemoteIPAddress $Config.ProxyEndpointIP | Where-Object {$_.CimClass.CimClassName -eq 'MSFT_NetIPAddress'})
 if($addresses.Count -ne 1 -or $addresses[0].AddressState -ne 'Preferred') {throw 'Apply требует Preferred IPv4 на маршруте к proxy.'}
 $address=$addresses[0]
 Assert-NetEndpointIP $address.IPAddress
 if($address.PrefixOrigin -ne 'Dhcp' -or (Get-Service Dhcp).Status -ne 'Running'){throw 'Для DhcpServerIP нужны DHCP-адрес на маршруте к proxy и служба Dhcp.'}
 $leases=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ('InterfaceIndex = '+[uint32]$address.InterfaceIndex))
 if($leases.Count -ne 1){throw 'Не найдена конфигурация адаптера на маршруте DHCP к proxy.'}
 $lease=$leases[0]
 if(-not $lease.DHCPEnabled -or $lease.DHCPServer -cne $Config.DhcpServerIP -or $address.IPAddress -notin $lease.IPAddress -or -not $lease.DHCPLeaseExpires -or $lease.DHCPLeaseExpires -le (Get-Date)){throw 'Актуальная DHCP-аренда на маршруте к proxy не подтверждена для указанного DhcpServerIP.'}
}
function Join-Values($value){(@($value)|ForEach-Object{[string]$_}|Sort-Object) -join ','}
function Default-Any($value){$text=Join-Values $value;if($text -in @('','Any')){'Any'}else{$text}}
function Read-RuleSignature($rule){
 $address=$rule|Get-NetFirewallAddressFilter
 $port=$rule|Get-NetFirewallPortFilter
 $app=$rule|Get-NetFirewallApplicationFilter
 $service=$rule|Get-NetFirewallServiceFilter
 $security=$rule|Get-NetFirewallSecurityFilter
 $interface=$rule|Get-NetFirewallInterfaceFilter
 $interfaceType=$rule|Get-NetFirewallInterfaceTypeFilter
 [ordered]@{
  Name=[string]$rule.Name;DisplayName=[string]$rule.DisplayName;Description=[string]$rule.Description;Group=[string]$rule.Group
  Enabled=[string]$rule.Enabled;Profile=[string]$rule.Profile;Direction=[string]$rule.Direction;Action=[string]$rule.Action
  EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;LooseSourceMapping=[string]$rule.LooseSourceMapping;LocalOnlyMapping=[string]$rule.LocalOnlyMapping
  LocalAddress=(Join-Values $address.LocalAddress);RemoteAddress=(Join-Values $address.RemoteAddress)
  Protocol=[string]$port.Protocol;LocalPort=(Join-Values $port.LocalPort);RemotePort=(Join-Values $port.RemotePort)
  DynamicTarget=[string]$port.DynamicTarget;IcmpType=(Default-Any $port.IcmpType)
  Program=[Environment]::ExpandEnvironmentVariables((Default-Any $app.Program)).ToLowerInvariant();Package=(Default-Any $app.Package);Service=(Default-Any $service.Service).ToLowerInvariant()
  InterfaceAlias=(Default-Any $interface.InterfaceAlias);InterfaceType=[string]$interfaceType.InterfaceType
  Authentication=[string]$security.Authentication;Encryption=[string]$security.Encryption;OverrideBlockRules=[string]$security.OverrideBlockRules
  LocalUser=(Default-Any $security.LocalUser);RemoteUser=(Default-Any $security.RemoteUser);RemoteMachine=(Default-Any $security.RemoteMachine)
 }|ConvertTo-Json -Compress
}
function Expected-RuleSignature($spec,[string]$runId){
 [ordered]@{
  Name=$spec.Name;DisplayName=$spec.Name;Description=('ExamLab Network '+$runId);Group=$script:Group
  Enabled='True';Profile='Any';Direction=$spec.Direction;Action='Allow'
  EdgeTraversalPolicy='Block';LooseSourceMapping='False';LocalOnlyMapping='False'
  LocalAddress='Any';RemoteAddress=(Join-Values $spec.RemoteAddress);Protocol=$spec.Protocol;LocalPort=$spec.LocalPort;RemotePort=$spec.RemotePort
  DynamicTarget='Any';IcmpType='Any';Program=[Environment]::ExpandEnvironmentVariables($spec.Program).ToLowerInvariant();Package='Any';Service=$spec.Service.ToLowerInvariant();InterfaceAlias='Any';InterfaceType='Any'
  Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules='False';LocalUser=$spec.LocalUser;RemoteUser='Any';RemoteMachine='Any'
 }|ConvertTo-Json -Compress
}
function Read-NetView($Config,[string]$Revision){
 $identity=Read-NetContext $Config $Revision
 $state=$null;$issues=@();$applyIssues=@();$present=@();$complete=$true
 if((Test-NetPathPresent $script:MetaPath)){
  Assert-NetPath $script:MetaPath
  $state=[IO.File]::ReadAllText($script:MetaPath)|ConvertFrom-Json
  if(@($state.PSObject.Properties).Count -ne 4 -or @($state.PSObject.Properties.Name|Where-Object{$_ -notin @('Schema','RunId','ComputerIdentity','ConfigRevision')}).Count -or $state.Schema -ne 1 -or [Guid]::Parse($state.RunId).ToString('D') -cne $state.RunId -or $state.ComputerIdentity -cne $identity -or $state.ConfigRevision -ine $Revision -or $null -eq $Config){throw 'Network ownership/config изменены; adoption не выполняется.'}
 }
 $gpoProfiles=@(Get-NetFirewallProfile -PolicyStore localhost -Name $script:Profiles)
 $gpoRules=@(Get-NetFirewallRule -PolicyStore localhost)
 $specs=@()
 if($state){$specs=@(Get-NetSpecs $Config)}
 foreach($p in $gpoProfiles){
  foreach($name in $script:Fields.Keys){
   $value=[string]$p.$name
   if($value -ceq 'NotConfigured'){$complete=$false;continue}
   if(-not $state -or $value -cne $script:Fields[$name]){$applyIssues+=('Чужое/изменённое GPO поле '+$p.Name+'.'+$name);if($state){$issues+=$applyIssues[-1]}}
  }
  foreach($name in @('AllowUserApps','AllowUserPorts')){if([string]$p.$name -cne 'NotConfigured'){$applyIssues+=('Чужое legacy GPO поле '+$p.Name+'.'+$name)}}
  $disabled=@($p.DisabledInterfaceAliases|Where-Object{$null -ne $_ -and [string]$_ -cne ''})
  if($disabled.Count -and -not($disabled.Count -eq 1 -and [string]$disabled[0] -ceq 'NotConfigured')){$applyIssues+=('Чужой DisabledInterfaceAliases '+$p.Name)}
 }
 if($gpoProfiles.Count -ne 3){$issues+='Не получены три GPO profiles';$applyIssues+=$issues[-1]}
 foreach($rule in $gpoRules){
  $spec=@($specs|Where-Object{$_.Name -ceq $rule.Name})
  if(-not $state -or $spec.Count -ne 1){
   $applyIssues+=('Чужое local GPO правило '+$rule.Name)
   if($rule.Name -like 'ExamLab.Network.*'){$issues+=$applyIssues[-1]};continue
  }
  if((Read-RuleSignature $rule) -cne (Expected-RuleSignature $spec[0] $state.RunId)){$issues+=('Изменены собственные filters '+$rule.Name)}
  $present+=[string]$rule.Name
 }
 if($present.Count -ne $specs.Count){$complete=$false}
 [pscustomobject]@{Intent=$state;Issues=$issues;ApplyIssues=$applyIssues;Complete=$complete;Present=$present;Specs=$specs;Profiles=$gpoProfiles;Identity=$identity}
}
function Update-NetPolicy {
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';& "$env:SystemRoot\System32\gpupdate.exe" /target:computer /force /wait:30 2>&1|Out-Null;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
 if($code -ne 0){throw 'gpupdate отказал; own intent сохранён, Normal отдельно.'}
}
function Assert-NetActive($View,[switch]$RulesOnly){
 foreach($spec in $View.Specs){
  $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Name $spec.Name)
  if($active.Count -ne 1 -or [string]$active[0].PolicyStoreSourceType -cne 'GroupPolicy' -or (Read-RuleSignature $active[0]) -cne (Expected-RuleSignature $spec $View.Intent.RunId)){throw ('ActiveStore не подтвердил собственное правило '+$spec.Name)}
 }
 if(-not $RulesOnly){
  $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $script:Profiles)
  if($profiles.Count -ne 3){throw 'Нет трёх ActiveStore profiles.'}
  foreach($p in $profiles){foreach($name in $script:Fields.Keys){if([string]$p.$name -cne $script:Fields[$name]){throw 'ActiveStore не подтвердил собственные поля.'}}}
 }
}
function Get-ExamNetworkStatus {
 [CmdletBinding()]param([AllowNull()]$Config,[Parameter(Mandatory=$true)][string]$ConfigRevision,[switch]$CheckApplyHost)
 $view=Read-NetView $Config $ConfigRevision
 Get-NetStatusFromView $view $Config $ConfigRevision -CheckApplyHost:$CheckApplyHost
}
function Get-NetStatusFromView($View,$Config,[string]$ConfigRevision,[switch]$CheckApplyHost){
 $state=if($View.Issues.Count){'Conflict'}elseif(-not $View.Intent){'NotConfigured'}elseif($View.Complete){'Applied'}else{'Applying'}
 $policyBlockers=@(($View.ApplyIssues + $View.Issues) | Select-Object -Unique)
 $applyBlockers=$policyBlockers
 if($CheckApplyHost -and $null -ne $Config -and $state -eq 'NotConfigured' -and -not $applyBlockers.Count){
  try{Assert-NetApplyHost $Config}catch{$applyBlockers+=$_.Exception.Message}
 }elseif($CheckApplyHost -and $state -eq 'Applied' -and -not $applyBlockers.Count){
  try{
   if('DhcpServerIP' -in $Config.PSObject.Properties.Name){Assert-NetApplyAddress $Config}
   Assert-NetApplyPrograms $Config
  }catch{$applyBlockers+=$_.Exception.Message}
 }
 $effectiveApplied=$false;$effectiveBlockers=@()
 if($state -eq 'Applied'){
  $effectiveBlockers=$policyBlockers
  if(-not $effectiveBlockers.Count){
   try{Assert-NetActive $View;$effectiveApplied=$true}catch{$effectiveBlockers+=$_.Exception.Message}
  }
 }
 [pscustomobject]@{
  State=$state;SourceNormal=($state -eq 'NotConfigured');NormalAllowed=($View.Issues.Count -eq 0)
  Blockers=@($View.Issues);NormalBlockers=@($View.Issues)
  ApplyAllowed=($null -ne $Config -and $state -eq 'NotConfigured' -and -not $applyBlockers.Count);ApplyBlockers=$applyBlockers
  EffectiveApplied=$effectiveApplied;EffectiveBlockers=$effectiveBlockers
  RunId=if($View.Intent){$View.Intent.RunId}else{$null};OwnRules=@($View.Present);ConfigRevision=$ConfigRevision;FullReady=$false;PersistentStoreWritten=$false
 }
}
function Assert-NetApplyHost($Config){
 $machine=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
 if($machine.PartOfDomain -or [int]$os.BuildNumber -lt 19041 -or [int]$os.ProductType -ne 1){throw 'Экспериментальный Apply требует standalone Windows client 19041+.'}
 $omadm=@()
 if(Test-NetPathPresent 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'){$omadm=@(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' -ErrorAction Stop)}
 if($omadm.Count -or @(Get-ScheduledTask|Where-Object{$_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*'}).Count){throw 'Обнаружены MDM management artifacts.'}
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$dsreg=(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1|Out-String);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
 foreach($flag in @('AzureAdJoined','EnterpriseJoined','DomainJoined','WorkplaceJoined')){if($code -ne 0 -or $dsreg -notmatch ('(?m)^\s*'+$flag+'\s*:\s*NO\s*$')){throw 'Unmanaged Windows precondition не подтверждён.'}}
 foreach($service in @('MpsSvc','BFE')){if((Get-Service $service).Status -ne 'Running'){throw 'Firewall services не готовы.'}}
 Assert-NetApplyAddress $Config
 Assert-NetApplyPrograms $Config
}
function Invoke-ExamNetworkUnderLock {
 [CmdletBinding()]param([Parameter(Mandatory=$true)][ValidateSet('Apply','Normal')][string]$Action,[AllowNull()]$Config,[Parameter(Mandatory=$true)][string]$ConfigRevision,[Parameter(Mandatory=$true)][IO.FileStream]$OperationLock)
 if(-not $OperationLock.CanRead -or -not $OperationLock.CanWrite -or [IO.Path]::GetFullPath($OperationLock.Name) -ine (Join-Path $script:DataRoot 'operation.lock')){throw 'Нужен живой общий operation.lock; caller удерживает FileShare.None.'}
 $view=Read-NetView $Config $ConfigRevision
 if($view.Issues.Count){throw ($view.Issues -join '; ')}
 if($Action -eq 'Apply'){
  if($null -eq $Config){throw 'Network не описан в pc.json.'}
  if($view.ApplyIssues.Count){throw ($view.ApplyIssues -join '; ')}
  if($view.Intent){
   if(-not $view.Complete){throw 'После частичного Apply требуется Normal.'}
   $status=Get-NetStatusFromView $view $Config $ConfigRevision -CheckApplyHost
   if($status.ApplyBlockers.Count){throw ($status.ApplyBlockers -join '; ')}
   if(-not $status.EffectiveApplied){throw ($status.EffectiveBlockers -join '; ')}
   return $status
  }
  Assert-NetApplyHost $Config
  $specs=@(Get-NetSpecs $Config)
  $state=[ordered]@{Schema=1;RunId=[Guid]::NewGuid().ToString('D');ComputerIdentity=$view.Identity;ConfigRevision=$ConfigRevision}
  $file=[IO.File]::Open($script:MetaPath,'CreateNew','Write','None')
  try{$bytes=[Text.Encoding]::UTF8.GetBytes(($state|ConvertTo-Json -Compress));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  $acl=New-Object Security.AccessControl.FileSecurity;$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Set-Acl -LiteralPath $script:MetaPath -AclObject $acl
  foreach($spec in $specs){
   $filters=@{Direction=$spec.Direction;Protocol=$spec.Protocol;LocalAddress='Any';RemoteAddress=$spec.RemoteAddress;LocalPort=$spec.LocalPort;RemotePort=$spec.RemotePort}
   if($spec.Program -ne 'Any'){$filters.Program=[Environment]::ExpandEnvironmentVariables($spec.Program)}
   if($spec.Service -ne 'Any'){$filters.Service=$spec.Service}
   if($spec.LocalUser -ne 'Any'){$filters.LocalUser=$spec.LocalUser}
   New-NetFirewallRule -PolicyStore localhost -Name $spec.Name -DisplayName $spec.Name -Description ('ExamLab Network '+$state.RunId) -Group $script:Group -Enabled True -Profile Any -Action Allow @filters|Out-Null
  }
  Update-NetPolicy
  $view=Read-NetView $Config $ConfigRevision
  if($view.Issues.Count -or $view.ApplyIssues.Count -or $view.Present.Count -ne $specs.Count){throw 'Собственные GPO rules не подтверждены до no-merge.'}
  Assert-NetActive $view -RulesOnly
  foreach($profileName in $script:Profiles){Set-NetFirewallProfile -PolicyStore localhost -Name $profileName -ThrottleLimit 1 -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -AllowInboundRules True -AllowLocalFirewallRules False -AllowLocalIPsecRules False}
  Update-NetPolicy
  $view=Read-NetView $Config $ConfigRevision
  if($view.Issues.Count -or -not $view.Complete){throw 'GPO Apply не подтверждён; Normal отдельно.'}
  $status=Get-NetStatusFromView $view $Config $ConfigRevision
  if(-not $status.EffectiveApplied){throw ($status.EffectiveBlockers -join '; ')}
  return $status
 }elseif($view.Intent){
  foreach($profileName in $script:Profiles){Set-NetFirewallProfile -PolicyStore localhost -Name $profileName -ThrottleLimit 1 -Enabled NotConfigured -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured -AllowInboundRules NotConfigured -AllowLocalFirewallRules NotConfigured -AllowLocalIPsecRules NotConfigured}
  Update-NetPolicy
  foreach($name in $view.Present){Remove-NetFirewallRule -PolicyStore localhost -Name $name}
  Update-NetPolicy
  $after=Read-NetView $Config $ConfigRevision
  if($after.Issues.Count -or $after.Present.Count){throw 'Normal не подтверждён; intent сохранён.'}
  foreach($p in $after.Profiles){foreach($name in $script:Fields.Keys){if([string]$p.$name -cne 'NotConfigured'){throw 'Normal поля не NotConfigured; intent сохранён.'}}}
  Remove-Item -LiteralPath $script:MetaPath
 }
 Get-ExamNetworkStatus $Config $ConfigRevision
}
Export-ModuleMember -Function Test-ExamNetworkConfig,Get-ExamNetworkStatus,Invoke-ExamNetworkUnderLock
