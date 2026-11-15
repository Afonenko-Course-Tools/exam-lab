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

function Test-ExamNetworkConfig {
 [CmdletBinding()]param([AllowNull()]$Config)
 if($null -eq $Config){return}
 $names=@($Config.PSObject.Properties.Name)
 if($Config -isnot [pscustomobject] -or $names.Count -ne 3 -or @($names|Where-Object{$_ -notin @('ProxyEndpointIP','ProxyEndpointPort','TechnicalAccess')}).Count){throw 'Network: только ProxyEndpointIP, ProxyEndpointPort, TechnicalAccess.'}
 if($Config.TechnicalAccess -isnot [array]){throw 'TechnicalAccess должен быть массивом, включая пустой.'}
 $pairs=@([pscustomobject]@{IP=$Config.ProxyEndpointIP;Port=$Config.ProxyEndpointPort})
 $seen=@{}
 foreach($a in $Config.TechnicalAccess){
  if($a -isnot [pscustomobject] -or @($a.PSObject.Properties).Count -ne 2 -or @($a.PSObject.Properties.Name|Where-Object{$_ -notin @('RemoteIP','LocalPort')}).Count){throw 'TechnicalAccess: только RemoteIP и LocalPort.'}
  $pairs+=[pscustomobject]@{IP=$a.RemoteIP;Port=$a.LocalPort}
  $key=([string]$a.RemoteIP)+':'+([string]$a.LocalPort)
  if($seen.ContainsKey($key)){throw 'Повтор TechnicalAccess.'};$seen[$key]=$true
 }
 foreach($pair in $pairs){
  $ip=$null
  if($pair.IP -isnot [string] -or $pair.IP -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or -not [Net.IPAddress]::TryParse($pair.IP,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -cne $pair.IP -or ($pair.Port -isnot [int] -and $pair.Port -isnot [long]) -or $pair.Port -lt 1 -or $pair.Port -gt 65535){throw 'Network требует literal IPv4 и целые порты 1..65535.'}
  $b=$ip.GetAddressBytes()
  if($b[0] -in @(0,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)){throw 'Network endpoint должен быть unicast IPv4 вне loopback/link-local.'}
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
function Read-NetContext($Config,[string]$Revision){
 Test-ExamNetworkConfig $Config
 if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Нужен Windows PowerShell 5.1 x64.'}
 $principal=New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Нужен повышенный административный токен.'}
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
 [pscustomobject]@{Name='ExamLab.Network.Proxy.Out';Direction='Outbound';LocalAddress='Any';RemoteAddress=$Config.ProxyEndpointIP;LocalPort='Any';RemotePort=[string]$Config.ProxyEndpointPort}
 $index=0
 foreach($a in $Config.TechnicalAccess){[pscustomobject]@{Name=('ExamLab.Network.Technical.'+$index+'.In');Direction='Inbound';LocalAddress='Any';RemoteAddress=$a.RemoteIP;LocalPort=[string]$a.LocalPort;RemotePort='Any'};$index++}
}
function Get-NetLocalAddress {
 $addresses=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.PrefixOrigin -eq 'Manual' -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)'})
 if($addresses.Count -ne 1){throw 'Apply требует заранее подготовленный единственный static Manual/Preferred IPv4.'}
 [string]$addresses[0].IPAddress
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
  Program=(Default-Any $app.Program);Package=(Default-Any $app.Package);Service=(Default-Any $service.Service)
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
  LocalAddress=$spec.LocalAddress;RemoteAddress=$spec.RemoteAddress;Protocol='TCP';LocalPort=$spec.LocalPort;RemotePort=$spec.RemotePort
  DynamicTarget='Any';IcmpType='Any';Program='Any';Package='Any';Service='Any';InterfaceAlias='Any';InterfaceType='Any'
  Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules='False';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'
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
  foreach($name in @('AllowUserApps','AllowUserPorts')){if([string]$p.$name -cne 'NotConfigured'){$applyIssues+=('Чужое legacy GPO поле '+$p.Name+'.'+$name);if($state){$issues+=$applyIssues[-1]}}}
  $disabled=@($p.DisabledInterfaceAliases|Where-Object{$null -ne $_ -and [string]$_ -cne ''})
  if($disabled.Count -and -not($disabled.Count -eq 1 -and [string]$disabled[0] -ceq 'NotConfigured')){$applyIssues+=('Чужой DisabledInterfaceAliases '+$p.Name);if($state){$issues+=$applyIssues[-1]}}
 }
 if($gpoProfiles.Count -ne 3){$issues+='Не получены три GPO profiles';$applyIssues+=$issues[-1]}
 foreach($rule in $gpoRules){
  $spec=@($specs|Where-Object{$_.Name -ceq $rule.Name})
  if(-not $state -or $spec.Count -ne 1){
   $applyIssues+=('Чужое local GPO правило '+$rule.Name)
   if($state -or $rule.Name -like 'ExamLab.Network.*'){$issues+=$applyIssues[-1]};continue
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
function Assert-NetActive($View,[switch]$ManagementOnly){
 foreach($spec in $View.Specs){
  if($ManagementOnly -and $spec.Direction -ne 'Inbound'){continue}
  $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Name $spec.Name)
  if($active.Count -ne 1 -or [string]$active[0].PolicyStoreSourceType -cne 'GroupPolicy' -or (Read-RuleSignature $active[0]) -cne (Expected-RuleSignature $spec $View.Intent.RunId)){throw 'Нет exact active GPO allow.'}
 }
 if(-not $ManagementOnly){
  $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $script:Profiles)
  if($profiles.Count -ne 3){throw 'Нет трёх ActiveStore profiles.'}
  foreach($p in $profiles){foreach($name in $script:Fields.Keys){if([string]$p.$name -cne $script:Fields[$name]){throw 'ActiveStore не подтвердил собственные поля.'}}}
 }
}
function Get-ExamNetworkStatus {
 [CmdletBinding()]param([AllowNull()]$Config,[Parameter(Mandatory=$true)][string]$ConfigRevision)
 $view=Read-NetView $Config $ConfigRevision
 $state=if($view.Issues.Count){'Conflict'}elseif(-not $view.Intent){'NotConfigured'}elseif($view.Complete){'Applied'}else{'Applying'}
 [pscustomobject]@{State=$state;SourceNormal=($state -eq 'NotConfigured');NormalAllowed=($view.Issues.Count -eq 0);Blockers=@($view.Issues);ApplyAllowed=($null -ne $Config -and -not $view.Intent -and -not $view.ApplyIssues.Count -and -not $view.Issues.Count);ApplyBlockers=@($view.ApplyIssues);RunId=if($view.Intent){$view.Intent.RunId}else{$null};OwnRules=@($view.Present);ConfigRevision=$ConfigRevision;FullReady=$false;PersistentStoreWritten=$false}
}
function Assert-NetApplyHost {
 $machine=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
 if($machine.PartOfDomain -or [int]$os.BuildNumber -lt 19041 -or [int]$os.ProductType -ne 1 -or ($machine.Manufacturer+' '+$machine.Model) -notmatch 'QEMU|KVM|Red Hat' -or -not (Test-NetPathPresent (Join-Path $env:ProgramData 'ExamLab-TestVM'))){throw 'Экспериментальный Apply требует standalone Windows client 19041+ в подготовленной QEMU/KVM VM.'}
 $omadm=@()
 if(Test-NetPathPresent 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'){$omadm=@(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' -ErrorAction Stop)}
 if($omadm.Count -or @(Get-ScheduledTask|Where-Object{$_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*'}).Count){throw 'Обнаружены MDM management artifacts.'}
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$dsreg=(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>&1|Out-String);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
 foreach($flag in @('AzureAdJoined','EnterpriseJoined','DomainJoined','WorkplaceJoined')){if($code -ne 0 -or $dsreg -notmatch ('(?m)^\s*'+$flag+'\s*:\s*NO\s*$')){throw 'Unmanaged Windows precondition не подтверждён.'}}
 foreach($service in @('MpsSvc','BFE')){if((Get-Service $service).Status -ne 'Running'){throw 'Firewall services не готовы.'}}
}
function Invoke-ExamNetworkUnderLock {
 [CmdletBinding()]param([Parameter(Mandatory=$true)][ValidateSet('Apply','Normal')][string]$Action,[AllowNull()]$Config,[Parameter(Mandatory=$true)][string]$ConfigRevision,[Parameter(Mandatory=$true)][IO.FileStream]$OperationLock)
 if(-not $OperationLock.CanRead -or -not $OperationLock.CanWrite -or [IO.Path]::GetFullPath($OperationLock.Name) -ine (Join-Path $script:DataRoot 'operation.lock')){throw 'Нужен живой общий operation.lock; caller удерживает FileShare.None.'}
 $view=Read-NetView $Config $ConfigRevision
 if($view.Issues.Count){throw ($view.Issues -join '; ')}
 if($Action -eq 'Apply'){
  if($null -eq $Config){throw 'Network не описан в pc.json.'}
  if($view.Intent){if($view.Complete){Assert-NetActive $view;return Get-ExamNetworkStatus $Config $ConfigRevision};throw 'Частичный собственный Apply: только Normal; автоматического продолжения нет.'}
  if($view.ApplyIssues.Count){throw ($view.ApplyIssues -join '; ')}
  Assert-NetApplyHost
  $null=Get-NetLocalAddress
  $specs=@(Get-NetSpecs $Config)
  $state=[ordered]@{Schema=1;RunId=[Guid]::NewGuid().ToString('D');ComputerIdentity=$view.Identity;ConfigRevision=$ConfigRevision}
  $file=[IO.File]::Open($script:MetaPath,'CreateNew','Write','None')
  try{$bytes=[Text.Encoding]::UTF8.GetBytes(($state|ConvertTo-Json -Compress));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  $acl=New-Object Security.AccessControl.FileSecurity;$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Set-Acl -LiteralPath $script:MetaPath -AclObject $acl
  foreach($spec in $specs){New-NetFirewallRule -PolicyStore localhost -Name $spec.Name -DisplayName $spec.Name -Description ('ExamLab Network '+$state.RunId) -Group $script:Group -Enabled True -Profile Any -Direction $spec.Direction -Action Allow -Protocol TCP -LocalAddress $spec.LocalAddress -RemoteAddress $spec.RemoteAddress -LocalPort $spec.LocalPort -RemotePort $spec.RemotePort|Out-Null}
  Update-NetPolicy
  $view=Read-NetView $Config $ConfigRevision
  if($view.Issues.Count -or $view.Present.Count -ne $specs.Count){throw 'Собственные GPO rules не подтверждены до no-merge.'}
  Assert-NetActive $view -ManagementOnly
  foreach($profileName in $script:Profiles){Set-NetFirewallProfile -PolicyStore localhost -Name $profileName -ThrottleLimit 1 -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -AllowInboundRules True -AllowLocalFirewallRules False -AllowLocalIPsecRules False}
  Update-NetPolicy
  $view=Read-NetView $Config $ConfigRevision
  if($view.Issues.Count -or -not $view.Complete){throw 'GPO Apply не подтверждён; Normal отдельно.'}
  Assert-NetActive $view
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
