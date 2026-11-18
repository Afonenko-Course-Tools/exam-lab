# Переносимая проверка: реальный PFE codec на временных файлах; Windows observations
# и результаты status в проверке orchestration явно подменены. Это не native-приёмка.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PolicyFileEditorPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PolicyFileEditorPath=(Resolve-Path -LiteralPath $PolicyFileEditorPath).Path
$errors=$null;$tokens=$null
$source=Join-Path $PSScriptRoot '../windows/ExamLab.Usb.psm1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$count=0
function Assert-Case([bool]$Ok,[string]$Name) { if (-not $Ok) {throw $Name}; $script:count++; "PASS $Name" }
function Assert-Refuse([scriptblock]$Code,[string]$Name) {
    $refused=$false;try { & $Code | Out-Null } catch {$refused=$true}
    Assert-Case $refused $Name
}
foreach ($name in @('Get-UsbItemIfPresent','Test-UsbHiveRoot','Test-UsbKey','Test-UsbSourceEntry','Test-OwnValue','Test-OwnedSource','Read-UsbMetadata','Write-UsbMetadata','Invoke-ExamLabUsbModeUnderLock')) {
    $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    . ([scriptblock]::Create($f.Extent.Text))
}
function Assert-SafeFilePath { param($Path) } # Только mocked ACL observation, не ACL Windows.
$usb='Software\Policies\Microsoft\Windows\RemovableStorageDevices'
$disk=$usb+'\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
$target='C:\Windows\System32\GroupPolicyUsers\S-1-5-32-545\User\registry.pol'
$good=[pscustomobject]@{Key=$disk;ValueName='Deny_Read';Type='DWord';Data=1}
Assert-Case (Test-UsbKey $disk) 'класс входит в USB scope'
Assert-Case (-not (Test-UsbKey ($usb+'Other'))) 'похожий prefix не захватывается'
foreach ($key in @('','Software','Software\Policies\Microsoft\Windows',$usb)) {
    Assert-Case (Test-UsbSourceEntry ([pscustomobject]@{Key=$key;ValueName='**SecureKey'})) "ancestor command: $key"
}
Assert-Case (-not (Test-UsbSourceEntry ([pscustomobject]@{Key='Software\OtherVendor';ValueName='**DeleteKeys'}))) 'другой vendor не захватывается'
Assert-Case (-not (Test-OwnedSource $target $good $null)) 'равное значение без intent не наше'
foreach ($state in @('Applying','Applied','Removing')) {
    Assert-Case (Test-OwnedSource $target $good ([pscustomobject]@{State=$state})) "точная source при $state"
}
Assert-Case (-not (Test-OwnedSource $target $good ([pscustomobject]@{State='Normal'}))) 'повторное появление после Normal чужое'
Assert-Case (-not (Test-OwnedSource 'C:\other\registry.pol' $good ([pscustomobject]@{State='Applied'}))) 'тот же Deny в другом GPO чужой'
foreach ($entry in @(
    [pscustomobject]@{Key=$disk;ValueName='Deny_Read';Type='String';Data='1'},
    [pscustomobject]@{Key=$disk;ValueName='Deny_Read';Type='DWord';Data=0},
    [pscustomobject]@{Key=$usb;ValueName='Deny_All';Type='DWord';Data=1},
    [pscustomobject]@{Key=$disk;ValueName='**Del.Deny_Read';Type='DWord';Data=1}
)) { Assert-Case (-not (Test-OwnValue $entry)) "чужое значение $($entry.ValueName)/$($entry.Type)/$($entry.Data)" }

# Реальная функция проверки отсутствия, явно подменённый Get-Item.
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction)
    if ($LiteralPath -eq 'missing') {throw [Management.Automation.ItemNotFoundException]::new('missing')}
    if ($LiteralPath -eq 'denied') {throw [UnauthorizedAccessException]::new('denied')}
    [pscustomobject]@{FullName=$LiteralPath}
}
Assert-Case ($null -eq (Get-UsbItemIfPresent missing)) 'явный ItemNotFound считается отсутствием'
Assert-Refuse {Get-UsbItemIfPresent denied} 'AccessDenied не превращается в пустую source/metadata'
Assert-Case ((Get-UsbItemIfPresent present).FullName -eq 'present') 'существующий item возвращается'
Remove-Item Function:Get-Item
foreach ($name in @('S-1-5-21-1-2-3-1001','S-1-12-1-1-2-3-4','S-1-5-19')) {
    Assert-Case (Test-UsbHiveRoot $name) "loaded hive включён: $name"
}
foreach ($name in @('.DEFAULT','S-1-12-1-1-2-3-4_Classes')) {
    Assert-Case (-not (Test-UsbHiveRoot $name)) "явно исключённый HKU root: $name"
}

$temp=Join-Path ([IO.Path]::GetTempPath()) ('usb-policy-logic-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$operation=$null
try {
    $data=$temp;$metaPath=Join-Path $temp 'usb.json';$operationPath=Join-Path $temp 'operation.lock'
    $currentRevision='A'*64;$oldRevision='B'*64
    Write-UsbMetadata Applied $oldRevision
    Assert-Case ((Read-UsbMetadata).ConfigRevision -ceq $oldRevision) 'metadata хранит только прежнюю собственную revision'
    foreach ($json in @(('{"Schema":"1","ConfigRevision":"'+$oldRevision+'","State":"Applied"}'),
        '{"Schema":1,"ConfigRevision":"bad","State":"Applied"}',
        ('{"Schema":1,"ConfigRevision":"'+$oldRevision+'","State":"Applied","Snapshot":{}}'))) {
        [IO.File]::WriteAllText($metaPath,$json)
        Assert-Refuse {Read-UsbMetadata} 'чужая/неизвестная metadata отклоняется'
    }
    Write-UsbMetadata Applied $oldRevision
    # Только orchestration с mocked status/PFE. Не Windows registry/GPO test.
    $script:statusCalls=0;$script:statuses=@();$global:usbMockRemove=0;$global:usbMockGpt=0
    function Get-ExamLabUsbStatus {
        param($ConfigRevision)
        $script:statusCalls++
        if (-not $script:statuses.Count) {throw 'unexpected status call'}
        $s=$script:statuses[0];$script:statuses=@($script:statuses | Select-Object -Skip 1);return $s
    }
    function New-MockedStatus([string]$State,[int]$Own,[bool]$Allowed=$true,[bool]$NoOp=$false) {
        [pscustomobject]@{State=$State;OwnSourceEntries=$Own;NormalAllowed=$Allowed;ExamAllowed=$Allowed;
            NormalBlockers=@('foreign policy');ExamBlockers=@('foreign policy');NormalNoOp=$NoOp;ExamNoOp=$NoOp;
            StoredConfigRevision=$oldRevision;ConfigRevision=$currentRevision;Conflicts=@();RequiresUserSignIn=$false}
    }
    $global:usbMockMeta=$metaPath
    New-Module -Name PolicyFileEditor -ScriptBlock {
        function Remove-PolicyFileEntry {
            param($Path,$Key,$ValueName)
            if (([IO.File]::ReadAllText($global:usbMockMeta)|ConvertFrom-Json).State -ne 'Removing') {throw 'intent must precede removal'}
            $global:usbMockRemove++
        }
        function Update-GptIniVersion {param($Path,$PolicyType);$global:usbMockGpt++}
        Export-ModuleMember -Function Remove-PolicyFileEntry,Update-GptIniVersion
    } | Import-Module -Force
    $operation=[IO.File]::Open($operationPath,'OpenOrCreate','ReadWrite','None')
    $wrong=[IO.File]::Open((Join-Path $temp 'wrong.lock'),'OpenOrCreate','ReadWrite','None')
    try { Assert-Refuse {Invoke-ExamLabUsbModeUnderLock normal $currentRevision $wrong} 'чужой lock не допускает даже status' } finally {$wrong.Dispose()}
    Assert-Case ($script:statusCalls -eq 0) 'проверка lock до fresh status'
    $before=(Get-FileHash $metaPath).Hash
    $script:statuses=@((New-MockedStatus Applied 1 $false))
    Assert-Refuse {Invoke-ExamLabUsbModeUnderLock normal $currentRevision $operation} 'foreign conflict до metadata/PFE mutation'
    Assert-Case ((Get-FileHash $metaPath).Hash -ceq $before -and $global:usbMockRemove -eq 0) 'отказ сохраняет intent/source'
    foreach ($state in @('Normal','NotConfigured')) {
        $script:statuses=@((New-MockedStatus $state 0 $true $true))
        $r=Invoke-ExamLabUsbModeUnderLock normal $currentRevision $operation
        Assert-Case (-not $r.Changed -and (Get-FileHash $metaPath).Hash -ceq $before -and $global:usbMockGpt -eq 0) "повтор $state не меняет metadata/GPT"
    }
    $script:statuses=@((New-MockedStatus Applied 1),(New-MockedStatus Removing 0),(New-MockedStatus Normal 0))
    $r=Invoke-ExamLabUsbModeUnderLock normal $currentRevision $operation
    Assert-Case ($r.Changed -and $r.RequiresUserSignIn -and $global:usbMockRemove -eq 1) 'normal адресно удаляет source и требует нового входа'
    $saved=Read-UsbMetadata
    Assert-Case ($saved.State -eq 'Normal' -and $saved.ConfigRevision -ceq $oldRevision) 'cleanup сохраняет прежнюю revision, не перепривязывает intent'
    Assert-Case ($script:statuses.Count -eq 0 -and $operation.CanRead) 'setter свежо проверяет и оставляет caller lock открытым'
    $operation.Dispose();$operation=$null
    $closed=[IO.File]::Open($operationPath,'Open','ReadWrite','None');$closed.Dispose()
    Assert-Refuse {Invoke-ExamLabUsbModeUnderLock normal $currentRevision $closed} 'закрытый lock отклоняется'
    Remove-Module PolicyFileEditor -Force

    # Настоящий ready PFE codec; NoGptIniUpdate допустим только в этом Linux test.
    Import-Module (Join-Path $PolicyFileEditorPath 'PolicyFileEditor.psd1') -Force
    $pol=Join-Path $temp 'registry.pol'
    Set-PolicyFileEntry -Path $pol -Key $disk -ValueName ForeignSibling -Type String -Data preserve -NoGptIniUpdate
    Set-PolicyFileEntry -Path $pol -Key 'Software\Policies\OtherVendor' -ValueName Foreign -Type DWord -Data 7 -NoGptIniUpdate
    Set-PolicyFileEntry -Path $pol -Key $disk -ValueName Deny_Read -Type DWord -Data 1 -NoGptIniUpdate
    Remove-PolicyFileEntry -Path $pol -Key $disk -ValueName Deny_Read -NoGptIniUpdate
    $entries=@(Get-PolicyFileEntry -Path $pol -All)
    Assert-Case ($entries.Count -eq 2) 'готовый PFE удаляет exact entry, сохраняя оба чужих значения'
    Assert-Case (@($entries | Where-Object {$_.ValueName -in @('Deny_Read','**Del.Deny_Read')}).Count -eq 0) 'NotConfigured без deletion tombstone'
    Assert-Case ((Get-PolicyFileEntry -Path $pol -Key $disk -ValueName ForeignSibling).Data -ceq 'preserve') 'чужой class sibling сохраняется codec, но canary его не принимает'
    Assert-Case ((Get-PolicyFileEntry -Path $pol -Key 'Software\Policies\OtherVendor' -ValueName Foreign).Data -eq 7) 'другой vendor сохраняется'
    $before=(Get-FileHash $pol).Hash
    Remove-PolicyFileEntry -Path $pol -Key $disk -ValueName Deny_Read -NoGptIniUpdate
    Assert-Case ((Get-FileHash $pol).Hash -ceq $before) 'повтор удаления отсутствующей entry сохраняет source bytes'
    $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    Assert-Case ($commands -notcontains 'Set-Acl' -and $commands -notcontains 'Invoke-CimMethod' -and $commands -notcontains 'reg.exe') 'нет setter ACL, lifecycle или hive commands'
    Assert-Case ($commands -notcontains 'Add-Type' -and $ast.Extent.Text -notmatch '[''"](?:DELETE|CLEAR)[''"]') 'нет своего codec или broad delete'
    "PASS $count; PowerShell $($PSVersionTable.PSVersion); Windows/ACL/GPT/effective USB НЕ испытывались"
} finally {
    if ($operation) {$operation.Dispose()}
    Remove-Module PolicyFileEditor -Force -ErrorAction SilentlyContinue
    Remove-Variable usbMockRemove,usbMockGpt,usbMockMeta -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temp -Recurse -Force
}
