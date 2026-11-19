#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Install', 'StartCollection', 'StopCollection')]
    [string]$Action = 'Install',
    [string]$MsiPath,
    [string]$ManagerIPv4,
    [string]$AgentKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Environment]::Is64BitProcess -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Нужен повышенный 64-битный Windows PowerShell.'
}

$marker = 'HKLM:\SOFTWARE\ExamLabWazuhPilot'
$code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabWazuh'
$installedScript = Join-Path $code 'Install-ExamLabWazuh.ps1'
$agent = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'ossec-agent'
$exe = Join-Path $agent 'wazuh-agent.exe'
$config = Join-Path $agent 'ossec.conf'
$clientKeys = Join-Path $agent 'client.keys'
$response = Join-Path $agent 'active-response\bin\exam-lab-alert.cmd'
$serviceName = 'WazuhSvc'
$msiHash = '54F83C01DD35573D8501EAB553EBDD72AD4DE75383636EFB25F01E782521E83281065F8075A369239C13A5A5E3F3599A754EB3204FF56CFCE2B2AFD9AE911152'
$utf8 = [Text.UTF8Encoding]::new($false)

function Assert-NoReparse([string]$Path) {
    for ($item = Get-Item -LiteralPath $Path -Force; $null -ne $item; $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'В пути собственной установки найдено перенаправление файловой системы.'
        }
    }
}

function Get-AgentService {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
}

function Assert-AgentService($Service) {
    if ($null -eq $Service -or $Service.StartName -ine 'LocalSystem' -or
        $Service.PathName -ine ('"{0}"' -f $exe)) {
        throw 'Служба WazuhSvc отсутствует или отличается от выделенной установки.'
    }
}

function Assert-OwnedInstallation($State, [switch]$CheckCollection) {
    if ($State.InstallState -cne 'Installed') {
        throw 'Подготовка Wazuh прервана. Проверьте состояние MSI и службы перед повтором.'
    }
    $service = Get-AgentService
    Assert-AgentService $service
    if ($service.StartMode -ne 'Manual') { throw 'Изменён режим запуска WazuhSvc.' }
    $files = @(
        @{ Path = $installedScript; Hash = $State.SourceSha256 },
        @{ Path = $exe; Hash = $State.AgentSha256 }
    )
    if ($CheckCollection) {
        $files += @(
            @{ Path = $config; Hash = $State.ConfigSha256 },
            @{ Path = $response; Hash = $State.ResponseSha256 },
            @{ Path = $clientKeys; Hash = $State.ClientKeySha256 }
        )
    }
    foreach ($file in $files) {
        Assert-NoReparse $file.Path
        if ((Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash -cne $file.Hash) {
            throw "Изменён файл выделенной установки Wazuh: $($file.Path)."
        }
    }
}

function Get-AgentKeyLine([string]$Path) {
    try {
        $inputFile = Get-Item -LiteralPath $Path -Force
        if ($inputFile.PSIsContainer -or $inputFile.Length -gt 1024) { throw 'Размер' }
        $encoded = [IO.File]::ReadAllText($inputFile.FullName).Trim()
        $line = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($encoded))
        if ($line -cnotmatch '^\d{3,8} [A-Za-z0-9_.-]+ [A-Za-z0-9.:/_-]+ [A-Fa-f0-9]{64}$') { throw 'Формат' }
        $line
    } catch {
        throw 'Не удалось прочитать один ключ, экспортированный менеджером Wazuh.'
    }
}

$mutex = [Threading.Mutex]::new($false, 'Global\ExamLabWazuhPilot')
$held = $false
try {
    try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { throw 'Установка или изменение службы Wazuh уже выполняется.' }
    $state = if (Test-Path -LiteralPath $marker) { Get-ItemProperty -LiteralPath $marker }
    if ($Action -ne 'Install') {
        if ($null -eq $state -or $PSCommandPath -ine $installedScript) {
            throw 'Действие доступно из установленного сценария выделенного агента Wazuh.'
        }
        if ($Action -eq 'StartCollection') {
            Assert-OwnedInstallation $state -CheckCollection
            $expectedStatus = 'Running'
            Start-Service -Name $serviceName
        } else {
            Assert-OwnedInstallation $state
            $expectedStatus = 'Stopped'
            Stop-Service -Name $serviceName
        }
        $service = Get-AgentService
        if ($service.State -ne $expectedStatus -or $service.StartMode -ne 'Manual') {
            throw "Состояние WazuhSvc не подтвердило действие $Action."
        }
        $service | Select-Object Name, State, StartMode
        return
    }

    $address = $null
    if (-not $MsiPath -or -not $AgentKeyPath -or -not [Net.IPAddress]::TryParse($ManagerIPv4, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $ManagerIPv4) {
        throw 'Укажите MsiPath, AgentKeyPath и IPv4 локального менеджера в десятичной записи.'
    }
    $keyLine = Get-AgentKeyLine $AgentKeyPath
    $msi = (Get-Item -LiteralPath $MsiPath).FullName
    $sourceHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $responseSource = Join-Path $PSScriptRoot '..\windows\alert\exam-lab-alert.cmd'
    $responseHash = (Get-FileHash -LiteralPath $responseSource -Algorithm SHA256).Hash
    if ($null -ne $state) {
        Assert-OwnedInstallation $state -CheckCollection
        if ($state.ManagerIPv4 -cne $ManagerIPv4 -or $state.SourceSha256 -cne $sourceHash -or
            $state.ResponseSha256 -cne $responseHash -or [IO.File]::ReadAllText($clientKeys).TrimEnd() -cne $keyLine) {
            throw 'Параметры или файлы отличаются от выделенной установки Wazuh.'
        }
        [pscustomobject]@{ Installed = $true; Changed = $false; Service = $serviceName }
        return
    }

    $uninstall = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'Wazuh*' }
    if ((Get-AgentService) -or $uninstall -or (Test-Path -LiteralPath $agent) -or (Test-Path -LiteralPath $code)) {
        throw 'Найдены существующая установка Wazuh или служебный каталог. Сначала разберите конфликт.'
    }
    Assert-NoReparse (Split-Path -Parent $code)
    Assert-NoReparse (Split-Path -Parent $agent)

    $adminSids = @('S-1-5-18', 'S-1-5-32-544')
    $folderAcl = [Security.AccessControl.DirectorySecurity]::new()
    $folderAcl.SetAccessRuleProtection($true, $false)
    $keyAcl = [Security.AccessControl.FileSecurity]::new()
    $keyAcl.SetAccessRuleProtection($true, $false)
    foreach ($value in $adminSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($value)
        $folderAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        $keyAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($code, $folderAcl)
    Assert-NoReparse $code
    $staged = Join-Path $code 'wazuh-agent-4.14.10-1.msi'
    try {
        [IO.File]::Copy($msi, $staged)
        if ((Get-FileHash -LiteralPath $staged -Algorithm SHA512).Hash -cne $msiHash) {
            throw 'SHA-512 MSI Wazuh 4.14.10-1 не совпадает.'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $staged
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -ne 'Wazuh Inc.') {
            throw 'Ожидается действительная подпись Wazuh Inc. на MSI.'
        }
        [void](New-Item -Path $marker)
        Set-ItemProperty -LiteralPath $marker -Name InstallState -Value 'Preparing'
        $installer = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $install = Start-Process -FilePath $installer -ArgumentList ('/i "{0}" /qn /norestart' -f $staged) -Wait -PassThru
        if ($install.ExitCode -ne 0) { throw "MSI Wazuh завершился кодом $($install.ExitCode)." }
        Assert-AgentService (Get-AgentService)
        Set-Service -Name $serviceName -StartupType Manual
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Stop-Service -Name $serviceName
            throw 'MSI неожиданно запустил службу Wazuh. Служба остановлена.'
        }
        Assert-NoReparse $config
        Assert-NoReparse (Split-Path -Parent $response)
        if (Test-Path -LiteralPath $response) { throw 'Команда Active Response уже существует.' }
        if (Test-Path -LiteralPath $clientKeys) {
            Assert-NoReparse $clientKeys
            if ((Get-Item -LiteralPath $clientKeys).Length -ne 0) { throw 'В агенте уже существует ключ регистрации.' }
        } else {
            [IO.File]::Create($clientKeys).Dispose()
        }
        Set-Acl -LiteralPath $clientKeys -AclObject $keyAcl
        [IO.File]::WriteAllText($clientKeys, "$keyLine`n", $utf8)
        $agentConfig = @"
<ossec_config>
  <client>
    <server><address>$ManagerIPv4</address><port>1514</port><protocol>tcp</protocol></server>
    <crypto_method>aes</crypto_method>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>no</auto_restart>
    <enrollment><enabled>no</enabled></enrollment>
  </client>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
    <only-future-events>yes</only-future-events>
    <query>*[System[Provider[@Name='ExamLab-Alert'] and EventID=6101 and Level=3]]</query>
  </localfile>
  <rootcheck><disabled>yes</disabled></rootcheck>
  <syscheck><disabled>yes</disabled></syscheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><disabled>yes</disabled></wodle>
  <wodle name="cis-cat"><disabled>yes</disabled></wodle>
  <wodle name="osquery"><disabled>yes</disabled></wodle>
  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
  <logging><log_format>plain</log_format></logging>
</ossec_config>
"@
        [IO.File]::WriteAllText($config, $agentConfig, $utf8)
        [IO.File]::Copy((Get-Item -LiteralPath $responseSource).FullName, $response)
        [IO.File]::Copy($PSCommandPath, $installedScript)
        if ((Get-FileHash -LiteralPath $installedScript).Hash -cne $sourceHash -or
            (Get-FileHash -LiteralPath $response).Hash -cne $responseHash) {
            throw 'Исходный сценарий изменился во время подготовки Wazuh.'
        }
        Set-ItemProperty -LiteralPath $marker -Name SourceSha256 -Value $sourceHash
        Set-ItemProperty -LiteralPath $marker -Name ResponseSha256 -Value $responseHash
        Set-ItemProperty -LiteralPath $marker -Name AgentSha256 -Value (Get-FileHash -LiteralPath $exe).Hash
        Set-ItemProperty -LiteralPath $marker -Name ConfigSha256 -Value (Get-FileHash -LiteralPath $config).Hash
        Set-ItemProperty -LiteralPath $marker -Name ClientKeySha256 -Value (Get-FileHash -LiteralPath $clientKeys).Hash
        Set-ItemProperty -LiteralPath $marker -Name ManagerIPv4 -Value $ManagerIPv4
        Set-ItemProperty -LiteralPath $marker -Name InstallState -Value 'Installed'
    } finally {
        if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged }
        if (-not (Test-Path -LiteralPath $marker)) { Remove-Item -LiteralPath $code }
    }
    [pscustomobject]@{ Installed = $true; Changed = $true; Service = $serviceName }
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
