#Requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateSet('Install', 'UpdateInstalledRunner', 'StartCollection', 'StopCollection', 'Uninstall')]
    [string]$Action = 'Install',
    [string]$MsiPath,
    [string]$ManagerIPv4,
    [string]$AgentKeyPath,
    [switch]$UsePublishedInstallers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Environment]::Is64BitProcess -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Нужен повышенный 64-битный PowerShell 7.'
}

$marker = 'HKLM:\SOFTWARE\ExamLabWazuhPilot'
$code = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabWazuh'
$installedScript = Join-Path $code 'Install-ExamLabWazuh.ps1'
$agent = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'ossec-agent'
$exe = Join-Path $agent 'wazuh-agent.exe'
$config = Join-Path $agent 'ossec.conf'
$internalOptions = Join-Path $agent 'local_internal_options.conf'
$clientKeys = Join-Path $agent 'client.keys'
$response = Join-Path $agent 'active-response\bin\exam-lab-alert.cmd'
$serviceName = 'WazuhSvc'
$msiHash = '54F83C01DD35573D8501EAB553EBDD72AD4DE75383636EFB25F01E782521E83281065F8075A369239C13A5A5E3F3599A754EB3204FF56CFCE2B2AFD9AE911152'
$expectedResponseSha256 = 'D54F8305B4DE1D9F3887AC3C0C055435ECBBEFEBF05E8992C3E1E20B337E0BAE'
$adminSids = @('S-1-5-18', 'S-1-5-32-544')
$trustedSids = $adminSids + @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
$trustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$previousRunnerHashes = @('EE78FF7A7C7997FEB7BE809AC8AC4D6FF84BCFD8E4A4DE9C7EAF5507D32A3AB3',
    '6E3A79D578AF46E53D50746BB216F7E9639DA8D4302F12B4DD6EED2885B16ADA')
$utf8 = [Text.UTF8Encoding]::new($false)
$staged = Join-Path $code 'wazuh-agent-4.14.10-1.msi'
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$uninstallRoots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

function Assert-NoReparse([string]$Path) {
    for ($item = Get-Item -LiteralPath $Path -Force; $null -ne $item; $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'В пути собственной установки найдено перенаправление файловой системы.'
        }
    }
}

function Assert-AdministrativePath([string]$Path, [switch]$Private, [switch]$AllowTrustedInstaller) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedSids) {
        throw "Чужой владелец пути Wazuh: $Path."
    }
    $writeAccess = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trustedSids) { continue }
        if ($AllowTrustedInstaller -and $rule.IsInherited -and $rule.IdentityReference.Value -eq $trustedInstallerSid) { continue }
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($Private -or ($rule.FileSystemRights -band $writeAccess)) { throw "Небезопасный доступ: $Path." }
    }
}

function Get-AgentService {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -OperationTimeoutSec 5
}

function Assert-AgentService($Service) {
    if ($null -eq $Service -or $Service.StartName -ine 'LocalSystem' -or
        $Service.PathName -ine ('"{0}"' -f $exe)) {
        throw 'Служба WazuhSvc отсутствует или отличается от выделенной установки.'
    }
}

function Assert-NoExistingAgent {
    $uninstall = Get-ItemProperty -Path ($uninstallRoots | ForEach-Object { Join-Path $_ '*' }) -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and ($_.DisplayName -like 'Wazuh*' -or $_.DisplayName -like 'OSSEC*') }
    if ((Get-AgentService) -or $uninstall -or (Test-Path -LiteralPath $agent)) {
        throw 'Найдена существующая установка Wazuh. Сначала разберите конфликт.'
    }
    Assert-NoLegacyOssec
}

function Assert-NoLegacyOssec {
    foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Services\OssecSvc', 'HKLM:\SOFTWARE\ossec',
        'HKLM:\SOFTWARE\WOW6432Node\ossec') + @($uninstallRoots | ForEach-Object { Join-Path $_ 'OSSEC' })) {
        if (Test-Path -LiteralPath $path) { throw 'Найдена собственная конфигурация OSSEC. MSI Wazuh мог бы удалить её.' }
    }
}

function Assert-WazuhMsiDirectory {
    $paths = @(foreach ($path in 'HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent',
        'HKLM:\SOFTWARE\Wazuh, Inc.\Wazuh Agent') {
        if (Test-Path -LiteralPath $path) { Get-ItemPropertyValue -LiteralPath $path -Name 'WazuhInstallDir' }
    })
    if ($paths.Count -ne 1 -or $paths[0] -isnot [string] -or $paths[0].TrimEnd('\') -ine $agent) {
        throw 'Каталог, зарегистрированный Wazuh MSI, отличается от выделенной установки.'
    }
}

function Assert-NoWazuhReparseChildren([IO.DirectoryInfo]$Directory) {
    foreach ($child in $Directory.EnumerateFileSystemInfos()) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "MSI Wazuh остановлен перед удалением. Найдено перенаправление: $($child.FullName)."
        }
        if ($child -is [IO.DirectoryInfo]) { Assert-NoWazuhReparseChildren $child }
    }
}

function Get-WazuhProductCode([string]$Path) {
    $automation = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    try {
        $database = $automation.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $automation, @($Path, 0))
        $properties = @{}
        foreach ($name in 'ProductCode','ProductVersion') {
            $view = $record = $null
            try {
                $query = 'SELECT `Value` FROM `Property` WHERE `Property` = ''{0}''' -f $name
                $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @($query))
                [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
                $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
                if (-not $record) { throw "В подписанном MSI нет значения $name." }
                $properties[$name] = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
            } finally {
                foreach ($object in $record, $view) {
                    if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
                }
            }
        }
        $productCode = $properties.ProductCode
        if ($properties.ProductVersion -cne '4.14.10') { throw 'Подписанный MSI имеет отличающуюся версию Wazuh.' }
        if ($productCode -cnotmatch '\A\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}\z') {
            throw 'В подписанном MSI нет корректного ProductCode.'
        }
        $productCode.ToUpperInvariant()
    } finally {
        foreach ($object in $database, $automation) {
            if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
        }
    }
}

function Read-WazuhPackage([string]$Path) {
    if (-not $UsePublishedInstallers -and (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash -cne $msiHash) {
        throw 'SHA-512 MSI Wazuh 4.14.10-1 не совпадает.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'Wazuh, Inc') {
        throw 'Ожидается действительная подпись Wazuh, Inc на MSI.'
    }
    Get-WazuhProductCode $Path
}

function Get-RegisteredWazuhProduct([string]$ProductCode) {
    if ($ProductCode -cnotmatch '\A\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}\z') {
        throw 'Некорректный ProductCode выделенной установки Wazuh.'
    }
    $products = @(foreach ($root in $uninstallRoots) {
        $path = Join-Path $root $ProductCode
        if (Test-Path -LiteralPath $path) { Get-ItemProperty -LiteralPath $path }
    })
    if ($products.Count -gt 1 -or ($products.Count -eq 1 -and
        (-not $products[0].PSObject.Properties['WindowsInstaller'] -or $products[0].WindowsInstaller -ne 1 -or
         -not $products[0].PSObject.Properties['DisplayName'] -or $products[0].DisplayName -cne 'Wazuh Agent' -or
         -not $products[0].PSObject.Properties['DisplayVersion'] -or $products[0].DisplayVersion -cne '4.14.10'))) {
        throw 'Регистрация MSI не совпадает с выделенным продуктом Wazuh.'
    }
    $products
}

function Invoke-WazuhMsi([string]$Arguments) {
    $arguments = "$Arguments /qn /norestart GENERATE_DUMP=0"
    if ($Action -eq 'Install' -and $UsePublishedInstallers -and $env:EXAMLAB_DIAGNOSTICS_DIR) {
        $logPath = Join-Path $env:EXAMLAB_DIAGNOSTICS_DIR 'wazuh-install.log'
        $arguments += ' /L*v "{0}"' -f $logPath
    }
    $process = Start-Process -FilePath $msiexec -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) { throw "MSI Wazuh завершился кодом $($process.ExitCode)." }
}

function Set-PreparedFile([string]$Path, [byte[]]$Bytes, $Acl) {
    $pending = "$Path.examlab-next"
    if (Test-Path -LiteralPath $pending) {
        Assert-AdministrativePath $pending
        Remove-Item -LiteralPath $pending
    }
    [IO.File]::Create($pending).Dispose()
    if ($Acl) { Set-Acl -LiteralPath $pending -AclObject $Acl }
    [IO.File]::WriteAllBytes($pending, $Bytes)
    if (Test-Path -LiteralPath $Path) {
        Assert-AdministrativePath $Path
        if ($Acl) { Set-Acl -LiteralPath $Path -AclObject $Acl }
        [IO.File]::Replace($pending, $Path, [NullString]::Value)
    } else {
        [IO.File]::Move($pending, $Path)
    }
}

function Set-CollectionService([string]$ExpectedState) {
    $current = Get-AgentService
    Assert-AgentService $current
    if ($current.StartMode -ne 'Manual') { throw 'Изменён режим запуска WazuhSvc.' }
    $pending = if ($ExpectedState -eq 'Running') { 'Start Pending' } else { 'Stop Pending' }
    if ($current.State -notin $ExpectedState, $pending) {
        $method = if ($ExpectedState -eq 'Running') { 'StartService' } else { 'StopService' }
        $result = Invoke-CimMethod -InputObject $current -MethodName $method -OperationTimeoutSec 5
        if ($result.ReturnValue -notin 0, 6, 10) { throw "Служба Wazuh отклонила $method, код $($result.ReturnValue)." }
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $current = Get-AgentService
        if ($current.State -eq $ExpectedState -and $current.StartMode -eq 'Manual') {
            return $current | Select-Object Name, State, StartMode
        }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt 8)
    throw "Служба Wazuh не подтвердила состояние $ExpectedState за отведённое время."
}

function Assert-OwnedInstallation($State, [switch]$CheckCollection, [string]$RunnerSha256) {
    if ($State.InstallState -cne 'Installed') {
        throw 'Подготовка Wazuh прервана. Проверьте состояние MSI и службы перед повтором.'
    }
    $service = Get-AgentService
    Assert-AgentService $service
    if ($State.PSObject.Properties['ProductCode'] -and -not (Get-RegisteredWazuhProduct $State.ProductCode)) {
        throw 'Регистрация выделенного MSI Wazuh отсутствует.'
    }
    if ($service.StartMode -ne 'Manual') { throw 'Изменён режим запуска WazuhSvc.' }
    if (-not $RunnerSha256) { $RunnerSha256 = $State.SourceSha256 }
    $files = @(
        @{ Path = $installedScript; Hash = $RunnerSha256 },
        @{ Path = $exe; Hash = $State.AgentSha256 }
    )
    Assert-AdministrativePath $agent
    if ($CheckCollection) {
        Assert-AdministrativePath (Split-Path -Parent $response)
        Assert-AdministrativePath $clientKeys -Private
        $files += @(
            @{ Path = $config; Hash = $State.ConfigSha256 },
            @{ Path = $internalOptions; Hash = $State.OptionsSha256 },
            @{ Path = $response; Hash = $State.ResponseSha256 },
            @{ Path = $clientKeys; Hash = $State.ClientKeySha256 }
        )
    }
    foreach ($file in $files) {
        Assert-AdministrativePath $file.Path
        if ((Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash -cne $file.Hash) {
            throw "Изменён файл выделенной установки Wazuh: $($file.Path)."
        }
    }
}

function Update-OwnedRunner($State, [string]$IncomingHash) {
    Assert-AdministrativePath $installedScript -Private
    $installedHash = (Get-FileHash -LiteralPath $installedScript).Hash
    if ($State.SourceSha256 -ceq $IncomingHash -and $installedHash -ceq $IncomingHash) {
        Assert-OwnedInstallation $State -CheckCollection
        return $false
    }
    # Старый маркер и новый файл возможны после прерывания атомарной замены.
    if ($State.SourceSha256 -cnotin $previousRunnerHashes -or
        ($installedHash -cne $State.SourceSha256 -and $installedHash -cne $IncomingHash)) {
        throw 'Версия установленного сценария не соответствует поддерживаемому переходу Wazuh.'
    }
    Assert-OwnedInstallation $State -CheckCollection -RunnerSha256 $installedHash
    if ((Get-AgentService).State -ne 'Stopped') { throw 'Обновление сценария требует остановленного WazuhSvc.' }
    if ($installedHash -cne $IncomingHash) {
        Set-PreparedFile $installedScript ([IO.File]::ReadAllBytes($PSCommandPath)) $null
    }
    if ((Get-FileHash -LiteralPath $installedScript).Hash -cne $IncomingHash) { throw 'Не совпал хеш после замены.' }
    Set-ItemProperty -LiteralPath $marker -Name SourceSha256 -Value $IncomingHash
    Assert-OwnedInstallation (Get-ItemProperty -LiteralPath $marker) -CheckCollection
    return $true
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

if ($Action -eq 'Install') {
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
    if ($responseHash -cne $expectedResponseSha256) { throw 'Неизвестная команда Active Response из комплекта.' }
    if (-not (Test-Path -LiteralPath $code)) {
        if (Test-Path -LiteralPath $marker) { throw 'Отсутствует каталог ранее установленного Wazuh.' }
        Assert-NoExistingAgent
        Assert-NoReparse (Split-Path -Parent $code)
        $folderAcl = [Security.AccessControl.DirectorySecurity]::new()
        $folderAcl.SetAccessRuleProtection($true, $false)
        foreach ($value in $adminSids) {
            $sid = [Security.Principal.SecurityIdentifier]::new($value)
            $folderAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        }
        [void][IO.FileSystemAclExtensions]::CreateDirectory($folderAcl, $code)
    }
}
Assert-AdministrativePath $code -Private
$lockPath = Join-Path $code 'service.lock'
if (Test-Path -LiteralPath $lockPath) { Assert-AdministrativePath $lockPath -Private }
try { $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None') }
catch { throw 'Не удалось получить исключительный доступ к выделенной установке Wazuh.' }
$removePrivate = $false
try {
    $state = if (Test-Path -LiteralPath $marker) { Get-ItemProperty -LiteralPath $marker }
    if ($Action -eq 'UpdateInstalledRunner') {
        $service = Get-AgentService
        if ($null -eq $state -or $state.InstallState -cne 'Installed' -or $null -eq $service -or $service.State -ne 'Stopped') {
            throw 'Обновление сценария требует завершённой установки и остановленного WazuhSvc.'
        }
        $incomingHash = (Get-FileHash -LiteralPath $PSCommandPath).Hash
        $changed = Update-OwnedRunner $state $incomingHash
        [pscustomobject]@{ Installed = $true; Changed = $changed; SourceSha256 = $incomingHash }
        return
    }
    if ($Action -ne 'Install') {
        if ($null -eq $state -or $PSCommandPath -ine $installedScript) {
            throw 'Действие доступно из установленного сценария выделенного агента Wazuh.'
        }
        if ($Action -eq 'Uninstall') {
            if (-not $state.PSObject.Properties['ProductCode'] -or $state.InstallState -cnotin 'Installed','Uninstalling') {
                throw 'Нет подтверждённого ProductCode собственной установки Wazuh.'
            }
            Assert-AdministrativePath $installedScript -Private
            if ((Get-FileHash -LiteralPath $installedScript).Hash -cne $state.SourceSha256) {
                throw 'Стало невозможно подтвердить установленный сценарий Wazuh.'
            }
            if (@(Get-ChildItem -LiteralPath $code -Force | Where-Object Name -cnotin 'Install-ExamLabWazuh.ps1','service.lock').Count) {
                throw 'Закрытый каталог содержит дополнительные файлы. Сохраните их и проверьте происхождение.'
            }
            $product = Get-RegisteredWazuhProduct $state.ProductCode
            if ($product) {
                $state.InstallState = 'Installed'
                Assert-OwnedInstallation $state -CheckCollection
                Assert-NoLegacyOssec
                Assert-WazuhMsiDirectory
                if ((Get-AgentService).State -ne 'Stopped') { throw 'Сначала завершите экзамен и остановите выделенный WazuhSvc.' }
                Assert-NoWazuhReparseChildren (Get-Item -LiteralPath $agent -Force)
                foreach ($path in $config, $internalOptions, $clientKeys, (Join-Path $agent 'installer.log')) {
                    if (Test-Path -LiteralPath "$path.save") { throw "Существующая резервная копия Wazuh сохранена: $path.save." }
                }
                $installerLog = Join-Path $agent 'installer.log'
                if (Test-Path -LiteralPath $installerLog) {
                    Assert-AdministrativePath $installerLog
                    Set-ItemProperty -LiteralPath $marker -Name InstallerLogSha256 -Value (Get-FileHash -LiteralPath $installerLog).Hash
                }
                Set-ItemProperty -LiteralPath $marker -Name InstallState -Value 'Uninstalling'
                Invoke-WazuhMsi ('/x {0}' -f $state.ProductCode)
            } elseif ($state.InstallState -cne 'Uninstalling') {
                throw 'Установленная регистрация MSI уже отсутствует. Сохранено исходное состояние учёта.'
            }
            if ((Get-RegisteredWazuhProduct $state.ProductCode) -or (Get-AgentService)) {
                throw 'Штатное удаление не подтвердило отсутствие продукта и службы.'
            }
            if (Test-Path -LiteralPath $agent) {
                # MSI переименовывает установочные файлы в *.save. Сверяем содержимое перед удалением.
                $remembered = Get-ItemProperty -LiteralPath $marker
                $ownedFiles = @(
                    @{ Path = $config; Hash = $state.ConfigSha256 },
                    @{ Path = $internalOptions; Hash = $state.OptionsSha256 },
                    @{ Path = $clientKeys; Hash = $state.ClientKeySha256 },
                    @{ Path = $response; Hash = $state.ResponseSha256 })
                if ($remembered.PSObject.Properties['InstallerLogSha256']) {
                    $ownedFiles += @{ Path = (Join-Path $agent 'installer.log'); Hash = $remembered.InstallerLogSha256 }
                }
                foreach ($file in $ownedFiles) {
                    foreach ($path in $file.Path, "$($file.Path).save") {
                        if (-not (Test-Path -LiteralPath $path)) { continue }
                        Assert-AdministrativePath $path
                        if ((Get-FileHash -LiteralPath $path).Hash -cne $file.Hash) {
                            throw "После удаления MSI сохранился изменённый файл: $path."
                        }
                        Remove-Item -LiteralPath $path
                    }
                }
                foreach ($path in (Join-Path $agent 'backup'), (Join-Path $agent 'upgrade'), $agent) {
                    if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
                    Assert-AdministrativePath $path
                    if (-not (Get-ChildItem -LiteralPath $path -Force | Select-Object -First 1)) {
                        [IO.Directory]::Delete($path)
                    }
                }
            }
            $removePrivate = $true
            [pscustomobject]@{ Removed = $true; ProductCode = $state.ProductCode; PreservedAgentDirectory = (Test-Path -LiteralPath $agent) }
            return
        }
        if ($Action -eq 'StartCollection') {
            Assert-OwnedInstallation $state -CheckCollection
            $alertCode = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabAlert'
            Assert-AdministrativePath $alertCode -AllowTrustedInstaller
            Assert-AdministrativePath (Join-Path $alertCode 'ExamLabAlert.ps1') -AllowTrustedInstaller
            if (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\ExamLabAlertPilot')) {
                throw 'Сначала инициализируйте локальный приёмник оповещения.'
            }
            Set-CollectionService 'Running'
        } else {
            if ($state.InstallState -ceq 'Uninstalling') {
                Assert-AdministrativePath $installedScript -Private
                if ((Get-FileHash -LiteralPath $installedScript).Hash -cne $state.SourceSha256) {
                    throw 'Изменён установленный сценарий Wazuh.'
                }
                if (-not (Get-RegisteredWazuhProduct $state.ProductCode) -and -not (Get-AgentService)) {
                    [pscustomobject]@{Name=$serviceName; State='Stopped'; StartMode=$null}
                    return
                }
                $state.InstallState = 'Installed'
            }
            Assert-OwnedInstallation $state
            Set-CollectionService 'Stopped'
        }
        return
    }

    if ($state -and $state.PSObject.Properties['InstallState'] -and $state.InstallState -ceq 'Installed') {
        Assert-AdministrativePath $clientKeys -Private
        if ($state.ManagerIPv4 -cne $ManagerIPv4 -or $state.ResponseSha256 -cne $responseHash -or
            [IO.File]::ReadAllText($clientKeys).TrimEnd() -cne $keyLine) {
            throw 'Параметры или файлы отличаются от выделенной установки Wazuh.'
        }
        $productCode = $null
        if (-not $state.PSObject.Properties['ProductCode']) {
            $productCode = Read-WazuhPackage $msi
            if (-not (Get-RegisteredWazuhProduct $productCode)) {
                throw 'Существующая регистрация Wazuh не совпадает с пакетом выпуска.'
            }
            Assert-WazuhMsiDirectory
        }
        $changed = Update-OwnedRunner $state $sourceHash
        if ($productCode) {
            Set-ItemProperty -LiteralPath $marker -Name ProductCode -Value $productCode
            $changed = $true
        }
        [pscustomobject]@{ Installed = $true; Changed = $changed; Service = $serviceName }
        return
    }

    if ($state -and $state.PSObject.Properties['InstallState'] -and $state.InstallState -cne 'Preparing') {
        throw 'Другое обслуживание выделенной установки Wazuh ещё не завершено.'
    }
    Assert-NoReparse (Split-Path -Parent $agent)

    $keyAcl = [Security.AccessControl.FileSecurity]::new()
    $keyAcl.SetAccessRuleProtection($true, $false)
    foreach ($value in $adminSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($value)
        $keyAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    $complete = $false
    try {
        if (Test-Path -LiteralPath $staged) { Assert-AdministrativePath $staged -Private }
        [IO.File]::Copy($msi, $staged, $true)
        $stagedHash = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash
        $productCode = Read-WazuhPackage $staged
        $digest = [Security.Cryptography.SHA256]::Create()
        try { $keyHash = [BitConverter]::ToString($digest.ComputeHash($utf8.GetBytes("$keyLine`n"))).Replace('-', '') }
        finally { $digest.Dispose() }
        $preparation = [ordered]@{
            ProductCode=$productCode; MsiSha256=$stagedHash; ManagerIPv4=$ManagerIPv4
            ClientKeySha256=$keyHash; SourceSha256=$sourceHash; ResponseSha256=$responseHash
        } | ConvertTo-Json -Compress
        if ($state -and $state.PSObject.Properties['Preparation']) {
            if ($state.Preparation -cne $preparation) { throw 'Пакет или регистрация изменились после начала установки Wazuh.' }
        } else {
            Assert-NoExistingAgent
            if (@(Get-ChildItem -LiteralPath $code -Force | Where-Object Name -cnotin 'service.lock','wazuh-agent-4.14.10-1.msi').Count) {
                throw 'Служебный каталог содержит файлы предыдущей подготовки Wazuh.'
            }
            if (-not $state) { [void](New-Item -Path $marker) }
            Set-ItemProperty -LiteralPath $marker -Name Preparation -Value $preparation
        }
        Set-ItemProperty -LiteralPath $marker -Name InstallState -Value 'Preparing'
        if (-not (Get-RegisteredWazuhProduct $productCode)) {
            Assert-NoExistingAgent
            Invoke-WazuhMsi ('/i "{0}"' -f $staged)
        }
        if (-not (Get-RegisteredWazuhProduct $productCode)) { throw 'Windows Installer не подтвердил регистрацию продукта Wazuh.' }
        Assert-WazuhMsiDirectory
        Assert-AgentService (Get-AgentService)
        Set-Service -Name $serviceName -StartupType Manual
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Set-CollectionService 'Stopped' | Out-Null
            throw 'MSI неожиданно запустил службу Wazuh. Служба остановлена.'
        }
        Assert-AdministrativePath $agent
        Assert-AdministrativePath $config
        Assert-AdministrativePath (Split-Path -Parent $response)
        if (Test-Path -LiteralPath $response) {
            Assert-AdministrativePath $response
            if ((Get-FileHash -LiteralPath $response).Hash -cne $responseHash) { throw 'Команда Active Response уже существует и отличается.' }
        }
        if (Test-Path -LiteralPath $clientKeys) {
            Assert-AdministrativePath $clientKeys
            if ((Get-Item -LiteralPath $clientKeys).Length -ne 0 -and
                (Get-FileHash -LiteralPath $clientKeys).Hash -cne $keyHash) { throw 'В агенте уже существует другой ключ регистрации.' }
        }
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
        Set-PreparedFile $config $utf8.GetBytes($agentConfig) $null
        Set-PreparedFile $internalOptions $utf8.GetBytes("agent.remote_conf=0`n") $null
        Set-PreparedFile $response ([IO.File]::ReadAllBytes((Get-Item -LiteralPath $responseSource).FullName)) $null
        Set-PreparedFile $installedScript ([IO.File]::ReadAllBytes($PSCommandPath)) $null
        Assert-AdministrativePath $installedScript -Private
        if ((Get-FileHash -LiteralPath $installedScript).Hash -cne $sourceHash -or
            (Get-FileHash -LiteralPath $response).Hash -cne $responseHash) {
            throw 'Исходный сценарий изменился во время подготовки Wazuh.'
        }
        Set-ItemProperty -LiteralPath $marker -Name SourceSha256 -Value $sourceHash
        Set-ItemProperty -LiteralPath $marker -Name ResponseSha256 -Value $responseHash
        Set-ItemProperty -LiteralPath $marker -Name AgentSha256 -Value (Get-FileHash -LiteralPath $exe).Hash
        Set-ItemProperty -LiteralPath $marker -Name ConfigSha256 -Value (Get-FileHash -LiteralPath $config).Hash
        Set-ItemProperty -LiteralPath $marker -Name OptionsSha256 -Value (Get-FileHash -LiteralPath $internalOptions).Hash
        Set-PreparedFile $clientKeys $utf8.GetBytes("$keyLine`n") $keyAcl
        Assert-AdministrativePath $clientKeys -Private
        Set-ItemProperty -LiteralPath $marker -Name ClientKeySha256 -Value (Get-FileHash -LiteralPath $clientKeys).Hash
        Set-ItemProperty -LiteralPath $marker -Name ManagerIPv4 -Value $ManagerIPv4
        Set-ItemProperty -LiteralPath $marker -Name ProductCode -Value $productCode
        Remove-Item -LiteralPath $staged
        Set-ItemProperty -LiteralPath $marker -Name InstallState -Value 'Installed'
        $complete = $true
    } finally {
        if (-not $complete -and (Test-Path -LiteralPath $staged)) { Remove-Item -LiteralPath $staged }
    }
    [pscustomobject]@{ Installed = $true; Changed = $true; Service = $serviceName }
} finally {
    $lock.Dispose()
    if ($removePrivate) {
        Remove-Item -LiteralPath $lockPath
        Remove-Item -LiteralPath $installedScript
        Remove-Item -LiteralPath $code
        Remove-Item -LiteralPath $marker
    }
}
