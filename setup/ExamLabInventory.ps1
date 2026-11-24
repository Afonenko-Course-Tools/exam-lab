[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$storage = 'root/Microsoft/Windows/Storage'
$unknown = 'недоступно'
$raw = Join-Path ([IO.Path]::GetDirectoryName($OutputPath)) 'inventory-raw'
[void][IO.Directory]::CreateDirectory($raw)

function Read-InventoryData([string]$Name, [scriptblock]$Read) {
    try {
        $data = @(& $Read)
        Export-Clixml -InputObject $data -LiteralPath (Join-Path $raw "$Name.clixml") -Depth 4
        $data
    } catch {
        $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $raw "$Name-error.txt") -Encoding UTF8
        throw
    }
}

function Section([string]$Title, [scriptblock]$Read) {
    ''
    "[$Title]"
    try {
        $rows = @(& $Read)
        if ($rows.Count) { $rows } else { 'Нет данных.' }
    } catch { 'Недоступно в текущем сеансе Windows.' }
}

function Size($Value) {
    if ($null -eq $Value) { return $unknown }
    '{0} байт ({1:N2} ГиБ)' -f [uint64]$Value, ($Value / 1GB)
}

function YesNo($Value) {
    if ($Value -is [bool]) { if ($Value) { 'да' } else { 'нет' } } else { $unknown }
}

function Letter($Value) {
    if ([string]$Value -match '\A([A-Za-z]):?(?:\\|\z)') { return $Matches[1].ToUpperInvariant() + ':' }
    '—'
}

function AssociationDeviceId($Reference) {
    if ($Reference -is [string]) {
        if ($Reference -match 'DeviceID="([^"\r\n]+)"') { $Matches[1] }
    } elseif ($null -ne $Reference -and $Reference.PSObject.Properties['DeviceID']) { $Reference.DeviceID }
}

function Read-InventoryPolicy([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ItemProperty -LiteralPath $Path
    foreach ($child in Get-ChildItem -LiteralPath $Path) { Get-ItemProperty -LiteralPath $child.PSPath }
}

function Text($Value) {
    if ($null -eq $Value -or [string]$Value -notmatch '\A[\p{L}\p{N} ()+.,_/@-]{1,90}\z') { return $unknown }
    [string]$Value
}

function Code($Value, $Names) {
    if ($null -eq $Value) { return $unknown }
    if ($Names.ContainsKey([int]$Value)) { return $Names[[int]$Value] }
    "код $([int]$Value)"
}

function VersionText($Value) {
    $match = [regex]::Match([string]$Value, '\A[0-9]+(?:[._+-][0-9]+){0,6}(?:\.windows\.[0-9]+)?\z')
    if ($match.Success -and $match.Length -le 40) { $match.Value }
}

$driveTypes = @{0='неизвестно';1='нет корня';2='съёмный';3='локальный';5='оптический';6='RAM-диск'}
$bus = @{0='неизвестно';1='SCSI';2='ATAPI';3='ATA';4='IEEE 1394';6='Fibre Channel';7='USB';8='RAID';9='iSCSI';10='SAS';11='SATA';12='SD';13='MMC';14='виртуальный';15='файловый виртуальный';16='Storage Spaces';17='NVMe';18='SCM';19='UFS'}
$styles = @{0='RAW';1='MBR';2='GPT'}
$media = @{
    1='Wi-Fi'; 8='беспроводная WAN'; 9='Wi-Fi'; 10='Bluetooth'; 12='WiMAX'; 14='Ethernet'
    15='Token Ring'; 16='IrDA'; 17='проводная WAN'; 18='проводная CoWAN'; 19='другой'
}

$lines = @(
    'ExamLab — инвентаризация Windows'
    'Локальная проверка чтения. Возможности провайдеров зависят от прав и редакции Windows.'
    Section 'Windows и системные диски' {
        $os = Read-InventoryData 'windows' { Get-CimInstance Win32_OperatingSystem -Property Caption,Version,BuildNumber,OSArchitecture,SystemDrive -OperationTimeoutSec 8 }
        $versionKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $edition = Get-ItemPropertyValue -LiteralPath $versionKey -Name EditionID -ErrorAction SilentlyContinue
        $display = Get-ItemPropertyValue -LiteralPath $versionKey -Name DisplayVersion -ErrorAction SilentlyContinue
        $ubr = Get-ItemPropertyValue -LiteralPath $versionKey -Name UBR -ErrorAction SilentlyContinue
        [ordered]@{ EditionID=$edition; DisplayVersion=$display; UBR=$ubr; Architecture=$env:PROCESSOR_ARCHITECTURE;
            SystemDrive=$os.SystemDrive; TempDrive=(Letter $env:TEMP); WindowsPowerShellVersion=[string]$PSVersionTable.PSVersion } |
            Export-Clixml -LiteralPath (Join-Path $raw 'windows-build.clixml')
        $build = if ($null -eq $ubr) { $os.BuildNumber } else { "$($os.BuildNumber).$ubr" }
        "ОС: $(Text $os.Caption), редакция: $(Text $edition), выпуск: $(Text $display)"
        "Версия: $(Text $os.Version), сборка: $(Text $build), архитектура: $(Text $env:PROCESSOR_ARCHITECTURE), разрядность ОС: $(Text $os.OSArchitecture)"
        "Системный диск Windows: $(Letter $os.SystemDrive), диск TEMP: $(Letter $env:TEMP)"
    }
    Section 'Компьютер и процессор' {
        $pc = Read-InventoryData 'computer' { Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model,TotalPhysicalMemory,PartOfDomain,Domain,PCSystemType -OperationTimeoutSec 8 }
        "Производитель: $(Text $pc.Manufacturer), модель: $(Text $pc.Model)"
        "Память: $(Size $pc.TotalPhysicalMemory), компьютер в домене: $(YesNo $pc.PartOfDomain)"
        foreach ($cpu in @(Read-InventoryData 'processors' { Get-CimInstance Win32_Processor -Property Name,NumberOfCores,NumberOfLogicalProcessors,Architecture,MaxClockSpeed -OperationTimeoutSec 8 })) {
            "Процессор: $(Text $cpu.Name), ядер: $($cpu.NumberOfCores), логических процессоров: $($cpu.NumberOfLogicalProcessors)"
        }
    }
    Section 'BIOS и UEFI' {
        $bios = Read-InventoryData 'bios' { Get-CimInstance Win32_BIOS -Property Manufacturer,SMBIOSBIOSVersion,ReleaseDate -OperationTimeoutSec 8 }
        "Производитель: $(Text $bios.Manufacturer), версия: $(Text $bios.SMBIOSBIOSVersion)"
        $firmware = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue
        $secureBoot = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
        [ordered]@{ FirmwareType=$firmware; SecureBootEnabled=$secureBoot } |
            Export-Clixml -LiteralPath (Join-Path $raw 'firmware.clixml')
        if ($firmware -eq 1) { 'Тип прошивки: BIOS' }
        elseif ($firmware -eq 2 -or $null -ne $secureBoot) { 'Тип прошивки: UEFI' }
        else { 'Тип прошивки: недоступно' }
    }
    Section 'Диски' {
        try {
            $disks = @(Read-InventoryData 'disk' { Get-CimInstance -Namespace $storage -ClassName MSFT_Disk -OperationTimeoutSec 8 })
            if (-not $disks.Count) { throw 'No disks returned.' }
            foreach ($disk in $disks | Sort-Object Number) {
                "Диск $($disk.Number): $(Code $disk.BusType $bus), $(Code $disk.PartitionStyle $styles), $(Size $disk.Size)"
            }
        } catch {
            foreach ($disk in @(Read-InventoryData 'disk-win32' { Get-CimInstance Win32_DiskDrive -OperationTimeoutSec 8 }) | Sort-Object Index) {
                "Диск $($disk.Index): интерфейс Win32 $(Text $disk.InterfaceType), разметка недоступна, $(Size $disk.Size)"
            }
        }
    }
    Section 'Разделы' {
        try {
            $partitions = @(Read-InventoryData 'partition' { Get-CimInstance -Namespace $storage -ClassName MSFT_Partition -OperationTimeoutSec 8 })
            if (-not $partitions.Count) { throw 'No partitions returned.' }
            foreach ($partition in $partitions | Sort-Object DiskNumber,PartitionNumber) {
                $mounts = @($partition.AccessPaths | Where-Object { $_ -match '\A[A-Za-z]:\\[^\\]' }).Count
                "Диск $($partition.DiskNumber), раздел $($partition.PartitionNumber), $(Letter $partition.DriveLetter), $(Size $partition.Size), Boot: $(YesNo $partition.IsBoot), System: $(YesNo $partition.IsSystem), точек монтирования в папках: $mounts"
            }
        } catch {
            $letters = @{}
            $mappingRead = $false
            try {
                $associations = @(Read-InventoryData 'logical-disk-to-partition' {
                    Get-CimInstance Win32_LogicalDiskToPartition -OperationTimeoutSec 8
                })
                foreach ($association in $associations) {
                    $partitionId = AssociationDeviceId $association.Antecedent
                    $driveId = AssociationDeviceId $association.Dependent
                    if ($partitionId -and $driveId -match '\A[A-Za-z]:\z') {
                        $letters[$partitionId] = @($letters[$partitionId]) + (Letter $driveId)
                    }
                }
                $mappingRead = $true
            } catch { }
            foreach ($partition in @(Read-InventoryData 'partition-win32' { Get-CimInstance Win32_DiskPartition -OperationTimeoutSec 8 }) | Sort-Object DiskIndex,Index) {
                $driveLetters = if ($letters.ContainsKey($partition.DeviceID)) {
                    ($letters[$partition.DeviceID] | Where-Object { $_ } | Sort-Object -Unique) -join ', '
                } elseif ($mappingRead) { '—' } else { $unknown }
                "Диск $($partition.DiskIndex), раздел $($partition.Index) (индекс Win32), буквы: $driveLetters, $(Size $partition.Size), BootPartition: $(YesNo $partition.BootPartition), System/точки монтирования: недоступно"
            }
        }
    }
    Section 'Локальные тома' {
        try {
            $volumes = @(Read-InventoryData 'volume' { Get-CimInstance -Namespace $storage -ClassName MSFT_Volume -Filter 'DriveType <> 4' -OperationTimeoutSec 8 })
            if (-not $volumes.Count) { throw 'No volumes returned.' }
            foreach ($volume in $volumes | Sort-Object DriveLetter) {
                "$(Letter $volume.DriveLetter) | $(Code $volume.DriveType $driveTypes) | $(Text $volume.FileSystem) | размер $(Size $volume.Size) | свободно $(Size $volume.SizeRemaining)"
            }
        } catch {
            foreach ($volume in @(Read-InventoryData 'volume-win32' { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 2 OR DriveType = 3 OR DriveType = 5 OR DriveType = 6' -OperationTimeoutSec 8 }) | Sort-Object DeviceID) {
                "$(Letter $volume.DeviceID) | $(Code $volume.DriveType $driveTypes) | $(Text $volume.FileSystem) | размер $(Size $volume.Size) | свободно $(Size $volume.FreeSpace)"
            }
        }
    }
    Section 'BitLocker' {
        $protection = @{0='выключена';1='включена';2='неизвестно'}
        $conversion = @{0='расшифрован';1='зашифрован';2='шифрование';3='расшифрование';4='шифрование приостановлено';5='расшифрование приостановлено'}
        $volumes = @(Read-InventoryData 'bitlocker' { Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -OperationTimeoutSec 8 })
        $index = 0
        foreach ($volume in $volumes) {
            $index++
            $status = $unknown
            try {
                $result = Read-InventoryData "bitlocker-conversion-$index" { Invoke-CimMethod -InputObject $volume -MethodName GetConversionStatus -OperationTimeoutSec 8 }
                if ($result.ReturnValue -eq 0) { $status = Code $result.ConversionStatus $conversion }
            } catch { }
            "$(Letter $volume.DriveLetter) | защита: $(Code $volume.ProtectionStatus $protection) | состояние: $status"
        }
    }
    Section 'TPM' {
        $tpm = @(Read-InventoryData 'tpm' { Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' -ClassName Win32_Tpm -OperationTimeoutSec 8 })
        "TPM обнаружен: $(YesNo ($tpm.Count -gt 0))"
        $ready = $unknown
        if ($tpm.Count -eq 1) {
            try {
                $result = Read-InventoryData 'tpm-ready' { Invoke-CimMethod -InputObject $tpm[0] -MethodName IsReady -OperationTimeoutSec 8 }
                if ($result.ReturnValue -eq 0) { $ready = YesNo $result.IsReady }
            } catch { }
        }
        "TPM готов: $ready"
    }
    Section 'Активные сетевые подключения' {
        $adapters = @(Read-InventoryData 'adapters' { Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetAdapter -OperationTimeoutSec 8 } | Where-Object MediaConnectState -eq 1)
        if (-not $adapters.Count) { 'Подключённых интерфейсов не обнаружено.'; return }
        $types = foreach ($adapter in $adapters) {
            if ($adapter.HardwareInterface -eq $false) { 'виртуальный' }
            elseif ($media.ContainsKey([int]$adapter.NdisPhysicalMedium)) { $media[[int]$adapter.NdisPhysicalMedium] }
            else { 'другой или неизвестный' }
        }
        $types | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" }
    }
    Section 'Версии выбранных программ' {
        $patterns = [ordered]@{
            'IntelliJ IDEA' = '^IntelliJ IDEA(?:\s|$)'
            'Java / JDK' = '^(?:Java(?:\s|$)|JDK(?:\s|$)|OpenJDK(?:\s|$)|Eclipse Temurin(?:\s|$)|Amazon Corretto(?:\s|$)|Microsoft Build of OpenJDK(?:\s|$)|Zulu(?:\s|$))'
            'Gradle' = '^Gradle(?:\s|$)'
            'Git' = '^Git(?:\s+version|\s+[0-9]|$)'
            'PowerShell 7' = '^PowerShell 7(?:[.\s]|$)'
            'WinDirStat' = '^WinDirStat(?:\s|$)'
        }
        $versions = @{}
        foreach ($name in $patterns.Keys) { $versions[$name] = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
        $installed = @(Read-InventoryData 'installed-programs' {
            $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            foreach ($root in $roots) {
                foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                    $displayName = $key.GetValue('DisplayName')
                    if ($displayName) {
                        [pscustomobject]@{
                            Scope=$root; DisplayName=$displayName; DisplayVersion=$key.GetValue('DisplayVersion')
                            Publisher=$key.GetValue('Publisher'); InstallDate=$key.GetValue('InstallDate')
                            InstallLocation=$key.GetValue('InstallLocation'); EstimatedSize=$key.GetValue('EstimatedSize')
                        }
                    }
                }
            }
        })
        foreach ($product in $installed) {
            foreach ($name in $patterns.Keys) {
                if ($product.DisplayName -match $patterns[$name]) {
                    $version = VersionText $product.DisplayVersion
                    if ($version) { [void]$versions[$name].Add($version) }
                    break
                }
            }
        }
        $programFiles = [Environment]::GetFolderPath('ProgramFiles')
        $binaries = @{ 'Git'='Git\cmd\git.exe'; 'PowerShell 7'='PowerShell\7\pwsh.exe'; 'WinDirStat'='WinDirStat\WinDirStat.exe' }
        foreach ($name in $binaries.Keys) {
            $binary = Join-Path $programFiles $binaries[$name]
            if ([IO.File]::Exists($binary)) {
                try {
                    $version = VersionText ([Diagnostics.FileVersionInfo]::GetVersionInfo($binary).ProductVersion)
                    if ($version) { [void]$versions[$name].Add($version) }
                } catch { }
            }
        }
        foreach ($directory in @(Get-ChildItem -LiteralPath $programFiles -Directory -Filter 'gradle-*' -ErrorAction SilentlyContinue)) {
            if ($directory.Name -match '\Agradle-([0-9]+(?:\.[0-9]+){1,4})\z' -and [IO.File]::Exists((Join-Path $directory.FullName 'bin\gradle.bat'))) {
                [void]$versions['Gradle'].Add($Matches[1])
            }
        }
        foreach ($name in $patterns.Keys) {
            $version = if ($versions[$name].Count) { ($versions[$name] | Sort-Object) -join ', ' } else { 'не найдено в выбранных источниках' }
            "$name`: $version"
        }
    }
)

$additional = [ordered]@{
    'ip-configuration' = { Get-NetIPConfiguration -Detailed }
    'ip-addresses' = { Get-NetIPAddress }
    'ip-interfaces' = { Get-NetIPInterface }
    'dns-clients' = { Get-DnsClient }
    'dns-servers' = { Get-DnsClientServerAddress }
    'ip-routes' = { Get-NetRoute }
    'network-profiles' = { Get-NetConnectionProfile }
    'firewall-profiles' = { Get-NetFirewallProfile -PolicyStore ActiveStore }
    'firewall-rules' = { Get-NetFirewallRule -PolicyStore ActiveStore }
    'firewall-addresses' = { Get-NetFirewallAddressFilter -PolicyStore ActiveStore }
    'firewall-ports' = { Get-NetFirewallPortFilter -PolicyStore ActiveStore }
    'firewall-apps' = { Get-NetFirewallApplicationFilter -PolicyStore ActiveStore }
    'firewall-services' = { Get-NetFirewallServiceFilter -PolicyStore ActiveStore }
    'firewall-security' = { Get-NetFirewallSecurityFilter -PolicyStore ActiveStore }
    'firewall-interfaces' = { Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore }
    'firewall-interface-types' = { Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore }
    'local-accounts' = { Get-LocalUser }
    'local-profiles' = { Get-CimInstance Win32_UserProfile -OperationTimeoutSec 8 }
    'defender-status' = { Get-MpComputerStatus }
    'usb-storage-service' = { Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start }
    'removable-storage-computer' = { Read-InventoryPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' }
    'removable-storage-user' = { Read-InventoryPolicy 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' }
    'device-install-restrictions' = { Read-InventoryPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' }
    'storage-mdm-policy' = { Read-InventoryPolicy 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Storage' }
    'windows-services' = {
        $serviceNames = 'Winmgmt', 'EventLog', 'Schedule', 'BFE', 'mpssvc', 'gpsvc', 'PolicyAgent', 'BDESVC', 'TBS', 'WinDefend'
        $filter = ($serviceNames | ForEach-Object { "Name='$_'" }) -join ' OR '
        Get-CimInstance Win32_Service -Filter $filter -Property Name,DisplayName,StartMode,State,Status,ProcessId -OperationTimeoutSec 8
    }
    'shared-pc-mdm' = { Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' -ClassName MDM_SharedPC -OperationTimeoutSec 8 }
    'shared-pc-policy' = { Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC' }
    'examlab-tasks' = { Get-ScheduledTask -TaskName 'ExamLab*' }
    'examlab-services' = { Get-Service -Name 'WazuhSvc' }
}
$available = 0
foreach ($name in $additional.Keys) {
    try { $null = Read-InventoryData $name $additional[$name]; $available++ } catch { }
}
foreach ($scope in 'USER', 'COMPUTER') {
    try {
        $ErrorActionPreference = 'Continue'
        & (Join-Path ([Environment]::GetFolderPath('System')) 'gpresult.exe') /SCOPE $scope /Z 2>&1 |
            Out-File -LiteralPath (Join-Path $raw "gpresult-$scope.txt") -Encoding UTF8
        $code = $LASTEXITCODE
        "ExitCode=$code" | Set-Content -LiteralPath (Join-Path $raw "gpresult-$scope-exit.txt") -Encoding UTF8
    } catch {
        $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $raw "gpresult-$scope-error.txt") -Encoding UTF8
    } finally { $ErrorActionPreference = 'Stop' }
}

$examlab = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab'
try {
    $root = Get-Item -LiteralPath $examlab -Force
    if ($root.PSIsContainer -and -not ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        foreach ($name in 'mode.json', 'controller-health.json', 'controller-policy-probe.json', 'controller-state.json') {
            try {
                $item = Get-Item -LiteralPath (Join-Path $examlab $name) -Force
                if (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    [IO.File]::Copy($item.FullName, (Join-Path $raw $name), $false)
                }
            } catch {
                $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $raw "$name-error.txt") -Encoding UTF8
            }
        }
    }
} catch { }

$lines += '', '[Подробные данные]', "Дополнительные источники прочитаны: $available из $($additional.Count).",
    'Данные и ошибки доступа находятся в папке inventory-raw внутри архива Check.'
[IO.File]::WriteAllLines($OutputPath, [string[]]$lines, [Text.UTF8Encoding]::new($true))
