[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$Release,
    [Parameter(Mandatory)][string]$Attempt,
    [Parameter(Mandatory)][int]$CheckExit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$storage = 'root/Microsoft/Windows/Storage'
$unknown = 'недоступно'
$report = [IO.Path]::GetDirectoryName($OutputPath)
$raw = Join-Path $report 'inventory-raw'
[void][IO.Directory]::CreateDirectory($raw)
$sourceStatus = [ordered]@{}

function Get-InventoryReadFailure($Failure) {
    if ($Failure.CategoryInfo.Category -in 'PermissionDenied', 'SecurityError' -or
        $Failure.Exception -is [UnauthorizedAccessException] -or
        ($Failure.Exception -is [Microsoft.Management.Infrastructure.CimException] -and
            $Failure.Exception.StatusCode -eq 'AccessDenied')) { return 'Отказано в чтении' }
    if ($Failure.Exception -is [Management.Automation.ItemNotFoundException]) { return 'Отсутствует' }
    return 'Ошибка источника'
}

function Read-InventoryData([string]$Name, [scriptblock]$Read) {
    try {
        $data = @(& $Read)
        Export-Clixml -InputObject $data -LiteralPath (Join-Path $raw "$Name.clixml") -Depth 4
        $sourceStatus[$Name] = if ($data.Count) { 'Прочитан' } else { 'Нет данных' }
        $data
    } catch {
        $sourceStatus[$Name] = Get-InventoryReadFailure $_
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
    } catch { "$(Get-InventoryReadFailure $_). Подробности в архиве." }
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
    try { $null = Get-Item -LiteralPath $Path }
    catch [Management.Automation.ItemNotFoundException] { return }
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

function Read-Report([string]$Name) {
    $path = Join-Path $report $Name
    if ([IO.File]::Exists($path)) { Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json }
}

function Read-PolicyConsole([string]$Name, [string]$Executable, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    & (Join-Path ([Environment]::GetFolderPath('System')) $Executable) @Arguments 2>&1 |
        Out-File -LiteralPath (Join-Path $raw "$Name.txt") -Encoding UTF8 -ErrorAction Stop
    $code = $LASTEXITCODE
    "ExitCode=$code" | Set-Content -LiteralPath (Join-Path $raw "$Name-exit.txt") -Encoding UTF8 -ErrorAction Stop
    if ($code -eq 0) { return 'Прочитан' }
    if ($code -in 5, -2147024891) { return 'Отказано в чтении' }
    'Ошибка источника'
}

$driveTypes = @{0='неизвестно';1='нет корня';2='съёмный';3='локальный';5='оптический';6='RAM-диск'}
$bus = @{0='неизвестно';1='SCSI';2='ATAPI';3='ATA';4='IEEE 1394';6='Fibre Channel';7='USB';8='RAID';9='iSCSI';10='SAS';11='SATA';12='SD';13='MMC';14='виртуальный';15='файловый виртуальный';16='Storage Spaces';17='NVMe';18='SCM';19='UFS'}
$styles = @{0='RAW';1='MBR';2='GPT'}
$media = @{
    1='Wi-Fi'; 8='беспроводная WAN'; 9='Wi-Fi'; 10='Bluetooth'; 12='WiMAX'; 14='Ethernet'
    15='Token Ring'; 16='IrDA'; 17='проводная WAN'; 18='проводная CoWAN'; 19='другой'
}

$check = Read-Report 'early-check.json'
$releasePlan = Read-Report 'release-plan.json'
$lines = @(
    'ExamLab — инвентаризация Windows'
    "Выпуск $Release. Обследование $Attempt. Код проверки предпосылок $CheckExit."
    'Локальная проверка чтения. Возможности провайдеров зависят от прав и редакции Windows.'
    Section 'Windows и системные диски' {
        $os = Read-InventoryData 'windows' { Get-CimInstance Win32_OperatingSystem -Property Caption,Version,BuildNumber,OSArchitecture,SystemDrive,OSLanguage,MUILanguages,Locale -OperationTimeoutSec 8 }
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
        "Язык интерфейса пользователя: $((Get-UICulture).Name), установленный язык Windows: $([Globalization.CultureInfo]::InstalledUICulture.Name)"
        "Языки интерфейса Windows: $(@($os.MUILanguages) -join ', '), локаль ОС: $($os.Locale)"
        "Системный диск Windows: $(Letter $os.SystemDrive), диск TEMP: $(Letter $env:TEMP)"
        'Редакция, сборка и язык нужны для сопоставления предпосылок Shared PC и установочных отказов.'
    }
    Section 'Компьютер и процессор' {
        $pc = Read-InventoryData 'computer' { Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model,TotalPhysicalMemory,PartOfDomain,Domain,PCSystemType -OperationTimeoutSec 8 }
        "Производитель: $(Text $pc.Manufacturer), модель: $(Text $pc.Model)"
        "Память: $(Size $pc.TotalPhysicalMemory), компьютер в домене: $(YesNo $pc.PartOfDomain)"
        foreach ($cpu in @(Read-InventoryData 'processors' { Get-CimInstance Win32_Processor -Property Name,NumberOfCores,NumberOfLogicalProcessors,Architecture,MaxClockSpeed -OperationTimeoutSec 8 })) {
            "Процессор: $(Text $cpu.Name), ядер: $($cpu.NumberOfCores), логических процессоров: $($cpu.NumberOfLogicalProcessors)"
        }
        'Конфигурация CPU и памяти нужна для сравнения нагрузки IDEA на ПК и VM.'
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
        'Разметка, файловая система и свободное место нужны для выбора томов установки и оценки области файловых ограничений.'
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
    Section 'Сетевые интерфейсы' {
        $adapters = @(Read-InventoryData 'adapters' { Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetAdapter -OperationTimeoutSec 8 })
        $types = foreach ($adapter in $adapters) {
            $type = if ($adapter.HardwareInterface -eq $false) { 'виртуальный' }
                elseif ($media.ContainsKey([int]$adapter.NdisPhysicalMedium)) { $media[[int]$adapter.NdisPhysicalMedium] }
                else { 'другой или неизвестный' }
            $connected = if ($adapter.MediaConnectState -eq 1) { 'подключён' }
                elseif ($adapter.MediaConnectState -eq 2) { 'отключён' } else { 'состояние неизвестно' }
            "$type ($connected)"
        }
        if ($types) { $types | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" } }
        else { 'Интерфейсы не обнаружены.' }
        'Тип интерфейса помогает сопоставить результаты измерений Ethernet, Wi-Fi и VM.'
    }
    Section 'Версии, пути и план программ' {
        if (-not $check -or -not $check.Before) {
            'Общий план программ недоступен. Сведения из реестра установок сохранены в архиве.'
        } else {
            $softwareNames = [ordered]@{ IDEA='IntelliJ IDEA'; JDK='Java / JDK'; Git='Git'; Gradle='Gradle'; WinDirStat='WinDirStat' }
            foreach ($kind in $softwareNames.Keys) {
                $tool = $check.Before.$kind
                $name = $softwareNames[$kind]
                if ($tool.State -eq 'Missing') { "$name — в проверенных местах не найдено."; continue }
                foreach ($candidate in @($tool.Candidates)) {
                    $version = if ($candidate.Version) { $candidate.Version } else { 'версия не подтверждена' }
                    $state = if ($candidate.Compatible) { 'подходит' }
                        elseif ($candidate.Error) { "проверка: $($candidate.Error)" } else { 'совместимость не подтверждена' }
                    "$name — $version; $($candidate.Path); $state."
                }
                foreach ($registered in @($tool.Registered | Where-Object { $_.Location -notin @($tool.Candidates | ForEach-Object Path) })) {
                    "$name — запись реестра: $($registered.Version); $($registered.Location)."
                }
            }
            $steps = if ($check.Plan) { $check.Plan.Actions }
            foreach ($step in $steps) {
                $operation = switch ($step.Operation) {
                    'Keep' { 'сохранить' }
                    'Install' { 'установить' }
                    'Block' { 'нужно решение администратора' }
                    default { $step.Operation }
                }
                "План $($step.Name) — $operation; путь $($step.Destination)."
            }
        }
        'Версии и пути показывают, какие программы можно сохранить и какие пакеты потребуются.'
    }
    Section 'Докачка и дисковое место' {
        if (-not $releasePlan) {
            'Оценка выпуска недоступна. Причины смотрите в отчёте проверки предпосылок.'
        } else {
            $runtime = if ($releasePlan.PowerShell7Ready) { 'подходящий файл найден; запуск не проверялся' }
                else { 'подходящий файл не подтверждён; учтён установщик' }
            "PowerShell 7 x64: $runtime."
            "Ожидаемая докачка: $(Size $releasePlan.DownloadBytes). Верхняя оценка: $(Size $releasePlan.DownloadUpperBoundBytes)."
            $space = $releasePlan.SpaceChecks | Select-Object -Last 1
            if ($space) {
                "Дополнительное место после установки: $(Size $space.EstimatedAdditionalInstalledBytes)."
                foreach ($volume in $space.Volumes) {
                    $state = switch ($volume.Status) {
                        'Available' { 'по оценке достаточно' }
                        'InsufficientSpace' { 'не хватает места' }
                        'EstimatedSpaceRisk' { 'пик может превысить свободное место' }
                        default { 'доступное место не подтверждено' }
                    }
                    "$($volume.MountPath) — свободно $(Size $volume.AvailableBytes); кэш $(Size $volume.CacheGrowthBytes); прирост $(Size $volume.AdditionalInstalledBytes); оценка пика $(Size $volume.EstimatedPeakBytes); $state."
                }
            }
            'Пик включает кэш, временные копии и оценку работы установщиков. Закрытый кэш учитывается как верхняя оценка.'
        }
    }
    Section 'Предпосылки установки' {
        $preflight = Read-Report 'pilot-preflight.json'
        $reasons = @(
            if ($check) { $check.Errors }
            if ($preflight) { $preflight.Blockers }
        ) | Where-Object { $_ }
        if ($reasons) { $reasons } elseif ($CheckExit -eq 0) { 'Проверка предпосылок завершена.' }
        else { 'См. подробный отчёт и дисковую оценку.' }
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
    'installed-programs' = {
        foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') {
            try { $entries = Get-ChildItem -LiteralPath $root }
            catch [Management.Automation.ItemNotFoundException] { continue }
            foreach ($key in $entries) {
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
    }
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
    'examlab-tasks' = { Get-ScheduledTask | Where-Object TaskName -like 'ExamLab-*' | Select-Object TaskName,TaskPath,State }
    'examlab-services' = {
        Get-CimInstance Win32_Service -Filter "Name='WazuhSvc' OR Name LIKE 'ExamLab%'" `
            -Property Name,DisplayName,StartMode,State,Status,ProcessId -OperationTimeoutSec 8
    }
    'applocker-local' = { Get-AppLockerPolicy -Local -Xml }
    'applocker-effective' = { Get-AppLockerPolicy -Effective -Xml }
    'software-restriction-computer' = { Read-InventoryPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' }
    'software-restriction-user' = { Read-InventoryPolicy 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' }
    'local-root-acls' = {
        foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' -Property DeviceID -OperationTimeoutSec 8)) {
            $root = "$($disk.DeviceID)\"
            try {
                $acl = Get-Acl -LiteralPath $root
                [pscustomobject]@{ Path=$root; Status='Прочитан'; Owner=$acl.Owner; Sddl=$acl.Sddl; Error=$null }
            } catch {
                [pscustomobject]@{ Path=$root; Status=(Get-InventoryReadFailure $_); Owner=$null; Sddl=$null; Error=$_.ToString() }
            }
        }
    }
}
$shown = 'usb-storage-service', 'removable-storage-computer', 'removable-storage-user', 'device-install-restrictions',
    'storage-mdm-policy', 'shared-pc-mdm', 'shared-pc-policy', 'examlab-tasks', 'examlab-services', 'applocker-effective',
    'applocker-local', 'firewall-profiles', 'software-restriction-computer', 'software-restriction-user', 'local-root-acls'
$observations = @{}
foreach ($name in $additional.Keys) {
    try {
        $data = @(Read-InventoryData $name $additional[$name])
        if ($name -in $shown) { $observations[$name] = $data }
    } catch { }
}
$policyConsole = [ordered]@{}
foreach ($scope in 'USER', 'COMPUTER') {
    try {
        $policyConsole["gpresult-$scope"] = Read-PolicyConsole "gpresult-$scope" 'gpresult.exe' @('/SCOPE', $scope, '/Z')
    } catch {
        $policyConsole["gpresult-$scope"] = Get-InventoryReadFailure $_
        $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $raw "gpresult-$scope-error.txt") -Encoding UTF8
    }
}
try { $policyConsole['auditpol'] = Read-PolicyConsole 'auditpol' 'auditpol.exe' @('/get', '/category:*', '/r') }
catch {
    $policyConsole['auditpol'] = Get-InventoryReadFailure $_
    $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $raw 'auditpol-error.txt') -Encoding UTF8
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

$lines += @(
    Section 'Задачи и службы ExamLab' {
        "Задачи, видимые текущему пользователю: $($sourceStatus['examlab-tasks'])."
        foreach ($task in $observations['examlab-tasks']) { "$($task.TaskPath)$($task.TaskName) — $($task.State)." }
        "Службы ExamLab и Wazuh: $($sourceStatus['examlab-services'])."
        foreach ($service in $observations['examlab-services']) { "$($service.Name) — $($service.State), запуск $($service.StartMode)." }
        'Имена и состояния нужны для обнаружения прежней или частичной установки.'
    }
    Section 'Действующие политики в пределах текущих прав' {
        "Аудит Windows: $($policyConsole['auditpol'])."
        "Групповые политики пользователя: $($policyConsole['gpresult-USER']); компьютера: $($policyConsole['gpresult-COMPUTER'])."
        $policyNames = [ordered]@{
            'applocker-local'='AppLocker, локальная политика'; 'applocker-effective'='AppLocker, результирующая политика';
            'software-restriction-computer'='Ограничение запуска компьютера (SRP)'; 'software-restriction-user'='Ограничение запуска пользователя (SRP)';
            'removable-storage-computer'='Доступ к съёмным носителям компьютера'; 'removable-storage-user'='Доступ к съёмным носителям пользователя';
            'device-install-restrictions'='Ограничения установки устройств'; 'storage-mdm-policy'='Ограничения MDM для хранилищ';
            'usb-storage-service'='Драйвер USBSTOR'; 'shared-pc-mdm'='Shared PC в MDM'; 'shared-pc-policy'='Shared PC в реестре';
            'firewall-profiles'='Действующие профили брандмауэра'; 'local-root-acls'='Права корней локальных томов'
        }
        foreach ($name in $policyNames.Keys) { "$($policyNames[$name]) — $($sourceStatus[$name])." }
        foreach ($profile in $observations['firewall-profiles']) {
            "$($profile.Name) — вход $($profile.DefaultInboundAction), выход $($profile.DefaultOutboundAction), включён $($profile.Enabled)."
        }
        foreach ($value in $observations['applocker-effective']) {
            foreach ($collection in ([xml]$value).SelectNodes('/AppLockerPolicy/RuleCollection')) {
                "AppLocker $($collection.GetAttribute('Type')) — $($collection.GetAttribute('EnforcementMode')), правил $($collection.SelectNodes('*').Count)."
            }
        }
        foreach ($root in $observations['local-root-acls']) { "$($root.Path) — $($root.Status)." }
        'Эти сведения помогают обнаружить действующие ограничения и возможные конфликты с подготовкой.'
    }
)
$sourceStatus | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $raw 'source-status.json') -Encoding UTF8
$available = @($additional.Keys | Where-Object { $sourceStatus[$_] -in 'Прочитан', 'Нет данных' }).Count
$lines += '', '[Подробные данные]', "Дополнительные источники прочитаны: $available из $($additional.Count).",
    'Данные и ошибки доступа находятся в папке inventory-raw внутри архива Check.'
[IO.File]::WriteAllLines($OutputPath, [string[]]$lines, [Text.UTF8Encoding]::new($true))
