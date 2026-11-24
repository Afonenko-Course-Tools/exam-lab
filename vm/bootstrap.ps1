#requires -Version 7.6
# Только подготовка одноразовой Windows VM; экзаменационные политики здесь отсутствуют.
$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ExamLab-VM'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem -or $env:COMPUTERNAME -ine 'EXAM-LAB-VM' -or
    -not [Environment]::Is64BitProcess -or -not (Test-Path -LiteralPath $root -PathType Container)) {
    throw 'Запустите подготовку от SYSTEM через SetupComplete в выделенной VM EXAM-LAB-VM.'
}
Remove-Item "$root\bootstrap-complete" -ErrorAction SilentlyContinue
Start-Transcript -Path "$root\bootstrap.log" -Append
try {
    # Штатные ADMX значения WinRM применяются до регистрации конечной точки.
    $winrmPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    New-Item -Path $winrmPolicy -Force | Out-Null
    New-ItemProperty $winrmPolicy -Name AllowBasic -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $winrmPolicy -Name AllowUnencryptedTraffic -Value 0 -PropertyType DWord -Force | Out-Null
    # NTLM шифрует WinRM сообщения. Basic и незашифрованные сообщения отключены.
    try {
        try {
            Enable-PSRemoting -SkipNetworkProfileCheck -Force
        } finally {
            # Enable-PSRemoting может включить широкие правила даже при частичном отказе.
            Get-NetFirewallRule | Where-Object Name -like 'WINRM-HTTP-In-TCP*' | Disable-NetFirewallRule
            $stockRulesEnabled = Get-NetFirewallRule -PolicyStore ActiveStore |
                Where-Object { $_.Name -like 'WINRM-HTTP-In-TCP*' -and $_.Enabled -eq 'True' }
            if ($stockRulesEnabled) { throw 'Штатные широкие правила WinRM остались включены.' }
        }
        if (-not (Get-NetFirewallRule -Name 'ExamLab-VM-WinRM' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name 'ExamLab-VM-WinRM' -DisplayName 'ExamLab VM WinRM (QEMU host)' `
                -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.2.2 -Profile Any | Out-Null
        }
        Set-NetFirewallRule -Name 'ExamLab-VM-WinRM' -Enabled True -Direction Inbound -Action Allow `
            -Profile Any -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.2.2
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name 'ExamLab-VM-WinRM'
        $address = @($rule | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)
        $port = $rule | Get-NetFirewallPortFilter
        if ($rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow' -or $rule.Direction -ne 'Inbound' `
            -or $rule.Profile -ne 'Any' -or $address.Count -ne 1 -or $address[0] -ne '10.0.2.2' `
            -or $port.Protocol -ne 'TCP' -or $port.LocalPort -ne '5985') {
            throw 'Не подтверждено правило WinRM для хоста QEMU.'
        }
        $endpoint = Get-PSSessionConfiguration -Name 'PowerShell.7'
        $endpointVersion = $null
        if ($endpoint.Name -cne 'PowerShell.7' -or
            -not [version]::TryParse([string]$endpoint.PSVersion, [ref]$endpointVersion) -or $endpointVersion.Major -ne 7) {
            throw 'Конечная точка WinRM PowerShell.7 не подтверждена.'
        }
        New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    } catch {
        # При невозможности подтвердить ограничение WinRM не должен принимать подключения.
        try { Set-Service WinRM -StartupType Disabled }
        finally { Stop-Service WinRM -Force }
        throw
    }
    Set-Service WinRM -StartupType Automatic
    # Эталон не должен засыпать во время автономного испытания.
    & powercfg.exe /change standby-timeout-ac 0
    & powercfg.exe /change monitor-timeout-ac 0
    $inventory = [ordered]@{
        CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
        OS = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
        Edition = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object EditionID,DisplayVersion,CurrentBuild,UBR
        Machine = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model
        WinRM = (Get-Service WinRM).Status.ToString()
        WinRMEndpoint = $endpoint.Name
        PowerShell = $PSVersionTable.PSVersion.ToString()
    }
    $inventory | ConvertTo-Json -Depth 5 | Set-Content "$root\inventory.json" -Encoding UTF8
    New-Item -ItemType File -Path "$root\bootstrap-complete" -Force | Out-Null
} finally { Stop-Transcript }
