# Только подготовка одноразовой Windows VM; экзаменационные политики здесь отсутствуют.
$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\ExamLab-VM'
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Remove-Item "$root\bootstrap-complete" -ErrorAction SilentlyContinue
Start-Transcript -Path "$root\bootstrap.log" -Append
try {
    # Штатные ADMX значения WinRM: provider Set-Item во время specialize может
    # повторно вызвать quickconfig без SkipNetworkProfileCheck на Public сети.
    $winrmPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    New-Item -Path $winrmPolicy -Force | Out-Null
    New-ItemProperty $winrmPolicy -Name AllowBasic -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $winrmPolicy -Name AllowUnencryptedTraffic -Value 0 -PropertyType DWord -Force | Out-Null
    # NTLM шифрует WinRM сообщения. Basic и незашифрованные сообщения отключены.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    if (-not (Get-NetFirewallRule -Name 'ExamLab-VM-WinRM' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'ExamLab-VM-WinRM' -DisplayName 'ExamLab VM WinRM (QEMU host)' `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.2.2 -Profile Any | Out-Null
    }
    Set-NetFirewallRule -Name 'ExamLab-VM-WinRM' -Enabled True -Direction Inbound -Action Allow `
        -Profile Any -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.2.2
    Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Disable-NetFirewallRule
    $rule = Get-NetFirewallRule -Name 'ExamLab-VM-WinRM'
    $address = @($rule | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)
    $port = $rule | Get-NetFirewallPortFilter
    if ($rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow' -or $rule.Direction -ne 'Inbound' `
        -or $rule.Profile -ne 'Any' -or $address.Count -ne 1 -or $address[0] -ne '10.0.2.2' `
        -or $port.Protocol -ne 'TCP' -or $port.LocalPort -ne '5985' `
        -or (Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Where-Object Enabled -eq True)) {
        throw 'Scoped WinRM firewall verification failed.'
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
    }
    $inventory | ConvertTo-Json -Depth 5 | Set-Content "$root\inventory.json" -Encoding UTF8
    New-Item -ItemType File -Path "$root\bootstrap-complete" -Force | Out-Null
} finally { Stop-Transcript }
