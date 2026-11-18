#requires -Version 5.1
<#
.SYNOPSIS
Проверяет и подготавливает инструменты на существующей Windows без экзаменационных политик.
.DESCRIPTION
Оба действия требуют повышенного административного token. Prepare устанавливает только отсутствующие инструменты.
Конфликт версий требует выбора подходящей существующей установки через явный путь.
Коды: 0 готово; 2 обнаружен блокирующий конфликт; 1 ошибка; 3010 нужен перезапуск.
#>
[CmdletBinding()]
param(
    [ValidateSet('Check','Prepare')][string]$Action = 'Check',
    [string]$CacheDirectory = "$env:ProgramData\ExamLab\Installers",
    [string]$ReportPath,
    [string]$IdeaPath,
    [string]$JdkPath,
    [string]$GitPath,
    [switch]$InstallAlongside,
    [switch]$SoftwareOnly,
    [switch]$DisableBundledGenerativePlugins
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$script:RebootRequired = $false
$script:Changes = [Collections.Generic.List[object]]::new()
$script:Failures = [Collections.Generic.List[string]]::new()
$script:InstallerLocks = [Collections.Generic.List[object]]::new()
$script:WorkingDirectory = $null
$pins = @{
    IDEA = @{ File='ideaIC-2025.2.6.4.exe'; Version='2025.2.6.4'; Publisher='JetBrains';
        Uri='https://download.jetbrains.com/idea/ideaIC-2025.2.6.4.exe';
        Hash='57301793b57b9f2b87a5c79fd06b619e6bbd881501d793ecd78482b20525ea34' }
    JDK = @{ File='OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi'; Version='25.0.5'; Publisher='Eclipse';
        Uri='https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi';
        Hash='e1d3c94032579dc16af9abb311f4552ba271466b74c8767e8ce39585a4c64d40' }
    Git = @{ File='Git-2.56.1-64-bit.exe'; Version='2.56.1'; Publisher='O=Johannes Schindelin';
        Uri='https://github.com/git-for-windows/git/releases/download/v2.56.1.windows.1/Git-2.56.1-64-bit.exe';
        Hash='c330c72e10b408cc39994bfefdb63542b0d93d21699325c3e0bd874af8a5a559' }
}

function Invoke-Native([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory) {
    # Перенаправление на уровне Process, чтобы stderr Java не стал ошибкой PS 5.1.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = ($Arguments -join ' ')
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    if ($WorkingDirectory) { $info.WorkingDirectory = $WorkingDirectory }
    if ([IO.Path]::GetFileName($Executable) -eq 'git.exe') {
        foreach ($name in @($info.EnvironmentVariables.Keys | Where-Object { $_ -like 'GIT_*' })) { $info.EnvironmentVariables.Remove($name) }
        $info.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
        $info.EnvironmentVariables['GIT_CONFIG_GLOBAL'] = 'NUL'
        $info.EnvironmentVariables['GIT_CONFIG_SYSTEM'] = 'NUL'
        $info.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
    }
    if ([IO.Path]::GetFileName($Executable) -in @('java.exe','javac.exe')) {
        foreach ($name in @('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','JDK_JAVAC_OPTIONS','CLASSPATH')) { $info.EnvironmentVariables.Remove($name) }
    }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "Не запущен $Executable" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); throw "Таймаут проверки $Executable" }
        [pscustomobject]@{ ExitCode=$process.ExitCode; Output=($stdout.Result + $stderr.Result).Trim() }
    } finally { $process.Dispose() }
}

function Get-UninstallEntries {
    # Win32_Product не используется: его запрос способен запустить MSI repair.
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty $key -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,InstallLocation,DisplayIcon | ForEach-Object {
            [pscustomobject]@{ Name=[string]$_.DisplayName; Version=[string]$_.DisplayVersion;
                Location=[string]$_.InstallLocation; DisplayIcon=[string]$_.DisplayIcon }
        }
    }
}

function Test-TrustedExecutable([string]$Path) {
    if (-not $script:IsAdmin) { return $true }
    # Elevated inventory не выполняет код из доступных обычному пользователю путей.
    $trusted = @('S-1-5-18','S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', $script:CurrentSid)
    $current = Get-Item -LiteralPath $Path
    $root = [IO.Path]::GetPathRoot($current.FullName)
    if ($root -notmatch '^[A-Za-z]:\\$') { return $false }
    $write = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($current -and $current.FullName.TrimEnd('\') -ne $root.TrimEnd('\')) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $current.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { return $false }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or $rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if (($rule.FileSystemRights -band $write) -and $rule.IdentityReference.Value -notin $trusted) { return $false }
        }
        if ($current -is [IO.FileInfo]) { $current = $current.Directory } else { $current = $current.Parent }
    }
    # На корне тома обычное CreateDirectories допустимо, DeleteChild/смена ACL — нет.
    $rootAcl = Get-Acl -LiteralPath $root
    $rootDanger = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rootAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $rootDanger) -and $rule.IdentityReference.Value -notin $trusted) { return $false }
    }
    return $true
}

function New-ProtectedDirectory {
    # Program Files защищает даже момент между созданием имени и установкой ACL.
    $base = [Environment]::GetFolderPath('ProgramFiles')
    if (-not (Test-TrustedExecutable $base)) { throw 'Program Files не имеет ожидаемых защищённых ACL; staging не создаётся' }
    $directory = Join-Path $base ('ExamLab-Setup-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $directory | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $directory
}

function Get-Tool([string]$Kind, [string]$ExplicitPath, [object[]]$Entries) {
    $paths = [Collections.Generic.List[string]]::new()
    $registered = @()
    if ($ExplicitPath) {
        $paths.Add([IO.Path]::GetFullPath($ExplicitPath))
    } else {
        switch ($Kind) {
            IDEA {
                $registered = @($Entries | Where-Object Name -match 'IntelliJ IDEA')
                foreach ($entry in $registered) { if ($entry.Location) { $paths.Add($entry.Location.TrimEnd('\')) } }
                foreach ($base in @("$env:ProgramFiles\JetBrains", "$env:LOCALAPPDATA\Programs")) {
                    if (Test-Path -LiteralPath $base) {
                        Get-ChildItem -LiteralPath $base -Directory | Where-Object Name -match 'IntelliJ|IDEA' |
                            ForEach-Object { $paths.Add($_.FullName) }
                    }
                }
                foreach ($cmd in @(Get-Command idea64.exe -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
            }
            JDK {
                $registered = @($Entries | Where-Object Name -match 'JDK|Java.*Development|Temurin.*Hotspot')
                foreach ($entry in $registered) { if ($entry.Location) { $paths.Add($entry.Location.TrimEnd('\')) } }
                foreach ($base in @("$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java", "$env:ProgramFiles\Microsoft")) {
                    if (Test-Path -LiteralPath $base) {
                        Get-ChildItem -LiteralPath $base -Directory | Where-Object Name -match 'jdk' |
                            ForEach-Object { $paths.Add($_.FullName) }
                    }
                }
                if ($env:JAVA_HOME) { $paths.Add($env:JAVA_HOME) }
                foreach ($cmd in @(Get-Command javac.exe -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
                foreach ($key in @('HKLM:\SOFTWARE\JavaSoft\JDK\*','HKLM:\SOFTWARE\JavaSoft\Java Development Kit\*')) {
                    Get-ItemProperty $key -ErrorAction SilentlyContinue | Select-Object JavaHome | ForEach-Object {
                        if ($_.JavaHome) { $paths.Add([string]$_.JavaHome) }
                    }
                }
            }
            Git {
                $registered = @($Entries | Where-Object Name -match '^Git( version)?( |$)')
                foreach ($entry in $registered) { if ($entry.Location) { $paths.Add($entry.Location.TrimEnd('\')) } }
                $paths.Add("$env:ProgramFiles\Git")
                foreach ($cmd in @(Get-Command git.exe -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
                $key = Get-ItemProperty 'HKLM:\SOFTWARE\GitForWindows' -ErrorAction SilentlyContinue | Select-Object InstallPath
                if ($key -and $key.InstallPath) { $paths.Add([string]$key.InstallPath) }
            }
        }
    }
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($path in @($paths | Sort-Object -Unique)) {
        $version = ''; $compatible = $false; $probe = ''; $errorText = ''
        try {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            switch ($Kind) {
                IDEA {
                    $productFile = Join-Path $path 'product-info.json'
                    if (-not (Test-Path -LiteralPath $productFile)) { continue }
                    $product = Get-Content -LiteralPath $productFile -Raw | ConvertFrom-Json
                    $version = [string]$product.version
                    $compatible = $product.productCode -eq 'IC' -and $version -match '^2025\.2(?:\.|$)' -and
                        (Test-Path -LiteralPath (Join-Path $path 'bin\idea64.exe'))
                    $probe = "product-info: $($product.productCode) $version build $($product.buildNumber)"
                }
                JDK {
                    $java = Join-Path $path 'bin\java.exe'; $javac = Join-Path $path 'bin\javac.exe'
                    if (-not (Test-Path -LiteralPath $java)) { continue }
                    if (-not (Test-TrustedExecutable $java) -or -not (Test-Path -LiteralPath $javac) -or -not (Test-TrustedExecutable $javac)) {
                        throw 'Elevated CLI blocked: путь JDK не защищён от записи обычным пользователем; выберите защищённую установку JDK'
                    }
                    $run = Invoke-Native $java @('--version')
                    $compile = $null
                    if (Test-Path -LiteralPath $javac) { $compile = Invoke-Native $javac @('--version') }
                    $match = [regex]::Match($run.Output, '(?:openjdk|java)\s+(\d+(?:\.\d+){0,3})')
                    $version = $match.Groups[1].Value
                    $compatible = $run.ExitCode -eq 0 -and $null -ne $compile -and $compile.ExitCode -eq 0 -and
                        $version -match '^25(?:\.|$)' -and $compile.Output -match '^javac 25(?:\.|\s|$)'
                    $probe = $run.Output + $(if ($compile) { "`n" + $compile.Output } else { '`njavac missing' })
                }
                Git {
                    $exe = Join-Path $path 'cmd\git.exe'
                    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $path 'bin\git.exe' }
                    if (-not (Test-Path -LiteralPath $exe)) { continue }
                    if (-not (Test-TrustedExecutable $exe)) { throw 'Elevated CLI blocked: путь Git не защищён от записи обычным пользователем; выберите защищённую установку Git' }
                    $run = Invoke-Native $exe @('--version')
                    $match = [regex]::Match($run.Output, 'git version (\d+\.\d+\.\d+)')
                    $version = $match.Groups[1].Value
                    $compatible = $run.ExitCode -eq 0 -and $match.Success -and [version]$version -ge [version]'2.56.1'
                    $probe = $run.Output
                }
            }
        } catch { $errorText = $_.Exception.Message }
        $candidates.Add([pscustomobject]@{ Path=$path; Version=$version; Compatible=[bool]$compatible; Probe=$probe; Error=$errorText })
    }
    $selected = @($candidates | Where-Object Compatible | Select-Object -First 1)
    $state = 'Missing'
    if ($selected.Count) { $state = 'Compatible' }
    elseif ($candidates.Count -or $registered.Count -or $ExplicitPath) { $state = 'Conflict' }
    [pscustomobject]@{ Name=$Kind; State=$state; Selected=$(if ($selected.Count) { $selected[0] } else { $null });
        Candidates=@($candidates.ToArray()); Registered=@($registered | Select-Object Name,Version,Location); ExplicitPath=[bool]$ExplicitPath }
}

function Get-Inventory {
    $entries = @(Get-UninstallEntries)
    [pscustomobject]@{ IDEA=(Get-Tool IDEA $IdeaPath $entries); JDK=(Get-Tool JDK $JdkPath $entries); Git=(Get-Tool Git $GitPath $entries) }
}

function Get-Platform {
    # Первые признаки ОС читаются через registry/native API до inventory и установок.
    $registry = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$registry.CurrentBuildNumber
    # IsWow64Process2 доступен с 1709; старые ОС отклоняются до вызова API.
    if ($build -lt 17763) { throw 'Conflict: нужны client Windows10 1809+ x64 (build не ниже 17763)' }
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
        catch { throw 'Conflict: не удалось определить native architecture Windows через IsWow64Process2; нужна client Windows10 1809+ x64' }
        if (-not $detected) { throw ('Conflict: IsWow64Process2 не определил native architecture Windows; Win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    } finally { $currentProcess.Dispose() }
    $x64 = $nativeMachine -eq 0x8664 # IMAGE_FILE_MACHINE_AMD64; эмуляция x64 на ARM64 не подходит.
    if (-not $x64) { throw ('Conflict: нужна native x64 Windows (AMD64); IsWow64Process2 NativeMachine=0x{0:X4}' -f $nativeMachine) }
    $product = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
    $client = $product.ProductType -eq 'WinNT'
    $edition = [string]$registry.EditionID
    $sharedPCEditions = @('Professional','ProfessionalN','ProfessionalEducation','ProfessionalEducationN',
        'ProfessionalWorkstation','ProfessionalWorkstationN','ProfessionalSingleLanguage','ProfessionalCountrySpecific',
        'Enterprise','EnterpriseN','EnterpriseS','EnterpriseSN','EnterpriseEval','EnterpriseSEval',
        'Education','EducationN','IoTEnterprise','IoTEnterpriseS','IoTEnterpriseSK')
    $editionEligible = $edition -in $sharedPCEditions
    $bridge = 'NotCheckedWithoutElevation'
    if ($script:IsAdmin) {
        try { $null = Get-CimClass -Namespace root\cimv2\mdm\dmmap -ClassName MDM_SharedPC -ErrorAction Stop; $bridge = 'Present' }
        catch { $bridge = 'UnknownOrUnavailable: ' + $_.Exception.Message }
    }
    $domain = $null; $memory = $null
    $observations = [Collections.Generic.List[string]]::new()
    try { $domain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain }
    catch { $observations.Add('DomainObservationUnavailable: ' + $_.Exception.Message) }
    try { $memory = [math]::Round([double](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).FreePhysicalMemory / 1MB,2) }
    catch { $observations.Add('MemoryObservationUnavailable: ' + $_.Exception.Message) }
    [pscustomobject]@{ Caption=[string]$registry.ProductName; Edition=$edition; Version=('10.0.'+$build); Build=$build;
        UBR=[int]$registry.UBR; NativeX64=$x64; NativeMachine=('0x{0:X4}' -f $nativeMachine);
        ArchitectureDetection='IsWow64Process2'; ClientWindows=$client; PowerShell=[string]$PSVersionTable.PSVersion;
        SoftwareEligible=($x64 -and $client -and $build -ge 17763 -and $PSVersionTable.PSVersion.Major -ge 5);
        SharedPCPlatformEligible=($client -and $build -ge 14393 -and $editionEligible); SharedPCBridge=$bridge;
        SharedPCEditionRecognition=$(if ($editionEligible) { 'KnownSupportedFamily' } elseif ($edition -match '^Core') { 'HomeUnsupported' } else { 'UnknownEdition' });
        PartOfDomain=$domain; FreeMemoryGiB=$memory; OptionalObservations=@($observations.ToArray());
        MatchesTestedOsBuild=($edition -eq 'EnterpriseEval' -and $build -eq 19045 -and [int]$registry.UBR -eq 2006);
        OsBuildMatchMeaning='Совпадает с ОС испытательного стенда; это не приёмка данного ПК и не проверка Guest/IDEA/USB/network.' }
}

function Get-EarlyPreflight($Platform) {
    $system = [Environment]::GetFolderPath('System')
    $modules = [ordered]@{}
    $specifications = @(
        @{ Name='NetSecurity'; Commands=@('Get-NetFirewallRule','Get-NetFirewallProfile','New-NetFirewallRule','Set-NetFirewallProfile') },
        @{ Name='ScheduledTasks'; Commands=@('Get-ScheduledTask','Register-ScheduledTask','Start-ScheduledTask') },
        @{ Name='Microsoft.PowerShell.LocalAccounts'; Commands=@('Get-LocalUser','Get-LocalGroup','Get-LocalGroupMember') }
    )
    foreach ($specification in $specifications) {
        $folder = Join-Path $system ('WindowsPowerShell\v1.0\Modules\' + $specification.Name)
        $available = @(Get-Module -ListAvailable -Name $folder | Where-Object Name -eq $specification.Name | Sort-Object Version -Descending)
        $manifest = Join-Path $folder ($specification.Name + '.psd1')
        if ($available.Count) { $manifest = $available[0].Path }
        $status = 'Absent'; $detail = ''; $commands = $false; $readProbe = $false; $moduleVersion = $null
        try {
            if (Test-Path -LiteralPath $manifest) {
                if (-not (Test-TrustedExecutable $manifest)) { throw 'Незащищённый путь штатного модуля' }
                $loaded = Import-Module -Name $manifest -PassThru -ErrorAction Stop
                $moduleVersion = [string]@($loaded | Where-Object Name -eq $specification.Name | Select-Object -First 1)[0].Version
                $commands = @($specification.Commands | Where-Object {
                    -not (Get-Command -Name $_ -Module $specification.Name -ListImported -ErrorAction SilentlyContinue)
                }).Count -eq 0
                if (-not $commands) { throw 'Не найден обязательный штатный cmdlet' }
                switch ($specification.Name) {
                    'NetSecurity' { $null = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop }
                    'ScheduledTasks' { $null = Get-ScheduledTask -ErrorAction Stop | Select-Object -First 1 }
                    'Microsoft.PowerShell.LocalAccounts' { $null = Get-LocalUser -ErrorAction Stop | Select-Object -First 1 }
                }
                $readProbe = $true; $status = 'Available'
            }
        } catch { $status = 'UnknownOrUnavailable'; $detail = $_.Exception.Message }
        $modules[$specification.Name] = [pscustomobject]@{ Status=$status; Manifest=$manifest; Version=$moduleVersion;
            RequiredCommandsPresent=$commands; AdministrativeReadProbe=$readProbe; Detail=$detail }
    }
    $gpoFiles = (Test-Path -LiteralPath (Join-Path $system 'gpedit.dll')) -and
        (Test-Path -LiteralPath (Join-Path $system 'gpupdate.exe'))
    $gpoClass = Test-Path 'HKLM:\SOFTWARE\Classes\CLSID\{EA502722-A23D-11D1-A7D3-0000F87571E3}\InprocServer32'
    $gpo = [pscustomobject]@{ Status=$(if ($gpoFiles -and $gpoClass) { 'BindingsPresent' } else { 'AbsentBindings' });
        FilesPresent=$gpoFiles; COMRegistrationPresent=$gpoClass;
        ProbeMeaning='Только штатные файлы и регистрация GroupPolicyObject; запись MLGPO и применение политик не выполняются';
        ExternalLGPO='Подписанный LGPO.exe поставляется отдельно с локальным пилотом' }
    $services = @('Schedule','BFE','MpsSvc','gpsvc' | ForEach-Object {
        $name = $_
        try { [pscustomobject]@{ Name=$name; Status=[string](Get-Service -Name $name -ErrorAction Stop).Status;
            StartValue=[int](Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name) -Name Start).Start } }
        catch { [pscustomobject]@{ Name=$name; Status='UnknownOrUnavailable'; StartValue=$null } }
    })
    $capabilities = $Platform.SharedPCPlatformEligible -and $Platform.SharedPCBridge -eq 'Present' -and
        $gpoFiles -and $gpoClass -and @($modules.Values | Where-Object Status -ne 'Available').Count -eq 0 -and
        @($services | Where-Object { $_.Status -eq 'UnknownOrUnavailable' -or $_.StartValue -eq 4 }).Count -eq 0
    [pscustomobject]@{ CompletedAtUtc=[DateTime]::UtcNow.ToString('o'); ElevatedAdministrator=$script:IsAdmin;
        KnownMinimums=[pscustomobject]@{ SoftwareWindowsBuild=17763; SharedPCWindowsBuild=14393;
            LocalMLGPOApi='IGroupPolicyObject2: Windows Vista+; общий предел этого скрипта Windows10 1809+';
            Architecture='Native x64'; PowerShell='Windows PowerShell 5.1';
            SharedPCEditions='Pro/Enterprise/Education/IoT Enterprise; Home не поддерживает экзаменационный Guest' };
        LocalMLGPO=$gpo; Modules=[pscustomobject]$modules; Services=$services;
        ServiceMeaning='Проверяется наличие и отсутствие Disabled; demand/trigger-start service может быть Stopped. Запуск/перенастройка не выполняются';
        ExamPlatformPrerequisitesAvailable=[bool]$capabilities; SoftwareOnlyRequested=[bool]$SoftwareOnly;
        Acceptance='Это чтение предпосылок, не проверка действия Guest/USB/network и не приёмка ПК' }
}

function Get-Installer([string]$Kind) {
    $pin = $pins[$Kind]
    $file = Join-Path $CacheDirectory $pin.File
    # Запускается только копия в новом admin-only staging, а не путь из общего cache.
    $staged = Join-Path $script:WorkingDirectory $pin.File
    if (Test-Path -LiteralPath $file) {
        $lock = [IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $script:InstallerLocks.Add($lock)
        if ((Get-FileHash -InputStream $lock -Algorithm SHA256).Hash -ne $pin.Hash) { throw "SHA256 $file не совпадает; файл не запускается и не заменяется автоматически" }
        $lock.Position = 0
        $output = [IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $lock.CopyTo($output) } finally { $output.Dispose() }
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $pin.Uri -OutFile $staged -UseBasicParsing
    }
    $stageLock = [IO.File]::Open($staged,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $script:InstallerLocks.Add($stageLock)
    if ((Get-FileHash -InputStream $stageLock -Algorithm SHA256).Hash -ne $pin.Hash) { throw "SHA256 staging $Kind не совпадает" }
    $signature = Get-AuthenticodeSignature -LiteralPath $staged
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch [regex]::Escape($pin.Publisher)) {
        throw "Недействительная или неожиданная подпись $Kind : $($signature.Status), $($signature.SignerCertificate.Subject)"
    }
    $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='InstallerVerified'; SHA256=$pin.Hash; Signer=$signature.SignerCertificate.Subject })
    $staged
}

function Install-Tool([string]$Kind, [string]$Installer, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) { throw "Каталог назначения уже существует: $Destination; автоматическая перезапись запрещена" }
    $arguments = @(); $exe = $Installer
    switch ($Kind) {
        JDK {
            $exe = "$env:SystemRoot\System32\msiexec.exe"
            $arguments = @('/i', "`"$Installer`"", '/qn','/norestart','ADDLOCAL=FeatureMain',
                "INSTALLDIR=`"$Destination`"", '/L*v', "`"$script:WorkingDirectory\jdk-install.log`"")
        }
        Git { $arguments = @('/VERYSILENT','/NORESTART','/ALLUSERS','/SP-','/o:PathOption=BashOnly', '/COMPONENTS=',"/DIR=`"$Destination`"", "/LOG=`"$script:WorkingDirectory\git-install.log`"") }
        IDEA {
            $config = Join-Path $script:WorkingDirectory 'idea-silent.config'
            @('mode=admin','launcher64=1','updatePATH=0','updateContextMenu=0','.java=0','.groovy=0','.kt=0') | Set-Content -LiteralPath $config -Encoding ASCII
            $arguments = @('/S',"/CONFIG=`"$config`"", "/LOG=`"$script:WorkingDirectory\idea-install.log`"", "/D=$Destination")
        }
    }
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
    $code = $process.ExitCode
    $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='Install'; ExitCode=$code; Destination=$Destination })
    if ($code -eq 3010) { $script:RebootRequired = $true }
    elseif ($code -ne 0) { throw "Установщик $Kind завершился с кодом $code; см. журнал в $script:WorkingDirectory" }
}

function Test-CLI($Inventory) {
    if ($Inventory.JDK.State -ne 'Compatible' -or $Inventory.Git.State -ne 'Compatible') { return [pscustomobject]@{ Passed=$false; Reason='Требуются подходящие JDK и Git' } }
    $temporary = New-ProtectedDirectory
    try {
        'class Hello { public static void main(String[] a) { System.out.print("exam-lab-java-ok"); } }' |
            Set-Content -LiteralPath (Join-Path $temporary 'Hello.java') -Encoding ASCII
        New-Item -ItemType Directory -Path (Join-Path $temporary 'empty-template') | Out-Null
        $javac = Invoke-Native (Join-Path $Inventory.JDK.Selected.Path 'bin\javac.exe') @('Hello.java') $temporary
        $java = Invoke-Native (Join-Path $Inventory.JDK.Selected.Path 'bin\java.exe') @('-cp','.','Hello') $temporary
        $gitExe = Join-Path $Inventory.Git.Selected.Path 'cmd\git.exe'
        if (-not (Test-Path -LiteralPath $gitExe)) { $gitExe = Join-Path $Inventory.Git.Selected.Path 'bin\git.exe' }
        $gitInit = Invoke-Native $gitExe @('init','--quiet','--template=empty-template') $temporary
        $gitStatus = Invoke-Native $gitExe @('status','--porcelain') $temporary
        [pscustomobject]@{ Passed=($javac.ExitCode -eq 0 -and $java.ExitCode -eq 0 -and $java.Output -eq 'exam-lab-java-ok' -and $gitInit.ExitCode -eq 0 -and $gitStatus.ExitCode -eq 0);
            JavacExit=$javac.ExitCode; JavaExit=$java.ExitCode; JavaOutput=$java.Output; GitInitExit=$gitInit.ExitCode; GitStatusExit=$gitStatus.ExitCode }
    } finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
}

function Get-EnvironmentObservation {
    $resolved = @{}
    foreach ($exe in @('java.exe','javac.exe','git.exe','idea64.exe')) {
        $resolved[$exe] = @(Get-Command $exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    }
    [pscustomobject]@{ MachineJAVA_HOME=[Environment]::GetEnvironmentVariable('JAVA_HOME','Machine');
        UserJAVA_HOME=[Environment]::GetEnvironmentVariable('JAVA_HOME','User');
        MachinePath=[Environment]::GetEnvironmentVariable('Path','Machine');
        UserPath=[Environment]::GetEnvironmentVariable('Path','User'); ResolvedCommands=$resolved }
}

function Get-IDEPlugins($Tool) {
    if ($Tool.State -ne 'Compatible') { return $null }
    $pluginRoot = Join-Path $Tool.Selected.Path 'plugins'
    $known = @(Get-ChildItem -LiteralPath $pluginRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match '^(fullLine|llm|ai-assistant|copilot|junie)$' | Select-Object -ExpandProperty Name)
    [pscustomobject]@{ KnownGenerativeDirectories=$known;
        BundledPluginClasspathPresent=(Test-Path -LiteralPath (Join-Path $pluginRoot 'plugin-classpath.txt'));
        GenerativePluginAbsence='Не подтверждено: отсутствие каталогов не исключает сохранённый bundled descriptor; нужны проверка плагинов и чистый запуск IDEA';
        UserPluginsAndOtherAssistants='Требуют ручной проверки в IDE и профилях обычного пользователя/Guest';
        OrdinaryCompletionInspectionRefactoringDebug='Не проверены этим инструментом' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:CurrentSid = $identity.User.Value
$script:IsAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$report = [ordered]@{ Timestamp=[DateTime]::UtcNow.ToString('o'); ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;
    Action=$Action; Platform=$null; Preflight=$null; Before=$null; After=$null;
    EnvironmentBefore=$null; EnvironmentAfter=$null; EnvironmentPreserved=$null; CLIProbe=$null; WorkingDirectory=$null;
    Changes=@(); Errors=@(); RebootRequired=$false; SoftwareReady=$false; ExamReady=$false;
    ManualChecks=@('Настоящий Shared PC Guest','IDEA: SDK/run/debug, completion/inspection/refactoring, отсутствие генеративных помощников',
        'Moodle и PrairieLearn','Физические флешки','Локальное завершение и сохранность обычных занятий') }
$exitCode = 0
try {
    if (-not $script:IsAdmin) { throw 'Запустите 64-битный Windows PowerShell от администратора (повышенный UAC token)' }
    if (-not [Environment]::Is64BitProcess) { throw 'Запустите 64-битный Windows PowerShell 5.1' }
    $report.Platform = Get-Platform
    $report.Preflight = Get-EarlyPreflight $report.Platform
    if (-not $report.Platform.SoftwareEligible -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw 'Conflict: нужны client Windows10 1809+ x64 и native Windows PowerShell5.1'
    }
    if (-not $SoftwareOnly -and -not $report.Preflight.ExamPlatformPrerequisitesAvailable) {
        throw 'Conflict: не подтверждены предпосылки GPO/SharedPC/NetSecurity/ScheduledTasks/LocalAccounts; см. Preflight. Для одних программ используйте явный -SoftwareOnly'
    }
    $report.EnvironmentBefore = Get-EnvironmentObservation
    $inventory = Get-Inventory
    $report.Before = $inventory
    if ($Action -eq 'Prepare') {
        foreach ($name in @('IDEA','JDK','Git')) {
            if ($inventory.$name.State -eq 'Conflict' -and
                -not ($InstallAlongside -and $name -in @('IDEA','JDK') -and -not $inventory.$name.ExplicitPath)) {
                throw "Conflict: $name. Выберите подходящий каталог через -${name}Path; IDEA/JDK можно установить отдельно с -InstallAlongside"
            }
        }
        $destinations = @{ IDEA="$env:ProgramFiles\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4";
            JDK="$env:ProgramFiles\Eclipse Adoptium\jdk-25"; Git="$env:ProgramFiles\Git" }
        $pending = @(@('JDK','Git','IDEA') | Where-Object {
            $inventory.$_.State -eq 'Missing' -or ($InstallAlongside -and $inventory.$_.State -eq 'Conflict' -and $_ -in @('IDEA','JDK'))
        })
        foreach ($name in $pending) {
            if (Test-Path -LiteralPath $destinations[$name]) { throw "Conflict: занят каталог $($destinations[$name]); разрешите конфликт вручную" }
        }
        if ($pending.Count) {
            $script:WorkingDirectory = New-ProtectedDirectory
            $report.WorkingDirectory = $script:WorkingDirectory
        }
        # Проверка всех требуемых файлов до первого запуска установщика.
        $installers = @{}
        foreach ($name in $pending) { $installers[$name] = Get-Installer $name }
        foreach ($name in @('JDK','Git','IDEA')) {
            if ($installers.ContainsKey($name)) { Install-Tool $name $installers[$name] $destinations[$name] }
            else { $script:Changes.Add([pscustomobject]@{ Tool=$name; Operation='PreservedCompatible'; Path=$inventory.$name.Selected.Path }) }
        }
        $inventory = Get-Inventory
        if ($inventory.IDEA.State -eq 'Compatible') {
            $freshIdea = $installers.ContainsKey('IDEA')
            $pluginRoot = Join-Path $inventory.IDEA.Selected.Path 'plugins'
            $excluded = @(@('plugin-classpath.txt','fullLine') | ForEach-Object { Join-Path $pluginRoot $_ } |
                Where-Object { Test-Path -LiteralPath $_ })
            if (($freshIdea -or $DisableBundledGenerativePlugins) -and $excluded.Count) {
                foreach ($path in $excluded) {
                    if (-not (Test-TrustedExecutable $path)) { throw 'Путь плагина или bundled descriptor не защищён от записи обычным пользователем; автоматическое перемещение запрещено' }
                }
                if (@(Get-Process -Name idea64 -ErrorAction SilentlyContinue).Count) { throw 'Закройте IDEA перед исключением Full Line; работающие IDE не останавливаются автоматически' }
                if (-not $script:WorkingDirectory) { $script:WorkingDirectory = New-ProtectedDirectory; $report.WorkingDirectory = $script:WorkingDirectory }
                # Bundled descriptors содержат plugin.xml даже после переноса fullLine.
                # Сначала переносим descriptor: при частичном отказе останется штатное
                # сканирование каталогов вместо ссылки на уже перенесённый плагин.
                $backup = Join-Path $script:WorkingDirectory ('excluded-plugins-' + [Guid]::NewGuid().ToString('N'))
                if (Test-Path -LiteralPath $backup) { throw 'Conflict: каталог резервной копии уже существует' }
                New-Item -ItemType Directory -Path $backup | Out-Null
                foreach ($path in $excluded) {
                    $destination = Join-Path $backup (Split-Path $path -Leaf)
                    Move-Item -LiteralPath $path -Destination $destination
                    $operation = if ((Split-Path $path -Leaf) -eq 'fullLine') { 'FullLineExcluded' } else { 'BundledPluginClasspathExcluded' }
                    $script:Changes.Add([pscustomobject]@{ Tool='IDEA'; Operation=$operation; Source=$path; Backup=$destination })
                }
            }
        }
    }
    $report.After = Get-Inventory
    $report.EnvironmentAfter = Get-EnvironmentObservation
    $report.EnvironmentPreserved = $report.EnvironmentBefore.MachineJAVA_HOME -ceq $report.EnvironmentAfter.MachineJAVA_HOME -and
        $report.EnvironmentBefore.UserJAVA_HOME -ceq $report.EnvironmentAfter.UserJAVA_HOME -and
        $report.EnvironmentBefore.MachinePath -ceq $report.EnvironmentAfter.MachinePath -and
        $report.EnvironmentBefore.UserPath -ceq $report.EnvironmentAfter.UserPath
    $report.CLIProbe = Test-CLI $report.After
    $report.PluginReview = Get-IDEPlugins $report.After.IDEA
    $report.SoftwareReady = $report.Platform.SoftwareEligible -and @('IDEA','JDK','Git').Where({ $report.After.$_.State -ne 'Compatible' }).Count -eq 0 -and $report.CLIProbe.Passed
    if (-not $report.SoftwareReady) { $exitCode = 2 }
    if (-not $report.EnvironmentPreserved) { $script:Failures.Add('Обнаружено изменение JAVA_HOME/PATH; автоматический откат не выполняется'); $exitCode = 1 }
    if ($script:RebootRequired -and $exitCode -eq 0 -and $script:Failures.Count -eq 0) { $exitCode = 3010 }
} catch {
    $script:Failures.Add($_.Exception.Message)
    $exitCode = 1
    if ($_.Exception.Message -like 'Conflict:*') { $exitCode = 2 }
    if ($report.Before) { try { $report.After = Get-Inventory } catch { $script:Failures.Add($_.Exception.Message) } }
} finally {
    foreach ($lock in $script:InstallerLocks) { $lock.Dispose() }
    if ($script:WorkingDirectory -and (Test-Path -LiteralPath $script:WorkingDirectory) -and
        @(Get-ChildItem -LiteralPath $script:WorkingDirectory -Force).Count -eq 0) {
        Remove-Item -LiteralPath $script:WorkingDirectory
        $report.WorkingDirectory = $null
    }
    $report.Changes = @($script:Changes.ToArray())
    $report.Errors = @($script:Failures.ToArray())
    $report.RebootRequired = $script:RebootRequired
    $report.ExitCode = $exitCode
    $json = $report | ConvertTo-Json -Depth 8
    if ($ReportPath) { $json | Set-Content -LiteralPath $ReportPath -Encoding UTF8 }
    Write-Output $json
}
exit $exitCode
