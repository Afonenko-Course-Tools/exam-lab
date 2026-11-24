#requires -Version 5.1
<#
.SYNOPSIS
Проверяет и подготавливает инструменты на существующей Windows без экзаменационных политик.
.DESCRIPTION
Check строит план по метаданным и доступен в Windows PowerShell 5.1 без повышения.
Prepare (Apply) и Verify требуют PowerShell 7.6 x64 и повышенного token.
Коды: 0 план выполним или инструменты готовы; 2 конфликт; 1 ошибка; 3010 нужен перезапуск.
.PARAMETER ExpectedPlanPath
Отчёт Check. Prepare сверяет действия, версии и пути перед изменениями.
.PARAMETER ReplaceIdeaPath
Явное согласие на удаление одной зарегистрированной машинной установки IDEA по её полному пути.
.PARAMETER UsePublishedInstallers
Внутренний режим локального пилота. Требует защищённый CacheDirectory с готовой HTTPS-поставкой.
.PARAMETER HumanOutput
Показывает в консоли путь к полному JSON-отчёту. Требует ReportPath.
#>
[CmdletBinding()]
param(
    [ValidateSet('Check','Prepare','Apply','Verify')][string]$Action = 'Check',
    [string]$CacheDirectory = "$env:ProgramData\ExamLab\Installers",
    [string]$ReportPath,
    [string]$IdeaPath,
    [string]$JdkPath,
    [string]$GitPath,
    [switch]$InstallAlongside,
    [switch]$SoftwareOnly,
    [switch]$DisableBundledGenerativePlugins,
    [string]$GradlePath,
    [switch]$UsePublishedInstallers,
    [string]$ExpectedPlanPath,
    [string]$ReplaceIdeaPath,
    [switch]$HumanOutput
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if ($HumanOutput -and -not $ReportPath) { throw 'HumanOutput requires ReportPath.' }
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
    Gradle = @{ File='gradle-9.8.2-bin.zip'; Version='9.8.2';
        Uri='https://services.gradle.org/distributions/gradle-9.8.2-bin.zip';
        Hash='21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607' }
}

function Invoke-Native([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory) {
    # Сохраняем stderr Java и stdout отдельно вместе с кодом завершения.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = if ($WorkingDirectory) { $WorkingDirectory } else { Split-Path $Executable -Parent }
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
        Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Select-Object DisplayName,DisplayVersion,InstallLocation,DisplayIcon,Publisher,UninstallString,PSPath | ForEach-Object {
            [pscustomobject]@{ Name=[string]$_.DisplayName; Version=[string]$_.DisplayVersion;
                Location=[string]$_.InstallLocation; DisplayIcon=[string]$_.DisplayIcon;
                Publisher=[string]$_.Publisher; UninstallString=[string]$_.UninstallString; RegistryPath=[string]$_.PSPath;
                Machine=$key.StartsWith('HKLM:', [StringComparison]::OrdinalIgnoreCase) }
        }
    }
}

function Test-TrustedExecutable([string]$Path, [switch]$ParentTrusted) {
    # Elevated inventory не выполняет код из доступных обычному пользователю путей.
    $trusted = @('S-1-5-18','S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($script:IsAdministratorAccount) { $trusted += $script:CurrentSid }
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
        if ($ParentTrusted) { return $true }
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

function New-SetupDirectory([string]$Directory, [switch]$AllowUserExecute) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $access = @{ 'S-1-5-18'='FullControl'; 'S-1-5-32-544'='FullControl' }
    if ($AllowUserExecute) {
        $access['S-1-5-32-545'] = 'ReadAndExecute'
        $access['S-1-5-32-546'] = 'ReadAndExecute'
    }
    foreach ($sid in $access.Keys) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier($sid)), $access[$sid], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.FileSystemAclExtensions]::CreateDirectory($acl, $Directory) | Out-Null
}

function New-ProtectedDirectory {
    $base = [Environment]::GetFolderPath('ProgramFiles')
    if (-not (Test-TrustedExecutable $base)) { throw 'Program Files не имеет ожидаемых защищённых ACL; staging не создаётся' }
    $directory = Join-Path $base ('ExamLab-Setup-' + [Guid]::NewGuid().ToString('N'))
    New-SetupDirectory $directory
    $directory
}

function Get-GradleDestination {
    Join-Path $env:ProgramFiles "gradle-$($pins.Gradle.Version)"
}

function Get-JdkDestination {
    Join-Path $env:ProgramFiles 'ExamLab-JDK-25'
}

function ConvertTo-ToolRoot([string]$Path, [string]$Kind) {
    $fullPath = [IO.Path]::GetFullPath($Path.Trim().Trim('"'))
    if ($fullPath -ne [IO.Path]::GetPathRoot($fullPath)) { $fullPath = $fullPath.TrimEnd('\', '/') }
    if ($Kind -eq 'JDK' -and [IO.Path]::GetFileName($fullPath) -ieq 'bin') {
        $fullPath = [IO.Path]::GetDirectoryName($fullPath)
    }
    $fullPath
}

function Get-IdeaRegisteredExecutable($Entry) {
    # Accept only the vendor executable directly registered for a standalone installation.
    $command = $Entry.UninstallString.Trim()
    if ($command -match '^"([^"]+\\bin\\uninstall\.exe)"$' -or $command -match '^([^"\r\n]+\\bin\\uninstall\.exe)$') {
        $path = $Matches[1]
        if ($path -match '^[A-Za-z]:\\') { [IO.Path]::GetFullPath($path) }
    }
}

function Assert-TrustedGradleTree([string]$Path) {
    if (-not (Test-TrustedExecutable $Path)) { throw "Незащищённый каталог Gradle: $Path" }
    $directories = [Collections.Generic.Stack[string]]::new()
    $directories.Push($Path)
    while ($directories.Count) {
        foreach ($item in Get-ChildItem -LiteralPath ($directories.Pop()) -Force) {
            if (-not (Test-TrustedExecutable $item.FullName -ParentTrusted)) { throw "Незащищённый файл или каталог Gradle: $($item.FullName)" }
            if ($item.PSIsContainer) { $directories.Push($item.FullName) }
        }
    }
}

function Get-Tool([string]$Kind, [string]$ExplicitPath, [object[]]$Entries, [switch]$VerifyVersion) {
    if ($UsePublishedInstallers) { Write-Host "Checking $Kind..." }
    $paths = [Collections.Generic.List[string]]::new()
    $registered = @()
    if ($ExplicitPath) {
        $paths.Add($ExplicitPath)
    } else {
        switch ($Kind) {
            IDEA {
                $registered = @($Entries | Where-Object Name -match 'IntelliJ IDEA')
                foreach ($entry in $registered) {
                    if ($entry.Location) { $paths.Add($entry.Location) }
                    else {
                        $uninstaller = Get-IdeaRegisteredExecutable $entry
                        if ($uninstaller) { $paths.Add((Split-Path (Split-Path $uninstaller -Parent) -Parent)) }
                    }
                }
                foreach ($base in @("$env:ProgramFiles\JetBrains", "$env:LOCALAPPDATA\Programs")) {
                    if (Test-Path -LiteralPath $base) {
                        Get-ChildItem -LiteralPath $base -Directory | Where-Object Name -match 'IntelliJ|IDEA' |
                            ForEach-Object { $paths.Add($_.FullName) }
                    }
                }
                foreach ($cmd in @(Get-Command idea64.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
            }
            JDK {
                $registered = @($Entries | Where-Object Name -match 'JDK|Java.*Development|Temurin.*Hotspot')
                $paths.Add((Get-JdkDestination))
                foreach ($entry in $registered) { if ($entry.Location) { $paths.Add($entry.Location) } }
                foreach ($base in @($env:ProgramFiles, "$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java", "$env:ProgramFiles\Microsoft")) {
                    if (Test-Path -LiteralPath $base) {
                        Get-ChildItem -LiteralPath $base -Directory | Where-Object Name -match '^jdk(?:[-_\d]|$)' |
                            ForEach-Object { $paths.Add($_.FullName) }
                    }
                }
                if ($env:JAVA_HOME) { $paths.Add($env:JAVA_HOME) }
                foreach ($cmd in @(Get-Command java.exe,javac.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
                    $directory = Split-Path $cmd.Source -Parent
                    if ((Split-Path $directory -Leaf) -ieq 'bin') { $paths.Add($directory) }
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
                foreach ($cmd in @(Get-Command git.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
                $key = Get-ItemProperty 'HKLM:\SOFTWARE\GitForWindows' -ErrorAction SilentlyContinue | Select-Object InstallPath
                if ($key -and $key.InstallPath) { $paths.Add([string]$key.InstallPath) }
            }
            Gradle {
                $paths.Add((Get-GradleDestination))
                foreach ($base in @($env:ProgramFiles, (Join-Path $env:ProgramFiles 'Gradle'))) {
                    if (Test-Path -LiteralPath $base -PathType Container) {
                        Get-ChildItem -LiteralPath $base -Filter 'gradle-*' -Directory |
                            ForEach-Object { $paths.Add($_.FullName) }
                    }
                }
                if ($env:GRADLE_HOME) { $paths.Add($env:GRADLE_HOME) }
                foreach ($cmd in @(Get-Command gradle.bat -CommandType Application -All -ErrorAction SilentlyContinue)) {
                    $paths.Add((Split-Path (Split-Path $cmd.Source -Parent) -Parent))
                }
            }
        }
    }
    $candidates = [Collections.Generic.List[object]]::new()
    $roots = @($paths | ForEach-Object {
        $candidatePath = $_
        try { ConvertTo-ToolRoot $candidatePath $Kind }
        catch { $candidates.Add([pscustomobject]@{ Path=$candidatePath; Version=''; Compatible=$false; Probe=''; Error=$_.Exception.Message }) }
    } | Sort-Object -Unique)
    foreach ($path in $roots) {
        $version = ''; $compatible = $false; $probe = ''; $errorText = ''
        try {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
            switch ($Kind) {
                IDEA {
                    $productFile = Join-Path $path 'product-info.json'
                    if (-not (Test-Path -LiteralPath $productFile)) { continue }
                    $product = Get-Content -LiteralPath $productFile -Raw -Encoding UTF8 | ConvertFrom-Json
                    $version = [string]$product.version
                    $launcher = Join-Path $path 'bin\idea64.exe'
                    $compatible = $product.productCode -eq 'IC' -and $version -match '^2025\.2(?:\.|$)' -and
                        (Test-Path -LiteralPath $launcher -PathType Leaf) -and (Test-TrustedExecutable $productFile) -and
                        (Test-TrustedExecutable $launcher)
                    $probe = "product-info: $($product.productCode) $version build $($product.buildNumber)"
                }
                JDK {
                    $java = Join-Path $path 'bin\java.exe'; $javac = Join-Path $path 'bin\javac.exe'
                    if (-not (Test-Path -LiteralPath $java -PathType Leaf)) { continue }
                    $release = Join-Path $path 'release'
                    if (Test-Path -LiteralPath $release -PathType Leaf) {
                        $details = Get-Content -LiteralPath $release -Raw
                        $version = [regex]::Match($details, '(?m)^JAVA_VERSION="(\d+(?:\.\d+){0,3})(?:[+"-])').Groups[1].Value
                    }
                    $probe = "release: JAVA_VERSION=$version"
                    if ($version -match '^25(?:\.|$)' -and (Test-Path -LiteralPath $javac -PathType Leaf)) {
                        if (-not (Test-TrustedExecutable $release) -or -not (Test-TrustedExecutable $java) -or -not (Test-TrustedExecutable $javac)) {
                            throw 'Путь JDK не защищён от записи обычным пользователем.'
                        }
                        $compatible = $true
                        if ($VerifyVersion) {
                            $run = Invoke-Native $java @('--version')
                            $compile = Invoke-Native $javac @('--version')
                            $version = [regex]::Match($run.Output, '(?:openjdk|java)\s+(\d+(?:\.\d+){0,3})').Groups[1].Value
                            $compatible = $run.ExitCode -eq 0 -and $compile.ExitCode -eq 0 -and
                                $version -match '^25(?:\.|$)' -and $compile.Output -match '^javac 25(?:\.|\s|$)'
                            $probe = "$($run.Output)`n$($compile.Output)"
                        }
                    }
                }
                Git {
                    $exe = Join-Path $path 'cmd\git.exe'
                    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $path 'bin\git.exe' }
                    if (-not (Test-Path -LiteralPath $exe)) { continue }
                    if (-not (Test-TrustedExecutable $exe)) { throw 'Путь Git не защищён от записи обычным пользователем.' }
                    $gitBinary = Join-Path $path 'mingw64\bin\git.exe'
                    if (-not (Test-Path -LiteralPath $gitBinary -PathType Leaf)) { $gitBinary = $exe }
                    if (-not (Test-TrustedExecutable $gitBinary)) { throw 'Двоичный файл Git не защищён от записи обычным пользователем.' }
                    $metadata = (Get-Item -LiteralPath $gitBinary).VersionInfo
                    $probe = "PE: ProductVersion=$($metadata.ProductVersion); FileVersion=$($metadata.FileVersion)"
                    $match = [regex]::Match("$($metadata.ProductVersion) $($metadata.FileVersion)", '\d+\.\d+\.\d+')
                    $version = $match.Value
                    if (-not $match.Success) {
                        $entry = $registered | Where-Object { $_.Machine -and $_.Location -and
                            (ConvertTo-ToolRoot $_.Location Git) -ieq $path } | Select-Object -First 1
                        if ($entry) { $version = [regex]::Match($entry.Version, '\d+\.\d+\.\d+').Value }
                    }
                    $compatible = $version -and [version]$version -ge [version]$pins.Git.Version
                    if ($VerifyVersion) {
                        $run = Invoke-Native $exe @('--version')
                        $version = [regex]::Match($run.Output, 'git version (\d+\.\d+\.\d+)').Groups[1].Value
                        $compatible = $run.ExitCode -eq 0 -and $version -and [version]$version -ge [version]$pins.Git.Version
                        $probe = $run.Output
                    }
                }
                Gradle {
                    $batch = Join-Path $path 'bin\gradle.bat'
                    if (-not (Test-Path -LiteralPath $batch -PathType Leaf)) { throw 'Отсутствует bin\gradle.bat' }
                    $lib = Join-Path $path 'lib'
                    if (-not (Test-Path -LiteralPath $lib -PathType Container)) { throw 'Отсутствует каталог lib Gradle' }
                    Assert-TrustedGradleTree $path
                    $core = @(Get-ChildItem -LiteralPath $lib -Filter 'gradle-core-*.jar' -File |
                        Where-Object Name -match '^gradle-core-\d+\.\d+\.\d+(?:-[\w.-]+)?\.jar$')
                    if ($core.Count -ne 1) { throw 'Ожидается один JAR gradle-core с версией Gradle' }
                    $version = $core[0].BaseName.Substring('gradle-core-'.Length)
                    $launcher = Join-Path $lib "gradle-launcher-$version.jar"
                    $compatible = $version -match '^9\.8\.\d+$' -and [version]$version -ge [version]$pins.Gradle.Version -and
                        (Test-Path -LiteralPath $launcher -PathType Leaf) -and
                        (Test-Path -LiteralPath (Join-Path $lib 'plugins') -PathType Container)
                    $probe = "Структура и ACL дистрибутива Gradle $version"
                }
            }
        } catch { $errorText = $_.Exception.Message }
        $candidates.Add([pscustomobject]@{ Path=$path; Version=$version; Compatible=[bool]$compatible; Probe=$probe; Error=$errorText })
    }
    $compatibleCandidates = $candidates | Where-Object Compatible
    if ($Kind -eq 'IDEA') {
        $compatibleCandidates = $compatibleCandidates | Sort-Object -Property @{Expression={[version]$_.Version};Descending=$true},Path
    } elseif ($Kind -eq 'JDK') {
        $own = Get-JdkDestination
        $compatibleCandidates = $compatibleCandidates | Sort-Object -Property @{Expression={$_.Path -ieq $own};Descending=$true},Path
    } elseif ($Kind -eq 'Gradle') {
        $compatibleCandidates = $compatibleCandidates | Sort-Object -Property @{Expression={[version]$_.Version};Descending=$true},Path
    }
    $selected = @($compatibleCandidates | Select-Object -First 1)
    $state = 'Missing'
    if ($selected.Count) { $state = 'Compatible' }
    elseif ($candidates.Count -or $registered.Count -or $ExplicitPath) { $state = 'Conflict' }
    [pscustomobject]@{ Name=$Kind; State=$state; Selected=$(if ($selected.Count) { $selected[0] } else { $null });
        Candidates=@($candidates.ToArray()); Registered=@($registered | Select-Object Name,Version,Location); ExplicitPath=[bool]$ExplicitPath }
}

function Get-Inventory([switch]$VerifyVersions) {
    $entries = @(Get-UninstallEntries)
    [pscustomobject]@{ IDEA=(Get-Tool IDEA $IdeaPath $entries); JDK=(Get-Tool JDK $JdkPath $entries -VerifyVersion:$VerifyVersions);
        Git=(Get-Tool Git $GitPath $entries -VerifyVersion:$VerifyVersions); Gradle=(Get-Tool Gradle $GradlePath $entries) }
}

function Get-IdeaReplacement($Inventory) {
    if ($ReplaceIdeaPath -notmatch '^[A-Za-z]:[\\/]') { throw 'Conflict: -ReplaceIdeaPath требует полный локальный путь.' }
    $target = ConvertTo-ToolRoot $ReplaceIdeaPath IDEA
    $candidate = @($Inventory.IDEA.Candidates | Where-Object Path -ieq $target)
    if ($candidate.Count -and $candidate[0].Compatible -and $candidate[0].Version -eq $pins.IDEA.Version) { return }
    $launcher = Join-Path $target 'bin\idea64.exe'
    $uninstaller = Join-Path $target 'bin\uninstall.exe'
    $matches = @(Get-UninstallEntries | Where-Object {
        $_.Name -match '^IntelliJ IDEA' -and (Get-IdeaRegisteredExecutable $_) -ieq $uninstaller
    })
    if (-not $matches.Count -and -not (Test-Path -LiteralPath $launcher) -and -not (Test-Path -LiteralPath $uninstaller)) { return }
    if ($candidate.Count -ne 1 -or -not $candidate[0].Version -or
        -not (Test-Path -LiteralPath $launcher -PathType Leaf) -or -not (Test-TrustedExecutable $launcher) -or
        -not (Test-TrustedExecutable (Join-Path $target 'product-info.json'))) {
        throw "Conflict: не подтверждён установленный экземпляр IntelliJ IDEA в $target."
    }
    if ($matches.Count -ne 1 -or -not $matches[0].Machine -or $matches[0].Publisher -notmatch 'JetBrains' -or
        ($matches[0].Location -and (ConvertTo-ToolRoot $matches[0].Location IDEA) -ine $target) -or
        -not (Test-Path -LiteralPath $uninstaller -PathType Leaf) -or -not (Test-TrustedExecutable $uninstaller)) {
        throw "Conflict: для $target нужна единственная машинная запись со штатным защищённым bin\uninstall.exe."
    }
    $environment = Get-EnvironmentObservation
    $registeredPaths = @($environment.MachinePath -split ';') + @($environment.UserPath -split ';')
    foreach ($entryPath in @($registeredPaths | Where-Object { $_ })) {
        $expanded = [Environment]::ExpandEnvironmentVariables($entryPath.Trim().Trim('"')).TrimEnd('\', '/')
        if ($expanded -ieq $target -or $expanded.StartsWith("$target\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Conflict: $target используется в PATH. Замену с сохранением прежнего PATH должен выполнить администратор."
        }
    }
    foreach ($process in @(Get-Process -Name idea64,idea -ErrorAction SilentlyContinue)) {
        if (-not $process.Path -or $process.Path.StartsWith("$target\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Conflict: закройте экземпляр IDEA в $target перед заменой."
        }
    }
    [pscustomobject]@{ Path=$target; Version=$candidate[0].Version; RegistryPath=$matches[0].RegistryPath;
        Build=$candidate[0].Probe; RegisteredVersion=$matches[0].Version;
        Uninstaller=$uninstaller; SHA256=(Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash }
}

function Get-SoftwarePlan($Inventory) {
    $destinations = @{ IDEA="$env:ProgramFiles\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4";
        JDK=(Get-JdkDestination); Git="$env:ProgramFiles\Git"; Gradle=(Get-GradleDestination) }
    $actions = [Collections.Generic.List[object]]::new()
    $packages = [Collections.Generic.List[object]]::new()
    $blockers = [Collections.Generic.List[string]]::new()
    $replacement = $null
    if ($ReplaceIdeaPath) {
        try {
            if ($IdeaPath) { throw 'Conflict: -IdeaPath и -ReplaceIdeaPath задают несовместимые действия.' }
            $replacement = Get-IdeaReplacement $Inventory
        } catch { $blockers.Add($_.Exception.Message) }
    }
    foreach ($name in $installOrder) {
        $tool = $Inventory.$name
        $selected = $tool.Selected
        $remove = $null
        $explicitIdeaReplacement = $name -eq 'IDEA' -and $ReplaceIdeaPath -and -not $blockers.Count
        if ($explicitIdeaReplacement) {
            $remove = $replacement
            $selected = $tool.Candidates | Where-Object { $_.Compatible -and $_.Version -eq $pins.IDEA.Version -and
                (-not $remove -or $_.Path -ine $remove.Path) } | Select-Object -First 1
        }
        $operation = 'Keep'
        if ($remove) { $operation = 'Replace' }
        $destination = $null
        if (-not $selected) {
            $alongside = -not $tool.ExplicitPath -and ($name -eq 'JDK' -or ($InstallAlongside -and $name -in @('IDEA','Gradle')))
            $existingTemurin25 = $name -eq 'JDK' -and @($tool.Registered | Where-Object {
                $_.Name -match 'Temurin' -and ($_.Version -match '^25(?:\.|$)' -or $_.Name -match '\b25(?:\.|\s|$)')
            }).Count -gt 0
            $destination = $destinations[$name]
            $reason = $null
            if ($existingTemurin25) {
                $reason = 'Непригодный Temurin 25 уже зарегистрирован. Второй MSI этой версии может изменить прежний JDK.'
            } elseif ($tool.State -eq 'Conflict' -and -not ($alongside -or $explicitIdeaReplacement)) {
                $reason = "Выберите подходящий каталог через -${name}Path. IDEA и Gradle можно установить рядом с -InstallAlongside."
            } elseif (Test-Path -LiteralPath $destination) {
                $reason = "Занят каталог назначения $destination."
            }
            if ($reason) {
                $operation = 'Block'
                $blockers.Add("${name}: $reason")
            } else {
                if (-not $remove) { $operation = 'Install' }
                $pin = $pins[$name]
                $packages.Add([pscustomobject]@{ Name=$name; File=$pin.File; SHA256=$pin.Hash; Uri=$pin.Uri; Destination=$destination })
            }
        }
        # Windows PowerShell 5.1 can serialize an empty pipeline as {} instead of null.
        $existingPath = $null
        $existingVersion = $null
        if ($selected) {
            $existingPath = $selected.Path
            $existingVersion = $selected.Version
        }
        $actions.Add([pscustomobject]@{ Name=$name; Operation=$operation;
            ExistingPath=$existingPath; ExistingVersion=$existingVersion;
            Destination=$destination; Replacement=$remove })
    }
    [pscustomobject]@{ Actions=$actions.ToArray(); Packages=$packages.ToArray(); Blockers=$blockers.ToArray() }
}

function Remove-ReplacedIdea($Approved) {
    $inventory = Get-Inventory
    $current = Get-IdeaReplacement $inventory
    if (-not $current -or ($current | ConvertTo-Json -Compress) -cne ($Approved | ConvertTo-Json -Compress)) {
        throw 'Conflict: экземпляр IDEA или штатный деинсталлятор изменился после проверки.'
    }
    Write-Host "Удаление IDEA $($Approved.Version) по согласованному пути $($Approved.Path)."
    $process = Start-Process -FilePath $Approved.Uninstaller -ArgumentList '/S' -WorkingDirectory (Split-Path $Approved.Uninstaller -Parent) -Wait -PassThru
    $script:Changes.Add([pscustomobject]@{ Tool='IDEA'; Operation='Uninstall'; Path=$Approved.Path; Version=$Approved.Version; ExitCode=$process.ExitCode })
    if ($process.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $Approved.Path 'bin\idea64.exe')) -or
        (Test-Path -LiteralPath $Approved.RegistryPath)) {
        throw "Деинсталляция IDEA в $($Approved.Path) не подтверждена, код $($process.ExitCode)."
    }
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
        SoftwareEligible=($x64 -and $client -and $build -ge 17763);
        SharedPCPlatformEligible=($client -and $build -ge 14393 -and $editionEligible); SharedPCBridge=$bridge;
        SharedPCEditionRecognition=$(if ($editionEligible) { 'KnownSupportedFamily' } elseif ($edition -match '^Core') { 'HomeUnsupported' } else { 'UnknownEdition' });
        PartOfDomain=$domain; FreeMemoryGiB=$memory; OptionalObservations=@($observations.ToArray());
        MatchesTestedOsBuild=($edition -eq 'EnterpriseEval' -and $build -eq 19045 -and [int]$registry.UBR -eq 2006);
        OsBuildMatchMeaning='Совпадает с ОС испытательного стенда; это не приёмка данного ПК и не проверка Guest/IDEA/USB/network.' }
}

function Get-EarlyPreflight($Platform, [switch]$InspectOnly) {
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
                if ($InspectOnly) {
                    if ($available.Count) { $moduleVersion = [string]$available[0].Version }
                    $commands = $null
                    $readProbe = $null
                    $status = 'PresentNotProbed'
                } else {
                    $loaded = Import-Module -Name $manifest -SkipEditionCheck -PassThru -ErrorAction Stop
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
            Architecture='Native x64'; PowerShell='PowerShell 7';
            SharedPCEditions='Pro/Enterprise/Education/IoT Enterprise; Home не поддерживает экзаменационный Guest' };
        LocalMLGPO=$gpo; Modules=[pscustomobject]$modules; Services=$services;
        ServiceMeaning='Проверяется наличие и отсутствие Disabled; demand/trigger-start service может быть Stopped. Запуск/перенастройка не выполняются';
        ExamPlatformPrerequisitesAvailable=$(if ($InspectOnly) { $null } else { [bool]$capabilities }); SoftwareOnlyRequested=[bool]$SoftwareOnly;
        Acceptance='Это чтение предпосылок, не проверка действия Guest/USB/network и не приёмка ПК' }
}

function Get-Installer([string]$Kind) {
    $pin = $pins[$Kind]
    if ($UsePublishedInstallers) { Write-Host "Preparing installation package for $Kind $($pin.Version)..." }
    $file = Join-Path $CacheDirectory $pin.File
    # Запускается только копия в новом admin-only staging, а не путь из общего cache.
    $staged = Join-Path $script:WorkingDirectory $pin.File
    if (Test-Path -LiteralPath $file) {
        $lock = [IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $script:InstallerLocks.Add($lock)
        $output = [IO.File]::Open($staged,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $lock.CopyTo($output) } finally { $output.Dispose() }
    } else {
        if ($UsePublishedInstallers) { throw "В поставке отсутствует $($pin.File)." }
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $pin.Uri -OutFile $staged -UseBasicParsing -TimeoutSec 600 -MaximumRedirection 6
    }
    $stageLock = [IO.File]::Open($staged,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $script:InstallerLocks.Add($stageLock)
    $verifiedHash = (Get-FileHash -InputStream $stageLock -Algorithm SHA256).Hash
    if ($verifiedHash -ne $pin.Hash) { throw "SHA256 staging $Kind не совпадает: $verifiedHash" }
    if ($Kind -eq 'Gradle') {
        $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='ArchiveVerified'; SHA256=$verifiedHash })
    } else {
        $signature = Get-AuthenticodeSignature -LiteralPath $staged
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch [regex]::Escape($pin.Publisher)) {
            throw "Недействительная или неожиданная подпись $Kind : $($signature.Status)"
        }
        $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='InstallerVerified'; SHA256=$verifiedHash; Signer=$signature.SignerCertificate.Subject })
    }
    $staged
}

function Install-Tool([string]$Kind, [string]$Installer, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) { throw "Каталог назначения уже существует: $Destination; автоматическая перезапись запрещена" }
    $arguments = @(); $exe = $Installer
    $logDirectory = $script:WorkingDirectory
    if ($UsePublishedInstallers -and $env:EXAMLAB_DIAGNOSTICS_DIR) {
        $logDirectory = $env:EXAMLAB_DIAGNOSTICS_DIR
    }
    switch ($Kind) {
        Gradle {
            if ($UsePublishedInstallers) { Write-Host "Extracting Gradle $($pins.Gradle.Version)..." }
            $base = Split-Path $Destination -Parent
            if (-not (Test-TrustedExecutable $base)) { throw 'Program Files не имеет ожидаемых защищённых ACL для Gradle' }
            $unpacking = Join-Path $script:WorkingDirectory 'gradle-unpack'
            New-Item -ItemType Directory -Path $unpacking | Out-Null
            try {
                # Защищённый ACL самого корня исключает наследование прав Program Files после переноса.
                $extracted = Join-Path $unpacking (Split-Path $Destination -Leaf)
                New-SetupDirectory $extracted -AllowUserExecute
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($Installer, $unpacking)
                $distribution = Get-Tool Gradle $extracted @()
                if ($distribution.State -ne 'Compatible' -or $distribution.Selected.Version -ne $pins.Gradle.Version) {
                    throw 'Проверенный ZIP не содержит ожидаемую структуру Gradle'
                }
                # Публикуем целый каталог на том же томе; Directory.Move не заменяет уже существующий путь.
                [IO.Directory]::Move($extracted, $Destination)
            } finally { Remove-Item -LiteralPath $unpacking -Recurse -Force }
            $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='Install'; ExitCode=0; Destination=$Destination })
            if ($UsePublishedInstallers) { Write-Host 'Gradle installation completed.' }
            return
        }
        JDK {
            $exe = "$env:SystemRoot\System32\msiexec.exe"
            $arguments = @('/i', "`"$Installer`"", '/qn','/norestart','ADDLOCAL=FeatureMain',
                "INSTALLDIR=`"$Destination`"", '/L*v', "`"$logDirectory\jdk-install.log`"")
        }
        Git { $arguments = @('/VERYSILENT','/NORESTART','/ALLUSERS','/SP-','/o:PathOption=BashOnly', '/COMPONENTS=',"/DIR=`"$Destination`"", "/LOG=`"$logDirectory\git-install.log`"") }
        IDEA {
            $config = Join-Path $script:WorkingDirectory 'idea-silent.config'
            @('mode=admin','launcher64=1','updatePATH=0','updateContextMenu=0','.java=0','.groovy=0','.kt=0') | Set-Content -LiteralPath $config -Encoding ASCII
            $arguments = @('/S',"/CONFIG=`"$config`"", "/LOG=`"$logDirectory\idea-install.log`"", "/D=$Destination")
        }
    }
    if ($UsePublishedInstallers) {
        Write-Host "Starting silent installation of $Kind $($pins[$Kind].Version). This may take several minutes."
    }
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
    $code = $process.ExitCode
    $script:Changes.Add([pscustomobject]@{ Tool=$Kind; Operation='Install'; ExitCode=$code; Destination=$Destination })
    if ($code -eq 3010) { $script:RebootRequired = $true }
    elseif ($code -ne 0) { throw "Установщик $Kind завершился с кодом $code; см. журнал в $logDirectory" }
    if ($UsePublishedInstallers) {
        $restartNotice = if ($code -eq 3010) { ' A restart is required.' } else { '' }
        Write-Host "$Kind installation completed.$restartNotice"
    }
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
    foreach ($exe in @('java.exe','javac.exe','git.exe','idea64.exe','gradle.bat')) {
        $resolved[$exe] = @(Get-Command $exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    }
    [pscustomobject]@{ MachineJAVA_HOME=[Environment]::GetEnvironmentVariable('JAVA_HOME','Machine');
        UserJAVA_HOME=[Environment]::GetEnvironmentVariable('JAVA_HOME','User');
        MachineGRADLE_HOME=[Environment]::GetEnvironmentVariable('GRADLE_HOME','Machine');
        UserGRADLE_HOME=[Environment]::GetEnvironmentVariable('GRADLE_HOME','User');
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
$script:IsAdministratorAccount = $script:IsAdmin -or 'S-1-5-32-544' -in @($identity.Groups | ForEach-Object Value)
$inspectOnly = $Action -eq 'Check'
$apply = $Action -in @('Prepare','Apply')
$report = [ordered]@{ Timestamp=[DateTime]::UtcNow.ToString('o'); ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;
    Action=$Action; Platform=$null; Preflight=$null; Plan=$null; Before=$null; After=$null;
    EnvironmentBefore=$null; EnvironmentAfter=$null; EnvironmentPreserved=$null; CLIProbe=$null; WorkingDirectory=$null;
    Changes=@(); Errors=@(); RebootRequired=$false; SoftwareReady=$false; ExamReady=$false;
    ManualChecks=@('Настоящий Shared PC Guest','IDEA: SDK/run/debug, completion/inspection/refactoring, отсутствие генеративных помощников',
        'Gradle с JDK 25: запуск и сборка исходного проекта в IDEA из Guest',
        'Moodle и PrairieLearn','Физические флешки','Локальное завершение и сохранность обычных занятий') }
$toolNames = @('IDEA','JDK','Git','Gradle')
$installOrder = @('JDK','Git','IDEA','Gradle')
$exitCode = 0
try {
    if (-not [Environment]::Is64BitProcess) { throw 'Conflict: запустите 64-битный PowerShell.' }
    if (-not $inspectOnly -and (-not $script:IsAdmin -or $PSVersionTable.PSVersion -lt [version]'7.6')) {
        throw 'Запустите 64-битный PowerShell 7.6 от администратора (повышенный UAC token).'
    }
    if ($UsePublishedInstallers) { Write-Host 'Checking Windows prerequisites...' }
    $report.Platform = Get-Platform
    $report.Preflight = Get-EarlyPreflight $report.Platform -InspectOnly:$inspectOnly
    if (-not $report.Platform.SoftwareEligible) {
        throw 'Conflict: нужна клиентская Windows 10 1809+ x64.'
    }
    if (-not $SoftwareOnly -and ((-not $inspectOnly -and -not $report.Preflight.ExamPlatformPrerequisitesAvailable) -or
        ($inspectOnly -and -not $report.Platform.SharedPCPlatformEligible))) {
        throw 'Conflict: не подтверждены предпосылки GPO/SharedPC/NetSecurity/ScheduledTasks/LocalAccounts; см. Preflight. Для одних программ используйте явный -SoftwareOnly'
    }
    $report.EnvironmentBefore = Get-EnvironmentObservation
    $inventory = Get-Inventory
    $report.Before = $inventory
    $report.Plan = Get-SoftwarePlan $inventory
    if ($report.Plan.Blockers.Count) { throw ('Conflict: ' + ($report.Plan.Blockers -join ' ')) }
    if ($apply) {
        if ($ExpectedPlanPath) {
            $expected = Get-Content -LiteralPath $ExpectedPlanPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($expected.Action -ne 'Check' -or $expected.ExitCode -ne 0 -or $null -eq $expected.Plan -or
                ($expected.Plan.Actions | ConvertTo-Json -Compress -Depth 6) -cne ($report.Plan.Actions | ConvertTo-Json -Compress -Depth 6)) {
                throw 'Conflict: план программ изменился. Сравните ожидаемые и текущие Plan.Actions и повторите Check.'
            }
        }
        $pending = @($report.Plan.Packages)
        if ($pending.Count -and $UsePublishedInstallers -and (-not $PSBoundParameters.ContainsKey('CacheDirectory') -or
            -not (Test-Path -LiteralPath $CacheDirectory -PathType Container) -or -not (Test-TrustedExecutable $CacheDirectory))) {
            throw 'Для локального пилота укажите защищённый каталог опубликованных установщиков.'
        }
        foreach ($actionItem in @($report.Plan.Actions | Where-Object { $_.Operation -eq 'Keep' -and $_.Name -in @('JDK','Git') })) {
            $observed = Get-Tool $actionItem.Name $actionItem.ExistingPath @() -VerifyVersion
            if ($observed.State -ne 'Compatible' -or $observed.Selected.Version -ne $actionItem.ExistingVersion) {
                throw "Conflict: проба $($actionItem.Name) не подтвердила план. См. Before и After."
            }
        }
        if ($pending.Count) {
            $script:WorkingDirectory = New-ProtectedDirectory
            $report.WorkingDirectory = $script:WorkingDirectory
        }
        # Проверка всех требуемых файлов до первого запуска установщика.
        $installers = @{}
        foreach ($package in $pending) { $installers[$package.Name] = Get-Installer $package.Name }
        foreach ($actionItem in $report.Plan.Actions) {
            $name = $actionItem.Name
            if ($actionItem.Replacement) {
                if ($script:RebootRequired) { continue }
                # Части выпуска IDEA могут использовать одну запись удаления Windows.
                # Сначала проверен весь кэш, затем выполняется явная замена.
                Remove-ReplacedIdea $actionItem.Replacement
            }
            if ($installers.ContainsKey($name)) {
                Install-Tool $name $installers[$name] $actionItem.Destination
            } else {
                if ($UsePublishedInstallers) { Write-Host "Keeping installed $name $($actionItem.ExistingVersion)." }
                $script:Changes.Add([pscustomobject]@{ Tool=$name; Operation='PreservedCompatible'; Path=$actionItem.ExistingPath })
            }
        }
        if ($UsePublishedInstallers) { Write-Host 'Verifying the installed tool versions...' }
        if (-not $script:RebootRequired) {
            foreach ($package in $pending) {
                $name = $package.Name
                $installed = Get-Tool $name $package.Destination @() -VerifyVersion
                if ($installed.State -ne 'Compatible' -or $installed.Selected.Version -ne $pins[$name].Version) {
                    throw "Не подтверждена версия $name $($pins[$name].Version) в $($package.Destination)."
                }
            }
        }
        $inventory = Get-Inventory
        if ($inventory.IDEA.State -eq 'Compatible') {
            $freshIdea = $installers.ContainsKey('IDEA')
            $pluginTarget = if ($freshIdea) { ($pending | Where-Object Name -eq 'IDEA').Destination } else { $inventory.IDEA.Selected.Path }
            $pluginRoot = Join-Path $pluginTarget 'plugins'
            $excluded = @(@('plugin-classpath.txt','fullLine') | ForEach-Object { Join-Path $pluginRoot $_ } |
                Where-Object { Test-Path -LiteralPath $_ })
            if (-not $script:RebootRequired -and ($freshIdea -or $DisableBundledGenerativePlugins) -and $excluded.Count) {
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
    $report.After = if ($inspectOnly) { $inventory } else { Get-Inventory -VerifyVersions }
    $report.EnvironmentAfter = Get-EnvironmentObservation
    $report.EnvironmentPreserved = $report.EnvironmentBefore.MachineJAVA_HOME -ceq $report.EnvironmentAfter.MachineJAVA_HOME -and
        $report.EnvironmentBefore.UserJAVA_HOME -ceq $report.EnvironmentAfter.UserJAVA_HOME -and
        $report.EnvironmentBefore.MachineGRADLE_HOME -ceq $report.EnvironmentAfter.MachineGRADLE_HOME -and
        $report.EnvironmentBefore.UserGRADLE_HOME -ceq $report.EnvironmentAfter.UserGRADLE_HOME -and
        $report.EnvironmentBefore.MachinePath -ceq $report.EnvironmentAfter.MachinePath -and
        $report.EnvironmentBefore.UserPath -ceq $report.EnvironmentAfter.UserPath
    if (-not $inspectOnly) {
        if ($UsePublishedInstallers) { Write-Host 'Testing Java compilation and local Git commands...' }
        $report.CLIProbe = Test-CLI $report.After
        $report.SoftwareReady = $report.Platform.SoftwareEligible -and $toolNames.Where({ $report.After.$_.State -ne 'Compatible' }).Count -eq 0 -and $report.CLIProbe.Passed
        if (-not $report.SoftwareReady) { $exitCode = 2 }
    }
    $report.PluginReview = Get-IDEPlugins $report.After.IDEA
    if (-not $report.EnvironmentPreserved) { $script:Failures.Add('Обнаружено изменение JAVA_HOME, GRADLE_HOME или PATH.'); $exitCode = 1 }
    if ($script:RebootRequired -and $report.EnvironmentPreserved -and $script:Failures.Count -eq 0) { $exitCode = 3010 }
} catch {
    if ($UsePublishedInstallers) { Write-Host "Tool preparation failed. $($_.Exception.Message)" }
    $script:Failures.Add($_.Exception.Message)
    $exitCode = 1
    if ($_.Exception.Message -like 'Conflict:*') { $exitCode = 2 }
    if ($report.Before) {
        try { $report.After = Get-Inventory -VerifyVersions:(!$inspectOnly) }
        catch { $script:Failures.Add($_.Exception.Message) }
        try { $report.EnvironmentAfter = Get-EnvironmentObservation }
        catch { $script:Failures.Add($_.Exception.Message) }
    }
} finally {
    foreach ($lock in $script:InstallerLocks) { $lock.Dispose() }
    if ($script:WorkingDirectory) {
        # The private working directory keeps logs; signed or pinned installer inputs are reusable upstream.
        foreach ($kind in $toolNames) {
            $stagedInstaller = Join-Path $script:WorkingDirectory $pins[$kind].File
            if (Test-Path -LiteralPath $stagedInstaller -PathType Leaf) {
                try { [IO.File]::Delete($stagedInstaller) }
                catch { Write-Warning "Не удалена временная копия установщика $stagedInstaller." }
            }
        }
    }
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
    if ($HumanOutput) { Write-Host "Software report saved to $ReportPath" }
    else { Write-Output $json }
}
exit $exitCode
