# Переносимый тест плана с временными файлами и подменой ACL, реестра и поиска команд.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$source = Join-Path $PSScriptRoot '..\setup\Prepare-ExamLab.ps1'
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst] -or
        ($node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$pins')) {
        . ([ScriptBlock]::Create($node.Extent.Text))
    }
}

function Test-TrustedExecutable([string]$Path, [switch]$ParentTrusted) { $true }
function Get-ItemProperty { [CmdletBinding()]param([string]$Path) }
function Get-Command { [CmdletBinding()]param([string[]]$Name, [string]$CommandType, [switch]$All) }
function Get-UninstallEntries { $registeredFixture }
function Invoke-Native { throw 'План запустил программу вместо чтения метаданных.' }
function Get-Item([string]$LiteralPath) {
    if ($LiteralPath -eq $gitBinaryFixture) { return [pscustomobject]@{ VersionInfo=$gitVersionFixture } }
    if ($LiteralPath -eq $winDirStatBinaryFixture) { return [pscustomobject]@{ VersionInfo=$winDirStatVersionFixture } }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath
}

function New-FixtureFile([string]$Path, [string]$Contents = '') {
    [void][IO.Directory]::CreateDirectory((Split-Path $Path -Parent))
    [IO.File]::WriteAllText($Path, $Contents)
}

function New-FixtureJdk([string]$Directory, [string]$Version) {
    New-FixtureFile (Join-Path $Directory 'bin/java.exe')
    New-FixtureFile (Join-Path $Directory 'bin/javac.exe')
    New-FixtureFile (Join-Path $Directory 'release') ('JAVA_VERSION="{0}"' -f $Version)
}

$shortage = [pscustomobject]@{ Status='InsufficientForStagedPackages'; Volume='C:\'; AvailableBytes=100;
    RequiredPackageStagingBytes=200; EstimatedPeakAdditionalBytes=300 }
$warnings = @(Confirm-SoftwareDiskSpace $shortage 3>&1)
if ($warnings.Count -ne 1 -or $warnings[0] -isnot [Management.Automation.WarningRecord]) {
    throw 'Check должен сообщить о нехватке места и продолжить.'
}
$blocked = $false
try { Confirm-SoftwareDiskSpace $shortage -Apply }
catch { $blocked = $_.Exception.Message -like 'Conflict:*200*' }
if (-not $blocked) { throw 'Apply должен остановиться при нехватке места для временных копий пакетов.' }
$shortage.Status = 'BelowEstimatedPeak'
$shortage.AvailableBytes = 250
$warnings = @(Confirm-SoftwareDiskSpace $shortage -Apply 3>&1)
if ($warnings.Count -ne 1 -or $warnings[0] -isnot [Management.Automation.WarningRecord]) {
    throw 'Apply должен продолжиться с предупреждением, если временные копии помещаются.'
}
'PASS Место: Check предупреждает, Apply блокируется только ниже размера временных копий.'

$UsePublishedInstallers = $InstallAlongside = $false
$IdeaPath = $JdkPath = $GitPath = $GradlePath = $ReplaceIdeaPath = $null
$installOrder = @('JDK', 'Git', 'IDEA', 'Gradle', 'WinDirStat')
$registeredFixture = @()
$gitBinaryFixture = $gitVersionFixture = $null
$winDirStatBinaryFixture = $winDirStatVersionFixture = $null
$previous = @{}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-software-plan-' + [Guid]::NewGuid().ToString('N'))
foreach ($name in 'ProgramFiles', 'LOCALAPPDATA', 'JAVA_HOME', 'GRADLE_HOME') {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name)
}
try {
    $env:ProgramFiles = Join-Path $temporary 'Program Files'
    $env:LOCALAPPDATA = Join-Path $temporary 'LocalAppData'
    $env:GRADLE_HOME = $null
    $oldJdk = Join-Path $env:ProgramFiles 'jdk-26.0.1'
    $env:JAVA_HOME = Join-Path $oldJdk 'bin'
    New-FixtureJdk $oldJdk '26.0.1'
    $inventory = Get-Inventory
    $candidates = @($inventory.JDK.Candidates)
    if ($candidates.Count -ne 1 -or $candidates[0].Path -ne $oldJdk -or $candidates[0].Version -ne '26.0.1') {
        throw 'Ожидался один кандидат JDK 26 с корневым путём и определённой версией.'
    }
    $plan = Get-SoftwarePlan $inventory
    $jdk = $plan.Actions | Where-Object Name -eq JDK
    if ($jdk.Operation -ne 'Install' -or $jdk.Destination -ne (Get-JdkDestination) -or $plan.Blockers.Count) {
        throw 'Ожидалась отдельная установка JDK 25 рядом с JDK 26.'
    }
    'PASS JDK: обнаружен корень по bin, запланирован отдельный JDK 25.'

    $gradlePlan = $plan.Actions | Where-Object Name -eq Gradle | ConvertTo-Json -Compress | ConvertFrom-Json
    if ($gradlePlan.Operation -ne 'Install' -or $null -ne $gradlePlan.ExistingPath -or $null -ne $gradlePlan.ExistingVersion) {
        throw 'Ожидались JSON null для версии и пути отсутствующей установки Gradle.'
    }
    'PASS План: версия и путь отсутствующего Gradle сериализованы как JSON null.'

    $component = $plan.Size.Components | Where-Object Name -eq WinDirStat
    $package = $plan.Packages | Where-Object Name -eq WinDirStat
    $knownPayload = ($plan.Packages | Measure-Object -Property PayloadBytes -Sum).Sum
    if ($component.Operation -ne 'Install' -or $package.File -ne $pins.WinDirStat.File -or
        $component.PayloadBytes -ne 2486272 -or $component.StagingBytes -le $component.PayloadBytes -or
        $component.AdditionalInstalledBytes -lt 2910384 -or $plan.Size.KnownPayloadBytes -ne $knownPayload -or
        $plan.Size.EstimatedAdditionalInstalledBytes -ne $plan.Size.EstimatedInstalledFootprintBytes) {
        throw 'Ожидался отдельный точный размер пакета WinDirStat и оценки места для новых программ.'
    }
    'PASS WinDirStat: новый MSI в плане, размер скачивания и оценки установки различаются.'

    $jdkHome = Get-JdkDestination
    New-FixtureJdk $jdkHome $pins.JDK.Version
    $JdkPath = Join-Path $jdkHome 'bin'
    $idea = Join-Path $env:ProgramFiles 'JetBrains/IntelliJ IDEA Community Edition'
    $ideaMetadata = @{ productCode='IC'; version=$pins.IDEA.Version; buildNumber='252.1' } | ConvertTo-Json -Compress
    New-FixtureFile (Join-Path $idea 'product-info.json') $ideaMetadata
    New-FixtureFile (Join-Path $idea 'bin/idea64.exe')
    $git = Join-Path $env:ProgramFiles 'Git'
    New-FixtureFile (Join-Path $git 'cmd/git.exe')
    $registeredFixture = @([pscustomobject]@{ Name='Git'; Version=$pins.Git.Version; Location=$git; Machine=$true })
    $gradle = Get-GradleDestination
    New-FixtureFile (Join-Path $gradle 'bin/gradle.bat')
    New-FixtureFile (Join-Path $gradle "lib/gradle-core-$($pins.Gradle.Version).jar")
    New-FixtureFile (Join-Path $gradle "lib/gradle-launcher-$($pins.Gradle.Version).jar")
    [void][IO.Directory]::CreateDirectory((Join-Path $gradle 'lib/plugins'))
    $winDirStatBinaryFixture = Join-Path $env:ProgramFiles 'WinDirStat/WinDirStat.exe'
    New-FixtureFile $winDirStatBinaryFixture
    $winDirStatVersionFixture = [pscustomobject]@{ ProductVersion=$pins.WinDirStat.Version; FileVersion="$($pins.WinDirStat.Version).2253" }
    $plan = Get-SoftwarePlan (Get-Inventory)
    $jdk = $plan.Actions | Where-Object Name -eq JDK
    if ($plan.Packages.Count -or $plan.Blockers.Count -or $jdk.ExistingPath -ne $jdkHome -or
        @($plan.Actions | Where-Object Operation -ne Keep).Count -or $plan.Size.KnownPayloadBytes -or
        $plan.Size.EstimatedAdditionalInstalledBytes -or $plan.Size.EstimatedStagingBytes -or
        $plan.Size.EstimatedInstalledFootprintBytes -le 0) {
        throw 'Повтор должен сохранить подходящие программы и оценку их места без нового скачивания или установки.'
    }
    'PASS Повтор: подходящие программы сохранены в плане, установщики не требуются.'

    $gitBinaryFixture = Join-Path $git 'mingw64/bin/git.exe'
    New-FixtureFile $gitBinaryFixture
    $gitRelease = "$($pins.Git.Version).windows.1"
    $gitVersionFixture = [pscustomobject]@{ ProductVersion=$gitRelease; FileVersion=$gitRelease }
    $inventory = Get-Inventory
    $plan = Get-SoftwarePlan $inventory
    if ($inventory.Git.State -ne 'Compatible' -or $inventory.Git.Selected.Version -ne $pins.Git.Version -or
        $plan.Blockers.Count -or $plan.Packages.Count) {
        throw 'Ожидалась пригодная версия Git из метаданных PE с суффиксом .windows.1.'
    }
    'PASS Git: версия PE с суффиксом .windows.1 распознана, экземпляр сохранён.'

    $winDirStatVersionFixture = [pscustomobject]@{ ProductVersion='2.9.2'; FileVersion='2.9.2.0' }
    $plan = Get-SoftwarePlan (Get-Inventory)
    $winDirStat = $plan.Actions | Where-Object Name -eq WinDirStat
    if ($winDirStat.Operation -ne 'Block' -or $plan.Size.Complete -or $plan.Packages.Count) {
        throw 'Несовместимая существующая версия WinDirStat должна блокировать автоматическую замену.'
    }
    'PASS WinDirStat: прежняя неподходящая версия сохраняется, требуется проверка администратора.'
} finally {
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
