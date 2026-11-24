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

$UsePublishedInstallers = $InstallAlongside = $false
$IdeaPath = $JdkPath = $GitPath = $GradlePath = $ReplaceIdeaPath = $null
$installOrder = @('JDK', 'Git', 'IDEA', 'Gradle')
$registeredFixture = @()
$gitBinaryFixture = $gitVersionFixture = $null
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
    $plan = Get-SoftwarePlan (Get-Inventory)
    $jdk = $plan.Actions | Where-Object Name -eq JDK
    if ($plan.Packages.Count -or $plan.Blockers.Count -or $jdk.ExistingPath -ne $jdkHome -or
        @($plan.Actions | Where-Object Operation -ne Keep).Count) {
        throw 'Повтор должен сохранить подходящие IDEA, JDK, Git и Gradle, включая выбранный JDK по bin.'
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
} finally {
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
