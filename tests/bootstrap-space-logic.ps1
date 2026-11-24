# Переносимый тест. Подменены чтение томов Win32, проверка Windows ACL и размеры компонентов.
# Проверяются расчёт порогов, отчёт и очистка реальных временных файлов по SHA-256.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$launcher = Join-Path $PSScriptRoot '../setup/Start-ExamLab.cmd'
$parts = [IO.File]::ReadAllText($launcher) -split '(?m)^:NativePowerShell\r?\n', 2
if ($parts.Count -ne 2) { throw 'Не найден PowerShell-блок CMD.' }
$source = $parts[1] -creplace '@[A-Z0-9_]+@', '0'
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in 'Test-Artifact', 'New-SpaceNeed', 'Test-ReleaseSpace', 'Remove-CachedReleaseInstallers') {
    $definition = $ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    }
    if (-not $definition) { throw "Не найдена функция $name." }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}

function Get-ReleaseVolume([string]$Path) {
    if (-not $script:fixtureVolumes.ContainsKey($Path)) { throw "Неожиданный путь тома $Path." }
    $script:fixtureVolumes[$Path]
}

function Get-InstallationSpaceNeeds {
    New-SpaceNeed $installation 'SetupFiles' 16MB
}

function Assert-ExamLabProtectedPath([string]$Path) {
    if ([IO.Path]::GetDirectoryName($Path) -cne $cache -or -not [IO.File]::Exists($Path)) {
        throw "Неожиданный файл тестового кэша $Path."
    }
}

function New-TestPackage([string]$Name) {
    $path = Join-Path $cache $Name
    [IO.File]::WriteAllText($path, 'known')
    @{ Name=$Name; Bytes=(Get-Item -LiteralPath $path).Length; SHA256=(Get-FileHash -LiteralPath $path).Hash }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-bootstrap-space-' + [Guid]::NewGuid().ToString('N'))
$cache = Join-Path $temporary 'cache'
$report = Join-Path $temporary 'report'
$installation = Join-Path $temporary 'installed'
try {
    [void][IO.Directory]::CreateDirectory($cache)
    [void][IO.Directory]::CreateDirectory($report)
    $script:fixtureVolumes = @{}
    $script:fixtureVolumes[$cache] = [pscustomobject]@{ Id='Cache'; MountPath='D:\'; FreeBytes=8MB; Error=$null }
    $script:fixtureVolumes[$installation] = [pscustomobject]@{ Id='Install'; MountPath='C:\'; FreeBytes=2MB; Error=$null }
    $plan = [pscustomobject]@{ Report=[ordered]@{
        CacheGrowthUpperBoundBytes=4MB; KnownCacheGrowthBytes=4MB; SpaceChecks=@()
    } }

    $action = 'Prefetch'
    if (-not (Test-ReleaseSpace $plan $true 'Initial')) { throw 'Prefetch зависит от места на томе установки.' }
    $script:fixtureVolumes[$cache].FreeBytes = 1MB
    if (Test-ReleaseSpace $plan $true 'Initial') { throw 'Prefetch пропустил известную нехватку места в кэше.' }
    $script:fixtureVolumes[$cache].FreeBytes = 8MB

    $action = 'Apply'
    if (Test-ReleaseSpace $plan $true 'Initial') { throw 'Apply пропустил известную нехватку места на томе установки.' }
    $saved = Get-Content -LiteralPath (Join-Path $report 'release-plan.json') -Raw | ConvertFrom-Json
    $installVolume = $saved.SpaceChecks[-1].Volumes | Where-Object VolumeId -CEQ 'Install'
    if ($installVolume.Status -cne 'InsufficientSpace' -or $installVolume.RequiredBytesForAction -ne 16MB) {
        throw 'В отчёте Apply потеряна причина отказа.'
    }

    $tools = @(New-TestPackage 'release.exe'; New-TestPackage 'renamed.exe'; New-TestPackage 'release.msi')
    [IO.File]::WriteAllText((Join-Path $cache 'renamed.exe'), 'wrong')
    [IO.File]::WriteAllText((Join-Path $cache 'foreign.exe'), 'known')
    Remove-CachedReleaseInstallers
    if (Test-Path -LiteralPath (Join-Path $cache 'release.exe')) { throw 'Закреплённый EXE остался в кэше.' }
    foreach ($name in 'renamed.exe', 'foreign.exe', 'release.msi') {
        if (-not (Test-Path -LiteralPath (Join-Path $cache $name) -PathType Leaf)) { throw "Очистка удалила $name." }
    }
    $cleanup = Get-Content -LiteralPath (Join-Path $report 'installer-cleanup.json') -Raw | ConvertFrom-Json
    if (($cleanup | Where-Object Name -CEQ 'renamed.exe').Status -cne 'Retained') {
        throw 'В отчёте очистки отсутствует сохранённый EXE с другим SHA-256.'
    }
    'PASS: раздельные тома, отказ при нехватке подтверждённого места и адресная очистка EXE.'
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
