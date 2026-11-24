# Переносимая проверка журнала на файловой системе. Windows ACL и планировщик здесь не проверяются.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-rollback-' + [guid]::NewGuid().ToString('N'))
$examLabReportsPath = $temporary
$examLabStatePath = $temporary
$examLabInstallChangesPath = Join-Path $temporary 'installation-pending.json'
[void][IO.Directory]::CreateDirectory($temporary)
try {
    $core = Join-Path $PSScriptRoot '..\setup\ExamLabMaintenance.Core.ps1'
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($core, [ref]$null, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    foreach ($definition in $ast.EndBlock.Statements) {
        if ($definition -is [Management.Automation.Language.FunctionDefinitionAst]) {
            . ([ScriptBlock]::Create($definition.Extent.Text))
        }
    }
    function Assert-ExamLabProtectedPath([string]$Path, [switch]$Readable) {
        if (-not (Test-Path -LiteralPath $Path) -or
            -not ([IO.Path]::GetFullPath($Path)).StartsWith($temporary, [StringComparison]::Ordinal)) {
            throw "Unexpected test path $Path."
        }
    }
    function Assert-FileContent([string]$Path, [string]$Expected) {
        if ([IO.File]::ReadAllText($Path) -cne $Expected) { throw "Unexpected file contents at $Path." }
    }

    $target = Join-Path $temporary 'installed.txt'
    $staged = Join-Path $temporary 'staged.txt'
    [IO.File]::WriteAllText($target, 'previous')
    Start-ExamLabInstallChanges
    [IO.File]::WriteAllText($staged, 'first')
    Set-ExamLabInstallFile $staged $target
    [IO.File]::WriteAllText($staged, 'second')
    Set-ExamLabInstallFile $staged $target
    Assert-FileContent $target 'second'
    $result = @(Invoke-ExamLabInstallRecovery)
    if ($result.Count -ne 2 -or $result.Status -contains 'Conflict') { throw 'Expected two rolled back versions.' }
    Assert-FileContent $target 'previous'
    if (Read-ExamLabInstallChanges) { throw 'Resolved installation journal was retained.' }

    Start-ExamLabInstallChanges
    [IO.File]::WriteAllText($staged, 'ours')
    Set-ExamLabInstallFile $staged $target
    [IO.File]::WriteAllText($target, 'foreign change')
    $result = @(Undo-ExamLabInstallChanges)
    if ($result.Count -ne 1 -or $result[0].Status -cne 'Conflict') { throw 'Foreign file change was not reported.' }
    Assert-FileContent $target 'foreign change'
    if (-not (Read-ExamLabInstallChanges)) { throw 'Unresolved changes were lost.' }
    [IO.File]::WriteAllText($target, 'ours')
    $null = Invoke-ExamLabInstallRecovery
    Assert-FileContent $target 'previous'

    Start-ExamLabInstallChanges
    [IO.File]::WriteAllText($staged, 'recorded')
    Add-ExamLabInstallChange ([ordered]@{
        Kind = 'File'; Target = $target; Staged = $staged; Backup = ($target + '.previous')
        Prior = (Get-FileHash -LiteralPath $target).Hash; Applied = (Get-FileHash -LiteralPath $staged).Hash
        Readable = $false
    })
    $null = Invoke-ExamLabInstallRecovery
    Assert-FileContent $target 'previous'
    if (Test-Path -LiteralPath $staged) { throw 'Unapplied staging file was retained.' }

    Start-ExamLabInstallChanges
    [IO.File]::WriteAllText($staged, 'committed')
    Set-ExamLabInstallFile $staged $target
    $journal = Read-ExamLabInstallChanges
    $journal.Committed = $true
    Write-ExamLabMaintenanceJson $examLabInstallChangesPath $journal
    $null = Invoke-ExamLabInstallRecovery
    Assert-FileContent $target 'committed'
    if (Read-ExamLabInstallChanges) { throw 'Committed installation journal was retained.' }

    Start-ExamLabInstallChanges
    Remove-ExamLabInstallFile $target
    if (Test-Path -LiteralPath $target) { throw 'Expected tracked removal.' }
    $null = Invoke-ExamLabInstallRecovery
    Assert-FileContent $target 'committed'

    if ((ConvertTo-ExamLabTaskDuration 'PT72H') -cne (ConvertTo-ExamLabTaskDuration 'P3D')) {
        throw 'Equivalent Task Scheduler durations have different representations.'
    }
    $expected = [ordered]@{ Arguments = '-Valid'; WorkingDirectory = '' }
    $actual = [ordered]@{ Arguments = '-Other'; WorkingDirectory = '' }
    $differences = @(Compare-ExamLabTaskFields 'Task.Actions[0]' $expected $actual)
    if ($differences.Count -ne 1 -or $differences[0].Field -cne 'Task.Actions[0].Arguments') {
        throw 'Task comparison omitted the changed action field.'
    }
    'PASS: файловый журнал установки, сохранность чужого файла и поля сверки задач. Windows API не вызывались.'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
