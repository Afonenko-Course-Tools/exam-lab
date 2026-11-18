# Эта проверка только разбирает исходники; Windows API не вызываются.
$ErrorActionPreference = 'Stop'
$failures = @()
Get-ChildItem -Path @((Join-Path $PSScriptRoot '..\windows'), (Join-Path $PSScriptRoot '..\setup'), $PSScriptRoot) -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    $failures += @($parseErrors)
}
if ($failures.Count) {
    $failures | Format-List
    throw 'Обнаружены ошибки синтаксиса PowerShell.'
}
'PASS: синтаксис PowerShell; политики Windows не испытывались.'
