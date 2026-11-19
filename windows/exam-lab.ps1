#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('prepare','check','exam','normal','poll')][string]$Action)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ExamLab.psm1') -Force
try {
    switch ($Action) {
        'poll' { Invoke-ExamLabControllerLoop }
        'prepare' { Initialize-ExamLab | ConvertTo-Json -Depth 6 }
        'check' { Get-ExamLabStatus | ConvertTo-Json -Depth 6 }
        'exam' { Set-ExamLabMode -Mode exam | ConvertTo-Json -Depth 6 }
        'normal' {
            $result = Set-ExamLabMode -Mode normal
            $result | ConvertTo-Json -Depth 7
            if ($result.Normal.Collection.Errors.Count) { exit 1 }
        }
    }
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
