# Переносимый тест. Подменены чтение томов Win32, проверка Windows ACL и размеры компонентов.
# Проверяются расчёт порогов, очистка файлов и квитанция диагностики с подменённым HTTP.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$launcher = Join-Path $PSScriptRoot '../setup/Start-ExamLab.Native.ps1.in'
$source = [IO.File]::ReadAllText($launcher) -creplace '@[A-Z0-9_]+@', '0'
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in 'Test-Artifact', 'New-SpaceNeed', 'Test-ReleaseSpace', 'Remove-CachedReleaseInstallers', 'Send-Diagnostics') {
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
    New-SpaceNeed $installation 'WorkingEstimates' 8MB
}

function Read-InstallVolumeReport {
    $saved = Get-Content -LiteralPath (Join-Path $report 'release-plan.json') -Raw | ConvertFrom-Json
    $saved.SpaceChecks[-1].Volumes | Where-Object VolumeId -CEQ 'Install'
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
    $installVolume = Read-InstallVolumeReport
    if ($installVolume.Status -cne 'InsufficientSpace' -or $installVolume.RequiredBytesForAction -ne 16MB) {
        throw 'В отчёте Apply потеряна причина отказа.'
    }

    $action = 'Check'
    if (Test-ReleaseSpace $plan $true 'Initial') { throw 'Check пропустил известную нехватку места.' }
    $installVolume = Read-InstallVolumeReport
    if ($installVolume.Status -cne 'InsufficientSpace' -or $installVolume.AvailableBytes -ne 2MB -or
        $installVolume.RequiredBytesForAction -ne 16MB -or -not $installVolume.Reason) {
        throw 'В отчёте Check отсутствуют измерение и причина отказа.'
    }

    $action = 'Apply'
    $script:fixtureVolumes[$installation].FreeBytes = 20MB
    $result = @(Test-ReleaseSpace $plan $true 'Initial' 3>&1)
    $warnings = @($result | Where-Object { $_ -is [Management.Automation.WarningRecord] })
    if ($result[-1] -ne $true -or $warnings.Count -ne 1) {
        throw 'Apply должен продолжиться с предупреждением при оценочном риске.'
    }
    $installVolume = Read-InstallVolumeReport
    if ($installVolume.Status -cne 'EstimatedSpaceRisk' -or $installVolume.RequiredBytesForAction -ne 16MB -or
        $installVolume.EstimatedPeakBytes -ne 24MB -or -not $installVolume.Reason) {
        throw 'В отчёте Apply потеряна причина предупреждения об оценочном риске.'
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
    'PASS: раздельные тома, отказ при подтверждённой нехватке, оценочный риск и адресная очистка EXE.'
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }

& {
    $offline = $admin = $false
    $baseUrl = 'https://fixture.invalid/install'
    $receiver = 'diagnostics-fixture'
    $reportId = 'c0ffee1234567890c0ffee1234567890'
    $response = [pscustomobject]@{ StatusCode=201; Body=(@{reportId=$reportId} | ConvertTo-Json -Compress) }
    $response | Add-Member ScriptMethod GetResponseStream {
        [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($this.Body))
    }
    $response | Add-Member ScriptMethod Dispose { }
    $request = [pscustomobject]@{
        Method=$null; ContentType=$null; AllowWriteStreamBuffering=$true; ContentLength=0L
        ServicePoint=[pscustomobject]@{ Expect100Continue=$true }; Uploaded=$null; Response=$response
    }
    $request | Add-Member ScriptMethod GetRequestStream {
        $this.Uploaded = [IO.MemoryStream]::new()
        $this.Uploaded
    }
    $request | Add-Member ScriptMethod GetResponse { $this.Response }
    $transport = [pscustomobject]@{ Calls=0; CurrentRequest=$request }
    $transport | Add-Member ScriptMethod Request { $this.Calls++; $this.CurrentRequest }
    function Start-BootstrapTransport { }

    $directory = Join-Path ([IO.Path]::GetTempPath()) ('exam-lab-bootstrap-receipt-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    try {
        $inputFile = Join-Path $directory 'report.txt'
        $archive = Join-Path $directory 'diagnostics.zip'
        $receiptPath = Join-Path $directory 'upload-result.json'
        [IO.File]::WriteAllText($inputFile, 'Synthetic Check report')
        Compress-Archive -LiteralPath $inputFile -DestinationPath $archive
        [IO.File]::WriteAllText((Join-Path $directory 'delivery-target.txt'), $receiver)
        $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($archiveHash.StartsWith($reportId, [StringComparison]::Ordinal)) { throw 'Тесту нужен независимый номер архива.' }

        if ((Send-Diagnostics $directory) -cne $reportId) { throw 'Случайный номер из ответа 201 отклонён.' }
        $uploaded = [IO.MemoryStream]::new($request.Uploaded.ToArray())
        try { $uploadedHash = (Get-FileHash -InputStream $uploaded -Algorithm SHA256).Hash.ToLowerInvariant() }
        finally { $uploaded.Dispose() }
        $saved = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($uploadedHash -cne $archiveHash -or $saved.reportId -cne $reportId -or $saved.archiveSha256 -cne $archiveHash) {
            throw 'Локальная квитанция не связывает номер с SHA-256 фактически отправленного ZIP.'
        }
        if ((Send-Diagnostics $directory) -cne $reportId -or $transport.Calls -ne 1) { throw 'ZIP с совпадающим SHA-256 отправлен повторно.' }

        [IO.File]::WriteAllText($receiptPath, $response.Body)
        if ((Send-Diagnostics $directory) -cne $reportId -or $transport.Calls -ne 1) { throw 'Квитанция прежнего формата вызвала повторную отправку.' }

        $saved.archiveSha256 = '0' * 64
        [IO.File]::WriteAllText($receiptPath, ($saved | ConvertTo-Json -Compress))
        if ((Send-Diagnostics $directory) -cne $reportId -or $transport.Calls -ne 2) { throw 'Квитанция с неверным SHA-256 помешала отправить ZIP.' }
        $retried = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($retried.archiveSha256 -cne $archiveHash) { throw 'Повтор не сохранил правильный SHA-256.' }
        'PASS: случайный номер из ответа 201, SHA-256 отправленного ZIP и проверка повтора для обеих форм квитанции.'
    } finally { Remove-Item -LiteralPath $directory -Recurse -Force }
}
