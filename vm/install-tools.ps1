# Одноразовая административная установка в собственный эталон QEMU.
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Manufacturer -notmatch 'QEMU' -or -not (Test-Path 'C:\ProgramData\ExamLab-VM\bootstrap-complete')) {
    throw 'Установка разрешена только внутри подготовленной QEMU VM exam-lab.'
}
$root = 'C:\ProgramData\ExamLab-VM'
$media = Get-Volume | Where-Object FileSystemLabel -eq 'EXAMTOOLS'
if (-not $media) { throw 'Подключите CD EXAMTOOLS.' }
$source = $media.DriveLetter + ':\'
Start-Transcript -Path "$root\tools-install.log" -Append
try {
    $hashes = @{
        'ideaIC.exe' = '57301793b57b9f2b87a5c79fd06b619e6bbd881501d793ecd78482b20525ea34'
        'temurin25.msi' = 'e1d3c94032579dc16af9abb311f4552ba271466b74c8767e8ce39585a4c64d40'
        'git.exe' = 'c330c72e10b408cc39994bfefdb63542b0d93d21699325c3e0bd874af8a5a559'
    }
    foreach ($file in $hashes.Keys) {
        $path = Join-Path $source $file
        if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $hashes[$file]) { throw "Несовпадение SHA256: $file" }
        $sig = Get-AuthenticodeSignature $path
        if ($sig.Status -ne 'Valid') { throw "Недействительная подпись $file : $($sig.Status)" }
        Write-Output "$file : $($sig.SignerCertificate.Subject)"
    }
    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "`"$source\temurin25.msi`"", '/qn', '/norestart',
        'ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJavaHome', 'INSTALLDIR="C:\Program Files\Eclipse Adoptium\jdk-25"',
        '/L*v', "`"$root\jdk-install.log`"")
    if ($process.ExitCode -notin 0,3010) { throw "JDK MSI exit $($process.ExitCode)" }
    $process = Start-Process (Join-Path $source 'git.exe') -Wait -PassThru -ArgumentList @('/VERYSILENT', '/NORESTART', '/ALLUSERS', '/SP-', "/LOG=`"$root\git-install.log`"")
    if ($process.ExitCode -ne 0) { throw "Git installer exit $($process.ExitCode)" }
    @('mode=admin','launcher64=1','updatePATH=1','updateContextMenu=0','.java=0','.groovy=0','.kt=0') | Set-Content "$root\idea-silent.config" -Encoding ASCII
    $process = Start-Process (Join-Path $source 'ideaIC.exe') -Wait -PassThru -ArgumentList @('/S', "/CONFIG=$root\idea-silent.config", "/LOG=$root\idea-install.log", '/D=C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4')
    if ($process.ExitCode -ne 0) { throw "IDEA installer exit $($process.ExitCode)" }
    # Community включает локальную генеративную Full Line. Убираем плагин до
    # первого запуска IDE; общий шаблон профилей пользователей не изменяется.
    $plugins = 'C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4\plugins'
    if (Test-Path "$plugins\fullLine") {
        New-Item -ItemType Directory -Path "$root\excluded-plugins" -Force | Out-Null
        Move-Item "$plugins\fullLine" "$root\excluded-plugins\fullLine" -Force
    }
    $lgpo = Join-Path $source 'LGPO.exe'
    $lgpoSignature = Get-AuthenticodeSignature $lgpo
    if ($lgpoSignature.Status -ne 'Valid' -or $lgpoSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'LGPO.exe должен иметь действительную подпись Microsoft.'
    }
    Copy-Item $lgpo "$root\LGPO.exe" -Force
    $inventory = [ordered]@{
        Java = & 'C:\Program Files\Eclipse Adoptium\jdk-25\bin\java.exe' --version
        Javac = & 'C:\Program Files\Eclipse Adoptium\jdk-25\bin\javac.exe' --version
        Git = & 'C:\Program Files\Git\cmd\git.exe' --version
        IDEA = Get-Content 'C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4\product-info.json' -Raw | ConvertFrom-Json | Select-Object name,version,buildNumber
        BundledPlugins = Get-ChildItem 'C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.4\plugins' -Directory | Select-Object -ExpandProperty Name
        ExcludedPlugins = 'org.jetbrains.completion.full.line (Full Line Code Completion)'
    }
    $inventory | ConvertTo-Json -Depth 5 | Set-Content "$root\tools-inventory.json" -Encoding UTF8
    New-Item -ItemType File -Path "$root\tools-installed" -Force | Out-Null
} finally { Stop-Transcript }
