#requires -Version 7.6
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$SoftwareReportPath,
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$GradleCachePath,
    [Parameter(ParameterSetName = 'Install')][string]$GradleArchivePath,
    [Parameter(Mandatory, ParameterSetName = 'Launch')][switch]$Launch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$distribution = 'gradle-9.8.2-bin.zip'
$distributionHash = '21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607'
$scriptName = 'Install-ExamLabIdea.ps1'
$configName = 'exam-lab-idea.json'
$utf8 = [Text.UTF8Encoding]::new($false)

function Set-LocalText([string]$Path, [string]$Text) {
    if ([IO.File]::Exists($Path) -and [IO.File]::ReadAllText($Path) -ceq $Text) { return }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, $Text, $utf8)
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        [IO.File]::Delete($temporary)
    }
}

function Copy-NewFile([string]$SourcePath, [string]$DestinationPath) {
    $source = [IO.File]::OpenRead($SourcePath)
    try {
        # Create with the destination directory's access rules.
        $destination = [IO.File]::Open($DestinationPath, 'CreateNew', 'Write', 'None')
        try { $source.CopyTo($destination) } finally { $destination.Dispose() }
    } finally { $source.Dispose() }
}

function ConvertTo-JavaPropertyPath([string]$Path) {
    # Java properties accept forward slashes and Unicode escape sequences.
    $normalized = $Path.Replace('\', '/')
    [regex]::Replace($normalized, '[^\u0020-\u007E]', {
        param($Match)
        '\u{0:x4}' -f [int][char]$Match.Value
    })
}

function Start-ExamLabIdea {
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot $configName) -Raw -Encoding UTF8 | ConvertFrom-Json -DateKind String
    if ($config.Schema -ne 1 -or $config.GradleDistributionSHA256 -ine $distributionHash) {
        throw 'ExamLab IDEA has not been configured for this release.'
    }
    $userRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ExamLab\IDEA'
    $gradleHome = Join-Path $userRoot 'gradle'
    # Gradle PathAssembler hashes the canonical distribution URL as MD5 encoded in base 36.
    $wrapper = Join-Path $gradleHome 'wrapper\dists\gradle-9.8.2-bin\8wepis63pzuhrlfaiy04bagwu'
    [void][IO.Directory]::CreateDirectory($wrapper)
    $initializer = Join-Path $gradleHome 'init.d'
    [void][IO.Directory]::CreateDirectory($initializer)
    $lockPath = Join-Path $userRoot 'prepare.lock'
    $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        $archive = Join-Path $wrapper $distribution
        $marker = "$archive.ok"
        $launcher = Join-Path $wrapper 'gradle-9.8.2\bin\gradle.bat'
        if (-not ([IO.File]::Exists($marker) -and [IO.File]::Exists($launcher)) -and
            -not [IO.File]::Exists($archive)) {
            $temporary = "$archive.part-exam-lab"
            try {
                [IO.File]::Delete($temporary)
                Copy-NewFile (Join-Path $PSScriptRoot $distribution) $temporary
                [IO.File]::Move($temporary, $archive)
            } finally {
                [IO.File]::Delete($temporary)
            }
        }

        $javaHome = ConvertTo-JavaPropertyPath $config.JdkHome
        Set-LocalText (Join-Path $gradleHome 'gradle.properties') @"
org.gradle.java.home=$javaHome
org.gradle.java.installations.paths=$javaHome
org.gradle.java.installations.auto-detect=false
org.gradle.java.installations.auto-download=false
"@
        Set-LocalText (Join-Path $initializer 'exam-lab.gradle') 'gradle.startParameter.offline = true'

        $ideaRoot = ConvertTo-JavaPropertyPath $userRoot
        $propertiesPath = Join-Path $userRoot 'idea.properties'
        Set-LocalText $propertiesPath @"
idea.config.path=$ideaRoot/config
idea.system.path=$ideaRoot/system
idea.plugins.path=$ideaRoot/plugins
idea.log.path=$ideaRoot/log
"@
    } finally {
        $lock.Dispose()
    }

    $env:JAVA_HOME = $config.JdkHome
    $env:GRADLE_USER_HOME = $gradleHome
    $env:GRADLE_RO_DEP_CACHE = $config.GradleCache
    $env:IDEA_PROPERTIES = $propertiesPath
    Start-Process -FilePath $config.IdeaExecutable
}

if ($Launch) {
    try { Start-ExamLabIdea } catch {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($_.Exception.Message, 'ExamLab - IDEA')
        exit 1
    }
    return
}

function Get-PlainItem([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unexpected path type: $Path"
    }
    $item
}

function Assert-ProtectedItem([string]$Path, [bool]$Directory) {
    $item = Get-PlainItem $Path $Directory
    $acl = Get-Acl -LiteralPath $item.FullName
    $trusted = @('S-1-5-18', 'S-1-5-32-544', $identity.User.Value,
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writes = [Security.AccessControl.FileSystemRights]'CreateFiles, CreateDirectories, WriteAttributes, WriteExtendedAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Unexpected owner: $Path"
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writes) -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            $rule.IdentityReference.Value -notin $trusted) {
            throw "Ordinary users can modify $Path"
        }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Environment]::Is64BitProcess -or -not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Install ExamLab IDEA from elevated 64-bit PowerShell 7.'
}
Assert-ProtectedItem $SoftwareReportPath $false
$software = Get-Content -LiteralPath $SoftwareReportPath -Raw -Encoding UTF8 | ConvertFrom-Json -DateKind String
if ($software.SoftwareReady -ne $true -or $software.RebootRequired -eq $true -or
    $software.After.JDK.Selected.Version -notmatch '^25(?:\.|$)') {
    throw 'A completed software report with a compatible JDK 25 is required.'
}
$idea = (Get-PlainItem (Join-Path $software.After.IDEA.Selected.Path 'bin\idea64.exe') $false).FullName
$jdk = (Get-PlainItem $software.After.JDK.Selected.Path $true).FullName
$cache = (Get-PlainItem $GradleCachePath $true).FullName
Assert-ProtectedItem $cache $true
Assert-ProtectedItem (Join-Path $cache 'modules-2') $true
$configText = [ordered]@{
    Schema = 1
    IdeaExecutable = $idea
    JdkHome = $jdk
    GradleCache = $cache
    GradleDistributionSHA256 = $distributionHash
} | ConvertTo-Json

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
Assert-ProtectedItem $programFiles $true
$installation = Join-Path $programFiles 'ExamLabIdea'
$entry = Join-Path $installation $scriptName
$configPath = Join-Path $installation $configName
$installedArchive = Join-Path $installation $distribution
$shell = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'ExamLab - IDEA.lnk'
$powershell = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'
$arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Launch' -f $entry
if (Test-Path -LiteralPath $shortcutPath) {
    [void](Get-PlainItem $shortcutPath $false)
    $shortcut = $shell.CreateShortcut($shortcutPath)
    if ($shortcut.TargetPath -ine $powershell -or $shortcut.Arguments -cne $arguments) {
        throw 'A different ExamLab - IDEA shortcut already exists.'
    }
}

if (Test-Path -LiteralPath $installation) {
    Assert-ProtectedItem $installation $true
    Assert-ProtectedItem $entry $false
    Assert-ProtectedItem $configPath $false
    Assert-ProtectedItem $installedArchive $false
    if ((Get-FileHash -LiteralPath $installedArchive -Algorithm SHA256).Hash -ine $distributionHash -or
        [IO.File]::ReadAllText($configPath) -cne $configText -or
        (Get-FileHash -LiteralPath $entry).Hash -ine (Get-FileHash -LiteralPath $PSCommandPath).Hash) {
        throw 'An existing ExamLab IDEA setup differs from this release. Review its protected files.'
    }
} else {
    if (-not $GradleArchivePath) { throw 'The verified Gradle distribution ZIP is required for first setup.' }
    Assert-ProtectedItem $GradleArchivePath $false
    $staging = "$installation-$([Guid]::NewGuid().ToString('N'))"
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $rights = @{ 'S-1-5-18' = 'FullControl'; 'S-1-5-32-544' = 'FullControl';
        'S-1-5-32-545' = 'ReadAndExecute'; 'S-1-5-32-546' = 'ReadAndExecute' }
    foreach ($sid in $rights.Keys) {
        $id = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($id, $rights[$sid], 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $staging)
    try {
        $archive = Join-Path $staging $distribution
        Copy-NewFile $GradleArchivePath $archive
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $distributionHash) {
            throw 'The Gradle distribution ZIP does not match the pinned SHA-256.'
        }
        [IO.File]::WriteAllBytes((Join-Path $staging $scriptName), [IO.File]::ReadAllBytes($PSCommandPath))
        [IO.File]::WriteAllText((Join-Path $staging $configName), $configText, $utf8)
        [IO.Directory]::Move($staging, $installation)
    } finally {
        if ([IO.Directory]::Exists($staging)) { [IO.Directory]::Delete($staging, $true) }
    }
}

if (-not (Test-Path -LiteralPath $shortcutPath)) {
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $powershell
    $shortcut.Arguments = $arguments
    $shortcut.IconLocation = "$idea,0"
    $shortcut.WindowStyle = 7
    $shortcut.Save()
}
Write-Host 'Desktop shortcut created: ExamLab - IDEA'
