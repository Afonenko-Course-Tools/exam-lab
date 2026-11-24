#requires -Version 7.6
$ErrorActionPreference = 'Stop'
$project = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'OrdinaryCourse'
New-Item -ItemType Directory -Path $project -Force | Out-Null
Set-Content (Join-Path $project 'DoNotDelete.txt') 'ExamLab ordinary class data: preserve through enable and finish.' -Encoding UTF8
Set-Content (Join-Path $project 'Hello.java') 'public class Hello { public static void main(String[] args) { System.out.println("ordinary-java-ok"); } }' -Encoding ASCII
& 'C:\Program Files\Eclipse Adoptium\jdk-25\bin\javac.exe' -g (Join-Path $project 'Hello.java')
if ($LASTEXITCODE -ne 0) { throw "javac exit $LASTEXITCODE" }
$java = & 'C:\Program Files\Eclipse Adoptium\jdk-25\bin\java.exe' -cp $project Hello
if ($LASTEXITCODE -ne 0 -or $java -ne 'ordinary-java-ok') { throw 'Java run failed.' }
& 'C:\Program Files\Git\cmd\git.exe' -c init.defaultBranch=main init --quiet $project
if ($LASTEXITCODE -ne 0) { throw "git init exit $LASTEXITCODE" }
[ordered]@{
    RunId = '__RUNID__'
    CreatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    AdministratorToken = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    User = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    SID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Profile = $env:USERPROFILE
    Project = $project
    Java = $java
    NotesSHA256 = (Get-FileHash (Join-Path $project 'DoNotDelete.txt') -Algorithm SHA256).Hash
    JavaSHA256 = (Get-FileHash (Join-Path $project 'Hello.java') -Algorithm SHA256).Hash
    Git = & 'C:\Program Files\Git\cmd\git.exe' -C $project status --porcelain
} | ConvertTo-Json | Set-Content (Join-Path $project 'baseline.json') -Encoding UTF8
