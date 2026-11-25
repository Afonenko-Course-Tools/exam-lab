#!/usr/bin/env python3
"""Подготовить Windows Setup и офлайн-CD для разработческой VM exam-lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import secrets
import shutil
import subprocess
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--accept-eula', action='store_true', help='Владелец прочитал и принял условия Windows Evaluation')
parser.add_argument('--powershell-msi', type=Path, required=True, help='Локальный проверяемый MSI PowerShell 7 x64')
args = parser.parse_args()
if not args.accept_eula:
    parser.error('Требуется разовое подтверждение владельца --accept-eula; см. docs/windows-vm.md')
powershell_pin = runpy.run_path(str(ROOT / 'scripts/build-windows-release.py'))
try:
    with args.powershell_msi.open('rb') as stream:
        powershell_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
except OSError as error:
    parser.error(f'Не удалось прочитать MSI PowerShell: {error}')
if powershell_sha256 != powershell_pin['PWSH_SHA256']:
    parser.error(f"MSI PowerShell не соответствует SHA-256 {powershell_pin['PWSH_MSI']}")
os.umask(0o077)
runtime = ROOT / '.local/vm'
runtime.mkdir(parents=True, exist_ok=True)
runtime.chmod(0o700)
credentials = runtime / 'credentials.json'
if not credentials.exists():
    credentials.write_text(json.dumps({
        'username': 'examadmin', 'password': 'Lab!' + secrets.token_hex(16),
        'student_username': 'labstudent', 'student_password': 'Lab!' + secrets.token_hex(16),
    }, indent=2) + '\n')
credentials.chmod(0o600)
creds = json.loads(credentials.read_text())
seed = runtime / 'seed'
seed.mkdir(exist_ok=True)
seed.chmod(0o700)
shutil.copyfile(ROOT / 'vm/bootstrap.ps1', seed / 'bootstrap.ps1')
shutil.copyfile(args.powershell_msi, seed / 'PowerShell.msi')
(seed / 'ExamLab-Seed.id').write_text('EXAM-LAB-DEVELOPMENT-SEED\n', encoding='ascii', newline='\r\n')
setup_complete = (ROOT / 'vm/bootstrap.cmd.in').read_text(encoding='ascii').replace(
    '@PWSH_SHA256@', powershell_sha256
).replace('@PWSH_VERSION@', powershell_pin['PWSH_VERSION'])
(seed / 'SetupComplete.cmd').write_text(setup_complete, encoding='ascii', newline='\r\n')
drives = ' '.join('DEFGHIJKLMNOPQRSTUVWXYZ')
stage_bootstrap = (
    f'cmd.exe /d /c for %D in ({drives}) do '
    r'@if exist %D:\ExamLab-Seed.id if exist %D:\SetupComplete.cmd call %D:\SetupComplete.cmd stage'
)
component = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
xml = f'''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
 <settings pass="windowsPE">
  <component name="Microsoft-Windows-International-Core-WinPE" {component}>
   <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
   <InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
  </component>
  <component name="Microsoft-Windows-Setup" {component}>
   <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
    <CreatePartitions>
     <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>500</Size></CreatePartition>
     <CreatePartition wcm:action="add"><Order>2</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
    </CreatePartitions>
    <ModifyPartitions>
     <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Active>true</Active><Format>NTFS</Format><Label>System</Label></ModifyPartition>
     <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
    </ModifyPartitions>
   </Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration>
   <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData></InstallFrom>
    <InstallTo><DiskID>0</DiskID><PartitionID>2</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI>
   </OSImage></ImageInstall>
   <UserData><AcceptEula>true</AcceptEula><FullName>Exam Lab</FullName><Organization>Local evaluation</Organization></UserData>
  </component>
 </settings>
 <settings pass="specialize">
  <component name="Microsoft-Windows-Shell-Setup" {component}><ComputerName>EXAM-LAB-VM</ComputerName><TimeZone>Belarus Standard Time</TimeZone></component>
  <component name="Microsoft-Windows-Deployment" {component}><RunSynchronous>
   <RunSynchronousCommand wcm:action="add"><Order>1</Order><Description>Prepare isolated lab management</Description>
    <Path>{escape(stage_bootstrap)}</Path>
   </RunSynchronousCommand>
  </RunSynchronous></component>
 </settings>
 <settings pass="oobeSystem">
  <component name="Microsoft-Windows-International-Core" {component}><InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
  <component name="Microsoft-Windows-Shell-Setup" {component}>
   <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
   <UserAccounts><LocalAccounts>
    <LocalAccount wcm:action="add"><Name>{creds['username']}</Name><DisplayName>Exam Lab Administrator</DisplayName><Group>Administrators</Group><Password><Value>{escape(creds['password'])}</Value><PlainText>true</PlainText></Password></LocalAccount>
    <LocalAccount wcm:action="add"><Name>{creds['student_username']}</Name><DisplayName>Ordinary Lab Student</DisplayName><Group>Users</Group><Password><Value>{escape(creds['student_password'])}</Value><PlainText>true</PlainText></Password></LocalAccount>
   </LocalAccounts></UserAccounts>
  </component>
 </settings>
</unattend>
'''
(seed / 'Autounattend.xml').write_text(xml)
subprocess.run(['xorriso', '-as', 'mkisofs', '-quiet', '-J', '-r', '-V', 'EXAMSEED', '-o', str(runtime / 'seed.iso'), str(seed)], check=True)
print('Создан .local/vm/seed.iso для разработки с PowerShell 7. Секреты: credentials.json, seed/Autounattend.xml, seed.iso; каталог 0700. После установки отключите CD и удалите ответы Windows Panther.')
