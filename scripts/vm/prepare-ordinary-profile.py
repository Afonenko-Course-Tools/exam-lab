#!/usr/bin/env python3
"""Настоящий обычный профиль и Java/Git через стандартный WinRM без admin token."""
import json
from pathlib import Path
import uuid
from pypsrp.client import Client

ROOT = Path(__file__).resolve().parents[2]
creds = json.loads((ROOT / '.local/vm/credentials.json').read_text())

def connect(username, password):
    return Client('127.0.0.1', port=15985, ssl=False, username=username,
                  password=password, auth='ntlm', encryption='always')

def execute(client, code):
    output, streams, failed = client.execute_ps(code)
    if failed:
        message = '\n'.join(str(error) for error in streams.error)
        raise RuntimeError(message.replace(creds['student_password'], '[redacted]'))
    return output

admin = connect(creds['username'], creds['password'])
state = json.loads(execute(admin, r'''
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'QEMU') {throw 'Only test QEMU VM.'}
$user=Get-LocalUser labstudent
$profile=Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value
if(-not $profile) {
 Add-Type -TypeDefinition 'using System; using System.Text; using System.Runtime.InteropServices; public static class ExamLabUserProfile { [DllImport("userenv.dll", CharSet=CharSet.Unicode)] public static extern int CreateProfile(string sid, string name, StringBuilder path, uint size); }'
 $path=New-Object Text.StringBuilder 260
 $hr=[ExamLabUserProfile]::CreateProfile($user.SID.Value,'labstudent',$path,260)
 if($hr -ne 0) {throw "CreateProfile HRESULT $hr"}
 $profile=Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value
}
$group=Get-LocalGroup -SID S-1-5-32-580
$member=[bool](Get-LocalGroupMember $group | Where-Object SID -eq $user.SID.Value)
[ordered]@{Profile=$profile.LocalPath.ToString();SID=$user.SID.Value;AlreadyMember=$member} | ConvertTo-Json -Compress
'''))
run_id = uuid.uuid4().hex
try:
    if not state['AlreadyMember']:
        execute(admin, "$g=Get-LocalGroup -SID S-1-5-32-580; Add-LocalGroupMember -Group $g -Member labstudent")
    ordinary = connect(creds['student_username'], creds['student_password'])
    body = (ROOT / 'vm/ordinary-user-probe.ps1').read_text(encoding='utf-8-sig')
    execute(ordinary, body.replace('__RUNID__', run_id))
    report_path = state['Profile'] + r'\Documents\OrdinaryCourse\baseline.json'
    destination = ROOT / '.local/vm/ordinary-baseline.json'
    admin.fetch(report_path, str(destination))
    report = json.loads(destination.read_text(encoding='utf-8-sig'))
    if report['RunId'] != run_id or report['SID'] != state['SID'] or report['AdministratorToken']:
        raise RuntimeError('Обычный token или свежесть результата не подтверждены.')
    print(json.dumps(report, ensure_ascii=False, indent=2))
finally:
    if not state['AlreadyMember']:
        execute(admin, "$g=Get-LocalGroup -SID S-1-5-32-580; Remove-LocalGroupMember -Group $g -Member labstudent; if(Get-LocalGroupMember $g | Where-Object Name -like '*\\labstudent') {throw 'Membership cleanup failed'}")
