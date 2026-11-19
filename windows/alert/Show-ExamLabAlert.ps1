[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$RunId,
    [Parameter(Mandatory)][string]$GuestSid,
    [Parameter(Mandatory)][int]$GuestSessionId
)

$ErrorActionPreference = 'Stop'
$base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ExamLabAlert'
$registryPath = 'HKLM:\SOFTWARE\ExamLabAlertPilot'
$uacPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$sid = $identity.User.Value
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
if (-not [Environment]::Is64BitProcess -or $PSScriptRoot -ne $base -or
    $sessionId -le 0 -or $sessionId -ne $GuestSessionId -or $sid -ne $GuestSid -or
    -not [Environment]::UserInteractive -or $identity.IsSystem -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Экран пробы запускается в интерактивном неповышенном сеансе Guest.'
}

function Test-Pending {
    $key = Get-Item -LiteralPath $registryPath
    try { $json = $key.GetValue('Status') } finally { $key.Dispose() }
    $state = if ($json) { ConvertFrom-Json -InputObject $json }
    return $null -ne $state -and $state.Phase -eq 'Pending' -and $state.RunId -eq $RunId.ToString('D') -and
        $state.GuestSid -eq $sid -and $state.SessionId -eq $sessionId
}

if (-not (Test-Pending)) { return }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

# IVirtualDesktopManager из Windows SDK: проверяем положение только своего окна.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ExamLab {
    [ComImport, Guid("A5CD92FF-29BE-454C-8D04-D82879FB3F1B")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IVirtualDesktopManager {
        void IsWindowOnCurrentVirtualDesktop(IntPtr window, [MarshalAs(UnmanagedType.Bool)] out bool current);
    }

    public sealed class DesktopVisibility {
        private readonly IVirtualDesktopManager manager =
            (IVirtualDesktopManager)Activator.CreateInstance(Type.GetTypeFromCLSID(
                new Guid("AA509086-5CA9-4C25-8F95-589D3C07B48A")));

        public bool IsCurrent(IntPtr window) {
            bool current;
            manager.IsWindowOnCurrentVirtualDesktop(window, out current);
            return current;
        }
    }
}
'@
$desktops = [ExamLab.DesktopVisibility]::new()
$alertText = "Подозрительная активность.`r`nПозовите преподавателя."

function New-AlertForm {
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Оповещение преподавателя'
    $form.FormBorderStyle = 'None'
    $form.WindowState = 'Maximized'
    $form.TopMost = $true
    $form.BackColor = [Drawing.Color]::FromArgb(119, 31, 40)
    $form.Add_FormClosing({
        param($sender, $event)
        if ($event.CloseReason -eq 'UserClosing') { $event.Cancel = $true }
    })

    $layout = [Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock = 'Fill'
    $layout.RowCount = 2
    $layout.ColumnCount = 1
    $layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 58)) | Out-Null
    $layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 42)) | Out-Null
    $form.Controls.Add($layout)

    $label = [Windows.Forms.Label]::new()
    $label.Text = $alertText
    $label.Dock = 'Fill'
    $label.TextAlign = 'BottomCenter'
    $label.ForeColor = [Drawing.Color]::White
    $label.Font = [Drawing.Font]::new('Segoe UI', 30)
    $label.Padding = [Windows.Forms.Padding]::new(16, 16, 16, 36)
    $layout.Controls.Add($label, 0, 0)

    $ack = [Windows.Forms.Button]::new()
    $ack.Text = 'Подтвердить как администратор'
    $ack.Font = [Drawing.Font]::new('Segoe UI', 14)
    $ack.UseVisualStyleBackColor = $false
    $ack.BackColor = [Drawing.Color]::White
    $ack.ForeColor = [Drawing.Color]::Black
    $ack.Size = [Drawing.Size]::new(360, 60)
    $ack.Anchor = 'Top'
    $layout.Controls.Add($ack, 0, 1)
    $ack.Tag = $label
    $ack.Add_Click({
        param($sender, $event)
        try {
            $uac = Get-ItemProperty -LiteralPath $uacPolicyPath
            if ($uac.EnableLUA -ne 1 -or $uac.PromptOnSecureDesktop -ne 1 -or
                $uac.ConsentPromptBehaviorUser -notin 1, 3) {
                $sender.Tag.Text = "$alertText`r`nЗапрос подтверждения запрещён политикой Windows."
                return
            }
            $powershell = Join-Path $PSHOME 'powershell.exe'
            $controller = Join-Path $base 'ExamLabAlert.ps1'
            $arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Action Acknowledge -RunId {1}' -f $controller, $RunId.ToString('D')
            $process = Start-Process -FilePath $powershell -ArgumentList $arguments -WorkingDirectory $base -Verb RunAs -Wait -PassThru
            if ($process.ExitCode -ne 0) { throw 'Ответ администратора не сохранён.' }
        } catch {
            $sender.Tag.Text = "$alertText`r`nПодтверждение не выполнено."
        }
    })

    return $form
}

$context = [Windows.Forms.ApplicationContext]::new()
$script:alertForm = New-AlertForm
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 1000
$timer.Add_Tick({
    try {
        if (-not (Test-Pending)) {
            $context.ExitThread()
            return
        }
        if ($script:alertForm.IsDisposed -or -not $desktops.IsCurrent($script:alertForm.Handle)) {
            # Новое окно получает активный стол; окна других приложений остаются на месте.
            $replacement = New-AlertForm
            $replacement.Show()
            $script:alertForm.Dispose()
            $script:alertForm = $replacement
        } elseif ($script:alertForm.WindowState -ne 'Maximized') {
            $script:alertForm.WindowState = 'Maximized'
        }
    } catch {
        Write-Warning ('Не удалось обновить экран тревоги: ' + $_.Exception.Message)
    }
})
try {
    $script:alertForm.Show()
    $timer.Start()
    [Windows.Forms.Application]::Run($context)
} finally {
    $timer.Dispose()
    $context.Dispose()
    $script:alertForm.Dispose()
}
