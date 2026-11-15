#!/usr/bin/env bash
# Запуск только собственного диска. Никаких операций над libvirt и сетями хоста.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
runtime="$root/.local/vm"
install_iso="$root/.local/iso/windows10-enterprise-eval-x64.iso"
mode=${1:-boot}
mkdir -p "$runtime"
if [[ -f "$runtime/qemu.pid" ]] && kill -0 "$(cat "$runtime/qemu.pid")" 2>/dev/null; then
    echo 'Эта VM уже работает.' >&2; exit 1
fi
args=()
case "$mode" in
    install)
        [[ -f "$runtime/seed.iso" && -f "$install_iso" ]] || { echo 'Сначала ISO и prepare-seed.py --accept-eula.' >&2; exit 1; }
        [[ ! -e "$runtime/reference.qcow2" ]] || { echo 'Установка не перезаписывает существующий диск.' >&2; exit 1; }
        qemu-img create -f qcow2 "$runtime/reference.qcow2" 100G
        args+=(-drive "file=$install_iso,format=raw,media=cdrom,if=ide,index=2,readonly=on")
        args+=(-drive "file=$runtime/seed.iso,format=raw,media=cdrom,if=ide,index=3,readonly=on")
        args+=(-boot order=c,once=d,menu=on)
        ;;
    boot)
        [[ -f "$runtime/reference.qcow2" ]] || { echo 'Нет установленного диска.' >&2; exit 1; }
        if [[ -f "$runtime/tools.iso" ]]; then
            args+=(-drive "file=$runtime/tools.iso,format=raw,media=cdrom,if=ide,index=2,readonly=on")
        fi
        ;;
    *) echo 'Использование: start-reference.sh install|boot' >&2; exit 2 ;;
esac
qemu-system-x86_64 -name exam-lab-reference -machine pc,accel=kvm -cpu host -smp 4 -m 8192 -rtc base=localtime \
    -drive "file=$runtime/reference.qcow2,format=qcow2,if=ide,index=0" \
    "${args[@]}" -device e1000,netdev=labnet \
    -netdev user,id=labnet,hostfwd=tcp:127.0.0.1:15985-:5985 \
    -vga std -vnc 127.0.0.1:5 -device qemu-xhci -device usb-tablet \
    -qmp "unix:$runtime/qmp.sock,server=on,wait=off" \
    -monitor "unix:$runtime/monitor.sock,server=on,wait=off" \
    -pidfile "$runtime/qemu.pid" -D "$runtime/qemu.log" -daemonize
echo 'VM запущена. VNC 127.0.0.1:5905; WinRM NTLM 127.0.0.1:15985; PID в .local/vm/qemu.pid.'
