#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    printf 'Использование: %s ПУТЬ-К-Start-ExamLab.cmd СЕТЬ-WINDOWS-В-CIDR [СЕТЬ-WINDOWS-В-CIDR ...]\n' "$0" >&2
    exit 2
fi
if [[ $(hostname -s) != exam-lab-pilot ]] || ! grep -Fq ' 10.135.250.231/16 ' <<<"$(ip -4 -o addr show)"; then
    printf 'Ожидалась выделенная VM exam-lab-pilot с адресом 10.135.250.231/16.\n' >&2
    exit 1
fi

launcher=$1
clients=$(python3 - "${@:2}" <<'PY'
import ipaddress
import sys

try:
    networks = dict.fromkeys(map(ipaddress.IPv4Network, sys.argv[1:]))
except ValueError as exc:
    raise SystemExit(f'Некорректная сеть клиентов: {exc}') from exc
for network in networks:
    if not network.subnet_of(ipaddress.IPv4Network('10.0.0.0/8')):
        raise SystemExit('Ожидались сети клиентов пилота внутри 10.0.0.0/8.')
    print(network)
PY
)
if [[ ! -s $launcher || ! -f $launcher || -L $launcher ]]; then
    printf 'Требуется непустой обычный файл: %s\n' "$launcher" >&2
    exit 1
fi

source_dir=$(dirname -- "${BASH_SOURCE[0]}")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

awk -v clients="$clients" '
    /WINDOWS_CLIENT_NETWORKS/ {
        count = split(clients, networks, "\n")
        for (i = 1; i <= count; i++) print "            allow " networks[i] ";"
        next
    }
    { print }
' "$source_dir/exam-lab-bootstrap-http.nginx.conf.example" > "$work/nginx.conf"

sudo -n cat /etc/nftables.conf | awk -v clients="$clients" '
    /# exam-lab-http-bootstrap$/ { next }
    { print }
    /^[[:space:]]*chain allow_pilot \{$/ {
        count = split(clients, networks, "\n")
        for (i = 1; i <= count; i++) {
            print "    ip daddr 10.135.250.231 ip saddr " networks[i] " tcp dport 80 accept # exam-lab-http-bootstrap"
        }
        found++
    }
    END { if (found != 1) exit 1 }
' > "$work/nftables.conf"
sudo -n nft --check --file "$work/nftables.conf"
sudo -n nginx -c "$work/nginx.conf" -t

destination=/srv/exam-lab-bootstrap
sudo -n install -d -o root -g root -m 0755 -- "$destination"
sudo -n install -o root -g root -m 0644 -- "$launcher" "$destination/.Start-ExamLab.cmd.next"
sudo -n mv -fT -- "$destination/.Start-ExamLab.cmd.next" "$destination/Start-ExamLab.cmd"

sudo -n install -d -o root -g root -m 0755 /etc/exam-lab-bootstrap
sudo -n install -o root -g root -m 0644 "$work/nginx.conf" /etc/exam-lab-bootstrap/nginx.conf.next
sudo -n mv -fT /etc/exam-lab-bootstrap/nginx.conf.next /etc/exam-lab-bootstrap/nginx.conf
sudo -n install -o root -g root -m 0644 "$source_dir/exam-lab-http-bootstrap.service" /etc/systemd/system/
sudo -n systemctl daemon-reload
sudo -n systemctl enable exam-lab-http-bootstrap.service
sudo -n systemctl reload-or-restart exam-lab-http-bootstrap.service

sudo -n install -o root -g root -m 0600 -- "$work/nftables.conf" /etc/nftables.conf.exam-lab-http
sudo -n nft --file /etc/nftables.conf.exam-lab-http
sudo -n mv -fT -- /etc/nftables.conf.exam-lab-http /etc/nftables.conf
printf 'Start-ExamLab.cmd доступен на http://10.135.250.231/ для %s\n' "$clients"
