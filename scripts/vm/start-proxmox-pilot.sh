#!/usr/bin/env bash
# Возобновить сохранённые службы только на пилотной Linux VM.
set -euo pipefail

if [[ $(hostname -s) != exam-lab-pilot ]] || ! ip -4 -o addr show | grep -q ' 10\.135\.250\.231/16 '; then
    echo 'Ожидалась выделенная VM exam-lab-pilot с адресом 10.135.250.231/16.' >&2
    exit 1
fi

pilot_home=${EXAMLAB_PILOT_HOME:-$HOME/exam-lab-campaign}
wazuh_home=${EXAMLAB_WAZUH_HOME:-$HOME/exam-wazuh-vm103}
controller="$pilot_home/git/exam-lab/controller/server.py"
db="$pilot_home/state/controller/controller.sqlite3"
tls="$pilot_home/state/controller-tls"
controller_unit=exam-lab-pilot-controller-panel

test -s "$tls/teacher-proxy-token"
nginx -e stderr -p "$tls/" -c nginx.conf -t

if ! systemctl is-active --quiet "$controller_unit"; then
    if [[ -L /opt/exam-lab/controller/current ]]; then
        sudo -n systemctl start "$controller_unit.service"
    else
        test -s "$db"
        sudo -n systemd-run --collect --unit "$controller_unit" --uid "$(id -u)" \
            --gid "$(id -g)" --working-directory "$pilot_home/git/exam-lab" \
            /usr/bin/python3 "$controller" --db "$db" serve \
            --teacher-proxy-token-file "$tls/teacher-proxy-token"
    fi
fi

if [[ -s "$tls/nginx.pid" ]] && kill -0 "$(cat "$tls/nginx.pid")" 2>/dev/null; then
    nginx -e stderr -p "$tls/" -c nginx.conf -s reload
else
    nginx -e stderr -p "$tls/" -c nginx.conf </dev/null >>"$pilot_home/logs/controller-nginx.log" 2>&1
fi

cd "$pilot_home/git/deployment"
python3 scripts/fixture.py up --env-file "$pilot_home/config/exam-server.env" --kind exam
python3 scripts/fixture.py up --env-file "$pilot_home/config/ordinary-server.env" --kind ordinary
bash "$wazuh_home/private/control.sh" up
