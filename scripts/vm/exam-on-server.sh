#!/usr/bin/env bash
set -euo pipefail

if [[ $(hostname -s) != exam-lab-pilot ]]; then
    echo 'Эта команда предназначена для пилотной VM 103.' >&2
    exit 1
fi

pilot=$HOME/exam-lab-campaign
if [[ ${1:-} == wazuh-status ]]; then
    exec docker exec exam-wazuh-vm103-wazuh.manager-1 /var/ossec/bin/agent_control -i 003
fi
if [[ -L /opt/exam-lab/controller/current ]]; then
    exec sudo -n -u examcontroller -- /usr/bin/python3 -Es \
        /opt/exam-lab/controller/current/server.py --db /var/lib/exam-lab-controller/controller.sqlite3 "$@"
fi
exec python3 "$pilot/git/exam-lab/controller/server.py" --db "$pilot/state/controller/controller.sqlite3" "$@"
