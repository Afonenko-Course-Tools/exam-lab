#!/usr/bin/env bash
# Переводит существующий контроллер VM 103 на отдельного системного пользователя.
set -euo pipefail

if [[ $# != 1 || ! ${1:-} =~ ^[0-9a-f]{40}$ ]]; then
    printf 'Использование: %s ПОЛНАЯ-РЕВИЗИЯ-ВЫПУСКА\n' "$0" >&2
    exit 2
fi
if [[ $EUID != 0 || $(hostname -s) != exam-lab-pilot ]] ||
    ! grep -Fq ' 10.135.250.231/16 ' <<<"$(ip -4 -o addr show)"; then
    printf 'Требуется root на выделенной VM exam-lab-pilot с адресом 10.135.250.231/16.\n' >&2
    exit 1
fi

revision=$1
unit=exam-lab-pilot-controller-panel.service
unit_file=/etc/systemd/system/$unit
operator=examadmin
operator_home=$(getent passwd "$operator" | cut -d: -f6)
pilot_home=$operator_home/exam-lab-campaign
old_checkout=$pilot_home/git/exam-lab
old_controller=$old_checkout/controller/server.py
old_db=$pilot_home/state/controller/controller.sqlite3
old_token=$pilot_home/state/controller-tls/teacher-proxy-token
release_root=/opt/exam-lab/controller
code_dir=$release_root/$revision
current=$release_root/current
service_user=examcontroller
state=/var/lib/exam-lab-controller
socket=/run/exam-lab-controller/teacher.sock
owner_uid=$(id -u examowner)

exec 9>/run/lock/exam-lab-controller-activate.lock
flock --exclusive 9

controller_ready() {
    systemctl is-active --quiet "$unit" &&
        [[ -S $socket && $(stat -c '%U:%a' "$socket") == "$service_user:666" ]] &&
        printf 'X-Exam-Teacher-Proxy: %s\n' "$(< "$state/teacher-proxy-token")" |
        curl --noproxy '*' --header @- --fail --silent --max-time 2 --output /dev/null \
            http://127.0.0.1:21651/exam/teacher/readiness
}

wait_until_ready() {
    local attempt
    for ((attempt=0; attempt<30; attempt++)); do
        if controller_ready; then
            return 0
        fi
        sleep .2
    done
    printf 'Новый контроллер не подтвердил готовность.\n' >&2
    return 1
}

service_command() {
    printf '%s' "/usr/bin/python3 -Es $release_root/$1/server.py --db $state/controller.sqlite3 serve --teacher-proxy-token-file $state/teacher-proxy-token --teacher-socket $socket --teacher-version $1 --owner-uid $owner_uid"
}

write_unit() {
    cat > "$1" <<EOF
[Unit]
Description=ExamLab controller for the isolated pilot
After=network.target

[Service]
User=$service_user
Group=$service_user
UMask=0077
StateDirectory=exam-lab-controller
StateDirectoryMode=0700
RuntimeDirectory=exam-lab-controller
RuntimeDirectoryMode=0755
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ExecStart=$(service_command "$revision")
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$1"
}

finish_rotation() {
    local rc=$?
    set +e
    if (( restore_previous )); then
        systemctl stop "$unit"
        if (( replaced_link )); then
            mv -fT -- "$link_stage/previous" "$current"
        fi
        if mv -fT -- "$rotation_stage/previous" "$unit_file" && systemctl daemon-reload &&
            systemctl start "$unit" && wait_until_ready; then
            printf 'Восстановлен запуск контроллера выпуска %s.\n' "$previous" >&2
        else
            printf 'Запуск прежнего контроллера требует проверки. Рабочая БД сохранена в %s.\n' "$state" >&2
        fi
    fi
    rm -rf -- "$rotation_stage" "$link_stage"
    exit "$rc"
}

for target in /opt/exam-lab "$release_root" "$code_dir"; do
    if [[ ! -d $target || -L $target || $(stat -c '%u:%a' "$target") != 0:755 ]]; then
        printf 'Ожидался каталог кода root с режимом 0755: %s\n' "$target" >&2
        exit 1
    fi
done
for file in server.py teacher_access.py tui.py; do
    target=$code_dir/$file
    if [[ ! -f $target || -L $target || $(stat -c '%u:%a' "$target") != 0:644 ]]; then
        printf 'Ожидался файл кода root с режимом 0644: %s\n' "$target" >&2
        exit 1
    fi
done

if [[ -L $current ]]; then
    previous=$(readlink -- "$current")
    if [[ ! $previous =~ ^[0-9a-f]{40}$ || $(stat -c '%u' "$current") != 0 ||
        ! -f $unit_file || -L $unit_file || $(stat -c '%u:%a' "$unit_file") != 0:644 ||
        ! -d $state || -L $state || $(stat -c '%U:%a' "$state") != "$service_user:700" ||
        ! -s $state/controller.sqlite3 || -L $state/controller.sqlite3 ||
        $(systemctl show -p FragmentPath --value "$unit") != "$unit_file" ||
        $(systemctl show -p User --value "$unit") != "$service_user" ||
        $(systemctl show -p ExecStart --value "$unit") != *"argv[]=$(service_command "$previous") ;"* ]]; then
        printf 'Активная конфигурация контроллера требует проверки администратора.\n' >&2
        exit 1
    fi
    systemctl start "$unit"
    wait_until_ready
    if [[ $previous == "$revision" ]]; then
        printf 'Контроллер выпуска %s уже активирован.\n' "$revision"
        exit 0
    fi

    rotation_stage=$(mktemp -d /etc/systemd/system/.exam-lab-controller-rotate.XXXXXXXX)
    link_stage=$(mktemp -d "$release_root/.current.XXXXXXXX")
    restore_previous=0
    replaced_link=0
    trap finish_rotation EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cp --preserve=mode,ownership -- "$unit_file" "$rotation_stage/previous"
    write_unit "$rotation_stage/next"
    ln -sT -- "$previous" "$link_stage/previous"
    ln -sT -- "$revision" "$link_stage/next"
    restore_previous=1
    systemctl stop "$unit"
    mv -fT -- "$rotation_stage/next" "$unit_file"
    systemctl daemon-reload
    systemctl start "$unit"
    wait_until_ready
    replaced_link=1
    mv -fT -- "$link_stage/next" "$current"
    restore_previous=0
    printf 'Контроллер переключён на выпуск %s, рабочая БД %s.\n' "$revision" "$state/controller.sqlite3"
    exit 0
fi

for target in "$state" "$current" "$unit_file"; do
    if [[ -e $target || -L $target ]]; then
        printf 'Путь требует проверки администратора перед переключением: %s\n' "$target" >&2
        exit 1
    fi
done
for target in "$old_db" "$old_token" "$old_controller"; do
    [[ -s $target && -f $target && ! -L $target ]]
done
[[ $owner_uid != "$(id -u "$operator")" ]]
old_gid=$(id -g "$operator")
old_args=(/usr/bin/python3 "$old_controller" --db "$old_db" serve --teacher-proxy-token-file "$old_token")
if ! systemctl is-active --quiet "$unit" ||
    [[ $(systemctl show -p FragmentPath --value "$unit") != "/run/systemd/transient/$unit" ]] ||
    [[ $(systemctl show -p User --value "$unit") != "$(id -u "$operator")" ]] ||
    [[ $(systemctl show -p Group --value "$unit") != "$old_gid" ]] ||
    [[ $(systemctl show -p WorkingDirectory --value "$unit") != "$old_checkout" ]] ||
    [[ $(systemctl show -p ExecStart --value "$unit") != *"argv[]=${old_args[*]} ;"* ]]; then
    printf 'Исходная systemd-служба контроллера отличается от ожидаемой.\n' >&2
    exit 1
fi

if ! getent passwd "$service_user" >/dev/null; then
    useradd --system --user-group --home-dir "$state" --no-create-home --shell /usr/sbin/nologin "$service_user"
fi
IFS=: read -r _ _ service_uid service_gid _ service_home service_shell < <(getent passwd "$service_user")
if [[ $service_uid == 0 || $service_uid == "$owner_uid" || $service_uid == "$(id -u "$operator")" ||
    $service_home != "$state" || $service_shell != /usr/sbin/nologin ||
    $(id -gn "$service_user") != "$service_user" || $(id -G "$service_user") != "$service_gid" ]]; then
    printf 'Системная учётная запись %s требует проверки администратора.\n' "$service_user" >&2
    exit 1
fi

state_stage=$(mktemp -d /var/lib/.exam-lab-controller.XXXXXXXX)
unit_stage=
restore_old=0
new_unit=0
new_state=0
new_link=0
wait_for_unloaded() {
    local attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if [[ $(systemctl show -p LoadState --value "$unit") == not-found ]]; then
            return 0
        fi
        sleep .1
    done
    return 1
}

finish() {
    local rc=$?
    set +e
    if (( restore_old )); then
        if (( new_link )); then rm -- "$current"; fi
        if (( new_unit )); then
            systemctl stop "$unit"
            systemctl disable "$unit"
            rm -- "$unit_file"
            systemctl daemon-reload
            systemctl reset-failed "$unit" 2>/dev/null
        fi
        if (( new_state )); then
            failed_state=$(mktemp -d /var/lib/.exam-lab-controller-not-active.XXXXXXXX)
            if [[ $failed_state ]] && rmdir -- "$failed_state" && mv -T -- "$state" "$failed_state"; then
                printf 'Состояние неактивированного контроллера сохранено в %s.\n' "$failed_state" >&2
            else
                printf 'Состояние неактивированного контроллера осталось в %s.\n' "$state" >&2
            fi
        fi
        if ! systemctl is-active --quiet "$unit"; then
            if wait_for_unloaded && systemd-run --collect --unit "$unit" --uid "$(id -u "$operator")" \
                --gid "$old_gid" --working-directory "$old_checkout" "${old_args[@]}"; then
                printf 'Восстановлен запуск прежнего контроллера.\n' >&2
            else
                printf 'Прежний контроллер требует ручного запуска. База сохранена в %s.\n' "$old_db" >&2
            fi
        fi
    fi
    rm -rf -- "$state_stage"
    if [[ $unit_stage ]]; then rm -f -- "$unit_stage"; fi
    exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

unit_stage=$(mktemp /etc/systemd/system/.exam-lab-controller.XXXXXXXX)
write_unit "$unit_stage"

restore_old=1
systemctl stop "$unit"
wait_for_unloaded
/usr/bin/python3 - "$old_db" "$state_stage/controller.sqlite3" <<'PY'
from contextlib import closing
from pathlib import Path
import sqlite3
import sys

source = Path(sys.argv[1]).as_uri() + '?mode=ro'
with closing(sqlite3.connect(source, uri=True)) as old, closing(sqlite3.connect(sys.argv[2])) as new:
    old.backup(new)
    if new.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
        raise SystemExit('Копия SQLite не прошла проверку целостности.')
PY
install -o "$service_user" -g "$service_user" -m 0600 "$old_token" "$state_stage/teacher-proxy-token"
chown -- "$service_user:$service_user" "$state_stage" "$state_stage/controller.sqlite3"
chmod 0700 "$state_stage"
chmod 0600 "$state_stage/controller.sqlite3"
mv -T -- "$state_stage" "$state"
new_state=1
mv -T -- "$unit_stage" "$unit_file"
new_unit=1
systemctl daemon-reload
systemctl start "$unit"
wait_until_ready
systemctl enable "$unit"
ln -sT -- "$revision" "$current"
new_link=1
restore_old=0
printf 'Контроллер выпуска %s запущен с БД %s.\n' "$revision" "$state/controller.sqlite3"
