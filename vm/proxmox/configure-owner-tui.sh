#!/usr/bin/env bash
# Готовит выделенную учётную запись владельца и код TUI на пилотной Linux VM.
set -euo pipefail

if [[ $# != 4 && $# != 5 ]]; then
    printf 'Использование: %s КАТАЛОГ-КОНТРОЛЛЕРА РЕВИЗИЯ ЭКЗАМЕН ПУБЛИЧНЫЙ-КЛЮЧ [FILE-TRACE-ID]\n' "$0" >&2
    exit 2
fi
if [[ $EUID != 0 || $(hostname -s) != exam-lab-pilot ]] ||
    ! grep -Fq ' 10.135.250.231/16 ' <<<"$(ip -4 -o addr show)"; then
    printf 'Требуется root на выделенной VM exam-lab-pilot с адресом 10.135.250.231/16.\n' >&2
    exit 1
fi

source_dir=$1
revision=$2
exam=$3
key_file=$4
trace_exam=${5:-}
if [[ ! $revision =~ ^[0-9a-f]{40}$ || ! $exam =~ ^[A-Za-z0-9._-]{1,64}$ ||
    $exam == -* || $exam == file-trace-* ]]; then
    printf 'Укажите полную Git-ревизию выпуска и идентификатор экзамена.\n' >&2
    exit 2
fi
if [[ $# == 5 && ! $trace_exam =~ ^file-trace-[A-Za-z0-9._-]{1,53}$ ]]; then
    printf 'Отдельный экзамен с записью файлов требует идентификатор вида file-trace-20261124.\n' >&2
    exit 2
fi
files=(server.py teacher_access.py tui.py)
for file in "${files[@]}"; do
    if [[ ! -s $source_dir/$file || ! -f $source_dir/$file || -L $source_dir/$file ]]; then
        printf 'Требуется обычный файл контроллера: %s\n' "$source_dir/$file" >&2
        exit 1
    fi
done
deps=$source_dir/tui-deps
if [[ ! -f $deps/textual/__init__.py || -L $deps ]] ||
    [[ -n $(find "$deps" ! -type d ! -type f -print -quit) ]]; then
    printf 'Требуется каталог зависимостей TUI без ссылок: %s\n' "$deps" >&2
    exit 1
fi
mapfile -t key_lines < "$key_file"
if (( ${#key_lines[@]} != 1 )) || ! ssh-keygen -l -f "$key_file" >/dev/null; then
    printf 'Ожидался один публичный ключ OpenSSH.\n' >&2
    exit 2
fi
read -r key_type key_blob _ <<< "${key_lines[0]}"
if [[ $key_type != ssh-ed25519 || ! $key_blob =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
    printf 'Ожидался публичный ключ ssh-ed25519.\n' >&2
    exit 2
fi

owner=examowner
owner_home=/var/lib/exam-lab-owner
owner_shell=/usr/sbin/nologin
ssh_owner=examowner-ssh
ssh_home=/var/lib/exam-lab-owner-ssh
release_root=/opt/exam-lab/controller
code_dir=$release_root/$revision
session_config=$release_root/owner-session
entry=$release_root/owner-tui-entry
launcher_dir=/usr/local/bin
launcher=$launcher_dir/exam-lab-tui
sudoers_dir=/etc/sudoers.d
sudoers=$sudoers_dir/exam-lab-owner-tui
old_auth_file=$owner_home/.ssh/authorized_keys
auth_file=$ssh_home/.ssh/authorized_keys
for target in /opt/exam-lab "$release_root" "$code_dir" "$owner_home" "$owner_home/.ssh" "$ssh_home" "$ssh_home/.ssh"; do
    if [[ -L $target ]] || { [[ -e $target ]] && [[ ! -d $target || $(stat -c '%u:%a' "$target") != 0:755 ]]; }; then
        printf 'Ожидался локальный каталог root с режимом 0755: %s\n' "$target" >&2
        exit 1
    fi
done
if [[ ! -d $launcher_dir || -L $launcher_dir || $(stat -c '%u:%a' "$launcher_dir") != 0:755 ]]; then
    printf 'Ожидался каталог запуска root с режимом 0755: %s\n' "$launcher_dir" >&2
    exit 1
fi
if [[ ! -d $sudoers_dir || -L $sudoers_dir || -z $(find "$sudoers_dir" -maxdepth 0 -user root ! -perm /022 -print) ]]; then
    printf 'Ожидался защищённый каталог правил sudo: %s\n' "$sudoers_dir" >&2
    exit 1
fi

check_root_file() {
    local file=$1 mode=$2
    if [[ -L $file ]] || { [[ -e $file ]] && [[ ! -f $file || $(stat -c '%u:%g:%a' "$file") != "0:0:$mode" ]]; }; then
        printf 'Ожидался локальный файл root:root с режимом %s: %s\n' "$mode" "$file" >&2
        exit 1
    fi
}
check_root_file "$old_auth_file" 644
check_root_file "$auth_file" 644
check_root_file "$launcher" 755
check_root_file "$entry" 755
check_root_file "$session_config" 644
check_root_file "$sudoers" 440

prepare_account() {
    local account=$1 account_home=$2 login_shell=$3 previous_shell=${4:-$3}
    local uid gid actual_home actual_shell password_status
    if getent passwd "$account" >/dev/null; then
        IFS=: read -r _ _ uid gid _ actual_home actual_shell < <(getent passwd "$account")
        read -r _ password_status _ < <(passwd -S "$account")
        if [[ $uid == 0 || $actual_home != "$account_home" || $password_status != L ||
            ( $actual_shell != "$login_shell" && $actual_shell != "$previous_shell" ) ||
            $(id -gn "$account") != "$account" || $(id -G "$account") != "$gid" ]]; then
            printf 'Существующая учётная запись %s требует проверки администратора.\n' "$account" >&2
            exit 1
        fi
    elif [[ -e $account_home ]]; then
        printf 'Каталог %s уже существует без выделенной учётной записи.\n' "$account_home" >&2
        exit 1
    else
        useradd --system --user-group --home-dir "$account_home" --no-create-home --shell "$login_shell" "$account"
    fi
}
prepare_account "$owner" "$owner_home" "$owner_shell" /bin/sh
prepare_account "$ssh_owner" "$ssh_home" /bin/sh
if [[ $(id -u "$owner") == "$(id -u "$ssh_owner")" ]]; then
    printf 'Панели и SSH требуются разные UID.\n' >&2
    exit 1
fi

forced_prefix='restrict,pty,command="/opt/exam-lab/controller/owner-tui '
previous_prefix='restrict,pty,command="/usr/bin/python3 -Es /opt/exam-lab/controller/'
key_suffix="\" $key_type $key_blob"
key_line="restrict,pty $key_type $key_blob"
if [[ -f $old_auth_file ]]; then
    mapfile -t known_keys < "$old_auth_file"
    if (( ${#known_keys[@]} != 1 )) ||
        [[ ${known_keys[0]} != "$key_line" && ${known_keys[0]} != "$forced_prefix"*"$key_suffix" &&
            ${known_keys[0]} != "$previous_prefix"*"$key_suffix" ]]; then
        printf 'Текущий ключ %s требует проверки администратора.\n' "$owner" >&2
        exit 1
    fi
fi
if [[ -f $auth_file ]] && ! cmp -s -- "$auth_file" <(printf '%s\n' "$key_line"); then
    printf 'Текущий ключ %s требует проверки администратора.\n' "$ssh_owner" >&2
    exit 1
fi

install -d -o root -g root -m 0755 /opt/exam-lab "$release_root" "$owner_home" "$owner_home/.ssh" "$ssh_home" "$ssh_home/.ssh"
stage=$(mktemp -d "$release_root/.stage.XXXXXXXX")
next_key=
next_launcher=
next_session=
next_entry=
next_sudoers=
cleanup() {
    rm -rf -- "$stage"
    local temporary
    for temporary in "$next_key" "$next_launcher" "$next_session" "$next_entry" "$next_sudoers"; do
        if [[ $temporary ]]; then rm -f -- "$temporary"; fi
    done
}
trap cleanup EXIT
for file in "${files[@]}"; do
    install -o root -g root -m 0644 "$source_dir/$file" "$stage/$file"
done
cp -R -- "$deps" "$stage/tui-deps"
chown -R root:root "$stage/tui-deps"
find "$stage/tui-deps" -type d -exec chmod 0755 {} +
find "$stage/tui-deps" -type f -exec chmod 0644 {} +
/usr/bin/python3 -m py_compile "$stage/"*.py
rm -rf -- "$stage/__pycache__"
if [[ -d $code_dir ]]; then
    for file in "${files[@]}"; do
        if [[ -L $code_dir/$file || ! -f $code_dir/$file || $(stat -c '%u:%a' "$code_dir/$file") != 0:644 ]] ||
            ! cmp -s -- "$stage/$file" "$code_dir/$file"; then
            printf 'По этому пути уже находится другой код: %s\n' "$code_dir/$file" >&2
            exit 1
        fi
    done
    if [[ -L $code_dir/tui-deps || ! -d $code_dir/tui-deps ]] ||
        [[ -n $(find "$code_dir/tui-deps" \( ! -user root -o -type l -o -perm /022 \) -print -quit) ]] ||
        ! diff -qr -- "$stage/tui-deps" "$code_dir/tui-deps"; then
        printf 'По этому пути уже находится другой набор зависимостей: %s\n' "$code_dir/tui-deps" >&2
        exit 1
    fi
else
    chmod 0755 "$stage"
    mv -T -- "$stage" "$code_dir"
fi

next_launcher=$(mktemp "$launcher_dir/.exam-lab-tui.XXXXXXXX")
cat > "$next_launcher" <<'SH_LAUNCHER'
#!/bin/sh
set -eu
if [ "$#" -ne 0 ]; then
    printf 'Запустите exam-lab-tui без аргументов.\n' >&2
    exit 2
fi
exec /usr/bin/sudo -n -u examowner -- /opt/exam-lab/controller/owner-tui-entry
SH_LAUNCHER

next_entry=$(mktemp "$release_root/.owner-tui-entry.XXXXXXXX")
cat > "$next_entry" <<'SH_ENTRY'
#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 2
root=/opt/exam-lab/controller
if ! { IFS= read -r exam && IFS= read -r trace_exam; } < "$root/owner-session"; then
    printf 'Настройки панели требуют проверки администратора.\n' >&2
    exit 1
fi
revision=$(/usr/bin/readlink -- "$root/current") || { printf 'Контроллер ещё не активирован.\n' >&2; exit 1; }
[ "${#revision}" -eq 40 ]
case $revision in *[!0-9a-f]*) exit 1 ;; esac
set -- /usr/bin/python3 -Es "$root/$revision/tui.py" \
    --socket /run/exam-lab-controller/teacher.sock --exam "$exam" --version "$revision"
if [ -n "$trace_exam" ]; then
    set -- "$@" --file-trace-exam "$trace_exam"
fi
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TERM="${TERM:-xterm}" COLORTERM="${COLORTERM:-}" "$@"
SH_ENTRY

next_sudoers=$(mktemp "$sudoers_dir/.exam-lab-owner-tui.XXXXXXXX")
cat > "$next_sudoers" <<'SUDOERS'
Defaults:examowner-ssh env_reset
examowner-ssh ALL=(examowner) NOPASSWD: NOSETENV: /opt/exam-lab/controller/owner-tui-entry ""
SUDOERS
chown root:root "$next_launcher" "$next_entry" "$next_sudoers"
chmod 0755 "$next_launcher" "$next_entry"
chmod 0440 "$next_sudoers"
visudo -cf "$next_sudoers"

check_installed() {
    local file=$1 candidate=$2
    if [[ -f $file ]] && ! cmp -s -- "$file" "$candidate"; then
        printf 'Существующий файл требует проверки администратора: %s\n' "$file" >&2
        exit 1
    fi
}
check_installed "$launcher" "$next_launcher"
check_installed "$entry" "$next_entry"
check_installed "$sudoers" "$next_sudoers"

next_session=$(mktemp "$release_root/.owner-session.XXXXXXXX")
printf '%s\n%s\n' "$exam" "$trace_exam" > "$next_session"
chmod 0644 "$next_session"
next_key=$(mktemp "$ssh_home/.ssh/.authorized_keys.XXXXXXXX")
printf '%s\n' "$key_line" > "$next_key"
chmod 0644 "$next_key"
chown root:root "$next_session" "$next_key"
mv -fT -- "$next_session" "$session_config"
if [[ ! -f $entry ]]; then
    mv -T -- "$next_entry" "$entry"
fi
if [[ ! -f $launcher ]]; then
    mv -T -- "$next_launcher" "$launcher"
fi
if [[ ! -f $sudoers ]]; then
    mv -T -- "$next_sudoers" "$sudoers"
fi
if ! /usr/bin/sudo -n -l -U "$ssh_owner" -u "$owner" -- "$entry" >/dev/null ||
    /usr/bin/sudo -n -l -U "$ssh_owner" -u "$owner" -- "$entry" test-argument >/dev/null 2>&1 ||
    /usr/bin/sudo -n -l -U "$ssh_owner" -u "$owner" -- /bin/sh >/dev/null 2>&1 ||
    /usr/bin/sudo -n -l -U "$ssh_owner" -u root -- "$entry" >/dev/null 2>&1; then
    printf 'Право запуска панели для %s требует проверки администратора.\n' "$ssh_owner" >&2
    exit 1
fi
mv -fT -- "$next_key" "$auth_file"
rm -f -- "$old_auth_file"
if [[ $(getent passwd "$owner" | cut -d: -f7) != "$owner_shell" ]]; then
    usermod --shell "$owner_shell" "$owner"
fi
printf 'SSH %s, UID %s. Панель %s, UID %s. Код %s. Команда exam-lab-tui.\n' \
    "$ssh_owner" "$(id -u "$ssh_owner")" "$owner" "$(id -u "$owner")" "$code_dir"
