#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'Использование: %s КАТАЛОГ-СБОРКИ КАТАЛОГ-ИНСТРУМЕНТОВ\n' "$0" >&2
    exit 2
fi
if [[ $(hostname -s) != exam-lab-pilot ]] || ! grep -Fq ' 10.135.250.231/16 ' <<<"$(ip -4 -o addr show)"; then
    printf 'Ожидалась выделенная VM exam-lab-pilot с адресом 10.135.250.231/16.\n' >&2
    exit 1
fi

release_dir=$1
tools_dir=$2
manifest=$(dirname -- "${BASH_SOURCE[0]}")/windows-release-tools.tsv
destination=/srv/exam-lab-release
umask 022

require_file() {
    if [[ ! -f $1 || -L $1 || ! -s $1 ]]; then
        printf 'Требуется непустой обычный файл: %s\n' "$1" >&2
        exit 1
    fi
}

shopt -s nullglob
bundles=("$release_dir"/exam-lab-*.zip)
if (( ${#bundles[@]} != 1 )) || [[ ! ${bundles[0]##*/} =~ ^exam-lab-[0-9a-f]{40}\.zip$ ]]; then
    printf 'В %s нужен один exam-lab-<40 символов ревизии>.zip\n' "$release_dir" >&2
    exit 1
fi
bundle=${bundles[0]##*/}
release=${bundle%.zip}
installer=$release.ps1
require_file "$release_dir/$bundle"
require_file "$release_dir/$installer"

files=()
while IFS=$'\t' read -r name version source; do
    [[ $name && $name != \#* ]] || continue
    if [[ ! $name =~ ^[A-Za-z0-9._-]+$ || $name == . || $name == .. || ! $version || ( $source != https://* && $source != - ) ]]; then
        printf 'Некорректная запись в %s: %s\n' "$manifest" "$name" >&2
        exit 1
    fi
    require_file "$tools_dir/$name"
    files+=("$name")
done < "$manifest"
if (( ${#files[@]} == 0 )); then
    printf 'Пустой список инструментов: %s\n' "$manifest" >&2
    exit 1
fi

install -d -o root -g root -m 0755 -- "$destination"
exec 9>"$destination/.publish.lock"
flock --exclusive 9
stage=$(mktemp -d -- "$destination/.publish.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT

mkdir -p -- "$stage/$release/tools"
install -m 0644 -- "$release_dir/$bundle" "$release_dir/$installer" "$stage/"
artifacts=()
for name in "${files[@]}"; do
    path="$release/tools/$name"
    install -m 0644 -- "$tools_dir/$name" "$stage/$path"
    read -r pin _ < <(sha256sum -- "$stage/$path")
    if ! grep -Fq -- "'$name' = '$pin'" "$stage/$installer"; then
        printf 'Инструмент не соответствует SHA-256 в установщике: %s\n' "$name" >&2
        exit 1
    fi
    artifacts+=("$path")
done
read -r pin _ < <(sha256sum -- "$stage/$bundle")
if ! grep -Fq -- "'$pin'" "$stage/$installer"; then
    printf 'Комплект не соответствует SHA-256 в установщике: %s\n' "$bundle" >&2
    exit 1
fi
artifacts+=("$bundle" "$installer")
if [[ -L $destination/$release || -L $destination/$release/tools ]] ||
    { [[ -e $destination/$release ]] && [[ ! -d $destination/$release/tools ]]; }; then
    printf 'Каталог инструментов выпуска имеет неожиданный тип: %s\n' "$destination/$release" >&2
    exit 1
fi
for path in "${artifacts[@]}"; do
    target=$destination/$path
    if [[ -L $target ]] || { [[ -e $target ]] && ! cmp -s -- "$stage/$path" "$target"; }; then
        printf 'По этому пути уже опубликован другой файл: %s\n' "$target" >&2
        exit 1
    fi
done

if [[ -e $destination/$release ]]; then
    for name in "${files[@]}"; do
        if [[ ! -f $destination/$release/tools/$name ]]; then
            printf 'В опубликованном выпуске отсутствует инструмент: %s\n' "$name" >&2
            exit 1
        fi
    done
else
    mv -T -- "$stage/$release" "$destination/$release"
fi
for path in "$bundle" "$installer"; do
    [[ -e $destination/$path ]] || mv -T -- "$stage/$path" "$destination/$path"
done
printf 'Опубликовано в %s: %s и %s (инструментов: %s)\n' \
    "$destination" "$installer" "$bundle" "${#files[@]}"
