#!/usr/bin/env bash
# Подготовить переносимый кеш зависимостей для выданной работы пилота.
set -euo pipefail

if [[ $# != 3 ]]; then
    echo 'Использование: build-pilot-gradle-cache.sh GRADLE STARTER_ZIP OUTPUT_ZIP' >&2
    exit 2
fi

gradle=$(realpath "$1")
starter=$(realpath "$2")
output=$(realpath -m "$3")
[[ ! -e "$output" ]] || { echo "Выходной архив уже существует: $output" >&2; exit 1; }
tmp=$(mktemp -d --tmpdir="$(dirname "$output")" .exam-lab-cache.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
unzip -q "$starter" -d "$tmp/project"

cat > "$tmp/cache.init.gradle" <<'GRADLE'
gradle.projectsEvaluated {
    rootProject.tasks.register('prepareExamDependencyCache') {
        doLast {
            ['apiCompileClasspath', 'apiRuntimeClasspath', 'testCompileClasspath', 'testRuntimeClasspath'].each {
                rootProject.configurations.getByName(it).resolve()
            }
        }
    }
}
GRADLE

GRADLE_USER_HOME="$tmp/gradle" "$gradle" --no-daemon --project-dir "$tmp/project" \
    --init-script "$tmp/cache.init.gradle" prepareExamDependencyCache
(
    cd "$tmp/gradle/caches"
    zip -qr "$tmp/cache.zip" modules-2 -x '*/modules-2.lock' '*/gc.properties'
)
ln -T -- "$tmp/cache.zip" "$output"
