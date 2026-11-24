#!/usr/bin/env python3
"""Собирает HTTPS-выпуск пилота и проверяемый CMD для загрузки по HTTP."""

import argparse
import base64
import hashlib
import io
from pathlib import Path
import re
import subprocess
import textwrap
from urllib.parse import urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PILOT_CONTROLLER_IP = "10.135.250.231"
PILOT_CONTROLLER_DNS = "controller.exam-server-20261119.test"
# https://github.com/PowerShell/PowerShell/releases/tag/v7.6.10
PWSH_VERSION = "7.6.10"
PWSH_MSI = f"PowerShell-{PWSH_VERSION}-win-x64.msi"
PWSH_SHA256 = "7d8daea48b450d4d62fcd1ac4d6faa7ac2db5e11aba5061ee81b7496adca8c07"
# https://github.com/windirstat/windirstat/releases/tag/release/v2.9.3
WINDIRSTAT_MSI = "WinDirStat-2.9.3-x64.msi"
WINDIRSTAT_SHA256 = "96c4c4beb63c7c5ad6b1a206f96560d7a9a2b6063f3cd175a82f392977a9af5d"
SOURCES = (
    "setup/Prepare-ExamLab.ps1",
    "setup/Install-ExamLabIdea.ps1",
    "setup/Install-LocalPilot.ps1",
    "setup/ExamLabRootTrust.ps1",
    "setup/ExamLabEnrollment.ps1",
    "setup/Collect-ExamLabDiagnostics.ps1",
    "setup/ExamLabMaintenance.ps1",
    "setup/ExamLabMaintenance.Core.ps1",
    "setup/Install-ExamLabWazuh.ps1",
    "windows/ExamLab.psm1",
    "windows/ExamLab.Usb.psm1",
    "windows/ExamLab.Controller.psm1",
    "windows/ExamNetwork.psm1",
    "windows/exam-lab.ps1",
    "windows/alert/ExamLabAlert.ps1",
    "windows/alert/Show-ExamLabAlert.ps1",
    "windows/alert/Test-ExamLabFileReadAudit.ps1",
    "windows/alert/Wait-ExamLabFileRead.ps1",
    "windows/alert/exam-lab-alert.cmd",
    "windows/LICENSE-exam-lab-0.1.0.txt",
)
TRACE_SOURCES = (
    "windows/trace/ExamLab.FileTrace.ps1",
    "windows/trace/windows-fileio-light.ps1",
    "windows/trace/Export-ExamLabFileTrace.ps1",
)
LEGACY_TRACE_SOURCES = (
    "tests/windows-fileio-light.ps1",
    "tests/Export-ExamLabFileTrace.ps1",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def published_tools(git, revision, tools_dir):
    manifest = git("show", f"{revision}:vm/proxmox/windows-release-tools.tsv").decode("utf-8")
    hashes = {}
    for line in manifest.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, _ = line.split("\t")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."} or name in hashes:
            raise ValueError(f"Недопустимое или повторное имя инструмента: {name}")
        source = tools_dir / name
        if not source.is_file() or source.is_symlink() or source.stat().st_size == 0:
            raise ValueError(f"Требуется непустой обычный файл: {source}")
        with source.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if hashes.get(PWSH_MSI) != PWSH_SHA256:
        raise ValueError(f"{PWSH_MSI} не соответствует SHA-256 опубликованного выпуска PowerShell")
    if WINDIRSTAT_MSI in hashes and hashes[WINDIRSTAT_MSI] != WINDIRSTAT_SHA256:
        raise ValueError(f"{WINDIRSTAT_MSI} не соответствует SHA-256 опубликованного выпуска WinDirStat")
    return hashes


def fill_template(template, substitutions):
    return re.sub(r"@([A-Z][A-Z0-9_]*)@", lambda match: substitutions[match[1]], template)


def read_root(path):
    certificate = path.read_bytes()
    if not 0 < len(certificate) <= 16384:
        raise ValueError(f"Файл CA имеет неожиданный размер: {path}")
    checked = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", str(path),
         "-subject", "-issuer", "-nameopt", "RFC2253", "-ext", "basicConstraints", "-checkend", "0", "-noout"],
        check=True, capture_output=True, text=True,
    )
    lines = checked.stdout.splitlines()
    if (len(lines) < 4 or not lines[0].startswith("subject=") or not lines[1].startswith("issuer=")
            or lines[0].partition("=")[2] != lines[1].partition("=")[2] or "CA:TRUE" not in checked.stdout):
        raise ValueError(f"Требуется действующий публичный корневой CA в DER: {path}")
    return certificate


def bootstrap_pem(certificate):
    body = textwrap.wrap(base64.b64encode(certificate).decode("ascii"), width=64)
    commands = [('>', '-----BEGIN CERTIFICATE-----')]
    commands.extend(('>>', line) for line in [*body, '-----END CERTIFICATE-----'])
    return "\n".join(f'{redirect} "%WORK%\\controller-ca.pem" echo {line}' for redirect, line in commands)


def bootstrap_check(script):
    encoded = base64.b64encode(script).decode("ascii")
    return "\n".join(f"rem EXAMLAB_EARLY_CHECK:{line}" for line in textwrap.wrap(encoded, width=100))


def bootstrap_private_paths(core):
    start = "# BEGIN EXAMLAB BOOTSTRAP PRIVATE PATHS\n"
    end = "\n# END EXAMLAB BOOTSTRAP PRIVATE PATHS"
    script = core.decode("utf-8-sig").replace("\r\n", "\n")
    _, found_start, remainder = script.partition(start)
    functions, found_end, _ = remainder.partition(end)
    if not found_start or not found_end or not functions.strip():
        raise ValueError("Не найден блок защиты путей для раннего запуска")
    return functions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=f"https://{PILOT_CONTROLLER_IP}:21650/install")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="HEAD", help="Точная Git-ревизия исходников")
    parser.add_argument("--launcher", type=Path, required=True, help="Путь к файлу Start-ExamLab.cmd для HTTP")
    parser.add_argument("--controller-ca", type=Path, required=True, help="Публичный CA контроллера в DER")
    parser.add_argument("--squid-ca", type=Path, required=True, help="Публичный CA Squid в DER")
    parser.add_argument("--tools-dir", type=Path, required=True, help="Проверенные файлы для HTTPS-публикации пилота")
    parser.add_argument("--moodle-activity-url", default="", help="HTTPS-адрес открываемой ярлыком LTI-активности Moodle")
    parser.add_argument("--file-trace-exam", default="", help="Точный examId для файловой пробы этой поставки")
    args = parser.parse_args()
    if args.file_trace_exam and not re.fullmatch(r"file-trace-[A-Za-z0-9._-]{1,53}", args.file_trace_exam):
        parser.error("--file-trace-exam требует допустимый examId с префиксом file-trace-")
    if args.moodle_activity_url and not re.fullmatch(
        r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/mod/lti/view\.php\?id=[1-9][0-9]*", args.moodle_activity_url
    ):
        parser.error("--moodle-activity-url требует HTTPS-адрес LTI-активности Moodle с id")
    try:
        activity_port = urlsplit(args.moodle_activity_url).port
    except ValueError:
        parser.error("--moodle-activity-url: неверный номер порта")
    if activity_port == 0:
        parser.error("--moodle-activity-url: неверный номер порта")
    if args.launcher.suffix.lower() != ".cmd" or args.launcher.resolve().is_relative_to(args.output.resolve()):
        parser.error("--launcher: укажите путь к файлу .cmd вне каталога HTTPS-публикации")
    try:
        certificate = read_root(args.controller_ca)
        squid_certificate = read_root(args.squid_ca)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    base = args.base_url.rstrip("/")
    url = urlsplit(base)
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+", base):
        parser.error("--base-url: укажите HTTPS-адрес каталога публикации")
    try:
        url.port
    except ValueError:
        parser.error("--base-url: неверный номер порта")
    if url.port == 0:
        parser.error("--base-url: неверный номер порта")

    def git(*command):
        return subprocess.check_output(["git", "-C", str(ROOT), *command])

    revision = git("rev-parse", "--verify", "--end-of-options", f"{args.revision}^{{commit}}").decode("ascii").strip()
    trace_sources = TRACE_SOURCES if git("ls-tree", revision, "windows/trace") else LEGACY_TRACE_SOURCES
    files = {path: git("show", f"{revision}:{path}") for path in (*SOURCES, *trace_sources)}
    files["windows/file-trace-exam.txt"] = args.file_trace_exam.encode("utf-8")
    response_pin = re.search(rb"(?m)^\$expectedResponseSha256 = '([0-9A-F]{64})'\r?$",
                             files["setup/Install-ExamLabWazuh.ps1"])
    if not response_pin or response_pin[1].decode("ascii").lower() != sha256(files["windows/alert/exam-lab-alert.cmd"]):
        parser.error("SHA-256 команды Active Response не совпадает с закреплённым значением установщика Wazuh")
    contents = io.BytesIO()
    with zipfile.ZipFile(contents, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in files.items():
            archive.writestr(zipfile.ZipInfo(path), data, zipfile.ZIP_DEFLATED)
    bundle = contents.getvalue()
    digest = sha256(bundle)
    try:
        tools_hashes = published_tools(git, revision, args.tools_dir)
    except ValueError as exc:
        parser.error(str(exc))
    filename = f"exam-lab-{revision}.zip"
    installer_name = f"exam-lab-{revision}.ps1"
    tools_url = f"{base}/exam-lab-{revision}/tools"
    tools_pins = ";\n        ".join(f"'{name}' = '{pin}'" for name, pin in tools_hashes.items())
    cmd = git("show", f"{revision}:setup/Start-ExamLab.cmd").decode("ascii")
    include_expanded_sizes = "@BUNDLE_EXPANDED_BYTES@" in cmd
    bootstrap_tools = []
    for name, pin in tools_hashes.items():
        if name == PWSH_MSI:
            continue
        path = args.tools_dir / name
        sizes = f"Bytes={path.stat().st_size}"
        if include_expanded_sizes:
            expanded = "$null"
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path) as archive:
                    expanded = sum(member.file_size for member in archive.infolist())
            sizes += f"; ExpandedBytes={expanded}"
        bootstrap_tools.append(f"@{{Name='{name}'; SHA256='{pin}'; {sizes}}}")
    template = git("show", f"{revision}:setup/Install-FromHttps.ps1.in").decode("utf-8-sig")
    installer = fill_template(template, {
        "BUNDLE_URL": f"{base}/{filename}",
        "BUNDLE_SHA256": digest,
        "REVISION": revision,
        "CONTROLLER_URL": f"https://{url.netloc}/exam/v1/poll",
        "ENROLLMENT_URL": f"https://{url.netloc}/install/enroll",
        "TOOLS_URL": tools_url,
        "TOOLS_SHA256": f"@{{{tools_pins}}}",
        "GRADLE_CACHE_URL": f"{tools_url}/gradle-exam-cache.zip",
        "LGPO_URL": f"{tools_url}/LGPO.zip",
        "PFE_URL": f"{tools_url}/PolicyFileEditor-3.0.1.zip",
        "WAZUH_URL": f"{tools_url}/wazuh-agent-4.14.10-1.msi",
        "MOODLE_ACTIVITY_URL": args.moodle_activity_url,
        "MAINTENANCE_CORE": files["setup/ExamLabMaintenance.Core.ps1"].decode("utf-8-sig"),
        "ENROLLMENT_CORE": files["setup/ExamLabEnrollment.ps1"].decode("utf-8-sig"),
    })
    load_roots = "\n    ".join(
        "$examLabStartCertificates.Add((ConvertFrom-PinnedRoot "
        f"([Convert]::FromBase64String('{base64.b64encode(cert).decode('ascii')}')) '{sha256(cert)}'))"
        for cert in (certificate, squid_certificate)
    )
    entrypoint = git("show", f"{revision}:setup/Start-ExamLab.ps1.in").decode("utf-8-sig")
    entrypoint = fill_template(entrypoint, {
        "ROOT_TRUST": files["setup/ExamLabRootTrust.ps1"].decode("utf-8-sig"),
        "LOAD_ROOTS": load_roots,
        "INSTALLER": installer,
        "DIAGNOSTICS_COLLECTOR": files["setup/Collect-ExamLabDiagnostics.ps1"].decode("utf-8-sig"),
    })
    installer_bytes = entrypoint.encode("utf-8-sig")

    # Windows 10 Schannel curl compares the server DNS name even with an IP SAN.
    native_base = base
    curl_resolve = ""
    if url.hostname == PILOT_CONTROLLER_IP:
        native_host = f"{PILOT_CONTROLLER_DNS}:{url.port}" if url.port else PILOT_CONTROLLER_DNS
        native_base = f"https://{native_host}{url.path}"
        curl_resolve = f' --resolve "{PILOT_CONTROLLER_DNS}:{url.port or 443}:{url.hostname}"'

    cmd_substitutions = {
        "REVISION": revision,
        "CONTROLLER_CA_PEM": bootstrap_pem(certificate),
        "CONTROLLER_CA_BASE64": base64.b64encode(certificate).decode("ascii"),
        "CONTROLLER_CA_SHA256": sha256(certificate),
        "CONTROLLER_CA_THUMBPRINT": hashlib.sha1(certificate, usedforsecurity=False).hexdigest(),
        "PWSH_VERSION": PWSH_VERSION,
        "CURL_RESOLVE": curl_resolve,
        "PWSH_FILE": PWSH_MSI,
        "PWSH_BYTES": (args.tools_dir / PWSH_MSI).stat().st_size,
        "PWSH_URL": f"{native_base}/exam-lab-{revision}/tools/{PWSH_MSI}",
        "PWSH_SHA256": PWSH_SHA256,
        "INSTALLER_FILE": installer_name,
        "INSTALLER_BYTES": len(installer_bytes),
        "INSTALLER_URL": f"{native_base}/{installer_name}",
        "INSTALLER_SHA256": sha256(installer_bytes),
        "DIAGNOSTICS_URL": f"{native_base}/diagnostics",
        "PREFETCH_BASE_URL": base,
        "BUNDLE_FILE": filename,
        "BUNDLE_BYTES": len(bundle),
        "BUNDLE_EXPANDED_BYTES": sum(len(data) for data in files.values()),
        "BUNDLE_SHA256": digest,
        "BOOTSTRAP_TOOLS": "@(" + ", ".join(bootstrap_tools) + ")",
        "EARLY_CHECK_PAYLOAD": bootstrap_check(files["setup/Prepare-ExamLab.ps1"]),
    }
    if "@BOOTSTRAP_PRIVATE_PATHS@" in cmd:
        cmd_substitutions["BOOTSTRAP_PRIVATE_PATHS"] = bootstrap_private_paths(files["setup/ExamLabMaintenance.Core.ps1"])
    cmd = fill_template(cmd, {name: str(value) for name, value in cmd_substitutions.items()})
    launcher_bytes = cmd.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / filename).write_bytes(bundle)
    (args.output / installer_name).write_bytes(installer_bytes)
    args.launcher.write_bytes(launcher_bytes)
    print(f"{base}/{installer_name}")
    print(f"{installer_name}  SHA-256 {sha256(installer_bytes)}")
    print(f"{filename}  SHA-256 {digest}")
    print(f"{args.launcher}  SHA-256 {sha256(launcher_bytes)}")


if __name__ == "__main__":
    main()
