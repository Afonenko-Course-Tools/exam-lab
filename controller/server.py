import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat


POLL_PATH = "/exam/v1/poll"
TEACHER_PATH = "/exam/teacher/readiness"
TEACHER_PROXY_HEADER = "X-Exam-Teacher-Proxy"
MAX_BODY = 4096
MAX_REVISION = 2_147_483_647
READINESS_TIMEOUT = 45
READINESS_CLOCK_SKEW = 5
IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,64}")
REASON = re.compile(r"[a-z0-9-]{1,64}")
UTC_MILLIS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{43})", re.IGNORECASE | re.ASCII)
TEACHER_PROXY_TOKEN = re.compile(r"[0-9a-f]{64}")
OUTCOMES = ("applied", "source-applied", "blocked", "error", "overridden")
ASSIGNMENT_FIELDS = {"revision", "mode", "examId"}
RESULT_FIELDS = ASSIGNMENT_FIELDS | {"outcome", "reason", "fullReady", "observedUtc"}
READINESS_FIELDS = {"revision", "bootUtc", "observedUtc", "machineReady", "guestSessionId"}
READINESS_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_readiness (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
    observation TEXT NOT NULL,
    last_machine_confirmation TEXT,
    last_guest_confirmation TEXT,
    guest_confirmed INTEGER NOT NULL DEFAULT 0
);
"""
SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    token_digest BLOB NOT NULL,
    last_seen TEXT,
    latest_report TEXT,
    last_applied TEXT
);
CREATE TABLE IF NOT EXISTS assignments (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 2147483647),
    exam_id TEXT,
    PRIMARY KEY (device_id, revision),
    UNIQUE (device_id, exam_id)
);
""" + READINESS_SCHEMA


class RequestError(ValueError):
    pass


def valid_code(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def utc_now():
    return datetime.now(timezone.utc)


def iso_utc(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def assignment(row):
    exam_id = row["exam_id"]
    return {"revision": row["revision"], "mode": "normal" if exam_id is None else "exam", "examId": exam_id}


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RequestError("invalid-json")
        obj[key] = value
    return obj


def valid_utc(value):
    if not valid_code(UTC_MILLIS, value):
        return False
    try:
        parse_utc(value)
    except ValueError:
        return False
    return True


def parse_readiness(obj, revision):
    if (
        not isinstance(obj, dict) or obj.keys() != READINESS_FIELDS
        or type(obj["revision"]) is not int or obj["revision"] != revision
        or not valid_utc(obj["bootUtc"]) or not valid_utc(obj["observedUtc"])
        or obj["observedUtc"] < obj["bootUtc"]
        or type(obj["machineReady"]) is not bool
        or (obj["guestSessionId"] is not None and not valid_code(IDENTIFIER, obj["guestSessionId"]))
    ):
        raise RequestError("invalid-readiness")
    return obj


def parse_poll(payload):
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as error:
        raise RequestError("invalid-json") from error
    if not isinstance(obj, dict) or obj.keys() not in ({"deviceId", "result"}, {"deviceId", "result", "readiness"}):
        raise RequestError("invalid-request")
    device_id = obj["deviceId"]
    if not valid_code(IDENTIFIER, device_id):
        raise RequestError("invalid-device-id")
    result = obj["result"]
    if result is None:
        if "readiness" in obj:
            raise RequestError("invalid-readiness")
        return device_id, result, None
    if not isinstance(result, dict) or result.keys() != RESULT_FIELDS:
        raise RequestError("invalid-result")
    revision = result["revision"]
    mode = result["mode"]
    exam_id = result["examId"]
    outcome = result["outcome"]
    reason = result["reason"]
    observed = result["observedUtc"]
    ready = result["fullReady"]
    if (
        type(revision) is not int or not 1 <= revision <= MAX_REVISION
        or mode not in ("normal", "exam")
        or (exam_id is not None if mode == "normal" else not valid_code(IDENTIFIER, exam_id))
        or outcome not in OUTCOMES
        or (outcome == "overridden" and mode != "exam")
        or (reason is not None if outcome == "applied" else not valid_code(REASON, reason))
        or type(ready) is not bool
        or (mode == "exam" and outcome == "applied" and not ready)
        or (outcome != "applied" and ready)
        or not valid_utc(observed)
    ):
        raise RequestError("invalid-result")
    readiness = parse_readiness(obj["readiness"], revision) if "readiness" in obj else None
    return device_id, result, readiness


def connect(path, create=False, *, read_only=False):
    mode = "rwc" if create else "rw"
    if read_only:
        mode = "ro"
    db = sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def device_row(db, device_id):
    return db.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()


def current_assignment(db, device_id):
    return assignment(db.execute(
        "SELECT revision, exam_id FROM assignments WHERE device_id = ? ORDER BY revision DESC LIMIT 1",
        (device_id,),
    ).fetchone())


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).digest()


def register(db, device_id, rotate=False):
    db.execute("BEGIN IMMEDIATE")
    exists = device_row(db, device_id) is not None
    token = secrets.token_urlsafe(32)
    if rotate:
        if not exists:
            raise ValueError("Устройство не зарегистрировано")
        db.execute("UPDATE devices SET token_digest = ? WHERE device_id = ?", (token_digest(token), device_id))
    else:
        if exists:
            raise ValueError("Устройство уже зарегистрировано")
        db.execute("INSERT INTO devices (device_id, token_digest) VALUES (?, ?)", (device_id, token_digest(token)))
        db.execute("INSERT INTO assignments VALUES (?, 1, NULL)", (device_id,))
    return token


def assign(db, device_id, exam_id):
    db.execute("BEGIN IMMEDIATE")
    if device_row(db, device_id) is None:
        raise ValueError("Устройство не зарегистрировано")
    current = current_assignment(db, device_id)
    if current["examId"] == exam_id:
        return current
    if current["revision"] == MAX_REVISION:
        raise ValueError("Исчерпаны номера назначений")
    try:
        db.execute("INSERT INTO assignments VALUES (?, ?, ?)", (device_id, current["revision"] + 1, exam_id))
    except sqlite3.IntegrityError as error:
        raise ValueError("Этот экзамен уже назначали устройству") from error
    return current_assignment(db, device_id)


def observation_age(observed_utc, now):
    return (now - parse_utc(observed_utc)).total_seconds()


def newer_report(previous_json, result, now):
    if result["outcome"] != "overridden" and observation_age(result["observedUtc"], now) < -READINESS_CLOCK_SKEW:
        return False
    if previous_json is None:
        return True
    previous = json.loads(previous_json)
    if result["revision"] != previous["revision"]:
        return result["revision"] > previous["revision"]
    if previous["outcome"] == "overridden" and result["outcome"] != "overridden":
        return False
    if result["outcome"] == "overridden" and previous["outcome"] != "overridden":
        return True
    if previous["outcome"] != "overridden" and observation_age(previous["observedUtc"], now) < -READINESS_CLOCK_SKEW:
        return True
    return result["observedUtc"] > previous["observedUtc"]


def machine_report_matches(report, active):
    return (
        report is not None and active["mode"] == "exam"
        and report["revision"] == active["revision"]
        and (report["outcome"] == "applied" or (
            report["outcome"] == "source-applied" and report["reason"] == "machine-policies-only"
        ))
    )


def elapsed_seconds(timestamp, now):
    return max(0, int((now - parse_utc(timestamp)).total_seconds()))


def fresh_observation(observation, now, stale_after=READINESS_TIMEOUT):
    age = observation_age(observation["observedUtc"], now)
    if not -READINESS_CLOCK_SKEW <= age < stale_after:
        return False
    received = observation.get("receivedUtc")
    return received is None or elapsed_seconds(received, now) < stale_after


def observation_matches_report(observation, report, active):
    return (
        machine_report_matches(report, active)
        and observation["proofObservedUtc"] == report["observedUtc"]
    )


def read_readiness(db, device_id):
    return db.execute("SELECT * FROM device_readiness WHERE device_id = ?", (device_id,)).fetchone()


def record_readiness(db, device_id, active, latest_report, result, readiness, now):
    row = read_readiness(db, device_id)
    previous = json.loads(row["observation"]) if row else None
    if (
        readiness is None or readiness["revision"] != active["revision"]
        or not fresh_observation(readiness, now)
        or (previous and previous["revision"] == readiness["revision"] and (
            readiness["bootUtc"], readiness["observedUtc"]
        ) <= (previous["bootUtc"], previous["observedUtc"]))
    ):
        if previous and previous["machineReady"] and not observation_matches_report(previous, latest_report, active):
            previous["machineReady"] = False
            db.execute(
                "UPDATE device_readiness SET observation = ?, guest_confirmed = 0 WHERE device_id = ?",
                (json.dumps(previous), device_id),
            )
        return

    machine_ready = (
        readiness["machineReady"] and machine_report_matches(latest_report, active)
        and all(latest_report[key] == result[key] for key in RESULT_FIELDS)
        and readiness["bootUtc"] <= result["observedUtc"] <= readiness["observedUtc"]
    )
    received = iso_utc(now)
    observation = {
        **readiness, "machineReady": machine_ready, "receivedUtc": received,
        "proofObservedUtc": result["observedUtc"] if machine_ready else None,
    }
    machine_confirmation = row["last_machine_confirmation"] if row else None
    if machine_ready:
        machine_confirmation = json.dumps({
            "revision": readiness["revision"], "bootUtc": readiness["bootUtc"],
            "observedUtc": readiness["observedUtc"], "receivedUtc": received,
        })
    # Согласие преподавателя действует только при непрерывном наблюдении того же сеанса.
    guest_confirmed = bool(
        machine_ready and row and row["guest_confirmed"] and previous["machineReady"]
        and all(previous[key] == readiness[key] for key in ("revision", "bootUtc", "guestSessionId"))
        and fresh_observation(previous, now)
    )
    db.execute(
        """INSERT INTO device_readiness (device_id, observation, last_machine_confirmation, guest_confirmed)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (device_id) DO UPDATE SET observation = excluded.observation,
               last_machine_confirmation = excluded.last_machine_confirmation, guest_confirmed = excluded.guest_confirmed""",
        (device_id, json.dumps(observation), machine_confirmation, guest_confirmed),
    )


def poll(db, device_id, token, result, readiness=None):
    db.execute("BEGIN IMMEDIATE")
    device = device_row(db, device_id)
    expected = bytes(32) if device is None else device["token_digest"]
    if not secrets.compare_digest(expected, token_digest(token)) or device is None:
        raise PermissionError("invalid-credentials")
    now = utc_now()
    active = current_assignment(db, device_id)
    latest_report = device["latest_report"]
    last_applied = device["last_applied"]
    if result is not None:
        assigned = db.execute(
            "SELECT revision, exam_id FROM assignments WHERE device_id = ? AND revision = ?",
            (device_id, result["revision"]),
        ).fetchone()
        if assigned is None or assignment(assigned) != {key: result[key] for key in ASSIGNMENT_FIELDS}:
            raise RequestError("unknown-assignment")
        report = json.dumps({**result, "receivedUtc": iso_utc(now)})
        if newer_report(latest_report, result, now):
            latest_report = report
        if result["outcome"] == "applied" and newer_report(last_applied, result, now):
            last_applied = report
    db.execute(
        "UPDATE devices SET last_seen = ?, latest_report = ?, last_applied = ? WHERE device_id = ?",
        (iso_utc(now), latest_report, last_applied, device_id),
    )
    record_readiness(db, device_id, active, json.loads(latest_report) if latest_report else None, result, readiness, now)
    return {"deviceId": device_id, **active}


def readiness_status(row, active, latest_report, now, stale_after):
    observation = json.loads(row["observation"]) if row else None
    current = observation if observation and observation["revision"] == active["revision"] else None
    machine_ready = bool(
        current and current["machineReady"] and observation_matches_report(current, latest_report, active)
        and fresh_observation(current, now, min(stale_after, READINESS_TIMEOUT))
    )
    return {
        "machineReady": machine_ready,
        "guestReady": machine_ready and bool(row["guest_confirmed"]),
        "bootUtc": current["bootUtc"] if current else None,
        "guestSessionId": current["guestSessionId"] if current else None,
        "lastObservationUtc": current["receivedUtc"] if current else None,
        "lastMachineConfirmation": json.loads(row["last_machine_confirmation"]) if row and row["last_machine_confirmation"] else None,
        "lastGuestConfirmation": json.loads(row["last_guest_confirmation"]) if row and row["last_guest_confirmation"] else None,
    }


def device_status(db, device, now, stale_after):
    device_id = device["device_id"]
    last_seen = device["last_seen"]
    age = elapsed_seconds(last_seen, now) if last_seen else None
    active = current_assignment(db, device_id)
    latest_report = json.loads(device["latest_report"]) if device["latest_report"] else None
    return {
        "deviceId": device_id,
        "assignment": active,
        "latestReport": latest_report,
        "lastApplied": json.loads(device["last_applied"]) if device["last_applied"] else None,
        "lastSeenUtc": last_seen,
        "connection": "never" if age is None else ("fresh" if age < stale_after else "stale"),
        "connectionAgeSeconds": age,
        "readiness": readiness_status(read_readiness(db, device_id), active, latest_report, now, stale_after),
    }


def status(db, device_id, stale_after):
    db.execute("BEGIN")
    device = device_row(db, device_id)
    if device is None:
        raise ValueError("Устройство не зарегистрировано")
    return device_status(db, device, utc_now(), stale_after)


def readiness_snapshots(db, now):
    db.execute("BEGIN")
    return [
        device_status(db, device, now, READINESS_TIMEOUT)
        for device in db.execute("SELECT * FROM devices ORDER BY device_id")
    ]


def readiness_table(db):
    rows = [(
        "ПК", "Назначение", "Ревизия", "Связь", "Можно входить", "Можно начинать", "Загрузка UTC", "Guest",
        "Машинная сверка UTC", "Проверка Guest UTC",
    )]
    connection = {"never": "не было", "fresh": "есть", "stale": "устарела"}
    for snapshot in readiness_snapshots(db, utc_now()):
        readiness = snapshot["readiness"]
        machine = readiness["lastMachineConfirmation"]
        guest = readiness["lastGuestConfirmation"]
        active = snapshot["assignment"]
        rows.append((
            snapshot["deviceId"], active["examId"] or active["mode"], str(active["revision"]), connection[snapshot["connection"]],
            "да" if readiness["machineReady"] else "нет", "да" if readiness["guestReady"] else "нет",
            readiness["bootUtc"] or "—", readiness["guestSessionId"] or "—",
            machine["receivedUtc"] if machine else "—", guest["confirmedUtc"] if guest else "—",
        ))
    widths = [max(map(len, column)) for column in zip(*rows)]
    return "\n".join("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip() for row in rows)


def readiness_html(snapshots, now):
    headings = (
        "ПК", "Назначение", "Ревизия", "Связь", "Можно входить", "Можно начинать",
        "Последний опрос UTC", "Последняя машинная сверка UTC", "Последняя проверка Guest UTC",
    )
    headers = "".join(f'<th scope="col">{escape(label)}</th>' for label in headings)
    connection = {"never": "Опросов ещё не было", "fresh": "Есть", "stale": "Нет связи"}
    rows = []
    for snapshot in snapshots:
        active = snapshot["assignment"]
        readiness = snapshot["readiness"]
        machine = readiness["lastMachineConfirmation"]
        guest = readiness["lastGuestConfirmation"]
        values = (
            active["examId"] or "Обычный режим", str(active["revision"]), connection[snapshot["connection"]],
            "Да" if readiness["machineReady"] else "Нет", "Да" if readiness["guestReady"] else "Нет",
            snapshot["lastSeenUtc"] or "—", machine["receivedUtc"] if machine else "—", guest["confirmedUtc"] if guest else "—",
        )
        cells = "".join(f"<td>{escape(value)}</td>" for value in values)
        rows.append(f'<tr><th scope="row">{escape(snapshot["deviceId"])}</th>{cells}</tr>')
    table = "".join(rows) or f'<tr><td colspan="{len(headings)}">Нет зарегистрированных ПК</td></tr>'
    return f"""<!doctype html>
<html lang="ru">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Готовность экзаменационных ПК</title>
<style>
  body {{ font: 1rem/1.5 system-ui, sans-serif; margin: 2rem; }}
  .table {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td, th {{ border-bottom: 1px solid #a0a8b2; padding: .55rem; text-align: left; }}
  tbody th {{ overflow-wrap: anywhere; }}
</style>
<main>
  <h1>Готовность экзаменационных ПК</h1>
  <p>Сводка на <time>{escape(iso_utc(now))}</time></p>
  <div class="table" role="region" aria-label="Статусы рабочих мест" tabindex="0">
    <table><thead><tr>{headers}</tr></thead><tbody>{table}</tbody></table>
  </div>
</main>
</html>"""


def confirm_guest(db, device_id, revision, boot_utc, guest_session_id):
    db.execute("BEGIN IMMEDIATE")
    device = device_row(db, device_id)
    if device is None:
        raise ValueError("Устройство не зарегистрировано")
    now = utc_now()
    snapshot = device_status(db, device, now, READINESS_TIMEOUT)
    readiness = snapshot["readiness"]
    if (
        guest_session_id is None or not readiness["machineReady"] or snapshot["assignment"]["revision"] != revision
        or readiness["bootUtc"] != boot_utc or readiness["guestSessionId"] != guest_session_id
    ):
        raise ValueError("Сверьте готовность машины, ревизию и текущий сеанс Guest")
    confirmation = {"revision": revision, "bootUtc": boot_utc, "guestSessionId": guest_session_id, "confirmedUtc": iso_utc(now)}
    db.execute(
        "UPDATE device_readiness SET last_guest_confirmation = ?, guest_confirmed = 1 WHERE device_id = ?",
        (json.dumps(confirmation), device_id),
    )
    return confirmation


class PollHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, _format, *_values):
        pass

    def reply(self, status_code, obj):
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        token = getattr(self.server, "teacher_proxy_token", None)
        proof = self.headers.get_all(TEACHER_PROXY_HEADER, [])
        if (
            self.path != TEACHER_PATH or token is None or len(proof) != 1
            or not valid_code(TEACHER_PROXY_TOKEN, proof[0]) or not secrets.compare_digest(token, proof[0])
        ):
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        now = utc_now()
        try:
            with closing(connect(self.server.db_path, read_only=True)) as db, db:
                snapshots = readiness_snapshots(db, now)
        except sqlite3.Error:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "database-unavailable"})
            return
        body = readiness_html(snapshots, now).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Language", "ru")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != POLL_PATH:
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        auth = self.headers.get_all("Authorization", [])
        bearer = BEARER.fullmatch(auth[0]) if len(auth) == 1 else None
        if bearer is None:
            self.reply(HTTPStatus.UNAUTHORIZED, {"error": "invalid-credentials"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,12}", lengths[0]) or "Transfer-Encoding" in self.headers:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid-content-length"})
            return
        length = int(lengths[0])
        if length > MAX_BODY:
            self.reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body-too-large"})
            return
        if self.headers.get_content_type() != "application/json":
            self.reply(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "invalid-content-type"})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise RequestError("incomplete-body")
            device_id, result, readiness = parse_poll(body)
            with closing(connect(self.server.db_path)) as db, db:
                response = poll(db, device_id, bearer[1], result, readiness)
        except RequestError as error:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except PermissionError:
            self.reply(HTTPStatus.UNAUTHORIZED, {"error": "invalid-credentials"})
        except sqlite3.Error:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "database-unavailable"})
        else:
            self.reply(HTTPStatus.OK, response)


def private_db_path(path):
    path = path.resolve()
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("Ограничьте доступ к каталогу БД до 0700")
    if path.exists() and path.stat().st_mode & 0o077:
        raise ValueError("Ограничьте доступ к файлу БД до 0600")
    return path


def read_teacher_proxy_token(path):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as token_file:
        metadata = os.fstat(token_file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
            raise ValueError("Владелец файла секрета должен совпадать с учётной записью контроллера, права 0600 или строже")
        try:
            token = token_file.read(66).decode("ascii").removesuffix("\n")
        except UnicodeDecodeError:
            raise ValueError("Недопустимый формат секрета Nginx") from None
    if not valid_code(TEACHER_PROXY_TOKEN, token):
        raise ValueError("Недопустимый формат секрета Nginx")
    return token


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Контроллер локального стенда exam-lab")
    parser.add_argument("--db", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    serve_cmd = commands.add_parser("serve", help="Запустить HTTP за локальным Nginx")
    serve_cmd.add_argument("--port", default=21651, type=int, metavar="PORT")
    serve_cmd.add_argument("--teacher-proxy-token-file", type=Path, metavar="PATH")
    for command in ("register", "rotate-token", "assign", "status", "confirm-guest"):
        commands.add_parser(command).add_argument("device_id")
    commands.add_parser("readiness", help="Показать готовность зарегистрированных ПК")
    commands.choices["assign"].add_argument("mode", choices=("normal", "exam"))
    commands.choices["assign"].add_argument("--exam-id")
    commands.choices["status"].add_argument("--stale-after", default=READINESS_TIMEOUT, type=int, metavar="SECONDS")
    confirm = commands.choices["confirm-guest"]
    confirm.add_argument("--revision", required=True, type=int)
    confirm.add_argument("--boot-utc", required=True)
    confirm.add_argument("--guest-session-id", required=True)
    confirm.add_argument("--file-probe", required=True, action="store_true")
    confirm.add_argument("--project", required=True, action="store_true")
    confirm.add_argument("--wazuh", required=True, action="store_true")
    args = parser.parse_args()
    command = args.command
    if command == "serve" and not 1 <= args.port <= 65535:
        parser.error("Порт должен быть в диапазоне от 1 до 65535")
    if hasattr(args, "device_id") and not valid_code(IDENTIFIER, args.device_id):
        parser.error("Недопустимый идентификатор устройства")
    if command == "assign" and (
        (args.mode == "exam" and not valid_code(IDENTIFIER, args.exam_id))
        or (args.mode == "normal" and args.exam_id is not None)
    ):
        parser.error("Допустимый --exam-id требуется для exam; у normal идентификатора нет")
    if command == "status" and args.stale_after < 1:
        parser.error("--stale-after должен быть больше нуля")
    if command == "confirm-guest" and (
        not 1 <= args.revision <= MAX_REVISION or not valid_utc(args.boot_utc)
        or not valid_code(IDENTIFIER, args.guest_session_id)
    ):
        parser.error("Недопустимая ревизия, время загрузки или идентификатор сеанса Guest")
    try:
        path = private_db_path(args.db)
        with closing(connect(path, create=command == "register")) as db, db:
            db.executescript(SCHEMA if command == "register" else READINESS_SCHEMA)
            if command == "serve":
                db.execute("SELECT 1 FROM devices LIMIT 1")
            elif command in ("register", "rotate-token"):
                result = register(db, args.device_id, rotate=command == "rotate-token")
            elif command == "assign":
                result = assign(db, args.device_id, args.exam_id)
            elif command == "confirm-guest":
                result = confirm_guest(db, args.device_id, args.revision, args.boot_utc, args.guest_session_id)
            elif command == "readiness":
                result = readiness_table(db)
            else:
                result = status(db, args.device_id, args.stale_after)
        if command == "serve":
            teacher_proxy_token = None
            if args.teacher_proxy_token_file:
                try:
                    teacher_proxy_token = read_teacher_proxy_token(args.teacher_proxy_token_file)
                except (OSError, ValueError):
                    # Ошибка настройки панели оставляет доступным опрос Windows.
                    pass
            with ThreadingHTTPServer(("127.0.0.1", args.port), PollHandler) as server:
                server.db_path = path
                server.teacher_proxy_token = teacher_proxy_token
                server.serve_forever()
        else:
            print(result if isinstance(result, str) else json.dumps(result, indent=2))
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Ошибка контроллера: {error}\n")
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
