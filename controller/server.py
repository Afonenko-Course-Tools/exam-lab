import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3


POLL_PATH = "/exam/v1/poll"
MAX_BODY = 4096
MAX_REVISION = 2_147_483_647
IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,64}")
REASON = re.compile(r"[a-z0-9-]{1,64}")
UTC_MILLIS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{43})", re.IGNORECASE | re.ASCII)
OUTCOMES = ("applied", "source-applied", "blocked", "error", "overridden")
ASSIGNMENT_FIELDS = {"revision", "mode", "examId"}
RESULT_FIELDS = ASSIGNMENT_FIELDS | {"outcome", "reason", "fullReady", "observedUtc"}
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
"""


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


def parse_poll(payload):
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as error:
        raise RequestError("invalid-json") from error
    if not isinstance(obj, dict) or obj.keys() != {"deviceId", "result"}:
        raise RequestError("invalid-request")
    device_id = obj["deviceId"]
    if not valid_code(IDENTIFIER, device_id):
        raise RequestError("invalid-device-id")
    result = obj["result"]
    if result is None:
        return device_id, result
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
        or not valid_code(UTC_MILLIS, observed)
    ):
        raise RequestError("invalid-result")
    try:
        parse_utc(observed)
    except ValueError as error:
        raise RequestError("invalid-result") from error
    return device_id, result


def connect(path, create=False):
    mode = "rwc" if create else "rw"
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


def newer_report(previous_json, result):
    if previous_json is None:
        return True
    previous = json.loads(previous_json)
    if result["revision"] != previous["revision"]:
        return result["revision"] > previous["revision"]
    if previous["outcome"] == "overridden" and result["outcome"] != "overridden":
        return False
    if result["outcome"] == "overridden" and previous["outcome"] != "overridden":
        return True
    return result["observedUtc"] > previous["observedUtc"]


def poll(db, device_id, token, result):
    db.execute("BEGIN IMMEDIATE")
    device = device_row(db, device_id)
    expected = bytes(32) if device is None else device["token_digest"]
    if not secrets.compare_digest(expected, token_digest(token)) or device is None:
        raise PermissionError("invalid-credentials")
    now = iso_utc(utc_now())
    latest_report = device["latest_report"]
    last_applied = device["last_applied"]
    if result is not None:
        assigned = db.execute(
            "SELECT revision, exam_id FROM assignments WHERE device_id = ? AND revision = ?",
            (device_id, result["revision"]),
        ).fetchone()
        if assigned is None or assignment(assigned) != {key: result[key] for key in ASSIGNMENT_FIELDS}:
            raise RequestError("unknown-assignment")
        report = json.dumps({**result, "receivedUtc": now})
        if newer_report(latest_report, result):
            latest_report = report
        if result["outcome"] == "applied" and newer_report(last_applied, result):
            last_applied = report
    db.execute(
        "UPDATE devices SET last_seen = ?, latest_report = ?, last_applied = ? WHERE device_id = ?",
        (now, latest_report, last_applied, device_id),
    )
    return {"deviceId": device_id, **current_assignment(db, device_id)}


def status(db, device_id, stale_after):
    db.execute("BEGIN")
    device = device_row(db, device_id)
    if device is None:
        raise ValueError("Устройство не зарегистрировано")
    last_seen = device["last_seen"]
    age = max(0, int((utc_now() - parse_utc(last_seen)).total_seconds())) if last_seen else None
    return {
        "deviceId": device_id,
        "assignment": current_assignment(db, device_id),
        "latestReport": json.loads(device["latest_report"]) if device["latest_report"] else None,
        "lastApplied": json.loads(device["last_applied"]) if device["last_applied"] else None,
        "lastSeenUtc": last_seen,
        "connection": "never" if age is None else ("fresh" if age < stale_after else "stale"),
        "connectionAgeSeconds": age,
    }


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
            device_id, result = parse_poll(body)
            with closing(connect(self.server.db_path)) as db, db:
                response = poll(db, device_id, bearer[1], result)
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


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Контроллер локального стенда exam-lab")
    parser.add_argument("--db", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    serve_cmd = commands.add_parser("serve", help="Запустить HTTP за локальным Nginx")
    serve_cmd.add_argument("--port", default=21651, type=int, metavar="PORT")
    for command in ("register", "rotate-token", "assign", "status"):
        commands.add_parser(command).add_argument("device_id")
    commands.choices["assign"].add_argument("mode", choices=("normal", "exam"))
    commands.choices["assign"].add_argument("--exam-id")
    commands.choices["status"].add_argument("--stale-after", default=45, type=int, metavar="SECONDS")
    args = parser.parse_args()
    command = args.command
    if command == "serve" and not 1 <= args.port <= 65535:
        parser.error("Порт должен быть в диапазоне от 1 до 65535")
    if command != "serve" and not valid_code(IDENTIFIER, args.device_id):
        parser.error("Недопустимый идентификатор устройства")
    if command == "assign" and (
        (args.mode == "exam" and not valid_code(IDENTIFIER, args.exam_id))
        or (args.mode == "normal" and args.exam_id is not None)
    ):
        parser.error("Допустимый --exam-id требуется для exam; у normal идентификатора нет")
    if command == "status" and args.stale_after < 1:
        parser.error("--stale-after должен быть больше нуля")
    try:
        path = private_db_path(args.db)
        with closing(connect(path, create=command == "register")) as db, db:
            if command == "serve":
                db.execute("SELECT 1 FROM devices LIMIT 1")
            elif command in ("register", "rotate-token"):
                if command == "register":
                    db.executescript(SCHEMA)
                result = register(db, args.device_id, rotate=command == "rotate-token")
            elif command == "assign":
                result = assign(db, args.device_id, args.exam_id)
            else:
                result = status(db, args.device_id, args.stale_after)
        if command == "serve":
            with ThreadingHTTPServer(("127.0.0.1", args.port), PollHandler) as server:
                server.db_path = path
                server.serve_forever()
        else:
            print(result if isinstance(result, str) else json.dumps(result, indent=2))
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Ошибка контроллера: {error}\n")
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
