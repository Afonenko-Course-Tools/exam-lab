import argparse
import base64
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import Lock
from time import monotonic
import unicodedata
from uuid import uuid4
from urllib.parse import urlsplit
from zipfile import is_zipfile

from teacher_access import serve_teacher


POLL_PATH = "/exam/v1/poll"
ENROLLMENT_PATH = "/install/enroll"
ENROLLMENT_CLAIM = re.compile(r"[0-9a-f]{64}")
ENROLLMENT_KEY = re.compile(rb"[0-9]{3,8} [A-Za-z0-9_.-]+ [A-Za-z0-9.:/_-]+ [A-Fa-f0-9]{64}")
MAX_ENROLLMENT_RECEIPT = 16384
FILE_TRACE_EXAM_PREFIX = "file-trace-"
TEACHER_PATH = "/exam/teacher/readiness"
TEACHER_PROXY_HEADER = "X-Exam-Teacher-Proxy"
MAX_BODY = 4096
MAX_REVISION = 2_147_483_647
READINESS_TIMEOUT = 45
READINESS_CLOCK_SKEW = 5
IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,64}")
REASON = re.compile(r"[a-z0-9-]{1,64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
UTC_MILLIS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{43})", re.IGNORECASE | re.ASCII)
TEACHER_PROXY_TOKEN = re.compile(r"[0-9a-f]{64}")
OUTCOMES = ("applied", "source-applied", "blocked", "error", "overridden")
ASSIGNMENT_FIELDS = {"revision", "mode", "examId"}
RESULT_FIELDS = ASSIGNMENT_FIELDS | {"outcome", "reason", "fullReady", "observedUtc"}
READINESS_FIELDS = {"revision", "bootUtc", "observedUtc", "machineReady", "guestSessionId"}
SESSION_FIELDS = ("revision", "bootUtc", "guestSessionId")
ALERT_FIELDS = set(SESSION_FIELDS) | {
    "alertId", "reason", "phase", "receivedUtc", "shownUtc", "acknowledgedUtc", "acknowledgedBy", "acknowledgementId",
}
ALERT_TARGET_FIELDS = (*SESSION_FIELDS, "alertId")
ALERT_ACK_TIMEOUT = 90
CAMPAIGN_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_campaign (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
    installation TEXT,
    installation_seen TEXT,
    report_observation TEXT,
    report_seen TEXT,
    guest_observation TEXT
);
CREATE TABLE IF NOT EXISTS exam_places (
    exam_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    student TEXT NOT NULL,
    submission TEXT,
    PRIMARY KEY (exam_id, device_id)
);
CREATE TABLE IF NOT EXISTS device_alerts (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    alert_id TEXT NOT NULL,
    report TEXT NOT NULL,
    acknowledgement TEXT,
    acknowledged_uid INTEGER,
    cancelled INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, alert_id)
);
"""
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
""" + READINESS_SCHEMA + CAMPAIGN_SCHEMA


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


def valid_text(value, limit):
    return (
        isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()
        and all(unicodedata.category(char)[0] != "C" for char in value)
    )


def parse_alert(obj):
    if not isinstance(obj, dict) or obj.keys() != ALERT_FIELDS:
        raise RequestError("invalid-alert")
    phase = obj["phase"]
    shown = obj["shownUtc"]
    acknowledged = obj["acknowledgedUtc"]
    if (
        not valid_code(UUID, obj["alertId"])
        or type(obj["revision"]) is not int or not 1 <= obj["revision"] <= MAX_REVISION
        or not valid_utc(obj["bootUtc"]) or not valid_code(IDENTIFIER, obj["guestSessionId"])
        or not valid_code(REASON, obj["reason"]) or not valid_utc(obj["receivedUtc"])
        or obj["receivedUtc"] < obj["bootUtc"] or phase not in ("received", "shown", "acknowledged")
        or (shown is not None and (not valid_utc(shown) or shown < obj["receivedUtc"]))
        or (phase == "received" and shown is not None) or (phase == "shown" and shown is None)
    ):
        raise RequestError("invalid-alert")
    if phase == "acknowledged":
        if (
            not valid_utc(acknowledged) or acknowledged < (shown or obj["receivedUtc"])
            or not valid_text(obj["acknowledgedBy"], 128)
            or (obj["acknowledgementId"] is not None and not valid_code(UUID, obj["acknowledgementId"]))
        ):
            raise RequestError("invalid-alert")
    elif any(obj[field] is not None for field in ("acknowledgedUtc", "acknowledgedBy", "acknowledgementId")):
        raise RequestError("invalid-alert")
    return obj


def parse_client(obj, readiness):
    if not isinstance(obj, dict) or obj.keys() != {"installation", "guestState", "alert"}:
        raise RequestError("invalid-client-report")
    install = obj["installation"]
    if install is not None and (
        not isinstance(install, dict) or install.keys() != {"version", "completedUtc"}
        or not valid_code(VERSION, install["version"]) or not valid_utc(install["completedUtc"])
    ):
        raise RequestError("invalid-installation-report")
    state = obj["guestState"]
    if (
        state not in (None, "present", "absent", "unknown")
        or (state in ("present", "absent") and (
            readiness is None or (readiness["guestSessionId"] is not None) != (state == "present")
        ))
    ):
        raise RequestError("invalid-guest-observation")
    if obj["alert"] is not None:
        parse_alert(obj["alert"])
    return obj


def parse_poll(payload):
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as error:
        raise RequestError("invalid-json") from error
    if not isinstance(obj, dict) or not {"deviceId", "result"} <= obj.keys() <= {"deviceId", "result", "readiness", "client"}:
        raise RequestError("invalid-request")
    device_id = obj["deviceId"]
    if not valid_code(IDENTIFIER, device_id):
        raise RequestError("invalid-device-id")
    result = obj["result"]
    if result is None:
        if "readiness" in obj:
            raise RequestError("invalid-readiness")
        return device_id, result, None, parse_client(obj["client"], None) if "client" in obj else None
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
    return device_id, result, readiness, parse_client(obj["client"], readiness) if "client" in obj else None


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


def authenticated_device(db, device_id, token):
    device = device_row(db, device_id)
    expected = bytes(32) if device is None else device["token_digest"]
    if not secrets.compare_digest(expected, token_digest(token)) or device is None:
        raise PermissionError("invalid-credentials")
    return device


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
    return assign_locked(db, device_id, exam_id)


def assign_locked(db, device_id, exam_id):
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


def same_fields(left, right, fields):
    return all(left[key] == right[key] for key in fields)


def matches_alert_session(alert, observation):
    return observation["state"] == "present" and same_fields(alert, observation, SESSION_FIELDS)


def record_alert(db, device_id, report, observation):
    alert_id = report["alertId"]
    row = db.execute("SELECT * FROM device_alerts WHERE device_id = ? AND alert_id = ?", (device_id, alert_id)).fetchone()
    if row is None:
        if not observation or not matches_alert_session(report, observation) or report["acknowledgementId"] is not None:
            return None
        db.execute("INSERT INTO device_alerts (device_id, alert_id, report) VALUES (?, ?, ?)",
                   (device_id, alert_id, json.dumps(report)))
        return report

    previous = json.loads(row["report"])
    if not same_fields(previous, report, (*ALERT_TARGET_FIELDS, "receivedUtc", "reason")):
        return None
    if previous["phase"] == "acknowledged":
        return previous
    if previous["shownUtc"] is not None and report["shownUtc"] != previous["shownUtc"]:
        return previous
    acknowledgement_id = report["acknowledgementId"]
    if acknowledgement_id is not None:
        command = json.loads(row["acknowledgement"]) if row["acknowledgement"] else None
        if (
            command is None or acknowledgement_id != command["acknowledgementId"]
            or report["acknowledgedBy"] != command["owner"]
            or observation_age(report["acknowledgedUtc"], parse_utc(command["requestedUtc"])) > READINESS_CLOCK_SKEW
            or report["acknowledgedUtc"] > command["expiresUtc"]
        ):
            return None
    elif not observation or not matches_alert_session(report, observation):
        # A local receipt for an already-known alert still describes the original Guest.
        if report["phase"] != "acknowledged":
            return None
    db.execute("UPDATE device_alerts SET report = ? WHERE device_id = ? AND alert_id = ?",
               (json.dumps(report), device_id, alert_id))
    return report


def record_campaign(db, device_id, client, result, readiness, active, now):
    now_utc = iso_utc(now)
    db.execute(
        """INSERT INTO device_campaign (device_id, report_observation, report_seen) VALUES (?, ?, ?)
           ON CONFLICT (device_id) DO UPDATE SET report_observation = excluded.report_observation,
               report_seen = excluded.report_seen""",
        (device_id, json.dumps(result) if result else None, now_utc),
    )
    if client is None:
        return None
    install = client["installation"]
    if install and observation_age(install["completedUtc"], now) < -READINESS_CLOCK_SKEW:
        install = None
    db.execute(
        "UPDATE device_campaign SET installation = ?, installation_seen = ? WHERE device_id = ?",
        (json.dumps(install) if install else None, now_utc, device_id),
    )
    stored = db.execute("SELECT guest_observation FROM device_campaign WHERE device_id = ?", (device_id,)).fetchone()[0]
    previous = json.loads(stored) if stored else None
    observation = None
    if active["mode"] == "exam" and readiness is not None and readiness["revision"] == active["revision"]:
        row = read_readiness(db, device_id)
        accepted = json.loads(row["observation"]) if row else None
        if (
            accepted and same_fields(accepted, readiness, (*SESSION_FIELDS, "observedUtc"))
            and fresh_observation(accepted, now) and (previous is None or (
                readiness["revision"], readiness["bootUtc"], readiness["observedUtc"]
            ) > (previous["revision"], previous["bootUtc"], previous["observedUtc"]))
        ):
            same_boot = previous and same_fields(previous, accepted, ("revision", "bootUtc"))
            observation = {
                **{key: accepted[key] for key in (*SESSION_FIELDS, "observedUtc", "receivedUtc")},
                "state": client["guestState"] or "unknown", "alertId": None,
                "lastGuestSessionId": accepted["guestSessionId"] if client["guestState"] == "present" else (
                    previous["lastGuestSessionId"] if same_boot else None
                ),
            }
            if observation["state"] in ("present", "absent"):
                for row in db.execute(
                    "SELECT alert_id, report FROM device_alerts WHERE device_id = ? AND acknowledgement IS NOT NULL AND cancelled = 0",
                    (device_id,),
                ).fetchall():
                    if not matches_alert_session(json.loads(row["report"]), observation):
                        db.execute("UPDATE device_alerts SET cancelled = 1 WHERE device_id = ? AND alert_id = ?",
                                   (device_id, row["alert_id"]))
            if previous and (not same_boot or (
                observation["state"] == "present" and previous["lastGuestSessionId"] != observation["guestSessionId"]
            )):
                db.execute("UPDATE exam_places SET submission = NULL WHERE device_id = ? AND exam_id = ?",
                           (device_id, active["examId"]))

    alert = None
    alert_report = client["alert"]
    if alert_report is not None and all(
        timestamp is None or observation_age(timestamp, now) >= -READINESS_CLOCK_SKEW
        for timestamp in (alert_report["receivedUtc"], alert_report["shownUtc"], alert_report["acknowledgedUtc"])
    ):
        alert = record_alert(db, device_id, alert_report, observation)
    if observation is None:
        return None
    if alert and matches_alert_session(alert, observation):
        observation["alertId"] = alert["alertId"]
    db.execute("UPDATE device_campaign SET guest_observation = ? WHERE device_id = ?", (json.dumps(observation), device_id))
    if not alert or observation["alertId"] is None or alert["phase"] == "acknowledged":
        return None
    row = db.execute("SELECT acknowledgement, cancelled FROM device_alerts WHERE device_id = ? AND alert_id = ?",
                     (device_id, alert["alertId"])).fetchone()
    if not row["acknowledgement"] or row["cancelled"] or not accepted["machineReady"]:
        return None
    command = json.loads(row["acknowledgement"])
    if command["expiresUtc"] <= now_utc:
        return None
    return {key: value for key, value in command.items() if key != "requestedUtc"}


def poll(db, device_id, token, result, readiness=None, client=None):
    db.execute("BEGIN IMMEDIATE")
    device = authenticated_device(db, device_id, token)
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
    response = {"deviceId": device_id, **active}
    command = record_campaign(db, device_id, client, result, readiness, active, now)
    if command:
        response["alertAcknowledgement"] = command
    return response


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
    return confirm_guest_locked(db, device_id, revision, boot_utc, guest_session_id)


def confirm_guest_locked(db, device_id, revision, boot_utc, guest_session_id):
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


def get_place(db, device_id, exam_id):
    return db.execute("SELECT * FROM exam_places WHERE exam_id = ? AND device_id = ?", (exam_id, device_id)).fetchone()


def campaign_observation(db, device_id, active, now):
    row = db.execute("SELECT guest_observation FROM device_campaign WHERE device_id = ?", (device_id,)).fetchone()
    saved = json.loads(row["guest_observation"]) if row and row["guest_observation"] else None
    readiness_row = read_readiness(db, device_id)
    latest = json.loads(readiness_row["observation"]) if readiness_row else None
    if (
        saved and latest and active["mode"] == "exam" and saved["revision"] == active["revision"]
        and same_fields(saved, latest, (*SESSION_FIELDS, "observedUtc")) and fresh_observation(saved, now)
    ):
        return saved
    return None


def installation_status(db, device_id, expected_version, now):
    row = db.execute("SELECT installation, installation_seen FROM device_campaign WHERE device_id = ?", (device_id,)).fetchone()
    if row and row["installation"] and elapsed_seconds(row["installation_seen"], now) < READINESS_TIMEOUT:
        report = json.loads(row["installation"])
        return {"status": "installed" if report["version"] == expected_version else "other-release", **report}
    return {"status": "unconfirmed"}


def display_alert(row, observation, now):
    report = json.loads(row["report"])
    command = json.loads(row["acknowledgement"]) if row["acknowledgement"] else None
    current = bool(observation and observation["alertId"] == report["alertId"] and matches_alert_session(report, observation))
    status = report["phase"]
    if status != "acknowledged" and command:
        status = "session-ended" if row["cancelled"] else (
            "expired" if command["expiresUtc"] <= iso_utc(now) else "requested"
        )
    return {**report, "current": current, "status": status, "acknowledgement": command,
            "requestedByUid": row["acknowledged_uid"]}


def confirmed_report(db, device_id, active, report, now):
    if not report or report["revision"] != active["revision"]:
        return None
    seen = db.execute("SELECT report_observation, report_seen FROM device_campaign WHERE device_id = ?",
                      (device_id,)).fetchone()
    if not seen:
        return report if fresh_observation(report, now) else None
    if (
        seen["report_observation"] and elapsed_seconds(seen["report_seen"], now) < READINESS_TIMEOUT
        and same_fields(report, json.loads(seen["report_observation"]), RESULT_FIELDS)
    ):
        return report
    return None


def teacher_snapshot(db, device, exam_id, version, now, details=False):
    device_id = device["device_id"]
    snapshot = device_status(db, device, now, READINESS_TIMEOUT)
    active = snapshot["assignment"]
    place = get_place(db, device_id, exam_id)
    intended_exam = active["examId"] == exam_id
    observation = campaign_observation(db, device_id, active, now) if intended_exam else None
    alert_rows = db.execute(
        "SELECT * FROM device_alerts WHERE device_id = ? ORDER BY rowid DESC LIMIT ?", (device_id, 10 if details else 1),
    ).fetchall()
    if observation and observation["alertId"] and (
        not alert_rows or alert_rows[0]["alert_id"] != observation["alertId"]
    ):
        row = db.execute("SELECT * FROM device_alerts WHERE device_id = ? AND alert_id = ?",
                         (device_id, observation["alertId"])).fetchone()
        if row:
            alert_rows = [row] + [historical for historical in alert_rows if historical["alert_id"] != row["alert_id"]]
    alerts = [display_alert(row, observation, now) for row in alert_rows]
    report = confirmed_report(db, device_id, active, snapshot["latestReport"], now)
    report_status = "pending"
    if snapshot["connection"] != "fresh":
        report_status = "offline"
    elif report:
        report_status = report["outcome"]
    guest_ready = bool(
        intended_exam and place and observation and observation["state"] == "present"
        and snapshot["readiness"]["guestReady"]
    )
    summary = {
        "deviceId": device_id, "student": place["student"] if place else None,
        "installation": installation_status(db, device_id, version, now), "connection": snapshot["connection"],
        "examId": active["examId"], "assignedMode": active["mode"], "reportStatus": report_status,
        "reportReason": report["reason"] if report else None,
        "machineReady": intended_exam and snapshot["readiness"]["machineReady"], "guestReady": guest_ready,
        "guestState": observation["state"] if observation else None, "submitted": bool(place and place["submission"]),
        "alert": {key: alerts[0][key] for key in ("current", "status", "reason")} if alerts else None,
    }
    if details:
        summary.update({
            "device": snapshot, "guestObservation": observation, "alerts": alerts,
            "submission": json.loads(place["submission"]) if place and place["submission"] else None,
        })
    return summary


def selected_guest(db, device, exam_id, target, now):
    active = current_assignment(db, device["device_id"])
    observation = campaign_observation(db, device["device_id"], active, now)
    if (
        active["examId"] != exam_id or not observation or observation["state"] != "present"
        or not same_fields(target, observation, SESSION_FIELDS)
    ):
        raise ValueError("Сеанс Guest изменился или связь устарела. Обновите список")
    return observation


def request_acknowledgement(db, device, exam_id, target, uid, now):
    device_id = device["device_id"]
    observation = selected_guest(db, device, exam_id, target, now)
    snapshot = device_status(db, device, now, READINESS_TIMEOUT)
    if not snapshot["readiness"]["machineReady"] or observation["alertId"] != target["alertId"]:
        raise ValueError("Эта тревога больше не актуальна")
    row = db.execute("SELECT * FROM device_alerts WHERE device_id = ? AND alert_id = ?",
                     (device_id, target["alertId"])).fetchone()
    if row is None:
        raise ValueError("Тревога не найдена")
    report = json.loads(row["report"])
    if not same_fields(report, target, ALERT_TARGET_FIELDS) or row["acknowledgement"] or report["phase"] == "acknowledged":
        raise ValueError("Для этой тревоги снятие уже запрошено или подтверждено")
    owner = pwd.getpwuid(uid).pw_name
    if not valid_code(IDENTIFIER, owner):
        raise ValueError("Недопустимое имя учётной записи владельца")
    command = {
        **target, "owner": owner, "acknowledgementId": str(uuid4()), "requestedUtc": iso_utc(now),
        "expiresUtc": iso_utc(now + timedelta(seconds=ALERT_ACK_TIMEOUT)),
    }
    db.execute("UPDATE device_alerts SET acknowledgement = ?, acknowledged_uid = ? WHERE device_id = ? AND alert_id = ?",
               (json.dumps(command), uid, device_id, target["alertId"]))
    return command


def reset_place_confirmation(db, device_id, exam_id):
    if current_assignment(db, device_id)["examId"] == exam_id:
        db.execute("UPDATE device_readiness SET guest_confirmed = 0 WHERE device_id = ?", (device_id,))


def group_assign(db, exam_id, mode, selection, now):
    devices = [row["device_id"] for row in db.execute("SELECT device_id FROM devices ORDER BY device_id")]
    if selection == "*":
        selection = [
            device_id for device_id in devices
            if get_place(db, device_id, exam_id) is not None or current_assignment(db, device_id)["examId"] == exam_id
        ]
    results = []
    for device_id in selection:
        try:
            if device_id not in devices:
                raise ValueError("ПК не зарегистрирован")
            active = current_assignment(db, device_id)
            device = device_row(db, device_id)
            latest = json.loads(device["latest_report"]) if device["latest_report"] else None
            report = confirmed_report(db, device_id, active, latest, now)
            local_cleanup = report and report["outcome"] == "overridden" and report["reason"] == "local-normal-source-confirmed"
            if active["mode"] == "exam" and active["examId"] != exam_id and not (mode == "exam" and local_cleanup):
                raise ValueError("Назначен другой экзамен")
            if mode == "normal" and active["mode"] == "exam" and not local_cleanup:
                place = get_place(db, device_id, exam_id)
                submission = json.loads(place["submission"]) if place and place["submission"] else None
                if submission is None:
                    raise ValueError("Сдача не подтверждена")
                observation = campaign_observation(db, device_id, active, now)
                if (
                    not observation or observation["state"] != "absent"
                    or not same_fields(submission, observation, ("revision", "bootUtc"))
                    or submission["guestSessionId"] != observation["lastGuestSessionId"]
                ):
                    raise ValueError("Выход Guest не подтверждён")
            assigned = assign_locked(db, device_id, exam_id if mode == "exam" else None)
            results.append({"deviceId": device_id, "status": "pending" if assigned != active else "unchanged"})
        except ValueError as error:
            results.append({"deviceId": device_id, "status": "blocked", "reason": str(error)})
    return results


TEACHER_ACTIONS = {
    "list": set(), "details": {"deviceId"}, "bind": {"deviceId", "student"}, "move": {"deviceId", "destination"},
    "exam": {"devices"}, "normal": {"devices"}, "guest": {"deviceId", "target", "checks"},
    "submit": {"deviceId", "target"}, "dismiss": {"deviceId", "target"},
}


def teacher_dispatch(db_path, owner_uid, expected_version, uid, request):
    if not isinstance(request, dict):
        raise ValueError("Недопустимая команда TUI")
    action = request.get("action")
    if (
        not isinstance(action, str) or action not in TEACHER_ACTIONS
        or request.keys() != {"action", "examId", "version"} | TEACHER_ACTIONS[action]
        or not valid_code(IDENTIFIER, request["examId"]) or request["version"] != expected_version
    ):
        raise ValueError("Недопустимая команда TUI")
    if action == "dismiss" and uid != owner_uid:
        raise PermissionError("Снятие тревоги доступно владельцу")
    exam_id, version = request["examId"], request["version"]
    if exam_id.startswith(FILE_TRACE_EXAM_PREFIX) and uid != owner_uid:
        raise PermissionError("Файловая диагностика доступна владельцу")
    read_only = action in ("list", "details")
    try:
        with closing(connect(db_path, read_only=read_only)) as db, db:
            db.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
            return teacher_command(db, uid, owner_uid, exam_id, version, action, request, utc_now())
    except sqlite3.Error:
        raise ValueError("База контроллера недоступна") from None


def teacher_command(db, uid, owner_uid, exam_id, version, action, request, now):
    if action == "list":
        devices = db.execute("SELECT * FROM devices ORDER BY device_id")
        return {"owner": uid == owner_uid, "places": [teacher_snapshot(db, device, exam_id, version, now) for device in devices]}
    if action in ("exam", "normal"):
        selected = request["devices"]
        if selected != "*" and (
            not isinstance(selected, list) or not 1 <= len(selected) <= 100
            or any(not valid_code(IDENTIFIER, device_id) for device_id in selected) or len(set(selected)) != len(selected)
        ):
            raise ValueError("Укажите номера зарегистрированных ПК или * для всех мест выбранного экзамена")
        return group_assign(db, exam_id, action, selected, now)
    device_id = request["deviceId"]
    device = device_row(db, device_id) if valid_code(IDENTIFIER, device_id) else None
    if device is None:
        raise ValueError("ПК не зарегистрирован")
    if action == "details":
        return teacher_snapshot(db, device, exam_id, version, now, details=True)
    place = get_place(db, device_id, exam_id)
    if action == "bind":
        student = request["student"]
        if not valid_text(student, 100):
            raise ValueError("Укажите ФИО без управляющих символов")
        if not place or place["student"] != student:
            db.execute("""INSERT INTO exam_places (exam_id, device_id, student) VALUES (?, ?, ?)
                       ON CONFLICT (exam_id, device_id) DO UPDATE SET student = excluded.student, submission = NULL""",
                       (exam_id, device_id, student))
            reset_place_confirmation(db, device_id, exam_id)
        return {"student": student}
    if action == "move":
        destination = request["destination"]
        if not valid_code(IDENTIFIER, destination) or not device_row(db, destination) or not place:
            raise ValueError("Проверьте исходное и новое место")
        if get_place(db, destination, exam_id):
            raise ValueError("На новом месте уже есть студент")
        db.execute("UPDATE exam_places SET device_id = ?, submission = NULL WHERE device_id = ? AND exam_id = ?",
                   (destination, device_id, exam_id))
        for moved in (device_id, destination):
            reset_place_confirmation(db, moved, exam_id)
        return {"student": place["student"], "deviceId": destination}

    target = request["target"]
    target_fields = ALERT_TARGET_FIELDS if action == "dismiss" else SESSION_FIELDS
    if (
        not isinstance(target, dict) or target.keys() != set(target_fields)
        or type(target["revision"]) is not int or not 1 <= target["revision"] <= MAX_REVISION
        or not valid_utc(target["bootUtc"]) or not valid_code(IDENTIFIER, target["guestSessionId"])
        or (action == "dismiss" and not valid_code(UUID, target["alertId"]))
    ):
        raise ValueError("Недопустимая привязка текущего сеанса")
    if action == "dismiss":
        return request_acknowledgement(db, device, exam_id, target, uid, now)
    if not place:
        raise ValueError("Сначала укажите студента на этом месте")
    selected_guest(db, device, exam_id, target, now)
    if action == "guest":
        if request["checks"] != ["file", "project", "wazuh"]:
            raise ValueError("Подтвердите файловый запрет, проект и Wazuh")
        return confirm_guest_locked(db, device_id, target["revision"], target["bootUtc"], target["guestSessionId"])
    snapshot = device_status(db, device, now, READINESS_TIMEOUT)
    if not snapshot["readiness"]["guestReady"]:
        raise ValueError("Сначала подтвердите место и текущий сеанс Guest")
    receipt = {**target, "confirmedUtc": iso_utc(now), "confirmedByUid": uid}
    db.execute("UPDATE exam_places SET submission = ? WHERE device_id = ? AND exam_id = ?",
               (json.dumps(receipt), device_id, exam_id))
    return receipt


DIAGNOSTICS_PATH = "/install/diagnostics"
MAX_DIAGNOSTICS_BODY = 8 * 1024 * 1024
MAX_DIAGNOSTICS_STORAGE = 128 * 1024 * 1024
MAX_DIAGNOSTICS_REPORTS = 256
FILE_TRACE_PATH = "/exam/v1/file-trace"
FILE_TRACE_CHUNK = 1024 * 1024
FILE_TRACE_IDLE_SECONDS = 120
FILE_TRACE_TOTAL_SECONDS = 120 * 60
FILE_TRACE_DISK_RESERVE = 128 * 1024 * 1024
FILE_TRACE_DIGEST = re.compile(r"[0-9A-Fa-f]{64}")
FILE_TRACE_LENGTH = re.compile(r"[1-9][0-9]{0,19}")
FILE_TRACE_REVISION = re.compile(r"[1-9][0-9]{0,9}")


class FileTraceError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = status


def file_trace_authorized(db, device_id, token, revision):
    authenticated_device(db, device_id, token)
    assigned = db.execute(
        "SELECT exam_id FROM assignments WHERE device_id = ? AND revision = ?", (device_id, revision),
    ).fetchone()
    exam_id = assigned["exam_id"] if assigned else None
    return exam_id is not None and exam_id.startswith(FILE_TRACE_EXAM_PREFIX)


def private_trace_directory(metadata):
    return stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid == os.geteuid()


def new_enrollment_device(db, device):
    current = current_assignment(db, device["device_id"])
    return device["last_seen"] is None and current == {"revision": 1, "mode": "normal", "examId": None}


def enrollment_receipt(path, db):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
            raise ValueError("Файл регистрации должен принадлежать контроллеру и иметь права 0600")
        contents = source.read(MAX_ENROLLMENT_RECEIPT + 1)
    try:
        if len(contents) > MAX_ENROLLMENT_RECEIPT:
            raise ValueError
        receipt = json.loads(contents, object_pairs_hook=unique_keys)
        if not isinstance(receipt, dict) or receipt.keys() != {"network", "registration", "wazuhKey"}:
            raise ValueError
        network = receipt["network"]
        reg = receipt["registration"]
        if not isinstance(reg, dict) or reg.keys() != {"url", "deviceId", "token"}:
            raise ValueError
        if (
            not valid_code(IDENTIFIER, reg["deviceId"]) or not isinstance(reg["token"], str)
            or not valid_code(BEARER, f"Bearer {reg['token']}")
        ):
            raise ValueError
        url = urlsplit(reg["url"])
        if (
            url.scheme != "https" or url.path != POLL_PATH or url.query or url.fragment
            or url.username is not None or not url.hostname
            or network["ControllerEndpoint"] != {"IP": url.hostname, "Port": url.port or 443}
            or network["WazuhEndpoint"]["Port"] != 1514
            or not ENROLLMENT_KEY.fullmatch(base64.b64decode(receipt["wazuhKey"], validate=True))
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("Недопустимый формат серверного файла регистрации") from None
    device = authenticated_device(db, reg["deviceId"], reg["token"])
    if not new_enrollment_device(db, device):
        raise ValueError("Для окна регистрации требуется новый ПК в исходном обычном режиме")
    return receipt


class EnrollmentSlot:
    def __init__(self, path):
        self.path = path
        self.state = path / "receipt.json"

    @contextmanager
    def locked(self):
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not private_trace_directory(os.fstat(directory)):
                raise ValueError("Каталог регистрации должен принадлежать контроллеру и иметь права 0700")
            fcntl.flock(directory, fcntl.LOCK_EX)
            yield directory
        finally:
            os.close(directory)

    def write(self, directory, state):
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path, delete=False) as stream:
            staging = Path(stream.name)
            try:
                json.dump(state, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
                staging.replace(self.state)
                os.fsync(directory)
            finally:
                staging.unlink(missing_ok=True)

    def arm(self, receipts, expires, *, replace_unclaimed=False):
        devices = {receipt["registration"]["deviceId"] for receipt in receipts}
        if not devices or len(devices) != len(receipts):
            raise ValueError("Для каждого места нужна отдельная регистрация ПК")
        expires = iso_utc(expires.astimezone(timezone.utc))
        if expires <= iso_utc(utc_now()):
            raise ValueError("Срок регистрации уже истёк")
        self.path.mkdir(mode=0o700, exist_ok=True)
        with self.locked() as directory:
            if self.state.exists():
                previous = self.read()
                if previous["expiresUtc"] > iso_utc(utc_now()) and (
                    not replace_unclaimed or any(place["claimDigest"] for place in previous["places"])
                ):
                    raise ValueError("Окно регистрации уже открыто. Закройте его перед заменой мест")
            self.write(directory, {
                "expiresUtc": expires,
                "places": [{"claimDigest": None, "receipt": receipt} for receipt in receipts],
            })

    def read(self):
        state = json.loads(self.state.read_text(encoding="utf-8"))
        if "places" not in state:
            state["places"] = [{"claimDigest": state.pop("claimDigest"), "receipt": state.pop("receipt")}]
        state["expiresUtc"] = iso_utc(datetime.fromisoformat(state["expiresUtc"]).astimezone(timezone.utc))
        return state

    def disarm(self):
        if not self.path.exists():
            return
        with self.locked() as directory:
            self.state.unlink(missing_ok=True)
            os.fsync(directory)

    def claim(self, claim, db):
        try:
            with self.locked() as directory:
                state = self.read()
                if state["expiresUtc"] <= iso_utc(utc_now()):
                    self.state.unlink()
                    os.fsync(directory)
                    return HTTPStatus.GONE, {"error": "enrollment-expired"}
                digest = token_digest(claim).hex()
                claimed = next((place for place in state["places"] if place["claimDigest"] and
                                secrets.compare_digest(place["claimDigest"], digest)), None)
                place = claimed or next((place for place in state["places"] if place["claimDigest"] is None), None)
                if place is None:
                    return HTTPStatus.CONFLICT, {"error": "enrollment-already-claimed"}
                registration = place["receipt"]["registration"]
                device = authenticated_device(db, registration["deviceId"], registration["token"])
                if claimed is None:
                    if not new_enrollment_device(db, device):
                        return HTTPStatus.GONE, {"error": "enrollment-unavailable"}
                    place["claimDigest"] = digest
                    self.write(directory, state)
                return HTTPStatus.OK, place["receipt"]
        except FileNotFoundError:
            return HTTPStatus.NOT_FOUND, {"error": "enrollment-closed"}


class FileTraceStore:
    def __init__(self, path):
        self.path = path

    def available(self):
        try:
            return private_trace_directory(self.path.lstat())
        except FileNotFoundError:
            return False

    def check_capacity(self, length):
        volume = os.statvfs(self.path)
        if length + FILE_TRACE_DISK_RESERVE > volume.f_bavail * volume.f_frsize:
            raise FileTraceError(HTTPStatus.INSUFFICIENT_STORAGE, "file-trace-capacity")

    def copy_and_check(self, incoming, set_timeout, length, digest, archive=None):
        checksum = hashlib.sha256()
        deadline = monotonic() + FILE_TRACE_TOTAL_SECONDS
        remaining = length
        while remaining:
            seconds_left = deadline - monotonic()
            if seconds_left <= 0:
                raise TimeoutError
            set_timeout(min(FILE_TRACE_IDLE_SECONDS, seconds_left))
            chunk = incoming.read1(min(FILE_TRACE_CHUNK, remaining))
            if not chunk:
                raise FileTraceError(HTTPStatus.BAD_REQUEST, "incomplete-body")
            if archive is not None:
                self.check_capacity(len(chunk))
                archive.write(chunk)
            checksum.update(chunk)
            remaining -= len(chunk)
        if not secrets.compare_digest(checksum.hexdigest(), digest):
            raise FileTraceError(HTTPStatus.BAD_REQUEST, "file-trace-digest-mismatch")

    def already_sealed(self, final, digest, length):
        if not final.exists():
            return False
        try:
            stored = (final / f"{digest}.zip").lstat()
        except FileNotFoundError:
            raise FileTraceError(HTTPStatus.CONFLICT, "file-trace-already-sealed") from None
        if not stat.S_ISREG(stored.st_mode) or stat.S_IMODE(stored.st_mode) != 0o600 or stored.st_size != length:
            raise FileTraceError(HTTPStatus.CONFLICT, "file-trace-already-sealed")
        return True

    def save(self, device_id, revision, digest, incoming, set_timeout, length):
        report_id = hashlib.sha256(f"file-trace:v1:{device_id}:{revision}".encode("ascii")).hexdigest()[:32]
        final = self.path / report_id
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not private_trace_directory(os.fstat(directory)):
                raise FileTraceError(HTTPStatus.NOT_FOUND, "not-found")
            if self.already_sealed(final, digest, length):
                self.copy_and_check(incoming, set_timeout, length, digest)
                os.fsync(directory)
                return HTTPStatus.OK, report_id

            self.check_capacity(length)
            with TemporaryDirectory(prefix=".incoming-", dir=self.path) as staging_path:
                staging = Path(staging_path)
                descriptor = os.open(staging / f"{digest}.zip", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                with os.fdopen(descriptor, "w+b") as archive:
                    self.copy_and_check(incoming, set_timeout, length, digest, archive)
                    archive.seek(0)
                    if archive.read(4) not in (b"PK\x03\x04", b"PK\x05\x06") or not is_zipfile(archive):
                        raise FileTraceError(HTTPStatus.BAD_REQUEST, "invalid-zip")
                    os.fsync(archive.fileno())
                staging_dir = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(staging_dir)
                    try:
                        staging.rename(final)
                    except OSError as error:
                        if error.errno not in (errno.EEXIST, errno.ENOTEMPTY) or not self.already_sealed(final, digest, length):
                            raise
                        os.fsync(directory)
                        return HTTPStatus.OK, report_id
                    os.fsync(directory)
                finally:
                    os.close(staging_dir)
            return HTTPStatus.CREATED, report_id
        finally:
            os.close(directory)


class DiagnosticStore:
    def __init__(self, path):
        self.path = path
        self.lock = Lock()

    def available(self):
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return False
        return (
            stat.S_ISDIR(metadata.st_mode)
            and not metadata.st_mode & 0o077
            and metadata.st_uid == os.geteuid()
        )

    def save(self, body):
        with self.lock:
            archives = [entry.stat() for entry in self.path.glob("*.zip")]
            if (
                len(archives) >= MAX_DIAGNOSTICS_REPORTS
                or sum(entry.st_size for entry in archives) + len(body) > MAX_DIAGNOSTICS_STORAGE
            ):
                return None
            report_id = uuid4().hex
            temporary = self.path / f".{report_id}.tmp"
            try:
                descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.rename(self.path / f"{report_id}.zip")
            finally:
                temporary.unlink(missing_ok=True)
            return report_id


class ControllerHTTPServer(ThreadingHTTPServer):
    # Клиенты одного экзамена могут начать выгрузку одновременно после normal.
    request_queue_size = 128


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

    def trusted_proxy(self):
        token = getattr(self.server, "teacher_proxy_token", None)
        proof = self.headers.get_all(TEACHER_PROXY_HEADER, [])
        return (
            token is not None and len(proof) == 1 and valid_code(TEACHER_PROXY_TOKEN, proof[0])
            and secrets.compare_digest(token, proof[0])
        )

    def do_GET(self):
        if self.path != TEACHER_PATH or not self.trusted_proxy():
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
        if self.path == ENROLLMENT_PATH:
            self.receive_enrollment()
            return
        if self.path == DIAGNOSTICS_PATH:
            self.receive_diagnostics()
            return
        if self.path == FILE_TRACE_PATH:
            self.receive_file_trace()
            return
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
            device_id, result, readiness, client = parse_poll(body)
            with closing(connect(self.server.db_path)) as db, db:
                response = poll(db, device_id, bearer[1], result, readiness, client)
        except RequestError as error:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except PermissionError:
            self.reply(HTTPStatus.UNAUTHORIZED, {"error": "invalid-credentials"})
        except sqlite3.Error:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "database-unavailable"})
        else:
            self.reply(HTTPStatus.OK, response)

    def receive_enrollment(self):
        if not self.trusted_proxy():
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,3}", lengths[0]) or "Transfer-Encoding" in self.headers:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid-content-length"})
            return
        length = int(lengths[0])
        if length > 512:
            self.reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body-too-large"})
            return
        if self.headers.get_content_type() != "application/json":
            self.reply(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "invalid-content-type"})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise RequestError("incomplete-body")
            try:
                payload = json.loads(body, object_pairs_hook=unique_keys)
            except (ValueError, RecursionError):
                raise RequestError("invalid-json") from None
            if not isinstance(payload, dict) or payload.keys() != {"claim"} or not valid_code(ENROLLMENT_CLAIM, payload["claim"]):
                raise RequestError("invalid-enrollment-claim")
            with closing(connect(self.server.db_path, read_only=True)) as db:
                status_code, response = EnrollmentSlot(self.server.db_path.parent / "windows-enrollment").claim(payload["claim"], db)
        except RequestError as error:
            status_code, response = HTTPStatus.BAD_REQUEST, {"error": str(error)}
        except TimeoutError:
            status_code, response = HTTPStatus.REQUEST_TIMEOUT, {"error": "enrollment-timeout"}
        except PermissionError:
            status_code, response = HTTPStatus.GONE, {"error": "enrollment-unavailable"}
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError):
            status_code, response = HTTPStatus.SERVICE_UNAVAILABLE, {"error": "enrollment-unavailable"}
        self.reply(status_code, response)

    def receive_file_trace(self):
        def exact_header(name):
            values = self.headers.get_all(name, [])
            return values[0] if len(values) == 1 else None

        try:
            store = getattr(self.server, "file_trace_store", None)
            if store is None or not store.available():
                raise FileTraceError(HTTPStatus.NOT_FOUND, "not-found")
            authorization = exact_header("Authorization")
            bearer = BEARER.fullmatch(authorization) if authorization else None
            if bearer is None:
                raise FileTraceError(HTTPStatus.UNAUTHORIZED, "invalid-credentials")
            device_id = exact_header("X-ExamLab-Device")
            revision = exact_header("X-ExamLab-Revision")
            digest = exact_header("X-ExamLab-Trace-Sha256")
            if (
                not valid_code(IDENTIFIER, device_id) or not valid_code(FILE_TRACE_REVISION, revision)
                or int(revision) > MAX_REVISION or not valid_code(FILE_TRACE_DIGEST, digest)
            ):
                raise FileTraceError(HTTPStatus.BAD_REQUEST, "invalid-file-trace-headers")
            length = exact_header("Content-Length")
            if not valid_code(FILE_TRACE_LENGTH, length) or "Transfer-Encoding" in self.headers:
                raise FileTraceError(HTTPStatus.BAD_REQUEST, "invalid-content-length")
            if exact_header("Content-Type") is None or self.headers.get_content_type() != "application/zip":
                raise FileTraceError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "invalid-content-type")
            revision = int(revision)
            with closing(connect(self.server.db_path, read_only=True)) as db:
                try:
                    allowed = file_trace_authorized(db, device_id, bearer[1], revision)
                except PermissionError as error:
                    raise FileTraceError(HTTPStatus.UNAUTHORIZED, "invalid-credentials") from error
            if not allowed:
                raise FileTraceError(HTTPStatus.FORBIDDEN, "file-trace-assignment-required")
            status, report_id = store.save(device_id, revision, digest.lower(), self.rfile, self.connection.settimeout, int(length))
            answer = {"reportId": report_id}
        except FileTraceError as error:
            status, answer = error.status, {"error": str(error)}
        except TimeoutError:
            status, answer = HTTPStatus.REQUEST_TIMEOUT, {"error": "file-trace-timeout"}
        except sqlite3.Error:
            status, answer = HTTPStatus.SERVICE_UNAVAILABLE, {"error": "database-unavailable"}
        except OSError as error:
            if error.errno in (errno.ENOSPC, errno.EDQUOT):
                status, answer = HTTPStatus.INSUFFICIENT_STORAGE, {"error": "file-trace-capacity"}
            else:
                status, answer = HTTPStatus.SERVICE_UNAVAILABLE, {"error": "file-trace-unavailable"}
        try:
            self.connection.settimeout(5)
            self.reply(status, answer)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def receive_diagnostics(self):
        store = getattr(self.server, "diagnostics_store", None)
        if store is None or not store.available():
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,12}", lengths[0]) or "Transfer-Encoding" in self.headers:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid-content-length"})
            return
        length = int(lengths[0])
        if length > MAX_DIAGNOSTICS_BODY:
            self.reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body-too-large"})
            return
        if self.headers.get_content_type() != "application/zip":
            self.reply(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "invalid-content-type"})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length or not body.startswith(b"PK\x03\x04") or not is_zipfile(BytesIO(body)):
                self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid-zip"})
                return
            report_id = store.save(body)
        except OSError:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "diagnostics-unavailable"})
            return
        if report_id is None:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "diagnostics-capacity"})
            return
        self.reply(HTTPStatus.CREATED, {"reportId": report_id})


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
    serve_cmd.add_argument("--teacher-socket", type=Path, metavar="PATH")
    serve_cmd.add_argument("--teacher-version", metavar="VERSION")
    serve_cmd.add_argument("--owner-uid", type=int, metavar="UID")
    serve_cmd.add_argument("--teacher-uid", type=int, action="append", default=[], metavar="UID")
    for command in ("register", "rotate-token", "assign", "status", "confirm-guest"):
        commands.add_parser(command).add_argument("device_id")
    arm = commands.add_parser("arm-enrollment", help="Открыть регистрацию подготовленных ПК")
    arm.add_argument("--receipt", required=True, action="append", type=Path, metavar="PATH")
    arm.add_argument("--minutes", type=int, default=20, choices=range(5, 61), metavar="MINUTES")
    commands.add_parser("close-enrollment", help="Закрыть окно регистрации и удалить временные данные")
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
    if command == "serve" and (
        bool(args.teacher_socket) != (args.owner_uid is not None)
        or (args.teacher_socket and not valid_code(VERSION, args.teacher_version))
        or (args.teacher_socket is None and (args.teacher_uid or args.teacher_version is not None))
        or (args.teacher_socket and any(not 1 <= uid < 4_294_967_295 for uid in (args.owner_uid, *args.teacher_uid)))
    ):
        parser.error("Для Unix-сокета TUI задайте версию комплекта, ненулевой UID владельца и, при необходимости, UID преподавателей")
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
            db.executescript(SCHEMA if command == "register" else READINESS_SCHEMA + CAMPAIGN_SCHEMA)
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
            elif command in ("arm-enrollment", "close-enrollment"):
                slot = EnrollmentSlot(path.parent / "windows-enrollment")
                if command == "arm-enrollment":
                    receipts = [enrollment_receipt(path, db) for path in args.receipt]
                    slot.arm(receipts, utc_now() + timedelta(minutes=args.minutes))
                    result = f"Регистрация открыта. Подготовлено мест: {len(receipts)}"
                else:
                    slot.disarm()
                    result = "Окно регистрации закрыто"
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
            teacher = nullcontext()
            if args.teacher_socket:
                try:
                    owner_name = pwd.getpwuid(args.owner_uid).pw_name
                except KeyError:
                    raise ValueError("Локальная учётная запись владельца TUI не найдена") from None
                if not valid_code(IDENTIFIER, owner_name):
                    raise ValueError("Недопустимое имя учётной записи владельца TUI")
                teacher = serve_teacher(
                    args.teacher_socket, (args.owner_uid, *args.teacher_uid),
                    lambda uid, request: teacher_dispatch(path, args.owner_uid, args.teacher_version, uid, request),
                )
            with ControllerHTTPServer(("127.0.0.1", args.port), PollHandler) as server, teacher:
                server.db_path = path
                server.diagnostics_store = DiagnosticStore(path.parent / "diagnostics")
                server.file_trace_store = FileTraceStore(path.parent / "file-traces")
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
