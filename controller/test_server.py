import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta, timezone
from http.client import HTTPConnection, RemoteDisconnected
from http.server import ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from server import (
    DIAGNOSTIC_ENROLLMENT_SCHEMA, DIAGNOSTICS_PATH, ENROLLMENT_PATH, MAX_BODY, MAX_DIAGNOSTICS_BODY,
    POLL_PATH, SCHEMA, TEACHER_PATH, TEACHER_PROXY_HEADER,
    DiagnosticEnrollment, DiagnosticStore, EnrollmentSlot, PollHandler, WazuhEnrollment, WazuhEnrollmentError,
    assign, confirm_guest, connect, enrollment_receipt,
    iso_utc, parse_utc, read_teacher_proxy_token, readiness_table, register, status, utc_now,
)


class ControllerTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "controller.sqlite3"
        with closing(connect(self.path, create=True)) as db, db:
            db.executescript(SCHEMA)
            self.token = register(db, "pc-01")
        self.start_server()
        self.addCleanup(self.stop_server)

    def start_server(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), PollHandler)
        self.server.db_path = self.path
        self.thread = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02})
        self.thread.start()

    def stop_server(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def send(self, payload, token=None, *, path=POLL_PATH, headers=None, source_ip=None):
        headers = {"Content-Type": "application/json; charset=utf-8", **(headers or {})}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        source_address = (source_ip, 0) if source_ip else None
        with closing(HTTPConnection(*self.server.server_address, timeout=2, source_address=source_address)) as client:
            client.request("POST", path, payload, headers)
            response = client.getresponse()
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            return response.status, json.loads(response.read())

    def poll(self, result=None, *, device_id="pc-01", token=None, readiness=None):
        payload = {"deviceId": device_id, "result": result}
        if readiness is not None:
            payload["readiness"] = readiness
        return self.send(json.dumps(payload), token or self.token)

    def get(self, path=TEACHER_PATH, *, headers=None):
        with closing(HTTPConnection(*self.server.server_address, timeout=2)) as client:
            client.request("GET", path, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("utf-8")

    def enable_teacher_panel(self):
        self.server.teacher_proxy_token = "a" * 64
        return {TEACHER_PROXY_HEADER: self.server.teacher_proxy_token}

    def assign(self, exam_id):
        with closing(connect(self.path)) as db, db:
            return assign(db, "pc-01", exam_id)

    def status(self, device_id="pc-01"):
        with closing(connect(self.path)) as db, db:
            return status(db, device_id, 45)

    def confirm(self, readiness):
        with closing(connect(self.path)) as db, db:
            return confirm_guest(db, "pc-01", readiness["revision"], readiness["bootUtc"], readiness["guestSessionId"])

    def clock(self, timestamp):
        clock = patch("server.utc_now", return_value=parse_utc(timestamp))
        self.addCleanup(clock.stop)
        return clock.start()

    def test_registration_assignment_and_restart(self):
        self.assertEqual("never", self.status()["connection"])
        self.assertEqual((200, {"deviceId": "pc-01", "revision": 1, "mode": "normal", "examId": None}), self.poll())
        exam = self.assign("exam-a")
        self.assertEqual(2, exam["revision"])
        self.assertEqual(exam, self.assign("exam-a"))
        self.assertEqual((200, {"deviceId": "pc-01", **exam}), self.poll())
        self.assertEqual(3, self.assign(None)["revision"])
        self.assertEqual(3, self.assign(None)["revision"])
        with self.assertRaises(ValueError):
            self.assign("exam-a")
        self.stop_server()
        self.start_server()
        self.assertEqual(3, self.poll()[1]["revision"])
        self.assertEqual(4, self.assign("exam-b")["revision"])

    def test_authentication_and_token_rotation(self):
        with closing(connect(self.path)) as db, db:
            second_token = register(db, "pc-02")
        self.assertEqual(401, self.poll(device_id="pc-02")[0])
        self.assertEqual(401, self.poll(token=second_token)[0])
        self.assertEqual(401, self.send(b"{}", token=None)[0])
        self.assertEqual("never", self.status()["connection"])
        self.assertEqual("never", self.status("pc-02")["connection"])
        exam = self.assign("exam-a")
        with closing(connect(self.path)) as db, db:
            new_token = register(db, "pc-01", rotate=True)
        self.assertEqual(401, self.poll()[0])
        self.assertEqual((200, {"deviceId": "pc-01", **exam}), self.poll(token=new_token))
        self.assertEqual(200, self.poll(device_id="pc-02", token=second_token)[0])

    def test_windows_enrollment_is_proxy_only_and_replays_same_claim(self):
        receipt = {
            "network": {
                "ProxyEndpointIP": "192.0.2.10", "ProxyEndpointPort": 3128, "TechnicalAccess": [],
                "ControllerEndpoint": {"IP": "192.0.2.10", "Port": 21650},
                "WazuhEndpoint": {"IP": "192.0.2.10", "Port": 1514},
            },
            "registration": {"url": "https://192.0.2.10:21650/exam/v1/poll", "deviceId": "pc-01", "token": self.token},
            "wazuhKey": base64.b64encode(b"002 pc-01 any " + b"b" * 64).decode(),
        }
        path = self.path.parent / "registration.json"
        path.touch(mode=0o600)
        path.write_text(json.dumps(receipt), encoding="utf-8")
        slot = EnrollmentSlot(self.path.parent / "windows-enrollment")
        with closing(connect(self.path)) as db:
            validated = enrollment_receipt(path, db)
        slot.path.mkdir(mode=0o700)
        with slot.locked() as directory:
            slot.write(directory, {
                "receipt": validated, "claimDigest": None,
                "expiresUtc": iso_utc(utc_now() + timedelta(minutes=20)),
            })
        claim = json.dumps({"claim": "f" * 64})
        proof = self.enable_teacher_panel()
        self.assertEqual(404, self.send(claim, path=ENROLLMENT_PATH)[0])
        self.assertEqual((200, receipt), self.send(claim, path=ENROLLMENT_PATH, headers=proof))
        self.assertEqual(200, self.poll()[0])
        self.assertEqual((200, receipt), self.send(claim, path=ENROLLMENT_PATH, headers=proof))
        other = json.dumps({"claim": "e" * 64})
        self.assertEqual(409, self.send(other, path=ENROLLMENT_PATH, headers=proof)[0])
        slot.disarm()
        self.assertEqual(404, self.send(claim, path=ENROLLMENT_PATH, headers=proof)[0])

    def test_windows_enrollment_ten_concurrent_places_and_retries(self):
        receipts = [{"registration": {"deviceId": "pc-01", "token": self.token}}]
        with closing(connect(self.path)) as db:
            for number in range(2, 11):
                device_id = f"pc-{number:02}"
                with db:
                    token = register(db, device_id)
                receipts.append({"registration": {"deviceId": device_id, "token": token}})
        slot = EnrollmentSlot(self.path.parent / "windows-enrollment")
        expires = (utc_now() + timedelta(minutes=20)).astimezone(timezone(timedelta(hours=3)))
        slot.arm(receipts, expires)
        self.assertEqual(iso_utc(expires.astimezone(timezone.utc)), json.loads(slot.state.read_text())["expiresUtc"])
        headers = self.enable_teacher_panel()

        def enroll(number):
            claim = json.dumps({"claim": f"{number:064x}"})
            return self.send(claim, path=ENROLLMENT_PATH, headers=headers)

        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(enroll, [0, 0, *range(1, 10)]))
        self.assertEqual(results[0], results[1])
        allocations = [results[0], *results[2:]]
        self.assertEqual([200] * 10, [code for code, _ in allocations])
        self.assertCountEqual([receipt for _, receipt in allocations], receipts)
        self.assertEqual((409, {"error": "enrollment-already-claimed"}), enroll(10))
        self.assertEqual(results[0], enroll(0))

    def test_diagnostics_before_enrollment_and_duplicate_at_capacity(self):
        self.server.db_path = self.path.parent / "unused.sqlite3"
        directory = self.path.parent / "diagnostics"
        self.server.diagnostics_store = DiagnosticStore(directory)
        headers = {"Content-Type": "application/zip"}

        def zip_body(content):
            buffer = BytesIO()
            with ZipFile(buffer, "w") as archive:
                archive.writestr("attempt/child-error.txt", content)
            return buffer.getvalue()

        body = zip_body(b"raw diagnostic bytes\0\xff")
        self.assertEqual(404, self.send(body, path=DIAGNOSTICS_PATH, headers=headers)[0])
        directory.mkdir(mode=0o700)
        self.assertEqual(400, self.send(body[:8], path=DIAGNOSTICS_PATH, headers=headers)[0])
        self.assertEqual(415, self.send(body, path=DIAGNOSTICS_PATH)[0])
        oversized = {**headers, "Content-Length": str(MAX_DIAGNOSTICS_BODY + 1)}
        self.assertEqual(413, self.send(b"", path=DIAGNOSTICS_PATH, headers=oversized)[0])
        with patch("server.MAX_DIAGNOSTICS_STORAGE", len(body)):
            first = self.send(body, path=DIAGNOSTICS_PATH, headers=headers)
            self.assertEqual(201, first[0])
            self.assertRegex(first[1]["reportId"], r"\A[0-9a-f]{32}\Z")
            self.assertEqual(first, self.send(body, path=DIAGNOSTICS_PATH, headers=headers))
            self.assertEqual(
                (503, {"error": "diagnostics-capacity"}),
                self.send(zip_body(b"different"), path=DIAGNOSTICS_PATH, headers=headers),
            )
        stored = list(directory.iterdir())
        self.assertEqual([f"{first[1]['reportId']}.zip"], [file.name for file in stored])
        self.assertEqual(body, stored[0].read_bytes())
        self.assertEqual(0o600, stored[0].stat().st_mode & 0o777)
        self.assertEqual(404, self.get(DIAGNOSTICS_PATH)[0])
        self.assertFalse(self.server.db_path.exists())

    def test_diagnostic_enrollment_two_clients_loss_replay_and_addressed_revocation(self):
        path = self.path.parent / "empty.sqlite3"
        with closing(connect(path, create=True)) as db, db:
            db.executescript(SCHEMA + DIAGNOSTIC_ENROLLMENT_SCHEMA)
            self.assertEqual(0, db.execute("SELECT count(*) FROM devices").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT count(*) FROM exam_places").fetchone()[0])
        wazuh = Mock(spec=WazuhEnrollment)

        def issue_key(name):
            key = f"{wazuh.get_or_create.call_count:03d} {name} any {name.removeprefix('diag-') * 2}"
            return base64.b64encode(key.encode("ascii")).decode("ascii")

        wazuh.get_or_create.side_effect = issue_key
        network = {
            "ControllerEndpoint": {"IP": "192.0.2.10", "Port": 21650},
            "WazuhEndpoint": {"IP": "192.0.2.10", "Port": 1514},
        }
        url = "https://192.0.2.10:21650/exam/v1/poll"
        self.server.db_path = path
        pilot = DiagnosticEnrollment(path.parent, url, network, wazuh)
        self.server.diagnostic_enrollment = pilot
        headers = self.enable_teacher_panel()

        def enroll(number, *, source_ip=None):
            claim = json.dumps({"claim": f"{number:064x}"})
            return self.send(claim, path=ENROLLMENT_PATH, headers=headers, source_ip=source_ip)

        # Ответ потерян после успешной записи. Следующий вызов приходит с другого адреса.
        with patch.object(PollHandler, "reply", return_value=None):
            with self.assertRaises(RemoteDisconnected):
                enroll(1, source_ip="127.0.0.1")
        self.assertEqual(1, wazuh.get_or_create.call_count)
        self.stop_server()
        self.start_server()
        self.server.db_path = path
        pilot = DiagnosticEnrollment(path.parent, url, network, wazuh)
        self.server.diagnostic_enrollment = pilot
        headers = self.enable_teacher_panel()
        first = enroll(1, source_ip="127.0.0.2")
        self.assertEqual(200, first[0])
        self.assertEqual(1, wazuh.get_or_create.call_count)
        second = enroll(2, source_ip="127.0.0.1")
        self.assertEqual(200, second[0])
        self.assertNotEqual(first[1]["wazuhKey"], second[1]["wazuhKey"])
        first_registration, second_registration = (receipt[1]["registration"] for receipt in (first, second))
        self.assertNotEqual(first_registration["deviceId"], second_registration["deviceId"])
        self.assertNotEqual(first_registration["token"], second_registration["token"])
        for registration in (first_registration, second_registration):
            device_id, token = registration["deviceId"], registration["token"]
            self.assertEqual((200, {"deviceId": device_id, "revision": 1, "mode": "normal", "examId": None}),
                             self.poll(device_id=device_id, token=token))
        self.assertEqual(first, enroll(1, source_ip="127.0.0.2"))
        with closing(connect(path)) as db, db:
            self.assertEqual(2, db.execute("SELECT count(*) FROM devices").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT count(*) FROM exam_places").fetchone()[0])
        with closing(connect(path)) as db, db:
            assign(db, first_registration["deviceId"], "isolated-exam")
        wazuh.revoke.side_effect = [WazuhEnrollmentError(), None]
        with closing(connect(path)) as db, self.assertRaises(WazuhEnrollmentError):
            pilot.revoke(first_registration["deviceId"], db)
        self.assertEqual((410, {"error": "diagnostic-enrollment-revoked"}), enroll(1))
        self.assertEqual(401, self.poll(device_id=first_registration["deviceId"], token=first_registration["token"])[0])
        self.assertEqual(second, enroll(2))
        with closing(connect(path)) as db, db:
            self.assertEqual("normal", status(db, first_registration["deviceId"], 45)["assignment"]["mode"])
        with closing(connect(path)) as db:
            pilot.revoke(first_registration["deviceId"], db)
        self.assertEqual([(first_registration["deviceId"],)] * 2, [entry.args for entry in wazuh.revoke.call_args_list])

    def test_wazuh_recovers_existing_named_agent_and_revokes_only_its_id(self):
        wazuh = object.__new__(WazuhEnrollment)
        wazuh.authorization = "Basic test"
        name = "diag-" + "a" * 32
        key = base64.b64encode(f"021 {name} any {'b' * 64}".encode()).decode()
        authorize = {"token": "test.token.value"}
        match = {"affected_items": [{"id": "021", "name": name}]}
        with patch.object(wazuh, "request", side_effect=[authorize, {"affected_items": []}, WazuhEnrollmentError(),
                                                         authorize, match, {"affected_items": [{"id": "021", "key": key}]},
                                                         authorize, match, {"affected_items": ["021"]}]) as request:
            with self.assertRaises(WazuhEnrollmentError):
                wazuh.get_or_create(name)
            self.assertEqual(key, wazuh.get_or_create(name))
            wazuh.revoke(name)
            self.assertEqual(("POST", "/agents", "Bearer test.token.value", {"name": name, "ip": "any"}),
                             request.call_args_list[2].args)
            self.assertEqual(("GET", "/agents/021/key", "Bearer test.token.value"), request.call_args_list[5].args)
            self.assertEqual(("DELETE", "/agents?agents_list=021&status=all&older_than=0s&purge=true", "Bearer test.token.value"),
                             request.call_args_list[8].args)

    def test_report_order_override_and_connection_age(self):
        normal = self.assign(None)
        exam = self.assign("exam-a")
        applied = {
            **exam, "outcome": "applied", "reason": None, "fullReady": True,
            "observedUtc": "2026-11-19T14:03:25.123Z",
        }
        self.assertEqual(200, self.poll(applied)[0])
        report = self.status()["latestReport"]
        self.assertEqual(applied["observedUtc"], report["observedUtc"])
        self.assertEqual(report, self.status()["lastApplied"])
        self.assertEqual(200, self.poll(applied)[0])
        self.assertEqual(report, self.status()["latestReport"])
        earlier = {**applied, **normal, "observedUtc": "2026-11-19T14:05:25.123Z"}
        self.assertEqual(200, self.poll(earlier)[0])
        self.assertEqual(report, self.status()["latestReport"])
        self.assertEqual(report, self.status()["lastApplied"])
        overridden = {
            **applied, "outcome": "overridden", "reason": "local-normal", "fullReady": False,
            "observedUtc": "2026-11-19T14:04:25.123Z",
        }
        self.assertEqual(200, self.poll(overridden)[0])
        self.assertEqual(200, self.poll(applied)[0])
        snapshot = self.status()
        self.assertEqual("overridden", snapshot["latestReport"]["outcome"])
        self.assertEqual("applied", snapshot["lastApplied"]["outcome"])
        self.assertEqual("fresh", snapshot["connection"])
        with closing(connect(self.path)) as db, db:
            seen = iso_utc(utc_now() - timedelta(seconds=90))
            db.execute("UPDATE devices SET last_seen = ?", (seen,))
        snapshot = self.status()
        self.assertEqual("stale", snapshot["connection"])
        self.assertGreaterEqual(snapshot["connectionAgeSeconds"], 90)
        self.assertEqual("overridden", snapshot["latestReport"]["outcome"])

    def test_invalid_report_preserves_state(self):
        exam = self.assign("exam-a")
        before = self.status()
        report = {
            **exam, "outcome": "blocked", "reason": "full-not-ready", "fullReady": False,
            "observedUtc": "2026-11-19T14:03:25.123Z",
        }
        for invalid in (
            {"examId": "exam-b"}, {"revision": 3}, {"revision": True},
            {"observedUtc": "2026-02-30T14:03:25.123Z"}, {"fullReady": 0},
            {"fullReady": True}, {"outcome": "applied", "reason": None},
        ):
            with self.subTest(invalid=invalid):
                code, response = self.poll({**report, **invalid})
                self.assertEqual(400, code)
                self.assertEqual({"error"}, response.keys())
        for bad_body in (b"{", b'{"deviceId":"pc-01","result":null,"result":null}',
                         b'{"deviceId":"pc-01","result":{"mode":"normal","mode":"exam"}}'):
            response = self.send(bad_body, self.token)
            self.assertEqual((400, {"error": "invalid-json"}), response)
        self.assertEqual((413, {"error": "body-too-large"}), self.send(b" " * (MAX_BODY + 1), self.token))
        self.assertEqual(404, self.send(b"{}", self.token, path="/register")[0])
        self.assertEqual(before, self.status())
        self.assertEqual(200, self.poll(report)[0])
        self.assertEqual("blocked", self.status()["latestReport"]["outcome"])
        self.assertIsNone(self.status()["lastApplied"])

    def test_readiness_follows_current_assignment_boot_and_guest(self):
        clock = self.clock("2026-11-19T14:00:16.000Z")
        exam = self.assign("exam-a")
        report = {
            **exam, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": "2026-11-19T14:00:05.000Z",
        }
        first = {
            "revision": exam["revision"], "bootUtc": "2026-11-19T14:00:00.000Z",
            "observedUtc": "2026-11-19T14:00:15.000Z", "machineReady": True, "guestSessionId": None,
        }
        self.assertEqual(200, self.poll(report)[0])
        self.assertFalse(self.status()["readiness"]["machineReady"])
        self.assertEqual((200, {"deviceId": "pc-01", **exam}), self.poll(report, readiness=first))
        self.assertTrue(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        with self.assertRaises(ValueError):
            self.confirm(first)

        guest_a = {**first, "guestSessionId": "guest-a", "observedUtc": "2026-11-19T14:00:30.000Z"}
        clock.return_value = parse_utc(guest_a["observedUtc"])
        self.assertEqual(200, self.poll(report, readiness=guest_a)[0])
        with self.assertRaises(ValueError):
            self.confirm({**guest_a, "guestSessionId": "guest-b"})
        approval = self.confirm(guest_a)
        self.assertTrue(self.status()["readiness"]["guestReady"])
        self.stop_server()
        self.start_server()
        self.assertTrue(self.status()["readiness"]["guestReady"])
        with closing(connect(self.path)) as db, db:
            table = readiness_table(db)
        for label in ("Можно входить", "Можно начинать", "guest-a", approval["confirmedUtc"]):
            self.assertIn(label, table)

        empty = {**guest_a, "guestSessionId": None, "observedUtc": "2026-11-19T14:00:45.000Z"}
        clock.return_value = parse_utc(empty["observedUtc"])
        self.assertEqual(200, self.poll(report, readiness=empty)[0])
        self.assertEqual(200, self.poll(report, readiness=guest_a)[0])  # Запоздалый пакет.
        self.assertIsNone(self.status()["readiness"]["guestSessionId"])
        same_logon = {**guest_a, "observedUtc": "2026-11-19T14:01:00.000Z"}
        clock.return_value = parse_utc(same_logon["observedUtc"])
        self.assertEqual(200, self.poll(report, readiness=same_logon)[0])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        self.confirm(same_logon)
        guest_b = {**guest_a, "guestSessionId": "guest-b", "observedUtc": "2026-11-19T14:01:15.000Z"}
        clock.return_value = parse_utc(guest_b["observedUtc"])
        self.assertEqual(200, self.poll(report, readiness=guest_b)[0])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        approval = self.confirm(guest_b)

        reboot = {**guest_b, "bootUtc": "2026-11-19T14:02:00.000Z", "observedUtc": "2026-11-19T14:02:15.000Z"}
        clock.return_value = parse_utc(reboot["observedUtc"])
        self.assertEqual(200, self.poll(report, readiness=reboot)[0])
        self.assertFalse(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        fresh_report = {**report, "observedUtc": "2026-11-19T14:02:20.000Z"}
        reboot["observedUtc"] = "2026-11-19T14:02:30.000Z"
        clock.return_value = parse_utc(reboot["observedUtc"])
        self.assertEqual(200, self.poll(fresh_report, readiness=reboot)[0])
        self.assertTrue(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])

        next_exam = self.assign("exam-b")
        self.assertEqual((200, {"deviceId": "pc-01", **next_exam}), self.poll(report, readiness=guest_b))
        status = self.status()["readiness"]
        self.assertFalse(status["machineReady"])
        self.assertFalse(status["guestReady"])
        self.assertIsNone(status["guestSessionId"])
        self.assertEqual(approval, status["lastGuestConfirmation"])

    def test_readiness_expires_even_with_legacy_polls_and_requires_new_approval(self):
        exam = self.assign("exam-a")
        report = {
            **exam, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": "2026-11-19T14:00:05.000Z",
        }
        evidence = {
            "revision": exam["revision"], "bootUtc": "2026-11-19T14:00:00.000Z",
            "observedUtc": "2026-11-19T14:00:15.000Z", "machineReady": True, "guestSessionId": "guest-a",
        }
        now = parse_utc("2026-11-19T14:00:16.000Z")
        with patch("server.utc_now", return_value=now) as clock:
            self.assertEqual(200, self.poll(report, readiness=evidence)[0])
            self.confirm(evidence)
            before = self.status()["readiness"]
            self.assertTrue(before["guestReady"])
            clock.return_value = now + timedelta(seconds=45)
            self.assertEqual("stale", self.status()["connection"])
            self.assertEqual(200, self.poll(report)[0])
            self.assertEqual(200, self.poll(report, readiness=evidence)[0])
            stale = self.status()
            self.assertEqual("fresh", stale["connection"])
            self.assertFalse(stale["readiness"]["machineReady"])
            self.assertFalse(stale["readiness"]["guestReady"])
            self.assertEqual(before["lastMachineConfirmation"], stale["readiness"]["lastMachineConfirmation"])
            self.assertEqual(before["lastGuestConfirmation"], stale["readiness"]["lastGuestConfirmation"])
            with self.assertRaises(ValueError):
                self.confirm(evidence)
            self.assertEqual(200, self.poll(report, readiness={**evidence, "observedUtc": iso_utc(clock.return_value)})[0])
            self.assertTrue(self.status()["readiness"]["machineReady"])
            self.assertFalse(self.status()["readiness"]["guestReady"])
            self.confirm(evidence)
            self.assertTrue(self.status()["readiness"]["guestReady"])

    def test_bad_readiness_and_local_normal_cannot_create_positive_status(self):
        self.clock("2026-11-19T14:00:45.000Z")
        exam = self.assign("exam-a")
        report = {
            **exam, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": "2026-11-19T14:00:05.000Z",
        }
        evidence = {
            "revision": exam["revision"], "bootUtc": "2026-11-19T14:00:00.000Z",
            "observedUtc": "2026-11-19T14:00:15.000Z", "machineReady": True, "guestSessionId": "guest-a",
        }
        before = self.status()
        for bad in ({"revision": 3}, {"machineReady": 1}, {"guestSessionId": "имя"}, {"bootUtc": "2026-11-19T14:00:20.000Z"}):
            with self.subTest(bad=bad):
                reply = self.poll(report, readiness={**evidence, **bad})
                self.assertEqual((400, {"error": "invalid-readiness"}), reply)
        self.assertEqual(401, self.poll(report, readiness=evidence, token="x" * 43)[0])
        self.assertEqual(before, self.status())
        self.assertEqual(200, self.poll({**report, "reason": "effective-readback-pending"}, readiness=evidence)[0])
        self.assertFalse(self.status()["readiness"]["machineReady"])
        report["observedUtc"] = "2026-11-19T14:00:20.000Z"
        evidence["observedUtc"] = "2026-11-19T14:00:30.000Z"
        self.assertEqual(200, self.poll(report, readiness=evidence)[0])
        self.confirm(evidence)
        error = {**report, "outcome": "error", "reason": "machine-apply-failed", "observedUtc": "2026-11-19T14:00:31.000Z"}
        self.assertEqual(200, self.poll(error)[0])
        report["observedUtc"] = "2026-11-19T14:00:32.000Z"
        self.assertEqual(200, self.poll(report)[0])
        self.assertFalse(self.status()["readiness"]["machineReady"])
        evidence["observedUtc"] = "2026-11-19T14:00:33.000Z"
        self.assertEqual(200, self.poll(report, readiness=evidence)[0])
        self.assertTrue(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        self.confirm(evidence)
        overridden = {
            **report, "outcome": "overridden", "reason": "local-normal", "observedUtc": "2026-11-19T14:00:35.000Z",
        }
        self.assertEqual(200, self.poll(overridden)[0])
        self.assertEqual(200, self.poll(report, readiness={**evidence, "observedUtc": "2026-11-19T14:00:45.000Z"})[0])
        self.assertFalse(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])

    def test_delayed_or_future_observation_does_not_extend_readiness(self):
        clock = self.clock("2026-11-19T14:00:15.000Z")
        exam = self.assign("exam-a")
        report = {
            **exam, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": "2026-11-19T14:00:05.000Z",
        }
        evidence = {
            "revision": exam["revision"], "bootUtc": "2026-11-19T14:00:00.000Z",
            "observedUtc": "2026-11-19T14:00:15.000Z", "machineReady": True, "guestSessionId": "guest-a",
        }
        self.assertEqual(200, self.poll(report, readiness=evidence)[0])
        self.confirm(evidence)
        confirmed = self.status()["readiness"]

        clock.return_value = parse_utc("2026-11-19T14:01:06.000Z")
        for observed in ("2026-11-19T14:00:20.000Z", "2026-11-19T14:01:12.000Z"):
            with self.subTest(observed=observed):
                self.assertEqual(200, self.poll(report, readiness={**evidence, "observedUtc": observed})[0])
                stale = self.status()["readiness"]
                self.assertFalse(stale["machineReady"])
                self.assertFalse(stale["guestReady"])
                self.assertEqual(confirmed["lastObservationUtc"], stale["lastObservationUtc"])
                with self.assertRaises(ValueError):
                    self.confirm(evidence)
        future = {**report, "observedUtc": "2026-11-19T14:02:00.000Z"}
        self.assertEqual(200, self.poll(future, readiness={**evidence, "observedUtc": future["observedUtc"]})[0])
        self.assertEqual(200, self.poll(future)[0])
        self.assertEqual(report["observedUtc"], self.status()["latestReport"]["observedUtc"])

        # Предыдущая версия могла сохранить отчёт с часами, ушедшими вперёд.
        with closing(connect(self.path)) as db, db:
            db.execute("UPDATE devices SET latest_report = ?", (json.dumps(future),))

        borderline = {**evidence, "observedUtc": "2026-11-19T14:00:22.000Z"}
        self.assertEqual(200, self.poll(report, readiness=borderline)[0])
        self.assertTrue(self.status()["readiness"]["machineReady"])
        self.assertFalse(self.status()["readiness"]["guestReady"])
        confirmation = self.confirm(borderline)
        clock.return_value += timedelta(seconds=1)
        stale = self.status()["readiness"]
        self.assertFalse(stale["machineReady"])
        self.assertFalse(stale["guestReady"])
        self.assertEqual(confirmation, stale["lastGuestConfirmation"])

    def test_teacher_panel_shows_status_and_last_confirmation(self):
        proof = self.enable_teacher_panel()
        clock = self.clock("2026-11-19T14:00:15.000Z")
        exam = self.assign("exam-a")
        report = {
            **exam, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": "2026-11-19T14:00:05.000Z",
        }
        evidence = {
            "revision": exam["revision"], "bootUtc": "2026-11-19T14:00:00.000Z",
            "observedUtc": "2026-11-19T14:00:15.000Z", "machineReady": True, "guestSessionId": "opaque-guest-id",
        }
        self.assertEqual(200, self.poll(report, readiness=evidence)[0])
        status_code, headers, panel = self.get(headers={**proof, "Authorization": f"Bearer {self.token}"})
        self.assertEqual(200, status_code)
        self.assertEqual("text/html; charset=utf-8", headers["Content-Type"])
        self.assertEqual("ru", headers["Content-Language"])
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn('<meta http-equiv="refresh" content="5">', panel)
        self.assertIn("Можно входить", panel)
        self.assertIn("Можно начинать", panel)
        self.assertIn("<td>Есть</td><td>Да</td><td>Нет</td>", panel)
        self.assertNotIn(self.token, panel)
        self.assertNotIn(proof[TEACHER_PROXY_HEADER], panel)
        self.assertNotIn(evidence["guestSessionId"], panel)

        confirmation = self.confirm(evidence)
        self.assertIn("<td>Есть</td><td>Да</td><td>Да</td>", self.get(headers=proof)[2])
        clock.return_value += timedelta(seconds=45)
        panel = self.get(headers=proof)[2]
        self.assertIn("<td>Нет связи</td><td>Нет</td><td>Нет</td>", panel)
        self.assertIn(confirmation["confirmedUtc"], panel)
        self.assertEqual(404, self.send(b"{}", self.token, path=TEACHER_PATH)[0])
        self.assertEqual(404, self.get(POLL_PATH)[0])
        self.assertEqual(404, self.get(TEACHER_PATH + "/")[0])

    def test_teacher_panel_escapes_stored_label(self):
        # Старая БД может содержать метку, записанную вне интерфейса контроллера.
        unsafe = '<a href="https://example.invalid">ссылка</a>'
        with closing(connect(self.path)) as db, db:
            db.execute("UPDATE assignments SET exam_id = ?", (unsafe,))
        status_code, _, panel = self.get(headers=self.enable_teacher_panel())
        self.assertEqual(200, status_code)
        self.assertNotIn(unsafe, panel)
        self.assertIn("&lt;a href=&quot;https://example.invalid&quot;&gt;ссылка&lt;/a&gt;", panel)

    def test_teacher_panel_requires_exact_proxy_proof_even_on_loopback(self):
        proof = {TEACHER_PROXY_HEADER: "a" * 64}
        self.assertEqual(404, self.get(headers=proof)[0])
        self.enable_teacher_panel()
        for headers in (None, {TEACHER_PROXY_HEADER: "b" * 64}, {"Authorization": f"Bearer {self.token}"}):
            self.assertEqual(404, self.get(headers=headers)[0])
        query = TEACHER_PATH + "?token=" + proof[TEACHER_PROXY_HEADER]
        status_code, _, response = self.get(query, headers=proof)
        self.assertEqual(404, status_code)
        self.assertEqual({"error": "not-found"}, json.loads(response))
        with closing(HTTPConnection(*self.server.server_address, timeout=2)) as client:
            client.putrequest("GET", TEACHER_PATH)
            client.putheader(TEACHER_PROXY_HEADER, proof[TEACHER_PROXY_HEADER])
            client.putheader(TEACHER_PROXY_HEADER, proof[TEACHER_PROXY_HEADER])
            client.endheaders()
            self.assertEqual(404, client.getresponse().status)
        self.assertEqual(200, self.get(headers=proof)[0])
        self.assertEqual(200, self.poll()[0])

    def test_teacher_proxy_token_requires_private_file_and_exact_format(self):
        path = self.path.parent / "teacher-proxy-token"
        token = "a" * 64
        path.write_text(token + "\n", encoding="ascii")
        path.chmod(0o600)
        self.assertEqual(token, read_teacher_proxy_token(path))
        path.chmod(0o640)
        with self.assertRaises(ValueError):
            read_teacher_proxy_token(path)
        path.chmod(0o600)
        path.write_text(token + "\n\n", encoding="ascii")
        with self.assertRaises(ValueError):
            read_teacher_proxy_token(path)


if __name__ == "__main__":
    unittest.main()
