from contextlib import closing
from datetime import timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from server import (
    MAX_BODY, POLL_PATH, SCHEMA, PollHandler,
    assign, connect, iso_utc, register, status, utc_now,
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

    def send(self, payload, token=None, *, path=POLL_PATH):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        with closing(HTTPConnection(*self.server.server_address, timeout=2)) as client:
            client.request("POST", path, payload, headers)
            response = client.getresponse()
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            return response.status, json.loads(response.read())

    def poll(self, result=None, *, device_id="pc-01", token=None):
        return self.send(json.dumps({"deviceId": device_id, "result": result}), token or self.token)

    def assign(self, exam_id):
        with closing(connect(self.path)) as db, db:
            return assign(db, "pc-01", exam_id)

    def status(self, device_id="pc-01"):
        with closing(connect(self.path)) as db, db:
            return status(db, device_id, 45)

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


if __name__ == "__main__":
    unittest.main()
