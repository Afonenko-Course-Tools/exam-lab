from contextlib import closing
import hashlib
from http.client import HTTPConnection
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
from socket import AF_UNIX, SOCK_STREAM, socket
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic, sleep
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from server import (
    FILE_TRACE_CHUNK, FILE_TRACE_PATH, POLL_PATH, SCHEMA, ControllerHTTPServer, FileTraceStore, PollHandler,
    assign, connect, register, teacher_dispatch,
)
from teacher_access import serve_teacher


def archive_with(payload):
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("file-trace.csv", payload)
    return stream.getvalue()


class FileTraceTest(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.db_path = Path(scratch.name) / "controller.sqlite3"
        self.store_path = self.db_path.parent / "file-traces"
        self.zip = archive_with(b"timestamp,operation,path\n")
        with closing(connect(self.db_path, create=True)) as db, db:
            db.executescript(SCHEMA)
            self.token = register(db, "pc-01")
        with closing(connect(self.db_path)) as db, db:
            self.other_token = register(db, "pc-02")
        self.server = ControllerHTTPServer(("127.0.0.1", 0), PollHandler)
        self.server.db_path = self.db_path
        self.server.file_trace_store = FileTraceStore(self.store_path)
        self.thread = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02})
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def set_assignment(self, exam_id, device_id="pc-01"):
        with closing(connect(self.db_path)) as db, db:
            return assign(db, device_id, exam_id)["revision"]

    def enable(self):
        self.store_path.mkdir(mode=0o700)
        return self.set_assignment("file-trace-probe")

    def headers(self, body, revision, **overrides):
        return {
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/zip",
            "X-ExamLab-Device": "pc-01", "X-ExamLab-Revision": str(revision),
            "X-ExamLab-Trace-Sha256": hashlib.sha256(body).hexdigest(), **overrides,
        }

    def request(self, method, path, body=None, headers=None):
        with closing(HTTPConnection(*self.server.server_address, timeout=3)) as client:
            client.request(method, path, body, headers or {})
            response = client.getresponse()
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            return response.status, json.loads(response.read())

    def upload(self, body, revision, **overrides):
        return self.request("POST", FILE_TRACE_PATH, body, self.headers(body, revision, **overrides))

    def poll(self):
        return self.request("POST", POLL_PATH, b'{"deviceId":"pc-01","result":null}', {
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
        })

    def test_explicit_private_directory_required_and_no_download_route(self):
        revision = self.set_assignment("file-trace-probe")
        self.assertEqual(404, self.upload(self.zip, revision)[0])
        substitute = self.store_path.with_name("other")
        substitute.mkdir(mode=0o700)
        self.store_path.symlink_to(substitute, target_is_directory=True)
        self.assertEqual(404, self.upload(self.zip, revision)[0])
        self.store_path.unlink()
        self.store_path.mkdir(mode=0o755)
        self.assertEqual(404, self.upload(self.zip, revision)[0])
        self.store_path.chmod(0o700)
        self.assertEqual(201, self.upload(self.zip, revision)[0])
        self.assertEqual(404, self.request("GET", FILE_TRACE_PATH)[0])
        self.assertEqual(200, self.poll()[0])

    def test_device_token_and_exact_historical_assignment(self):
        historical_revision = self.enable()
        standard_exam = self.set_assignment("regular-exam")
        normal_revision = self.set_assignment(None)
        self.set_assignment("regular-exam-b", device_id="pc-02")
        self.assertEqual(401, self.upload(self.zip, historical_revision, Authorization="invalid")[0])
        self.assertEqual(401, self.upload(self.zip, historical_revision, Authorization=f"Bearer {self.other_token}")[0])
        self.assertEqual(403, self.upload(self.zip, historical_revision, **{
            "Authorization": f"Bearer {self.other_token}", "X-ExamLab-Device": "pc-02",
        })[0])
        for revision in (standard_exam, normal_revision, normal_revision + 1):
            self.assertEqual((403, {"error": "file-trace-assignment-required"}), self.upload(self.zip, revision))
        self.assertEqual([], list(self.store_path.iterdir()))
        self.assertEqual(201, self.upload(self.zip, historical_revision)[0])
        self.assertEqual(normal_revision, self.poll()[1]["revision"])

    def test_streams_and_seals_one_archive_with_exact_idempotence(self):
        revision = self.enable()
        body = archive_with(b"x" * (FILE_TRACE_CHUNK + 4096))
        digest = hashlib.sha256(body).hexdigest()
        header = {"X-ExamLab-Trace-Sha256": digest.upper()}
        status, response = self.upload(body, revision, **header)
        self.assertEqual(201, status)
        report_id = response["reportId"]
        self.assertRegex(report_id, r"^[a-f0-9]{32}$")
        saved = self.store_path / report_id / f"{digest}.zip"
        self.assertEqual(body, saved.read_bytes())
        self.assertEqual(0o600, saved.stat().st_mode & 0o777)
        self.assertEqual(0o700, saved.parent.stat().st_mode & 0o777)
        self.assertEqual((200, response), self.upload(body, revision))

        forged = archive_with(b"y" * (FILE_TRACE_CHUNK + 4096))
        self.assertEqual((400, {"error": "file-trace-digest-mismatch"}), self.upload(forged, revision, **header))
        self.assertEqual((409, {"error": "file-trace-already-sealed"}), self.upload(self.zip, revision))
        self.assertEqual([saved.parent], list(self.store_path.iterdir()))
        self.assertEqual(body, saved.read_bytes())

    def test_rejects_bad_metadata_digest_zip_and_capacity_without_residue(self):
        revision = self.enable()
        self.assertEqual(400, self.upload(self.zip, revision, **{"X-ExamLab-Device": "../../foo/bar"})[0])
        self.assertEqual(400, self.upload(self.zip, f"0{revision}")[0])
        self.assertEqual(400, self.upload(self.zip, 2147483648)[0])
        self.assertEqual(400, self.upload(self.zip, revision, **{"Transfer-Encoding": "chunked"})[0])
        self.assertEqual(415, self.upload(self.zip, revision, **{"Content-Type": "application/octet-stream"})[0])
        self.assertEqual((400, {"error": "invalid-zip"}), self.upload(b"PK\x03\x04not-a-zip", revision))
        self.assertEqual((400, {"error": "file-trace-digest-mismatch"}), self.upload(self.zip, revision, **{
            "X-ExamLab-Trace-Sha256": "0" * 64,
        }))
        with patch("server.FILE_TRACE_DISK_RESERVE", shutil.disk_usage(self.store_path).free):
            self.assertEqual((507, {"error": "file-trace-capacity"}), self.upload(self.zip, revision))
        self.assertEqual([], list(self.store_path.iterdir()))
        self.assertEqual(201, self.upload(self.zip, revision)[0])

    def test_idle_upload_leaves_another_seat_and_poll_responsive(self):
        revision = self.enable()
        other_revision = self.set_assignment("file-trace-probe", device_id="pc-02")
        with patch("server.FILE_TRACE_IDLE_SECONDS", 1), closing(HTTPConnection(*self.server.server_address, timeout=3)) as stalled:
            stalled.putrequest("POST", FILE_TRACE_PATH)
            for name, value in self.headers(self.zip, revision).items():
                stalled.putheader(name, value)
            stalled.putheader("Content-Length", str(len(self.zip)))
            stalled.endheaders()
            deadline = monotonic() + 0.7
            while not list(self.store_path.glob(".incoming-*")) and monotonic() < deadline:
                sleep(0.01)
            self.assertTrue(list(self.store_path.glob(".incoming-*")))
            status, received = self.upload(self.zip, other_revision, **{
                "Authorization": f"Bearer {self.other_token}", "X-ExamLab-Device": "pc-02",
            })
            self.assertEqual(201, status)
            self.assertEqual(200, self.poll()[0])
            response = stalled.getresponse()
            self.assertEqual(408, response.status)
            self.assertEqual({"error": "file-trace-timeout"}, json.loads(response.read()))
        self.assertEqual([self.store_path / received["reportId"]], list(self.store_path.iterdir()))
        self.assertEqual(201, self.upload(self.zip, revision)[0])

    def test_owner_only_scope_enforced_on_raw_teacher_socket(self):
        version = "0.2.0-test"
        uid = os.getuid()
        owner_uid = uid + 1
        socket_path = self.db_path.parent / "teacher.sock"
        def request_peer(exam_id, action, **fields):
            request = {"action": action, "examId": exam_id, "version": version, **fields}
            with socket(AF_UNIX, SOCK_STREAM) as peer:
                peer.settimeout(2)
                peer.connect(os.fspath(socket_path))
                peer.sendall(json.dumps(request).encode("utf-8") + b"\n")
                with peer.makefile("rb") as response:
                    return json.loads(response.readline())

        dispatch = lambda peer_uid, request: teacher_dispatch(self.db_path, owner_uid, version, peer_uid, request)
        with serve_teacher(socket_path, (uid,), dispatch):
            for action, fields in (
                ("list", {}), ("details", {"deviceId": "pc-01"}), ("bind", {"deviceId": "pc-01", "student": "Проба"}),
                ("exam", {"devices": ["pc-01"]}), ("normal", {"devices": ["pc-01"]}),
            ):
                with self.subTest(action=action):
                    self.assertIn("владельцу", request_peer("file-trace-probe", action, **fields)["error"])
            self.assertEqual(1, self.poll()[1]["revision"])
            ordinary = request_peer("ordinary-exam", "exam", devices=["pc-02"])
            self.assertEqual("pending", ordinary["result"][0]["status"])
            self.assertIn("places", request_peer("ordinary-exam", "list")["result"])
        dispatch_owner = lambda peer_uid, request: teacher_dispatch(self.db_path, uid, version, peer_uid, request)
        with serve_teacher(socket_path, (uid,), dispatch_owner):
            self.assertIn("places", request_peer("file-trace-probe", "list")["result"])
            assigned = request_peer("file-trace-probe", "exam", devices=["pc-01"])
            self.assertEqual("pending", assigned["result"][0]["status"])
