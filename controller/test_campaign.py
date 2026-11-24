import asyncio
from contextlib import closing
from datetime import timedelta
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event
from unittest import TestCase
from unittest.mock import patch

from textual.widgets import Button, Input, Static

from server import (
    READINESS_TIMEOUT, SCHEMA, assign, connect, iso_utc, parse_poll, parse_utc, poll, register, teacher_dispatch,
)
from teacher_access import serve_teacher
from tui import ConfirmDialog, ExamTUI, GroupDialog, PlaceDialog, call


class CampaignTest(TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name) / "controller.db"
        self.owner = os.getuid()
        self.teacher = self.owner + 1
        self.version = "0.2.0-test"
        self.exam = "java-pilot"
        self.clock = patch("server.utc_now", return_value=parse_utc("2026-11-23T12:00:15.000Z")).start()
        self.addCleanup(patch.stopall)
        self.boot = "2026-11-23T12:00:00.000Z"
        self.installation = {"version": self.version, "completedUtc": self.boot}
        self.alert_id = "33333333-3333-4444-8111-333333333333"
        self.session = "a" * 64
        with closing(connect(self.path, create=True)) as db, db:
            db.executescript(SCHEMA)
            self.token = register(db, "pc-01")
        with closing(connect(self.path)) as db, db:
            self.second_token = register(db, "pc-02")

    def advance(self, seconds):
        self.clock.return_value += timedelta(seconds=seconds)

    def action(self, action, *, uid=None, exam=None, version=None, **fields):
        request = {"action": action, "examId": exam or self.exam, "version": version or self.version, **fields}
        return teacher_dispatch(self.path, self.owner, self.version, self.owner if uid is None else uid, request)

    def current(self):
        return self.action("details", deviceId="pc-01")

    def send(self, result=None, *, guest="unknown", session=None, alert=None, install=None, boot=None, legacy=False):
        readiness = None if result is None else {
            "revision": result["revision"], "bootUtc": boot or self.boot, "observedUtc": iso_utc(self.clock.return_value),
            "machineReady": result["outcome"] == "source-applied" and result["mode"] == "exam",
            "guestSessionId": session,
        }
        body = {"deviceId": "pc-01", "result": result}
        if readiness:
            body["readiness"] = readiness
        if not legacy:
            body["client"] = {"guestState": guest, "alert": alert, "installation": install}
        with closing(connect(self.path)) as db, db:
            device_id, result, readiness, client = parse_poll(json.dumps(body).encode())
            return poll(db, device_id, self.token, result, readiness, client)

    def assign(self, exam=None):
        response = self.action("exam", exam=exam, devices=["pc-01"])
        self.assertEqual("pending", response[0]["status"])
        return self.current()["device"]["assignment"]

    def applied(self, assignment):
        return {
            **assignment, "outcome": "source-applied", "reason": "machine-policies-only", "fullReady": False,
            "observedUtc": iso_utc(self.clock.return_value),
        }

    def alert(self, phase="received", **fields):
        return {
            "alertId": self.alert_id, "revision": self.current()["device"]["assignment"]["revision"],
            "bootUtc": self.boot, "guestSessionId": self.session, "reason": "control-signal", "phase": phase,
            "receivedUtc": iso_utc(self.clock.return_value), "shownUtc": None, "acknowledgedUtc": None,
            "acknowledgedBy": None, "acknowledgementId": None, **fields,
        }

    def present_alert(self):
        report = self.applied(self.assign())
        alert = self.alert()
        self.send(report, guest="present", session=self.session, alert=alert)
        target = {key: alert[key] for key in ("revision", "bootUtc", "guestSessionId", "alertId")}
        return report, alert, target

    def test_owner_dismiss_is_bound_to_guest_revision_boot_alert_and_device(self):
        report, alert, target = self.present_alert()
        self.assertEqual("received", self.current()["alert"]["status"])
        with self.assertRaises(PermissionError):
            self.action("dismiss", uid=self.teacher, deviceId="pc-01", target=target)
        with self.assertRaises(ValueError):
            self.action("dismiss", deviceId="pc-02", target=target)
        for field, value in (("revision", 1), ("bootUtc", "2026-11-23T11:00:00.000Z"),
                             ("guestSessionId", "other"), ("alertId", "11111111-1111-1111-1111-111111111111")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.action("dismiss", deviceId="pc-01", target={**target, field: value})
        self.advance(1)
        alert = {**alert, "phase": "shown", "shownUtc": iso_utc(self.clock.return_value)}
        self.send(report, guest="present", session=self.session, alert=alert)
        self.assertEqual("shown", self.current()["alert"]["status"])
        issued = self.action("dismiss", deviceId="pc-01", target=target)
        self.assertEqual(pwd.getpwuid(self.owner).pw_name, issued["owner"])
        self.assertEqual("requested", self.current()["alert"]["status"])
        with self.assertRaises(ValueError):
            self.action("dismiss", deviceId="pc-01", target=target)
        self.assertNotIn("alertAcknowledgement", self.send(report, guest="present", session=self.session, alert=alert))
        self.advance(1)
        first = self.send(report, guest="present", session=self.session, alert=alert)["alertAcknowledgement"]
        self.advance(1)
        again = self.send(report, guest="present", session=self.session, alert=alert)["alertAcknowledgement"]
        self.assertEqual(first, again)
        self.assertEqual(issued["acknowledgementId"], first["acknowledgementId"])
        acknowledged_utc = iso_utc(self.clock.return_value)
        self.advance(1)
        self.assertNotIn("alertAcknowledgement", self.send(report, guest="present", session="guest-b", alert=alert))
        self.assertEqual("session-ended", self.current()["alerts"][0]["status"])
        receipt = {
            **alert, "phase": "acknowledged", "acknowledgedUtc": acknowledged_utc,
            "acknowledgedBy": issued["owner"], "acknowledgementId": issued["acknowledgementId"],
        }
        self.advance(1)
        self.send(report, guest="present", session="guest-b", alert={**receipt, "acknowledgedBy": "wrong-owner"})
        self.assertEqual("session-ended", self.current()["alerts"][0]["status"])
        self.advance(1)
        self.assertNotIn("alertAcknowledgement", self.send(report, guest="present", session="guest-b", alert=receipt))
        self.assertEqual("acknowledged", self.current()["alerts"][0]["status"])
        self.assertFalse(self.current()["alerts"][0]["current"])

    def test_stale_observation_and_expired_dismiss_do_not_issue(self):
        report, alert, target = self.present_alert()
        self.advance(READINESS_TIMEOUT)
        with self.assertRaises(ValueError):
            self.action("dismiss", deviceId="pc-01", target=target)
        self.send(self.applied(self.current()["device"]["assignment"]), guest="present", session=self.session, alert=alert)
        issued = self.action("dismiss", deviceId="pc-01", target=target)
        self.advance(91)
        newer = {**report, "observedUtc": iso_utc(self.clock.return_value)}
        self.assertNotIn("alertAcknowledgement", self.send(newer, guest="present", session=self.session, alert=alert))
        self.assertEqual("expired", self.current()["alerts"][0]["status"])
        self.assertLess(issued["expiresUtc"], iso_utc(self.clock.return_value))

    def test_group_keeps_offline_distinct_and_normal_requires_submitted_guest_exit(self):
        self.send(install=self.installation)
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        self.action("bind", deviceId="pc-02", student="Второй Студент")
        group = self.action("exam", devices="*")
        self.assertEqual(["pending", "pending"], [row["status"] for row in group])
        repeat = self.action("exam", devices="*")
        self.assertEqual(["unchanged", "unchanged"], [row["status"] for row in repeat])
        active = self.current()["device"]["assignment"]
        self.advance(1)
        report = self.applied(active)
        self.send(report, guest="present", session=self.session, install=self.installation)
        fifth = self.action("list")["places"]
        self.assertEqual(["source-applied", "offline"], [row["reportStatus"] for row in fifth])
        self.assertEqual("installed", fifth[0]["installation"]["status"])
        target = {"revision": active["revision"], "bootUtc": self.boot, "guestSessionId": self.session}
        self.assertEqual("blocked", self.action("normal", devices=["pc-01"])[0]["status"])
        with self.assertRaises(ValueError):
            self.action("submit", deviceId="pc-01", target=target)
        self.action("guest", deviceId="pc-01", target=target, checks=["file", "project", "wazuh"])
        self.action("submit", deviceId="pc-01", target=target)
        self.advance(1)
        self.send(report, guest="unknown")
        self.assertEqual("Выход Guest не подтверждён", self.action("normal", devices=["pc-01"])[0]["reason"])
        self.advance(1)
        self.send(report, guest="absent")
        result = self.action("normal", devices="*", targets={"pc-01": target})
        self.assertEqual(["pending", "blocked"], [row["status"] for row in result])
        self.assertEqual("normal", self.send(report)["mode"])

    def test_group_wildcard_excludes_other_registrations_and_previous_assignments(self):
        self.assertEqual([], self.action("exam", devices="*"))
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        self.action("exam", devices=["pc-02"])
        for device_id in ("old-free", "old-assigned", "old-finished"):
            with closing(connect(self.path)) as db, db:
                register(db, device_id)
        with closing(connect(self.path)) as db, db:
            assign(db, "old-assigned", "past-exam")
        with closing(connect(self.path)) as db, db:
            assign(db, "old-finished", self.exam)
        with closing(connect(self.path)) as db, db:
            assign(db, "old-finished", None)
        for action in ("exam", "normal"):
            self.assertEqual(["pc-01", "pc-02"], [row["deviceId"] for row in self.action(action, devices="*")])
        self.assertEqual("pending", self.action("exam", devices=["old-free"])[0]["status"])

    def run_tui(self, scenario, owner_uid=None, *, file_trace_exam=None, manual_pilot=False, observe=None):
        socket_path = self.path.parent / "tui.sock"
        args = type("Arguments", (), {
            "socket": socket_path, "exam": self.exam, "version": self.version,
            "file_trace_exam": file_trace_exam, "manual_pilot": manual_pilot,
        })
        if owner_uid is None:
            owner_uid = self.owner
        def dispatch(uid, request):
            if observe:
                observe(request)
            return teacher_dispatch(self.path, owner_uid, self.version, uid, request)
        with serve_teacher(socket_path, (self.owner,), dispatch):
            asyncio.run(scenario(ExamTUI(args)))

    def test_tui_mouse_group_live_keyboard_and_resize(self):
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        self.action("exam", devices=["pc-02"])
        for n in range(3, 35):
            with closing(connect(self.path)) as db, db:
                register(db, f"pc-{n:02d}")
        self.action("exam", exam="old-exam", devices=["pc-03"])

        async def exercise(app):
            app.POLL_SECONDS = 0.3
            async with app.run_test(size=(80, 24)) as pilot:
                await app.workers.wait_for_complete()
                self.assertEqual("pc-01", app.cursor_device())
                self.assertEqual("textual-light", app.theme)
                self.assertFalse(app.query("#scope-controls"))
                self.assertEqual("pc-01 · —", app.table.get_cell("pc-01", "place").plain)
                self.assertTrue(await pilot.click("#places", offset=(1, 2)))
                self.assertEqual("pc-02", app.cursor_device())
                self.assertTrue(await pilot.click("#places", offset=(1, 2)))
                await app.workers.wait_for_complete()
                self.assertIsInstance(app.screen, PlaceDialog)
                self.assertFalse(app.screen.query("#bind"))
                await pilot.press("escape", "up")
                self.assertEqual("pc-01", app.cursor_device())
                self.assertTrue(await pilot.click("#mark-exam"))
                self.assertEqual({"pc-01", "pc-02"}, app.marked)
                self.assertTrue(await pilot.click("#exam"))
                self.assertIsInstance(app.screen, ConfirmDialog)
                self.assertIn("Мест выбрано 2", app.screen.message)
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertIsInstance(app.screen, GroupDialog)
                self.assertEqual(["pc-01", "pc-02"], [row["deviceId"] for row in app.screen.results])
                self.assertIn("Нет свежей связи", app.screen.query_one("#message", Static).content.plain)

                report = self.applied(self.current()["device"]["assignment"])
                self.send(report, guest="absent", install=self.installation)
                await pilot.pause(0.7)
                self.assertIn("Можно входить в Guest", app.screen.query_one("#message", Static).content.plain)
                await pilot.press("escape")
                self.assertTrue(app.table.get_cell("pc-01", "version").plain.startswith("✓ "))
                self.assertEqual("Подгот.", app.table.get_cell("pc-01", "mode").plain)
                self.assertEqual("Есть", app.table.get_cell("pc-01", "connection").plain)
                self.assertEqual("Можно входить", app.table.get_cell("pc-01", "action").plain)

                app.table.focus()
                await pilot.press(*(["down"] * 22))
                before = app.cursor_device()
                await pilot.pause(0.7)
                scrolled = app.table.scroll_y
                self.assertGreater(scrolled, 0)
                await pilot.pause(0.7)
                self.assertEqual((before, scrolled), (app.cursor_device(), app.table.scroll_y))
                await pilot.resize_terminal(57, 18)
                await pilot.pause()
                self.assertEqual(before, app.cursor_device())
                self.assertLessEqual(sum(app.columns) + 10, app.table.region.width)
                for button in app.query(".toolbar Button").results(Button):
                    self.assertLessEqual(button.region.right, 57, button.id)
                    self.assertEqual(1, button.region.height, button.id)
                self.assertTrue(await pilot.click("#help"))
                self.assertIn("Ожидаемый выпуск", app.screen.query_one("#message", Static).content)

        self.run_tui(exercise)

    def test_tui_owner_sees_and_confirms_exact_current_alert(self):
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        report, _, target = self.present_alert()

        async def teacher(app):
            async with app.run_test(size=(80, 24)) as pilot:
                await app.workers.wait_for_complete()
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertIsInstance(app.screen, PlaceDialog)
                self.assertFalse(app.screen.query("#dismiss-alert"))

        async def owner(app):
            async with app.run_test(size=(80, 24)) as pilot:
                await app.workers.wait_for_complete()
                self.assertIn("контрольный сигнал", app.query_one("#selected", Static).content.plain)
                self.assertTrue(await pilot.click("#actions"))
                await app.workers.wait_for_complete()
                self.assertTrue(await pilot.click("#dismiss-alert"))
                self.assertIsInstance(app.screen, ConfirmDialog)
                self.assertIn(target["alertId"], str(app.screen.message))
                self.advance(1)
                self.send(report, guest="present", session="changed")
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertIn("Сеанс Guest изменился", app.screen.query_one("#message", Static).content)
                self.assertIsNone(self.current()["alerts"][0]["acknowledgement"])

        self.run_tui(teacher, self.teacher)
        self.run_tui(owner)

    def test_tui_manual_submission_check_remains_visible_when_pc_stops_polling(self):
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        active = self.assign()
        target = {"revision": active["revision"], "bootUtc": self.boot, "guestSessionId": self.session}
        self.send(self.applied(active), guest="present", session=self.session)
        self.action("guest", deviceId="pc-01", target=target, checks=["file", "project", "wazuh"])

        async def exercise(app):
            app.POLL_SECONDS = 60
            async with app.run_test(size=(57, 18)) as pilot:
                await app.workers.wait_for_complete()
                selected = app.query_one("#selected", Static)
                self.assertIn("Связь с ПК · есть", selected.content.plain)
                self.assertIn("Отчёт ПК · политики ПК применены", selected.content.plain)
                self.assertIn("Готовность ПК · есть", selected.content.plain)
                self.assertIn("Сверка сдачи · отметки преподавателя пока нет", selected.content.plain)
                self.assertIn("ФИО вручную", selected.content.plain)
                self.assertEqual("Требуется LTI", app.table.get_cell("pc-01", "action").plain)
                await pilot.press("down")
                self.assertIn("Связь с ПК · первого опроса ещё не было", selected.content.plain)
                await pilot.press("up", "enter")
                await app.workers.wait_for_complete()
                self.assertTrue(app.screen.query_one("#guest", Button).disabled)
                self.assertTrue(await pilot.click("#submit"))
                self.assertIsInstance(app.screen, ConfirmDialog)
                self.assertIn("PrairieLearn", app.screen.message)
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertTrue(self.current()["submitted"])
                self.advance(READINESS_TIMEOUT)
                app.action_reload()
                await app.workers.wait_for_complete()
                self.assertIn("Связь с ПК · нет свежего опроса", selected.content.plain)
                self.assertIn("Отчёт ПК · нет свежего результата", selected.content.plain)
                self.assertIn("Сверка сдачи · преподаватель сверил в PrairieLearn", selected.content.plain)

        self.run_tui(exercise)

    def test_tui_review_after_exit_and_return_target_exact_guest(self):
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        active = self.assign()
        report = self.applied(active)
        target = {"revision": active["revision"], "bootUtc": self.boot, "guestSessionId": self.session}
        self.send(report, guest="present", session=self.session)
        self.action("guest", deviceId="pc-01", target=target, checks=["file", "project", "wazuh"])
        self.advance(1)
        self.send(report, guest="absent")
        commands = []

        def observe(request):
            if request["action"] in ("submit", "normal"):
                commands.append(request)

        async def exercise(app):
            app.POLL_SECONDS = 60
            async with app.run_test(size=(57, 18)) as pilot:
                await app.workers.wait_for_complete()
                selected = app.query_one("#selected", Static)
                self.assertIn("Учебный Студент", selected.content.plain)
                self.assertIn("Guest · вышел", selected.content.plain)
                self.assertEqual("Сверить сдачу", app.table.get_cell("pc-01", "action").plain)

                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertTrue(await pilot.click("#submit"))
                self.assertIn("Guest вышел", app.screen.message)
                self.assertIn("PrairieLearn", app.screen.message)
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertEqual(target, commands[-1]["target"])
                self.assertIn("Сверка сдачи · преподаватель сверил в PrairieLearn", selected.content.plain)
                self.assertEqual("Вернуть режим", app.table.get_cell("pc-01", "action").plain)

                await pilot.press("n")
                self.assertIsInstance(app.screen, ConfirmDialog)
                self.assertIn("ПК pc-01", app.screen.message)
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertEqual({"pc-01": target}, commands[-1]["targets"])
                self.assertIsInstance(app.screen, GroupDialog)
                self.assertEqual("pending", app.screen.results[0]["status"])
                self.assertEqual("normal", self.current()["assignedMode"])
                self.assertNotIn("Guest · вышел", selected.content.plain)
                self.assertIn("Прошлый выход · ФИО вручную · Учебный Студент", selected.content.plain)
                await pilot.press("escape", "enter")
                await app.workers.wait_for_complete()
                place_info = app.screen.query_one(".dialog-content Static", Static).content.plain
                self.assertIn("Последний подтверждённый выход Guest · ФИО вручную · Учебный Студент", place_info)

        self.run_tui(exercise, observe=observe)

    def test_tui_file_trace_switch_is_owner_only_and_scopes_requests(self):
        file_trace_exam = "file-trace-20261124"
        old_started, old_release, hold_old_list = Event(), Event(), Event()
        requests = []
        self.action("bind", deviceId="pc-01", student="Обычный Студент")
        self.action("bind", exam=file_trace_exam, deviceId="pc-02", student="Студент Пилота")

        def observe(request):
            action, exam = request["action"], request["examId"]
            requests.append((action, exam))
            if action == "list" and exam == self.exam and hold_old_list.is_set():
                hold_old_list.clear()
                old_started.set()
                old_release.wait(5)

        async def teacher(app):
            async with app.run_test(size=(57, 18)) as pilot:
                await app.workers.wait_for_complete()
                self.assertFalse(app.query_one("#scope-controls").display)
                await pilot.press("f2")
                self.assertEqual(self.exam, app.scope.exam_id)
                self.assertEqual([("list", self.exam)], requests)

        async def owner(app):
            async with app.run_test(size=(57, 18)) as pilot:
                await app.workers.wait_for_complete()
                self.assertTrue(app.query_one("#scope-controls").display)
                self.assertIn("Обычный экзамен", app.query_one("#scope-state", Static).content.plain)
                await pilot.press("a")
                self.assertEqual({"pc-01"}, app.marked)
                hold_old_list.set()
                app.reload()
                try:
                    self.assertTrue(await asyncio.to_thread(old_started.wait, 2))
                    self.assertTrue(await pilot.click("#switch-exam"))
                    self.assertEqual(file_trace_exam, app.scope.exam_id)
                    self.assertFalse(app.rows or app.marked or app.connected)
                    self.assertTrue(app.query_one("#exam", Button).disabled)
                    label = app.query_one("#scope-state", Static)
                    switch = app.query_one("#switch-exam", Button)
                    self.assertIn("Экзамен с записью файлов", label.content.plain)
                    self.assertLessEqual(label.content.cell_len + 1, label.region.width)
                    self.assertLessEqual(switch.region.right, 57)
                    self.assertEqual({"list"}, {action for action, _ in requests})
                finally:
                    old_release.set()
                await app.workers.wait_for_complete()
                await pilot.pause()
                await app.workers.wait_for_complete()
                self.assertIsNone(app.rows["pc-01"]["student"])
                self.assertEqual("Студент Пилота", app.rows["pc-02"]["student"])
                self.assertEqual({"list"}, {action for action, _ in requests})

                self.assertTrue(await pilot.click("#actions"))
                await app.workers.wait_for_complete()
                self.assertTrue(await pilot.click("#bind"))
                self.assertIn(file_trace_exam, app.screen.message)
                app.screen.query_one(Input).value = "Новый Студент"
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertEqual("Обычный Студент", self.current()["student"])
                self.assertEqual("Новый Студент", self.action("details", exam=file_trace_exam, deviceId="pc-01")["student"])

                for action in ("exam", "normal"):
                    self.assertTrue(await pilot.click(f"#{action}"))
                    self.assertIn(file_trace_exam, app.screen.message)
                    self.assertTrue(await pilot.click("#confirm"))
                    await app.workers.wait_for_complete()
                    self.assertEqual(file_trace_exam, app.screen.exam)
                    await pilot.press("escape")
                self.assertEqual(file_trace_exam, self.current()["examId"])
                self.assertEqual(
                    [(name, file_trace_exam) for name in ("bind", "exam", "normal")],
                    [(action, exam) for action, exam in requests if action in ("bind", "exam", "normal")],
                )
                await pilot.press("f2")
                await app.workers.wait_for_complete()
                self.assertEqual(self.exam, app.scope.exam_id)
                self.assertEqual("Обычный Студент", app.rows["pc-01"]["student"])

        self.run_tui(teacher, self.teacher, file_trace_exam=file_trace_exam, observe=observe)
        self.run_tui(owner, file_trace_exam=file_trace_exam, observe=observe)

    def test_tui_cli_reserves_file_trace_for_explicit_switch(self):
        for extra in ([], ["--file-trace-exam", "file-trace-20261125"]):
            with self.subTest(extra=extra):
                result = subprocess.run(
                    [sys.executable, "-Es", str(Path(__file__).with_name("tui.py")),
                     "--exam", "file-trace-20261124", "--version", self.version,
                     "--socket", str(self.path.parent / "tui.sock"), *extra],
                    capture_output=True, encoding="utf-8", timeout=8,
                )
                self.assertEqual(2, result.returncode)
                self.assertIn("обычный идентификатор в --exam", result.stderr)

    def test_tui_manual_pilot_is_owner_only_on_regular_exam(self):
        async def teacher(app):
            async with app.run_test(size=(80, 24)) as pilot:
                await app.workers.wait_for_complete()
                self.assertNotIn("Ручная проба", app.query_one("#banner", Static).content.plain)
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertIsInstance(app.screen, PlaceDialog)
                self.assertFalse(app.screen.query("#bind"))

        async def owner(app):
            async with app.run_test(size=(80, 24)) as pilot:
                await app.workers.wait_for_complete()
                self.assertIn("Ручная проба", app.query_one("#banner", Static).content.plain)
                self.assertFalse(app.query("#scope-controls"))
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertTrue(await pilot.click("#bind"))
                app.screen.query_one(Input).value = "Учебный Студент"
                self.assertTrue(await pilot.click("#confirm"))
                await app.workers.wait_for_complete()
                self.assertEqual("Учебный Студент", self.current()["student"])
                self.assertIn("ФИО вручную", app.query_one("#selected", Static).content.plain)
                self.assertEqual(self.exam, app.scope.exam_id)

        self.run_tui(teacher, self.teacher, manual_pilot=True)
        self.run_tui(owner, manual_pilot=True)

    def test_changed_guest_invalidates_submission_and_local_normal_can_start_explicit_new_exam(self):
        report, _, target = self.present_alert()
        target.pop("alertId")
        self.action("bind", deviceId="pc-01", student="Учебный Студент")
        self.action("guest", deviceId="pc-01", target=target, checks=["file", "project", "wazuh"])
        self.action("submit", deviceId="pc-01", target=target)
        self.advance(1)
        self.send(report, guest="present", session="new-guest")
        self.advance(1)
        self.send(report, guest="absent")
        self.assertEqual("Сдача не подтверждена", self.action("normal", devices=["pc-01"])[0]["reason"])
        stopped = {**report, "outcome": "overridden", "reason": "local-normal-source-confirmed",
                   "observedUtc": iso_utc(self.clock.return_value)}
        self.send(stopped)
        self.advance(46)
        self.send(stopped)
        self.assertEqual("overridden", self.current()["reportStatus"])
        self.assertEqual("unchanged", self.action("exam", devices=["pc-01"])[0]["status"])
        self.assertEqual("pending", self.action("exam", exam="java-next", devices=["pc-01"])[0]["status"])
        self.assertEqual("java-next", self.send(stopped)["examId"])

    def test_installation_freshness_and_server_pinned_version(self):
        self.send(install=self.installation)
        self.assertEqual("installed", self.current()["installation"]["status"])
        with self.assertRaises(ValueError):
            self.action("list", version="spoofed-expected-release")
        self.send(install={**self.installation, "version": "0.1.0"})
        self.assertEqual("other-release", self.current()["installation"]["status"])
        self.advance(READINESS_TIMEOUT)
        self.send(legacy=True)
        self.assertEqual("fresh", self.current()["connection"])
        self.assertEqual("unconfirmed", self.current()["installation"]["status"])

    def test_unix_peer_credentials_are_used_without_identity_in_request(self):
        socket_path = self.path.parent / "teacher.sock"
        args = type("Arguments", (), {"socket": socket_path, "exam": self.exam, "version": self.version})
        dispatch = lambda uid, request: teacher_dispatch(self.path, self.teacher, self.version, uid, request)
        with serve_teacher(socket_path, (self.owner,), dispatch):
            self.assertFalse(call(args, "list")["owner"])
            with self.assertRaisesRegex(ValueError, "владельцу"):
                call(args, "dismiss", deviceId="pc-01", target={})
            with self.assertRaisesRegex(ValueError, "команда"):
                call(args, "list", uid=self.teacher)
        with serve_teacher(socket_path, (self.teacher,), dispatch):
            with self.assertRaisesRegex(ValueError, "не допущена"):
                call(args, "list")
