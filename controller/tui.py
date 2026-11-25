import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
from socket import AF_UNIX, SOCK_STREAM, socket
import sys

dependencies = Path(__file__).with_name("tui-deps")
if dependencies.is_dir():
    sys.path.insert(0, str(dependencies))

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static


GREEN, YELLOW, RED, CYAN = "#145c3d", "#734800", "#912138", "#215973"
HEADING = "#153c56"
REPORT = {
    "pending": ("ожидает", YELLOW), "offline": ("нет свежего результата", YELLOW),
    "applied": ("применён", GREEN), "source-applied": ("применён", GREEN),
    "blocked": ("отказ", RED), "error": ("ошибка", RED),
    "overridden": ("локальный", CYAN),
}
CONNECTION = {
    "fresh": ("есть", GREEN), "stale": ("нет свежего опроса", RED),
    "never": ("первого опроса ещё не было", YELLOW),
}
CONNECTION_BRIEF = {"fresh": "Есть", "stale": "Нет", "never": "Ждём"}
ALERT = {
    "received": ("Получена", RED), "shown": ("На экране", RED),
    "acknowledged": ("Снята", GREEN), "requested": ("Снимается", YELLOW),
    "expired": ("Просрочена", RED), "session-ended": ("Сеанс завершён", "dim"),
}
ALERT_REASON = {"control-signal": "контрольный сигнал", "canary-read": "чтение контрольного файла"}
REPORT_REASON = {
    "full-not-ready": ("Нет допуска", "Полный режим недоступен"),
    "guest-still-present": ("Guest открыт", "Дождитесь выхода Guest"),
    "machine-preflight-failed": ("Проверки ПК", "Проверки ПК завершились отказом"),
    "machine-apply-failed": ("Ошибка политик", "Не удалось применить политики ПК"),
    "local-action-failed": ("Ошибка режима", "Не удалось переключить режим"),
    "local-normal-incomplete": ("Снятие не заверш.", "Локальное снятие ограничений не завершено"),
    "collection-stop-failed": ("Ошибка записи", "Не удалось остановить запись"),
}
MANUAL_STUDENT = "ФИО вручную"
IDENTITY_REFUSAL = {
    "conflict": ("Конфликт LTI", "Связь LTI для этого Guest противоречива. Проверьте вход студента."),
    "revoked": ("Связь отозвана", "Связь LTI для этого Guest отозвана."),
}
INSTALLATION = {
    "installed": ("✓", GREEN, "Установлен ожидаемый выпуск"),
    "other-release": ("≠", YELLOW, "Установлен другой выпуск"),
    "unconfirmed": ("?", YELLOW, "Нет свежего итогового отчёта"),
}
ASSIGNMENT_RESULT = {
    "pending": ("Назначение записано", YELLOW),
    "unchanged": ("Уже назначено", CYAN),
    "blocked": ("Отказ", RED),
}
SESSION_FIELDS = ("revision", "bootUtc", "guestSessionId")
FILE_TRACE_LABEL = "Экзамен с записью файлов"
REGULAR_LABEL = "Обычный экзамен"
FILE_TRACE_PREFIX = "file-trace-"
FILE_TRACE_ID = re.compile(FILE_TRACE_PREFIX + r"[A-Za-z0-9._-]{1,53}")
HELP = """↑ ↓  Выбрать место     Enter  Открыть действия на месте
Пробел  Отметить ПК     A  Отметить места этого экзамена
E  Включить экзамен     N  Вернуть в обычный режим
Tab  Перейти к кнопкам   R  Обновить   F1  Справка   Q  Выйти

Мышь выбирает строку и нажимает кнопки. Повторный щелчок по строке открывает её действия.
Команды применяются к отмеченным ПК или к выбранной строке.
Возврат в обычный режим после экзамена требует сверки сдачи преподавателем и выхода Guest.
Сдачу и оценку смотрите в PrairieLearn. В панели видна отметка ручной сверки.
В колонке «Версия» ✓ означает ожидаемый выпуск по итоговому отчёту, ≠ — другой выпуск, ? — нет подтверждения.
Для снятия тревоги владелец подтверждает конкретное событие в действиях на месте."""


@dataclass(frozen=True)
class ExamScope:
    exam_id: str
    generation: int = 0


def call(args, action, *, exam_id=None, **fields):
    request = {"action": action, "examId": exam_id or args.exam, "version": args.version, **fields}
    with socket(AF_UNIX, SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(os.fspath(args.socket))
        connection.sendall(json.dumps(request).encode("utf-8") + b"\n")
        with connection.makefile("rb") as response:
            line = response.readline(524_289)
        if not line.endswith(b"\n") or len(line) > 524_288:
            raise ValueError("Контроллер не вернул полный ответ")
        reply = json.loads(line.decode("utf-8"))
    if "error" in reply:
        raise ValueError(reply["error"])
    return reply["result"]


def exam_places(places, exam_id):
    return {row["deviceId"] for row in places if row["student"] is not None or row["examId"] == exam_id}


def place_student(row, *, manual=False):
    if row.get("sessionIdentityStatus") in IDENTITY_REFUSAL:
        return None
    student = row.get("sessionStudent")
    if student is None and manual:
        return row["student"]
    return student


def student_for_guest(row, *, manual=False):
    if manual or row.get("sessionStudentSource") == "lti":
        return place_student(row, manual=manual)
    return None


def place_title(row, *, manual=False):
    device = row["deviceId"]
    student = place_student(row, manual=manual)
    if not student:
        return device
    source = f" · {MANUAL_STUDENT}" if row.get("sessionStudentSource") != "lti" else ""
    return f"{device}{source} · {student}"


def alert_label(alert):
    return ALERT_REASON.get(alert["reason"], alert["reason"])


def machine_report(row):
    if row["reportReason"] == "local-normal-source-confirmed":
        return "источники политик очищены локально", CYAN
    if row["reportStatus"] == "source-applied":
        if row["assignedMode"] == "normal":
            return "источники политик очищены", GREEN
        return "политики ПК применены", GREEN
    if row["reportStatus"] == "applied":
        return "режим применён", GREEN
    return REPORT[row["reportStatus"]]


def reported_mode(row):
    if row["reportReason"] == "local-normal-source-confirmed":
        return "Снят", CYAN
    if row["connection"] == "fresh":
        if row["reportStatus"] == "applied":
            return ("Экзамен" if row["assignedMode"] == "exam" else "Обычный"), GREEN
        if row["reportStatus"] == "source-applied":
            return ("Подгот." if row["assignedMode"] == "exam" else "Снят"), CYAN
    return "Неясен", YELLOW


def report_reason(row, *, brief=False):
    if row["reportStatus"] not in ("blocked", "error"):
        return None
    reason = row["reportReason"]
    return REPORT_REASON.get(reason, (reason, reason))[0 if brief else 1]


def place_guidance(row, exam_id, *, brief=False, owner=False, manual=False):
    def label(short, full, color):
        return short if brief else full, color

    if row["connection"] != "fresh":
        return label("Ждём опрос", "Нет свежей связи с ПК", YELLOW)
    if row["reportReason"] == "local-normal-source-confirmed":
        return label("Проверить вход", "Проверьте обычный вход после локального снятия.", CYAN)
    if row["examId"] and row["examId"] != exam_id:
        return label("Другой экзамен", f"Другой экзамен — {row['examId']}", YELLOW)
    if row["reportStatus"] in ("blocked", "error"):
        return report_reason(row, brief=brief) or "Смотреть отказ", RED
    if row["assignedMode"] == "normal":
        if row["reportStatus"] in ("applied", "source-applied"):
            return label("Проверить вход", "Проверьте обычный вход.", GREEN)
        return label("Ждём отчёт", "Ожидается отчёт о режиме.", YELLOW)
    alert = row["alert"]
    if alert and alert["current"]:
        if alert["status"] == "requested":
            return label("Снятие тревоги", "Ожидается подтверждение снятия от ПК.", YELLOW)
        if alert["status"] in ("received", "shown"):
            return ("Снять тревогу" if owner else "Позвать владельца") + ("" if brief else "."), RED
        if alert["status"] == "expired":
            return label("Снятие истекло", "Истёк срок команды снятия тревоги.", RED)
    if identity_refusal := IDENTITY_REFUSAL.get(row.get("sessionIdentityStatus")):
        return label(*identity_refusal, RED)
    if row["submitted"]:
        if row.get("canReturnToNormal"):
            return label("Вернуть режим", "Guest вышел. Доступен обычный режим.", GREEN)
        return label("Дождаться выхода", "Дождитесь подтверждения выхода Guest.", YELLOW)
    student = student_for_guest(row, manual=manual)
    if row["guestReady"] and student:
        return label("Можно начинать", "Преподаватель сверил Guest. Можно начинать.", GREEN)
    if row.get("canSubmitAfterExit"):
        return label("Сверить сдачу", "Guest вышел. Сверьте сдачу в PrairieLearn.", CYAN)
    if row["machineReady"]:
        if row["guestState"] == "absent":
            return label("Можно входить", "ПК готов. Можно входить в Guest.", GREEN)
        if row["guestState"] == "present" and student:
            return label("Сверить Guest", "Guest открыт. Подтвердите место и проверки.", YELLOW)
        if row["guestState"] == "present" and row.get("sessionStudentSource") == "manual":
            return label("Требуется LTI", "Для этого Guest требуется подтверждённая связь через LTI.", YELLOW)
        if row["guestState"] == "present":
            return label("Открыть задание", "Ожидает открытия задания через Moodle.", YELLOW)
        return label("Ждём Guest", "Ожидается подтверждение состояния Guest.", YELLOW)
    return label("Ждём готовность", "Ожидается подтверждение готовности ПК.", YELLOW)


def place_information(row, exam_id, *, compact=False, owner=False, manual=False):
    result = Text()
    connection, connection_color = CONNECTION[row["connection"]]
    report, report_color = machine_report(row)
    result.append("Связь с ПК · ")
    result.append(connection, connection_color)
    if (age := row.get("connectionAgeSeconds")) is not None:
        result.append(f" · {age} с назад" if age < 60 else f" · {age // 60} мин назад")
    result.append("\nОтчёт ПК · ")
    result.append(report, report_color)
    if reason := report_reason(row):
        result.append(f" · {reason}", RED)
    exam_place = row["assignedMode"] == "exam" and row["examId"] == exam_id
    if exam_place:
        result.append("\nГотовность ПК · ")
        result.append("есть" if row["machineReady"] else "не подтверждена", GREEN if row["machineReady"] else YELLOW)
    guest_separator = " · Guest · " if exam_place and compact else "\nGuest · "
    last_exit = row.get("lastGuestExit")
    if row["guestState"] == "present":
        result.append(f"{guest_separator}открыт")
    elif row["guestState"] == "absent":
        state = "вышел" if last_exit and row.get("sessionStudent") else "отсутствует"
        result.append(f"{guest_separator}{state}")
    elif exam_place:
        result.append(f"{guest_separator}состояние неизвестно")
    if place_student(row, manual=manual) or row["submitted"]:
        result.append("\nСверка сдачи · ")
        if row["submitted"]:
            result.append("преподаватель сверил в PrairieLearn", GREEN)
        else:
            result.append("отметки преподавателя пока нет", YELLOW)
    if not report_reason(row):
        result.append("\n")
        result.append(*place_guidance(row, exam_id, owner=owner, manual=manual))
    alert = row["alert"]
    if alert and (alert["current"] or (row["examId"] == exam_id and alert["status"] == "acknowledged")):
        label, color = ALERT[alert["status"]]
        result.append("\n")
        result.append(f"Тревога · {label} · {alert_label(alert)}", color)
    if last_exit and (not compact or not row.get("sessionStudent")):
        label = "Прошлый выход" if compact else "Последний подтверждённый выход Guest"
        source = f"{MANUAL_STUDENT} · " if last_exit.get("source") != "lti" else ""
        result.append(f"\n{label} · {source}{last_exit['student']}")
        if not compact:
            result.append(f" · {last_exit['exitedUtc']}")
    if not compact:
        _, installation_color, installation = INSTALLATION[row["installation"]["status"]]
        result.append("\n")
        result.append(installation, installation_color)
        version = row["installation"].get("version")
        if version:
            result.append(f" · {version[:12] if compact else version}")
    return result


class Dialog(ModalScreen):
    BINDINGS = [Binding("escape", "cancel", "Закрыть", show=False)]

    def on_resize(self, event):
        self.set_class(event.size.width < 72, "compact")

    def action_cancel(self):
        self.dismiss(None)


class MessageDialog(Dialog):
    def __init__(self, title, content):
        super().__init__()
        self.title_text = title
        self.content_text = content

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.title_text, classes="dialog-title", markup=False)
            with VerticalScroll(classes="dialog-content"):
                yield Static(self.content_text, markup=False, id="message")
            yield Button("Закрыть", id="close", variant="primary")

    def on_button_pressed(self, event):
        self.action_cancel()


class ConfirmDialog(Dialog):
    def __init__(self, title, text, *, prompt=None, value=""):
        super().__init__()
        self.title_text = title
        self.message = text
        self.prompt = prompt
        self.value = value

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.title_text, classes="dialog-title", markup=False)
            with VerticalScroll(classes="dialog-content"):
                yield Static(self.message, markup=False)
            if self.prompt:
                yield Input(value=self.value, placeholder=self.prompt, id="answer", max_length=100)
            yield Static("", id="input-error", markup=False)
            with Horizontal(classes="button-row"):
                yield Button("Отмена", id="cancel")
                yield Button("Подтвердить", id="confirm", variant="primary")

    def on_mount(self):
        self.query_one("#answer" if self.prompt else "#cancel").focus()

    def confirm(self):
        if self.prompt:
            answer = self.query_one(Input).value.strip()
            if not answer:
                self.query_one("#input-error", Static).update("Заполните поле")
                return
            self.dismiss(answer)
        else:
            self.dismiss(True)

    def on_input_submitted(self, event):
        self.confirm()

    def on_button_pressed(self, event):
        if event.button.id == "confirm":
            self.confirm()
        else:
            self.action_cancel()


class PlaceDialog(Dialog):
    def __init__(self, detail, exam_id, owner, *, manual=False):
        super().__init__()
        self.detail = detail
        self.exam_id = exam_id
        self.owner = owner
        self.manual = manual

    def compose(self) -> ComposeResult:
        row = self.detail
        name = place_title(row, manual=self.manual)
        can_dismiss = any(alert["current"] and alert["status"] in ("received", "shown") for alert in row["alerts"])
        guest_confirmable = row["guestState"] == "present" and bool(student_for_guest(row, manual=self.manual))
        can_submit = (row["guestReady"] and place_student(row, manual=self.manual)) or row.get("canSubmitAfterExit")
        with Vertical(classes="dialog"):
            yield Static(name, classes="dialog-title", markup=False)
            with VerticalScroll(classes="dialog-content"):
                yield Static(place_information(row, self.exam_id, owner=self.owner, manual=self.manual), markup=False)
            if self.manual:
                with Horizontal(classes="button-row"):
                    yield Button("Назначить ФИО для пробы", id="bind")
                    yield Button("Пересадить", id="move", disabled=not row["student"])
            with Horizontal(classes="button-row"):
                yield Button("Подтвердить Guest", id="guest", disabled=not (guest_confirmable and row["machineReady"]))
                yield Button("Сверить сдачу", id="submit", variant="success", disabled=not can_submit or row["submitted"])
                if self.owner:
                    yield Button("Снять тревогу", id="dismiss-alert", variant="error", disabled=not can_dismiss)
            with Horizontal(classes="button-row"):
                yield Button("Отчёт", id="details")
                yield Button("Закрыть", id="close")

    def on_button_pressed(self, event):
        self.dismiss(None if event.button.id == "close" else event.button.id)


class GroupDialog(MessageDialog):
    def __init__(self, mode, results, exam, *, owner=False, manual=False):
        super().__init__("Экзамен · результаты по ПК" if mode == "exam" else "Обычный режим · результаты по ПК", "")
        self.mode = mode
        self.results = results
        self.exam = exam
        self.owner = owner
        self.manual = manual

    def update_reports(self, rows, *, fresh=True):
        report = Text()
        if not fresh:
            report.append("Нет связи с контроллером. Последняя сводка устарела.\n\n", RED)
        for entry in self.results:
            device = entry["deviceId"]
            label, color = ASSIGNMENT_RESULT[entry["status"]]
            report.append(f"{device} · ", "bold")
            if entry["status"] == "blocked":
                report.append(f"{label} · {entry['reason']}", color)
            else:
                row = rows.get(device)
                if row and row["assignedMode"] == self.mode and (self.mode == "normal" or row["examId"] == self.exam):
                    state = place_guidance(row, self.exam, owner=self.owner, manual=self.manual)
                    if entry["status"] == "unchanged":
                        report.append(f"{label} · ", color)
                    report.append(*state)
                else:
                    report.append(f"{label} · ждём свежий отчёт ПК", color)
            report.append("\n")
        self.query_one("#message", Static).update(report)


class ExamTUI(App):
    ENABLE_COMMAND_PALETTE = False
    POLL_SECONDS = 3.0
    CSS = """
    Screen { background: #f5f7fa; color: #233649; }
    #banner { height: 1; background: #dce8f1; color: #153c56; padding: 0 1; text-style: bold; }
    #scope-controls { height: 1; margin: 0 1; background: #e8eff5; }
    #scope-state { width: 1fr; height: 1; padding-left: 1; text-wrap: nowrap; }
    #switch-exam { margin: 0; }
    #summary { height: 1; padding: 0 1; margin-top: 1; color: #215973; }
    #places-panel { height: 1fr; min-height: 3; margin: 0 1; border: round #8ca3b6; }
    #places { height: 1fr; background: #ffffff; color: #233649; scrollbar-size: 1 1; }
    #places > .datatable--header { background: #dce8f1; color: #153c56; text-style: bold; }
    #places > .datatable--odd-row { background: #f1f5f9; }
    #places > .datatable--cursor { background: #c9e2f5; color: #153c56; text-style: bold; }
    #places > .datatable--hover { background: #e2eef7; }
    #places-empty { height: 1; padding: 0 1; color: #4a6378; }
    #selected { height: auto; max-height: 8; padding: 0 1; margin: 0 1; background: #e8eff5; }
    #notice { height: 1; padding: 0 1; color: #4a6378; }
    #key-hint { height: 1; padding: 0 1; background: #dce8f1; color: #153c56; }
    .toolbar { height: 1; grid-size: 4 1; grid-gutter: 0 1; margin: 0 1; }
    .toolbar Button { width: 100%; margin: 0; }
    #mode-actions { grid-size: 2 1; margin-bottom: 1; }
    .button-row { height: 1; }
    Button { border: none !important; height: 1; min-width: 4; width: auto; margin-right: 1; }
    Button:focus { text-style: bold underline; }
    Dialog { background: #435b70 28%; align: center middle; }
    .dialog { width: 68; max-width: 96%; height: auto; max-height: 94%;
              padding: 1 2; border: round #8ca3b6; background: #ffffff; }
    .dialog-title { color: #153c56; text-style: bold; height: auto; margin-bottom: 1; }
    .dialog-content { height: auto; max-height: 14; margin-bottom: 1; scrollbar-size: 1 1; }
    .dialog-content Static { height: auto; }
    .dialog .button-row { margin-top: 1; }
    #input-error { height: auto; color: #912138; }
    #answer { height: 3; }
    Screen.compact #mode-actions { margin-bottom: 0; }
    Screen.compact #selected { max-height: 7; }
    Screen.compact #summary { margin-top: 0; }
    Screen.compact .dialog { padding: 0 1; }
    """
    BINDINGS = [
        Binding("space", "toggle_mark", "Отметить", show=False),
        Binding("a", "mark_exam", "Места экзамена", show=False),
        Binding("e", "group('exam')", "Экзамен", show=False),
        Binding("n", "group('normal')", "Обычный", show=False),
        Binding("f1", "help", "Справка", show=False),
        Binding("f2", "switch_exam", "Сменить экзамен", show=False),
        Binding("r", "reload", "Обновить", show=False),
        Binding("q", "quit", "Выход", show=False),
    ]

    def __init__(self, args):
        super().__init__()
        self.theme = "textual-light"
        self.args = args
        self.file_trace_exam = getattr(args, "file_trace_exam", None)
        self.manual_pilot = getattr(args, "manual_pilot", False)
        self.scope = ExamScope(args.exam)
        self.rows = {}
        self.shown_ids = ()
        self.columns = ()
        self.owner = False
        self.marked = set()
        self.updated = None
        self.connected = False
        self.refreshing = False
        self.mutating = False
        self.request_lock = asyncio.Lock()
        self.active_group = None
        self.terminal_width = 80

    def compose(self) -> ComposeResult:
        yield Static(id="banner", markup=False)
        if self.file_trace_exam:
            with Horizontal(id="scope-controls") as scope_controls:
                scope_controls.display = False
                yield Static(id="scope-state", markup=False)
                yield Button(FILE_TRACE_LABEL, id="switch-exam", tooltip="Сменить открытый список · F2")
        yield Static("Подключение к контроллеру…", id="summary", markup=False)
        with Vertical(id="places-panel"):
            yield DataTable(
                id="places", cursor_type="row", zebra_stripes=True, fixed_columns=2, show_row_labels=False,
            )
            yield Static("Загрузка списка ПК…", id="places-empty", markup=False)
        yield Static("Выберите место", id="selected", markup=False)
        yield Static(id="notice", markup=False)
        with Grid(classes="toolbar"):
            yield Button("Отметить", id="mark")
            yield Button("Группа", id="mark-exam", tooltip="Отметить все места этого экзамена")
            yield Button("Действия", id="actions")
            yield Button("Справка", id="help")
        with Grid(id="mode-actions", classes="toolbar"):
            yield Button("Включить экзамен", id="exam", variant="primary")
            yield Button("Вернуть в обычный режим", id="normal", variant="success")
        yield Static("↑↓ Место  Enter Действия  Space Отметить  R Обновить  Q Выйти", id="key-hint", markup=False)

    @property
    def table(self):
        return self.query_one("#places", DataTable)

    @property
    def file_trace_active(self):
        return self.scope.exam_id == self.file_trace_exam

    @property
    def manual_placement(self):
        return self.owner and (self.file_trace_active or self.manual_pilot)

    def on_mount(self):
        self.terminal_width = self.size.width
        self.query_one("#places-panel").border_title = "Рабочие места"
        self.table.focus()
        self.update_layout()
        self.set_interval(self.POLL_SECONDS, self.reload)
        self.reload()

    def on_resize(self, event):
        self.terminal_width = event.size.width
        if self.is_mounted:
            self.call_after_refresh(self.update_layout)

    def update_layout(self):
        compact = self.terminal_width < 72
        self.screen_stack[0].set_class(compact, "compact")
        if compact:
            hints = "↑↓ Место  Enter Меню  Space Метка  F1 Справка  Q Выход"
        else:
            hints = "↑↓ Место  Enter Действия  Space Отметить  R Обновить  Q Выйти"
        self.query_one("#key-hint", Static).update(hints)
        self.render_table()
        self.update_summary()

    async def request(self, scope, action, **fields):
        async with self.request_lock:
            return await asyncio.to_thread(call, self.args, action, exam_id=scope.exam_id, **fields)

    def action_reload(self):
        if self.screen is self.screen_stack[0]:
            self.reload()

    @work
    async def reload(self):
        if self.refreshing or self.mutating:
            return
        self.refreshing = True
        scope = self.scope
        try:
            summary = await self.request(scope, "list")
        except (OSError, ValueError) as error:
            if scope != self.scope:
                return
            self.connected = False
            self.update_summary()
            self.notice(f"Нет связи с контроллером · {error}", RED)
            if self.active_group and self.active_group.is_mounted:
                self.active_group.update_reports(self.rows, fresh=False)
        else:
            if scope != self.scope:
                return
            self.owner = summary["owner"]
            if self.file_trace_active and not self.owner:
                if isinstance(self.screen, Dialog):
                    self.screen.dismiss(None)
                self.select_exam(self.args.exam)
                return
            if not self.connected:
                self.notice("Связь с контроллером восстановлена" if self.updated else "")
            self.connected = True
            self.updated = datetime.now().astimezone()
            self.rows = {row["deviceId"]: row for row in summary["places"]}
            self.marked.intersection_update(self.rows)
            self.render_table()
            self.update_summary()
            group = self.active_group
            if group and group.is_mounted:
                group.update_reports(self.rows)
        finally:
            self.refreshing = False
            if scope != self.scope:
                self.reload()

    def select_exam(self, exam_id):
        self.scope = ExamScope(exam_id, self.scope.generation + 1)
        self.rows.clear()
        self.marked.clear()
        self.updated = None
        self.connected = False
        self.notice("")
        self.render_table()
        self.update_summary()
        if not self.refreshing:
            self.reload()

    def action_switch_exam(self):
        if self.screen is not self.screen_stack[0] or not self.file_trace_exam or not self.owner or self.mutating:
            return
        self.select_exam(self.args.exam if self.file_trace_active else self.file_trace_exam)

    def cursor_device(self):
        index = self.table.cursor_row
        return self.shown_ids[index] if 0 <= index < len(self.shown_ids) else None

    def notice(self, value, style=""):
        self.query_one("#notice", Static).update(Text(value, style=style))

    def update_summary(self):
        banner = Text("Экзаменационные места", style=f"bold {HEADING}")
        if self.manual_placement:
            banner.append("  ·  Ручная проба", f"bold {YELLOW}")
        banner.append(f"  {self.scope.exam_id} · {self.args.version[:12]}")
        if self.owner:
            banner.append("  ·  Владелец", f"bold {GREEN}")
        self.query_one("#banner", Static).update(banner)
        if self.file_trace_exam:
            self.query_one("#scope-controls", Horizontal).display = self.owner
            label = FILE_TRACE_LABEL if self.file_trace_active else REGULAR_LABEL
            color = YELLOW if self.file_trace_active else CYAN
            self.query_one("#scope-state", Static).update(Text(f"Список · {label}", f"bold {color}"))
            switch = self.query_one("#switch-exam", Button)
            switch.label = REGULAR_LABEL if self.file_trace_active else FILE_TRACE_LABEL
            switch.variant = "default" if self.file_trace_active else "warning"
        rows = self.rows.values()
        fresh = sum(row["connection"] == "fresh" for row in rows)
        alerts = sum(bool(row["alert"] and row["alert"]["current"] and row["alert"]["status"] != "acknowledged") for row in rows)
        ready = sum(row["guestReady"] and bool(student_for_guest(row, manual=self.manual_placement)) for row in rows)
        compact = self.terminal_width < 72
        divider = " · " if compact else "  ·  "
        line = Text(f"Опрос ПК {fresh}/{len(rows)}{divider}Guest {ready}{divider}")
        line.append(f"{'Трев.' if compact else 'Тревоги'} {alerts}", f"bold {RED}" if alerts else "")
        line.append(f"{divider}Метки {len(self.marked)}{divider}")
        stamp = self.updated.strftime("%H:%M:%S") if self.updated else None
        if self.connected:
            line.append(f"Сводка {stamp}", GREEN)
        else:
            line.append(f"Сводка {stamp} устарела" if stamp else "Связь…", YELLOW)
        self.query_one("#summary", Static).update(line)
        self.update_selection()

    def update_selection(self):
        device = self.cursor_device()
        row = self.rows.get(device)
        if row:
            heading = place_title(row, manual=self.manual_placement)
            info = Text(overflow="ellipsis", no_wrap=True)
            info.append(heading, f"bold {HEADING}")
            if self.marked:
                info.append(f" · Команды для отмеченных ПК ({len(self.marked)})")
            if not self.connected:
                info.append(" · устаревшая сводка", YELLOW)
            info.append("\n")
            info.append_text(place_information(
                row, self.scope.exam_id, compact=True, owner=self.owner, manual=self.manual_placement,
            ))
        else:
            info = Text("Выберите место", style="dim")
        selected = self.query_one("#selected", Static)
        if selected.content != info:
            selected.update(info)
        for name in ("actions", "mark", "mark-exam", "exam", "normal"):
            available = device is not None and (name in ("mark", "mark-exam") or (self.connected and not self.mutating))
            self.query_one(f"#{name}", Button).disabled = not available
        if self.file_trace_exam:
            self.query_one("#switch-exam", Button).disabled = self.mutating

    def table_values(self, row):
        device = row["deviceId"]
        mark = Text("✓", f"bold {GREEN}") if device in self.marked else Text("·", "dim")
        person = Text(device, style=f"bold {HEADING}")
        student = place_student(row, manual=self.manual_placement)
        if student and row.get("sessionStudentSource") != "lti":
            person.append(" · вручную", YELLOW)
        person.append(f" · {student}" if student else " · —", style="" if student else "dim")
        installation_symbol, color, _ = INSTALLATION[row["installation"]["status"]]
        installation = Text(installation_symbol, color)
        version = row["installation"].get("version")
        if version:
            installation.append(f" {version}")
        elif row["connection"] != "fresh":
            installation = Text("—", "dim")
        connection = Text(CONNECTION_BRIEF[row["connection"]], CONNECTION[row["connection"]][1])
        alert = row["alert"]
        alert_visible = alert and (alert["current"] or (row["examId"] == self.scope.exam_id and alert["status"] == "acknowledged"))
        return {
            "mark": mark, "place": person, "version": installation, "mode": Text(*reported_mode(row)),
            "connection": connection,
            "action": Text(*place_guidance(
                row, self.scope.exam_id, brief=True, owner=self.owner, manual=self.manual_placement,
            )),
            "alert": Text(*ALERT[alert["status"]]) if alert_visible else Text("—", "dim"),
        }

    def row_cells(self, device, columns):
        values = self.table_values(self.rows[device])
        for key, _, width in columns:
            value = values[key]
            value.truncate(width, overflow="ellipsis")
            yield value

    def render_table(self):
        table = self.table
        # The panel has one cell of margin and one border cell on each side.
        available = max(54, self.terminal_width) - 4
        columns = [("mark", "•", 1), ("place", "ПК · Студент", 0)]
        if self.terminal_width >= 72:
            columns.append(("version", "Версия", 7))
        columns.extend((("mode", "Режим", 8), ("connection", "Связь", 5), ("action", "Действие", 17)))
        if self.terminal_width >= 100:
            columns.append(("alert", "Тревога", 10))
        # Two padding cells per column and one cell for the scrollbar.
        place_width = available - sum(width + 2 for _, _, width in columns) - 1
        columns[1] = ("place", "ПК · Студент" if place_width >= 12 else "Место", place_width)
        widths = tuple(width for _, _, width in columns)
        ids = tuple(self.rows)
        current = self.cursor_device()
        old_index = table.cursor_row
        old_y = table.scroll_y
        if ids != self.shown_ids or widths != self.columns:
            table.clear(columns=True)
            for key, label, width in columns:
                table.add_column(label, width=width, key=key)
            for device in ids:
                table.add_row(*self.row_cells(device, columns), key=device)
            self.columns = widths
            self.shown_ids = ids
            if ids:
                new_index = ids.index(current) if current in self.rows else min(old_index, len(ids) - 1)
                table.move_cursor(row=new_index, scroll=False)
                table.call_after_refresh(table.scroll_to, y=max(0, old_y + new_index - old_index), animate=False)
        else:
            for device in ids:
                for (column, _, _), value in zip(columns, self.row_cells(device, columns)):
                    if table.get_cell(device, column) != value:
                        table.update_cell(device, column, value)
        empty = self.query_one("#places-empty", Static)
        empty.display = not ids
        if not ids:
            empty.update("Нет зарегистрированных ПК" if self.connected else "Ожидается список ПК")
        self.update_selection()

    def on_data_table_row_highlighted(self, event):
        self.update_selection()

    def on_data_table_row_selected(self, event):
        self.open_place()

    def action_toggle_mark(self):
        if self.screen is not self.screen_stack[0]:
            return
        device = self.cursor_device()
        if device:
            self.marked.symmetric_difference_update({device})
            self.render_table()
            self.update_summary()

    def action_mark_exam(self):
        if self.screen is not self.screen_stack[0]:
            return
        eligible = exam_places(self.rows.values(), self.scope.exam_id)
        if not eligible:
            self.notice("Пока нет назначенных мест этого экзамена", YELLOW)
        else:
            self.marked = set() if self.marked == eligible else eligible
            self.render_table()
            self.update_summary()

    def action_help(self):
        if self.screen is self.screen_stack[0]:
            scope_help = ""
            if self.file_trace_exam and self.owner:
                scope_help = (
                    "\n\nF2  Сменить список экзамена. После смены выберите ПК и отдельно подтвердите назначение."
                    f"\nОткрытый экзамен {self.scope.exam_id}."
                )
            self.push_screen(MessageDialog("Управление", f"{HELP}{scope_help}\n\nОжидаемый выпуск {self.args.version}"))

    def scoped_message(self, message):
        if self.file_trace_active:
            return f"{FILE_TRACE_LABEL} · {self.scope.exam_id}\n{message}"
        return message

    def action_group(self, mode):
        if self.screen is not self.screen_stack[0] or not self.connected or self.mutating:
            return
        selection = sorted(self.marked) if self.marked else [self.cursor_device()]
        if selection == [None]:
            return
        if len(selection) > 100:
            self.notice("Контроллер принимает до 100 ПК за одно действие", YELLOW)
            return
        title = "Включить экзамен" if mode == "exam" else "Вернуть в обычный режим"
        target = f"ПК {selection[0]}" if len(selection) == 1 else f"Мест выбрано {len(selection)}\n{', '.join(selection)}"
        fields = {"devices": selection}
        if mode == "normal":
            fields["targets"] = {
                device: session for device in selection if (session := self.rows[device].get("normalTarget"))
            }
        scope = self.scope
        self.push_screen(
            ConfirmDialog(title, self.scoped_message(target)),
            lambda accepted: self.change(scope, mode, **fields) if accepted else None,
        )

    @work
    async def open_place(self):
        if self.screen is not self.screen_stack[0] or not self.connected or self.mutating:
            return
        device = self.cursor_device()
        if not device:
            return
        scope = self.scope
        try:
            detail = await self.request(scope, "details", deviceId=device)
        except (OSError, ValueError) as error:
            if scope == self.scope:
                self.notice(str(error), RED)
            return
        if scope == self.scope and self.screen is self.screen_stack[0] and self.cursor_device() == device:
            self.push_screen(
                PlaceDialog(detail, scope.exam_id, self.owner, manual=self.manual_placement),
                lambda action: self.place_action(scope, detail, action),
            )

    def place_action(self, scope, detail, action):
        if action is None or scope != self.scope:
            return
        if action == "details":
            self.push_screen(MessageDialog("Технический отчёт", json.dumps(detail, ensure_ascii=False, indent=2)))
            return
        device = detail["deviceId"]
        fields = {"deviceId": device}
        if action == "bind" and self.manual_placement:
            self.push_screen(
                ConfirmDialog("Назначить студента", self.scoped_message(f"Рабочее место {device}"),
                              prompt="Фамилия Имя", value=detail["student"] or ""),
                lambda answer: self.change(scope, "bind", **fields, student=answer) if answer else None,
            )
            return
        if action == "move" and self.manual_placement:
            self.push_screen(
                ConfirmDialog("Пересадить студента", self.scoped_message(f"{detail['student']} — {device}"),
                              prompt="Номер нового ПК"),
                lambda answer: self.change(scope, "move", **fields, destination=answer) if answer else None,
            )
            return
        if action == "dismiss-alert":
            if not self.owner:
                return
            alert = next((alert for alert in detail["alerts"] if alert["current"] and alert["status"] in ("received", "shown")), None)
            if not alert:
                self.notice("На этом ПК нет актуальной тревоги", YELLOW)
                return
            target = {key: alert[key] for key in (*SESSION_FIELDS, "alertId")}
            fields["target"] = target
            action = "dismiss"
            title = "Снять текущую тревогу"
            question = f"{device} · {alert_label(alert)}\nТекущий Guest · событие {alert['alertId']}"
        elif action in ("guest", "submit"):
            guest = detail["guestObservation"]
            exited = action == "submit" and detail.get("canSubmitAfterExit")
            if action == "guest":
                student = student_for_guest(detail, manual=self.manual_placement)
            else:
                student = place_student(detail, manual=self.manual_placement)
            if exited:
                session = detail["lastGuestExit"]
                name = session["student"]
            elif guest and guest["state"] == "present" and student:
                session = guest
                name = student
            else:
                self.notice("Требуется подтверждённый сеанс Guest", YELLOW)
                return
            fields["target"] = {key: session[key] for key in SESSION_FIELDS}
            place = f"{name} — {device}"
            if action == "guest":
                title = "Подтвердить место и текущий Guest"
                question = f"{place}\nМесто сверено, контрольное чтение запрещено, проект доступен, Wazuh готов?"
                fields["checks"] = ["file", "project", "wazuh"]
            else:
                title = "Отметить сверку сдачи"
                state = "Guest вышел." if exited else "Guest открыт."
                question = f"{place}\n{state} Вы сверили сдачу этого студента в PrairieLearn?"
        else:
            return
        self.push_screen(
            ConfirmDialog(title, self.scoped_message(question)),
            lambda accepted: self.change(scope, action, **fields) if accepted else None,
        )

    @work
    async def change(self, scope, action, **fields):
        if scope != self.scope:
            return
        if not self.connected or self.mutating:
            self.notice("Подождите восстановления связи или окончания текущего действия", YELLOW)
            return
        self.mutating = True
        self.update_selection()
        self.notice("Контроллер принимает действие…", YELLOW)
        try:
            result = await self.request(scope, action, **fields)
        except (OSError, ValueError) as error:
            self.notice(str(error), RED)
            self.push_screen(MessageDialog("Действие не подтверждено", str(error)))
        else:
            if action in ("exam", "normal"):
                group = GroupDialog(action, result, scope.exam_id, owner=self.owner, manual=self.manual_placement)
                self.active_group = group
                await self.push_screen(group, self.close_group)
                group.update_reports({})
            notes = {
                "bind": "Студент назначен", "move": "Студент пересажен", "guest": "Текущий Guest подтверждён",
                "submit": "Отметка о сверке в PrairieLearn записана.",
                "dismiss": "Снятие запрошено. Ожидается подтверждение ПК.",
            }
            self.notice(notes.get(action, "Результаты назначения обновляются по отчётам ПК"), CYAN)
        finally:
            self.mutating = False
            self.update_selection()
            self.reload()

    def close_group(self, _):
        self.active_group = None

    def on_button_pressed(self, event):
        action = event.button.id
        if action == "mark":
            self.action_toggle_mark()
        elif action == "mark-exam":
            self.action_mark_exam()
        elif action in ("exam", "normal"):
            self.action_group(action)
        elif action == "actions":
            self.open_place()
        elif action == "help":
            self.action_help()
        elif action == "switch-exam":
            self.action_switch_exam()


def main():
    parser = argparse.ArgumentParser(description="Рабочие места экзамена")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--exam", required=True)
    parser.add_argument("--file-trace-exam", help="Дополнительный экзамен с записью файлов для владельца")
    parser.add_argument("--manual-pilot", action="store_true", help="Ручная рассадка для сопровождаемой пробы владельца")
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.exam.startswith(FILE_TRACE_PREFIX):
        parser.error("Укажите обычный идентификатор в --exam, а file-trace-* передайте через --file-trace-exam")
    if args.file_trace_exam is not None and not FILE_TRACE_ID.fullmatch(args.file_trace_exam):
        parser.error("--file-trace-exam требует идентификатор вида file-trace-20261124")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        parser.exit(1, "Для панели нужен терминал. При подключении по SSH используйте -t.\n")
    ExamTUI(args).run()


if __name__ == "__main__":
    main()
