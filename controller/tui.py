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


GREEN, YELLOW, RED, CYAN = "#8fedaf", "#ffd482", "#ff8697", "#8ae8ed"
REPORT = {
    "pending": ("ожидает", YELLOW), "offline": ("нет связи", RED),
    "applied": ("применён", GREEN), "source-applied": ("применён", GREEN),
    "blocked": ("отказ", RED), "error": ("ошибка", RED),
    "overridden": ("локальный", CYAN),
}
ALERT = {
    "received": ("Получена", RED), "shown": ("На экране", RED),
    "acknowledged": ("Снята", GREEN), "requested": ("Снимается", YELLOW),
    "expired": ("Просрочена", RED), "session-ended": ("Сеанс завершён", "dim"),
}
ALERT_BRIEF = {"shown": "Экран", "requested": "Снятие", "expired": "Истекла", "session-ended": "Закрыта"}
ALERT_REASON = {"control-signal": "контрольный сигнал", "canary-read": "чтение контрольного файла"}
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
E  Назначить экзамен    N  Вернуть в обычный режим
Tab  Перейти к кнопкам   R  Обновить   F1  Справка   Q  Выйти

Мышь выбирает строку и нажимает кнопки. Повторный щелчок по строке открывает её действия.
Если ПК отмечены, «Экзамен» и «Обычный» действуют на всю отмеченную группу. Иначе используется текущая строка.
«Обычный» после экзамена требует подтверждённой сдачи и выхода Guest. Режим виден по свежему отчёту ПК.
В узком окне Э означает экзамен, О — обычный режим.
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


def alert_label(alert):
    return ALERT_REASON.get(alert["reason"], alert["reason"])


def place_state(row, exam_id):
    if row["reportReason"] == "local-normal-source-confirmed":
        return "Ограничения сняты локально. Проверьте обычный вход.", CYAN
    if row["reportStatus"] == "offline":
        return "Нет свежей связи с ПК", RED
    if row["examId"] and row["examId"] != exam_id:
        return f"Другой экзамен — {row['examId']}", YELLOW
    if row["assignedMode"] == "normal":
        if row["reportStatus"] in ("applied", "source-applied"):
            return "Ограничения сняты. Проверьте обычный вход.", GREEN
        label, color = REPORT[row["reportStatus"]]
        return f"Обычный режим · {label}", color
    if row["submitted"]:
        if row["guestState"] == "absent":
            return "Сдача подтверждена, Guest вышел. Доступен обычный режим.", GREEN
        return "Сдача подтверждена. Дождитесь выхода Guest.", GREEN
    if row["guestReady"]:
        return "Guest подтверждён. Можно начинать.", GREEN
    if row["machineReady"]:
        if row["guestState"] == "present":
            return "Guest открыт. Подтвердите место и проверки.", YELLOW
        return "ПК готов. Можно входить в Guest.", GREEN
    label, color = REPORT[row["reportStatus"]]
    return f"Экзамен · {label}", color


def place_information(row, exam_id, *, compact=False):
    state, color = place_state(row, exam_id)
    result = Text()
    result.append(state, color)
    alert = row["alert"]
    if alert and alert["current"]:
        label, color = ALERT[alert["status"]]
        result.append("\n")
        result.append(f"Тревога · {label} · {alert_label(alert)}", color)
    if not compact or not (alert and alert["current"]):
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
    def __init__(self, detail, exam_id, owner):
        super().__init__()
        self.detail = detail
        self.exam_id = exam_id
        self.owner = owner

    def compose(self) -> ComposeResult:
        row = self.detail
        name = f"{row['student'] or 'Свободное место'} — {row['deviceId']}"
        can_dismiss = any(alert["current"] and alert["status"] in ("received", "shown") for alert in row["alerts"])
        guest_present = row["guestState"] == "present" and bool(row["student"])
        with Vertical(classes="dialog"):
            yield Static(name, classes="dialog-title", markup=False)
            with VerticalScroll(classes="dialog-content"):
                yield Static(place_information(row, self.exam_id), markup=False)
            with Horizontal(classes="button-row"):
                yield Button("Назначить ФИО", id="bind")
                yield Button("Пересадить", id="move", disabled=not row["student"])
                yield Button("Подтвердить Guest", id="guest", disabled=not (guest_present and row["machineReady"]))
            with Horizontal(classes="button-row"):
                yield Button("Сдача", id="submit", variant="success", disabled=not row["guestReady"])
                if self.owner:
                    yield Button("Снять тревогу", id="dismiss-alert", variant="error", disabled=not can_dismiss)
                yield Button("Отчёт", id="details")
                yield Button("Закрыть", id="close")

    def on_button_pressed(self, event):
        self.dismiss(None if event.button.id == "close" else event.button.id)


class GroupDialog(MessageDialog):
    def __init__(self, mode, results, exam):
        super().__init__("Экзамен · результаты по ПК" if mode == "exam" else "Обычный режим · результаты по ПК", "")
        self.mode = mode
        self.results = results
        self.exam = exam

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
                    state, style = place_state(row, self.exam)
                    if entry["status"] == "unchanged":
                        report.append(f"{label} · ", color)
                    report.append(state, style)
                else:
                    report.append(f"{label} · ждём свежий отчёт ПК", color)
            report.append("\n")
        self.query_one("#message", Static).update(report)


class ExamTUI(App):
    ENABLE_COMMAND_PALETTE = False
    POLL_SECONDS = 3.0
    CSS = """
    Screen { background: #101822; color: #e6edf3; }
    #banner { height: 1; background: #245574; color: #f0f8ff; padding: 0 1; text-style: bold; }
    #scope-controls { height: 1; margin: 0 1; background: #192b3a; }
    #scope-state { width: 1fr; height: 1; padding-left: 1; text-wrap: nowrap; }
    #switch-exam { margin: 0; }
    #summary { height: 1; padding: 0 1; margin-top: 1; color: #9be4e9; }
    #places-panel { height: 1fr; min-height: 3; margin: 0 1; border: round #416477; }
    #places { height: 1fr; background: #14232e; color: #edf4f8; scrollbar-size: 1 1; }
    #places > .datatable--header { background: #254451; color: #d7eff2; text-style: bold; }
    #places > .datatable--odd-row { background: #182b36; }
    #places > .datatable--cursor { background: #355873; color: #ffffff; text-style: bold; }
    #places > .datatable--hover { background: #263d4c; }
    #places-empty { height: 1; padding: 0 1; color: #bbd0dc; }
    #selected { height: 4; padding: 0 1; margin: 0 1; color: #e6edf3; background: #192b3a; }
    #notice { height: 1; padding: 0 1; color: #bfd0da; }
    #key-hint { height: 1; padding: 0 1; background: #245574; color: #f0f8ff; }
    .toolbar { height: 1; grid-size: 6 1; grid-gutter: 0 1; margin: 0 1 1 1; }
    .toolbar Button { width: 100%; margin: 0; }
    .button-row { height: 1; }
    Button { border: none !important; height: 1; min-width: 4; width: auto; margin-right: 1; }
    Button:focus { text-style: bold underline; }
    Dialog { background: #101822 80%; align: center middle; }
    .dialog { width: 68; max-width: 96%; height: auto; max-height: 94%;
              padding: 1 2; border: round #67b9d1; background: #182a38; }
    .dialog-title { color: #b6f0ff; text-style: bold; height: auto; margin-bottom: 1; }
    .dialog-content { height: auto; max-height: 14; margin-bottom: 1; scrollbar-size: 1 1; }
    .dialog-content Static { height: auto; }
    .dialog .button-row { margin-top: 1; }
    #input-error { height: auto; color: #ff818c; }
    #answer { height: 3; }
    Screen.compact .toolbar { grid-size: 3 2; height: 2; margin: 0 1; }
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
        self.args = args
        self.file_trace_exam = getattr(args, "file_trace_exam", None)
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
            yield Button("Экзамен", id="exam", variant="primary")
            yield Button("Обычный", id="normal", variant="success")
            yield Button("Действия", id="actions")
            yield Button("Справка", id="help")
        yield Static("↑↓ Место  Enter Действия  Space Отметить  R Обновить  Q Выйти", id="key-hint", markup=False)

    @property
    def table(self):
        return self.query_one("#places", DataTable)

    @property
    def file_trace_active(self):
        return self.scope.exam_id == self.file_trace_exam

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
        banner = Text(" EXAM LAB ", style="bold white on #356986")
        banner.append(f"  {self.scope.exam_id} · {self.args.version[:12]}")
        if self.owner:
            banner.append("  ·  Владелец", "bold #cef0b8")
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
        ready = sum(row["guestReady"] for row in rows)
        compact = self.terminal_width < 72
        divider = " · " if compact else "  ·  "
        line = Text(f"Сеть {fresh}/{len(rows)}{divider}Guest {ready}{divider}")
        line.append(f"{'Трев.' if compact else 'Тревоги'} {alerts}", f"bold {RED}" if alerts else "")
        line.append(f"{divider}Метки {len(self.marked)}{divider}")
        stamp = self.updated.strftime("%H:%M:%S") if self.updated else None
        if self.connected:
            line.append(f"Связь {stamp}", GREEN)
        else:
            line.append(f"Сводка {stamp} устарела" if stamp else "Связь…", YELLOW)
        self.query_one("#summary", Static).update(line)
        self.update_selection()

    def update_selection(self):
        device = self.cursor_device()
        row = self.rows.get(device)
        if row:
            heading = f"{row['student'] or 'Свободное место'} — {device}"
            info = Text(overflow="ellipsis", no_wrap=True)
            info.append(heading, "bold #b6f0ff")
            info.append("\n")
            info.append_text(place_information(row, self.scope.exam_id, compact=True))
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

    def table_values(self, row, widths):
        _, place_width, installation_width, report_width, alert_width = widths
        device = row["deviceId"]
        mark = Text("✓", f"bold {GREEN}") if device in self.marked else Text("·", "dim")
        device_label = Text(device, style="bold #b6f0ff")
        device_label.truncate(max(7, place_width // 2), overflow="ellipsis")
        student = Text(row["student"] or "—", style="" if row["student"] else "dim")
        student.truncate(place_width - device_label.cell_len - 3, overflow="ellipsis")
        person = student.append(" — ").append_text(device_label)
        installation_symbol, color, _ = INSTALLATION[row["installation"]["status"]]
        installation = Text(installation_symbol, color)
        version = row["installation"].get("version")
        if version:
            installation.append(f" {version[:installation_width - 2]}")
        elif row["connection"] != "fresh":
            installation = Text("—", "dim")
        report, color = REPORT[row["reportStatus"]]
        mode = "Экз." if row["assignedMode"] == "exam" else "Обыч."
        if report_width < 15:
            mode = mode[0]
        if row["reportReason"] == "local-normal-source-confirmed":
            report = "снят локально" if report_width >= 15 else "лок. снят"
        elif row["examId"] and row["examId"] != self.scope.exam_id:
            report, color = "другой", YELLOW
        alert = row["alert"]
        label, alert_color = "—", "dim"
        if alert and (alert["current"] or (row["examId"] == self.scope.exam_id and alert["status"] == "acknowledged")):
            label, alert_color = ALERT[alert["status"]]
            if alert_width < 12:
                label = ALERT_BRIEF.get(alert["status"], label)
        return mark, person, installation, Text(f"{mode} {report}", color), Text(label, alert_color)

    def render_table(self):
        table = self.table
        # The panel has one cell of margin and one border cell on each side.
        available = max(51, self.terminal_width - 4)
        # A cell has padding on both sides. One column is reserved for the scrollbar.
        widths = (1, available - 48, 10, 16, 10)
        if available < 69:
            widths = (1, available - 39, 6, 13, 8)
        labels = ("•", "Студент — ПК", "Версия", "Режим", "Тревога")
        ids = tuple(self.rows)
        current = self.cursor_device()
        old_index = table.cursor_row
        old_y = table.scroll_y
        if ids != self.shown_ids or widths != self.columns:
            table.clear(columns=True)
            for i, (label, width) in enumerate(zip(labels, widths)):
                table.add_column(label, width=width, key=str(i))
            for device in ids:
                table.add_row(*self.table_values(self.rows[device], widths), key=device)
            self.columns = widths
            self.shown_ids = ids
            if ids:
                new_index = ids.index(current) if current in self.rows else min(old_index, len(ids) - 1)
                table.move_cursor(row=new_index, scroll=False)
                table.call_after_refresh(table.scroll_to, y=max(0, old_y + new_index - old_index), animate=False)
        else:
            for device in ids:
                for i, value in enumerate(self.table_values(self.rows[device], widths)):
                    column = str(i)
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
        title = "Назначить экзамен" if mode == "exam" else "Вернуть в обычный режим"
        scope = self.scope
        self.push_screen(
            ConfirmDialog(title, self.scoped_message(f"ПК: {', '.join(selection)}")),
            lambda accepted: self.change(scope, mode, devices=selection) if accepted else None,
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
            self.push_screen(PlaceDialog(detail, scope.exam_id, self.owner), lambda action: self.place_action(scope, detail, action))

    def place_action(self, scope, detail, action):
        if action is None or scope != self.scope:
            return
        if action == "details":
            self.push_screen(MessageDialog("Технический отчёт", json.dumps(detail, ensure_ascii=False, indent=2)))
            return
        device = detail["deviceId"]
        fields = {"deviceId": device}
        if action == "bind":
            self.push_screen(
                ConfirmDialog("Назначить студента", self.scoped_message(f"Рабочее место {device}"),
                              prompt="Фамилия Имя", value=detail["student"] or ""),
                lambda answer: self.change(scope, "bind", **fields, student=answer) if answer else None,
            )
            return
        if action == "move":
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
        else:
            guest = detail["guestObservation"]
            if not guest or guest["state"] != "present" or not detail["student"]:
                self.notice("Назначьте студента и откройте Guest", YELLOW)
                return
            fields["target"] = {key: guest[key] for key in SESSION_FIELDS}
            name = f"{detail['student']} — {device}"
            if action == "guest":
                title = "Подтвердить место и текущий Guest"
                question = f"{name}\nМесто сверено, контрольное чтение запрещено, проект доступен, Wazuh готов?"
                fields["checks"] = ["file", "project", "wazuh"]
            else:
                title = "Подтвердить сдачу"
                question = f"{name}\nPrairieLearn подтвердил сдачу в текущем Guest?"
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
                group = GroupDialog(action, result, scope.exam_id)
                self.active_group = group
                await self.push_screen(group, self.close_group)
                group.update_reports({})
            notes = {
                "bind": "Студент назначен", "move": "Студент пересажен", "guest": "Текущий Guest подтверждён",
                "submit": "Сдача подтверждена. Дождитесь выхода Guest.",
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
