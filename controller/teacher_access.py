from contextlib import contextmanager
import errno
import json
import os
from socket import AF_UNIX, SO_PEERCRED, SOL_SOCKET, SOCK_STREAM, socket
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer
import stat
import struct
from threading import Thread


# Групповое завершение передаёт до 100 целей с идентификатором сеанса у каждой.
MAX_TEACHER_REQUEST = 32768
PEER_CREDENTIALS = struct.Struct("=iII")


class TeacherHandler(StreamRequestHandler):
    timeout = 5

    def handle(self):
        _, uid, _ = PEER_CREDENTIALS.unpack(
            self.connection.getsockopt(SOL_SOCKET, SO_PEERCRED, PEER_CREDENTIALS.size)
        )
        try:
            if uid not in self.server.allowed_uids:
                raise PermissionError("Эта учётная запись не допущена в TUI")
            payload = self.rfile.readline(MAX_TEACHER_REQUEST + 1)
            if not payload.endswith(b"\n") or len(payload) > MAX_TEACHER_REQUEST:
                raise ValueError("Недопустимый размер запроса TUI")
            try:
                request = json.loads(payload.decode("utf-8"))
            except (ValueError, RecursionError):
                raise ValueError("Некорректный запрос TUI") from None
            response = {"result": self.server.dispatch(uid, request)}
        except (ValueError, PermissionError) as error:
            response = {"error": str(error)}
        except TimeoutError:
            return
        try:
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass


def prepare_socket_path(path):
    if not path.is_absolute():
        raise ValueError("Для TUI требуется абсолютный путь Unix-сокета")
    parent = path.parent.stat()
    allowed_owners = {0, os.geteuid()}
    if parent.st_uid not in allowed_owners or parent.st_mode & 0o022:
        raise ValueError("Каталог Unix-сокета должен принадлежать root или контроллеру и запрещать запись другим")
    try:
        previous = path.lstat()
    except FileNotFoundError:
        return
    if previous.st_uid != os.geteuid() or not stat.S_ISSOCK(previous.st_mode):
        raise ValueError("Путь Unix-сокета TUI занят")
    with socket(AF_UNIX, SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(os.fspath(path))
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise
        else:
            raise ValueError("TUI уже слушает на этом пути")
    path.unlink()


@contextmanager
def serve_teacher(path, allowed_uids, dispatch):
    prepare_socket_path(path)
    with ThreadingUnixStreamServer(os.fspath(path), TeacherHandler) as server:
        server.daemon_threads = True
        server.allowed_uids = frozenset(allowed_uids)
        server.dispatch = dispatch
        try:
            path.chmod(0o666)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield
            finally:
                server.shutdown()
                thread.join()
        finally:
            path.unlink(missing_ok=True)
