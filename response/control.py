"""Narrow local control socket for the unprivileged dashboard."""
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import stat
import struct
import sqlite3
import threading


def management_token(state):
    path = Path(state) / 'dashboard-token'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Dashboard token must be a private regular file owned by the worker')
    else:
        with os.fdopen(fd, 'w') as output:
            output.write(secrets.token_urlsafe(32))
            output.flush()
            os.fsync(output.fileno())
    token = path.read_text().strip()
    if len(token) < 32:
        raise ValueError('Invalid dashboard token file')
    return token


def overview(queue):
    queue.db.row_factory = sqlite3.Row
    requests = [dict(r) for r in queue.db.execute('SELECT * FROM requests ORDER BY created DESC LIMIT 500')]
    for row in requests:
        row['response'] = json.loads(row['response'])
        row['target'] = json.loads(row['target'])
    audit = [dict(r) for r in queue.db.execute('SELECT * FROM audit ORDER BY seq DESC LIMIT 500')]
    count = queue.db.execute("SELECT COUNT(*) FROM requests WHERE status='pending'").fetchone()[0]
    return {'requests': requests, 'audit': audit, 'pending_count': count, 'limit': 500}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        try:
            _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in self.server.allowed_uids:
                raise ValueError('Unauthorized control socket client')
            line = self.rfile.readline(65537)
            if len(line) > 65536:
                raise ValueError('Control request too large')
            request = json.loads(line)
            command = request.get('command')
            queue = self.server.factory()
            try:
                with self.server.lock:
                    if command == 'overview':
                        result = overview(queue)
                    elif command in ('approve', 'reject', 'pause', 'resume'):
                        token = request.get('token')
                        local_admin = request.get('cli') is True and uid == self.server.owner_uid and command in ('pause', 'resume')
                        if not local_admin and (not isinstance(token, str) or not hmac.compare_digest(token, self.server.token)):
                            self.wfile.write(b'{"error":"Management token required","code":403}\n')
                            return
                        request_id = request.get('id', '')
                        if not isinstance(request_id, str) or not re.fullmatch('[0-9a-f]{64}', request_id):
                            raise ValueError('Invalid response request ID')
                        actor = ('CLI uid=' if local_admin else 'dashboard uid=') + str(uid)
                        if command in ('pause', 'resume'):
                            status = queue.preservation_state(request_id, command == 'resume', actor=actor)
                        else:
                            queue.decide(request_id, command == 'approve', actor=actor)
                            status = 'queued' if command == 'approve' else 'rejected'
                        result = {'status': status, 'id': request_id}
                    else:
                        raise ValueError('Unsupported control command')
            finally:
                queue.db.close()
            self.wfile.write(json.dumps({'result': result}).encode() + b'\n')
        except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
            self.wfile.write(json.dumps({'error': str(error), 'code': 409}).encode() + b'\n')


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, factory, token, dashboard_uid=None, dashboard_gid=None, lock=None):
        path = Path(path)
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Control socket directory must be owned by worker and not writable by others')
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError('Refusing to replace unexpected control socket path')
            # systemd starts only one worker; refuse to unlink a live listener.
            with socket.socket(socket.AF_UNIX) as probe:
                try:
                    probe.connect(str(path))
                except ConnectionRefusedError:
                    path.unlink()
                else:
                    raise ValueError('Control socket already active')
        self.factory, self.token = factory, token
        self.lock = lock or threading.RLock()
        self.owner_uid = os.geteuid()
        self.allowed_uids = {os.geteuid()}
        if dashboard_uid is not None:
            self.allowed_uids.add(dashboard_uid)
        super().__init__(str(path), Handler)
        os.chmod(path, 0o660)
        if dashboard_gid is not None:
            os.chown(path.parent, -1, dashboard_gid)
            os.chown(path, -1, dashboard_gid)
        self.path = path

    def server_close(self):
        super().server_close()
        self.path.unlink(missing_ok=True)


def call(path, request):
    request = dict(request, cli=True)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(30)
        connection.connect(str(path))
        connection.sendall(json.dumps(request).encode() + b'\n')
        with connection.makefile('rb') as stream:
            result = json.loads(stream.readline(65537))
        if 'error' in result:
            raise ValueError(result['error'])
        return result['result']
