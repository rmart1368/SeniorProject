"""Durable Linux response queue. Only local collector journal records are trusted input."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import threading

OPERATION_LOCK = threading.RLock()

UNITS = ('chompedr-ssh.service', 'chompedr-processes.service', 'chompedr-files.service')
ACTIONS = {'block_ip', 'terminate_process', 'suspend_process', 'quarantine_file', 'delete_file', 'preserve_file'}
MODES = {'dry_run', 'automatic', 'approval_required'}


def field(event, path):
    if not isinstance(path, str) or not path or any(not x or any(c.isspace() for c in x) for x in path.split('.')):
        raise ValueError('Invalid target field path')
    for part in path.split('.'):
        event = event[part]
    return event


def file_parent(path):
    """Open each parent without following symlinks; caller owns returned descriptor."""
    if not isinstance(path, str) or not path.startswith('/') or path == '/' or '\x00' in path:
        raise ValueError('File target must be an absolute path')
    parts = path.split('/')[1:]
    if any(x in ('', '.', '..') for x in parts):
        raise ValueError('File target must not contain empty or relative components')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def resolve(response, event):
    action = response['action']
    target = response['target']
    if action == 'preserve_file':
        raise ValueError('preserve_file must be armed from the configured preservation rule source before changes occur')
    if action not in ACTIONS:
        raise ValueError('Unsupported action: ' + str(action))
    if action in ('terminate_process', 'suspend_process'):
        pid = field(event, target['pid_field'])
        ticks = field(event, target['start_time_field'])
        if type(pid) is not int or pid <= 1 or pid == os.getpid() or type(ticks) is not int or ticks < 0:
            raise ValueError('Process target requires PID > 1 and nonnegative start ticks')
        return {'pid': pid, 'start_ticks': ticks}
    value = field(event, target['field'])
    if action == 'block_ip':
        if not isinstance(value, str):
            raise ValueError('IP target must be a string')
        address = ipaddress.ip_address(value)
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError('Loopback, unspecified and multicast addresses are protected')
        return {'ip': str(address)}
    parent, name = file_parent(value)
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('File target must be a regular file with one link')
        expected = event.get('file', {}).get('after') or {}
        # Require event-time identity, not merely the file found after journal delay.
        if (expected.get('inode') != info.st_ino or expected.get('device') != info.st_dev
                or expected.get('size') != info.st_size
                or expected.get('modified_seconds', -1) * 1000000000 + expected.get('modified_nanoseconds', -1) != info.st_mtime_ns):
            raise ValueError('File action requires matching event file.after identity and modification time')
        return {'path': value, 'identity': identity(info)}
    finally:
        os.close(parent)


def execute(response, target, state, request_id):
    action = response['action']
    if action == 'preserve_file':
        from preserve import activate
        return activate(state, request_id, target['path'], refresh=target.get('refresh_baseline', False))
    if action in ('terminate_process', 'suspend_process'):
        pid = target['pid']
        # pidfd pins the process across the identity check and signal delivery.
        fd = os.pidfd_open(pid)
        try:
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[19]) != target['start_ticks']:
                raise ValueError('Process identity changed')
            signal.pidfd_send_signal(fd, signal.SIGTERM if action == 'terminate_process' else signal.SIGSTOP)
        finally:
            os.close(fd)
        return 'Signal delivered; termination is not guaranteed'
    if action == 'block_ip':
        raw = response.get('duration')
        timeout = None
        if raw is not None:
            if not isinstance(raw, str) or len(raw) < 2 or raw[-1] not in 'smhd' or not raw[:-1].isascii() or not raw[:-1].isdigit() or not 0 < int(raw[:-1]) <= 4294967295:
                raise ValueError('Invalid block duration')
            timeout = int(raw[:-1]) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[raw[-1]]
        address = ipaddress.ip_address(target['ip'])
        rule = f'rule family="ipv{address.version}" source address="{address}" drop'
        command = ['/usr/bin/firewall-cmd', '--add-rich-rule=' + rule]
        if timeout is not None:
            command.append('--timeout=' + str(timeout))
        subprocess.run(command, check=True, capture_output=True, timeout=15)
        return 'Runtime firewalld block installed' + (' with timeout' if timeout else ' until firewall reload/reboot or manual removal')
    if action not in ('delete_file', 'quarantine_file'):
        raise ValueError('Unsupported action')
    parent, name = file_parent(target['path'])
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if identity(info) != target['identity'] or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('File identity changed since request was queued')
        quarantine = state / 'quarantine'
        quarantine.mkdir(mode=0o700, exist_ok=True)
        destination = quarantine / request_id
        if destination.exists():
            raise ValueError('Quarantine destination already exists')
        # Atomic rename; cross-filesystem operations deliberately fail, never copy/delete.
        os.rename(name, destination, src_dir_fd=parent)
        moved = os.stat(destination, follow_symlinks=False)
        # Rename changes ctime. Compare the remaining captured identity fields.
        if identity(moved)[:4] != target['identity'][:4] or not stat.S_ISREG(moved.st_mode):
            raise ValueError('File changed during rename; retained in quarantine for manual review')
        if action == 'delete_file':
            destination.unlink()
            return 'Deleted verified file'
        return 'Quarantined at ' + str(destination)
    finally:
        os.close(parent)


class Queue:
    def __init__(self, state, executor=execute):
        self.state = Path(state).absolute()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in [self.state, *self.state.parents]:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError('State path must not contain symlinks')
        info = self.state.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('State directory must be owned by current user with mode 0700')
        self.executor = executor
        self.db = sqlite3.connect(self.state / 'responses.sqlite3', timeout=30)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, rule_id TEXT, response TEXT, target TEXT, status TEXT, detail TEXT, created REAL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, id TEXT, status TEXT, detail TEXT, at REAL);
CREATE TABLE IF NOT EXISTS progress(key TEXT PRIMARY KEY, value TEXT);
''')

    def transition(self, request_id, status, detail):
        self.db.execute('UPDATE requests SET status=?, detail=? WHERE id=?', (status, detail, request_id))
        self.db.execute('INSERT INTO audit(id,status,detail,at) VALUES(?,?,?,?)', (request_id, status, detail, time.time()))

    def ingest(self, record):
        if record.get('_SYSTEMD_UNIT') not in UNITS or not isinstance(record.get('__CURSOR'), str):
            return
        try:
            alert = json.loads(record.get('MESSAGE', ''))
        except (ValueError, TypeError):
            return
        if not isinstance(alert, dict) or not isinstance(alert.get('response', []), list):
            return
        with self.db:
            for index, response in enumerate(alert.get('response', [])):
                key = json.dumps([record['_SYSTEMD_UNIT'], alert.get('alert_id', record['__CURSOR']), index, response], sort_keys=True)
                request_id = hashlib.sha256(key.encode()).hexdigest()
                if self.db.execute('SELECT 1 FROM requests WHERE id=?', (request_id,)).fetchone():
                    continue
                target = None
                status = 'failed'
                try:
                    if response.get('mode', 'dry_run') not in MODES:
                        raise ValueError('Unknown response mode')
                    target = resolve(response, alert['event'])
                    mode = response.get('mode', 'dry_run')
                    status = {'automatic': 'queued', 'approval_required': 'pending', 'dry_run': 'dry_run'}[mode]
                    detail = 'Target captured; mode=' + mode
                except (ValueError, KeyError, TypeError, OSError) as error:
                    detail = str(error)
                self.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)', (request_id, alert.get('rule_id'), json.dumps(response), json.dumps(target), status, detail, time.time()))
                self.db.execute('INSERT INTO audit(id,status,detail,at) VALUES(?,?,?,?)', (request_id, status, detail, time.time()))
            self.db.execute('INSERT OR REPLACE INTO progress VALUES(?,?)', ('cursor', record['__CURSOR']))

    def decide(self, request_id, approve, actor=None):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT status FROM requests WHERE id=?', (request_id,)).fetchone()
            if row is None or row[0] != 'pending':
                raise ValueError('Only a pending request can be approved or rejected')
            self.transition(request_id, 'queued' if approve else 'rejected', ('Operator approved' if approve else 'Operator rejected') + '; ' + (actor or 'CLI uid=' + str(os.geteuid())))

    def preservation_state(self, request_id, resume, actor=None):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT response,target,status FROM requests WHERE id=?', (request_id,)).fetchone()
            if row is None or json.loads(row[0])['action'] != 'preserve_file':
                raise ValueError('Request is not a preservation guard')
            if row[2] != ('paused' if resume else 'active'):
                raise ValueError('Only an active guard can pause, and only a paused guard can resume')
            response, target = json.loads(row[0]), json.loads(row[1])
            if resume:
                target['refresh_baseline'] = True
                self.db.execute('UPDATE requests SET target=? WHERE id=?', (json.dumps(target), request_id))
            status = ('pending' if response.get('mode') == 'approval_required' else 'queued') if resume else 'paused'
            detail = ('Resume requested; capture a new baseline at activation' if resume else 'Preservation paused for maintenance')
            self.transition(request_id, status, detail + '; ' + (actor or 'CLI uid=' + str(os.geteuid())))
            return status

    def run_one(self):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute("SELECT id,response,target FROM requests WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None:
                return False
            request_id, response, target = row
            self.transition(request_id, 'executing', 'Claimed; interrupted execution requires manual investigation, never automatic retry')
        try:
            detail = self.executor(json.loads(response), json.loads(target), self.state, request_id)
            status = 'active' if json.loads(response)['action'] == 'preserve_file' else 'succeeded'
        except Exception as error:
            status, detail = 'failed', str(error)
        with self.db:
            self.transition(request_id, status, detail)
        print(json.dumps({'response_id': request_id, 'status': status, 'detail': detail}), flush=True)
        return True

    def rows(self, audit=False):
        self.db.row_factory = sqlite3.Row
        rows = [dict(row) for row in self.db.execute('SELECT * FROM ' + ('audit ORDER BY seq' if audit else 'requests ORDER BY created'))]
        if not audit:
            for row in rows:
                row['response'] = json.loads(row['response'])
                row['target'] = json.loads(row['target'])
        return rows


def follow(queue, preservation=None):
    import selectors
    cursor = queue.db.execute("SELECT value FROM progress WHERE key='cursor'").fetchone()
    command = ['/usr/bin/journalctl', '--follow', '--output=json', '--no-pager', '--lines=all']
    command += ['--after-cursor=' + cursor[0]] if cursor else ['--since=-60s']
    for unit in UNITS:
        command += ['--unit', unit]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as journal:
        try:
            os.set_blocking(journal.stdout.fileno(), False)
            buffer = b''
            with selectors.DefaultSelector() as selector:
                selector.register(journal.stdout, selectors.EVENT_READ)
                while journal.poll() is None:
                    with OPERATION_LOCK:
                        if preservation is not None:
                            try:
                                preservation.tick()
                            except Exception as error:
                                print('Preservation error: ' + str(error), file=sys.stderr, flush=True)
                        for _ in range(100):
                            if not queue.run_one():
                                break
                    for key, _ in selector.select(1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            continue
                        buffer += chunk
                        if len(buffer) > 8 * 1024 * 1024:
                            raise ValueError('Journal record exceeded 8 MiB')
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            queue.ingest(json.loads(line))
            raise RuntimeError('Journal follower exited: ' + str(journal.returncode))
        finally:
            if journal.poll() is None:
                journal.terminate()
            journal.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=Path('/var/lib/chomp-edr/responses'))
    parser.add_argument('--preserve-rules', type=Path, default=Path('/etc/chomp-edr/preserve.yaml'))
    parser.add_argument('--binary', type=Path, default=Path('/usr/local/lib/chomp-edr/chompedr'))
    parser.add_argument('--socket', type=Path, default=Path('/run/chomp-edr-response/control.sock'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('follow', help='Consume trusted local collector journal records and execute queued actions')
    sub.add_parser('list')
    sub.add_parser('audit')
    sub.add_parser('dashboard-token', help='Display the private browser approval token to the administrator')
    for name in ('approve', 'reject', 'pause', 'resume'):
        sub.add_parser(name).add_argument('id')
    args = parser.parse_args()
    os.umask(0o077)
    queue = Queue(args.state)
    if args.command == 'follow':
        import pwd
        from control import ControlServer, management_token
        import threading
        try:
            account = pwd.getpwnam('chompedr-dashboard')
        except KeyError:
            account = None
        control = ControlServer(args.socket, lambda: Queue(args.state), management_token(queue.state),
                                account.pw_uid if account else None, account.pw_gid if account else None, lock=OPERATION_LOCK)
        thread = threading.Thread(target=control.serve_forever, daemon=True)
        thread.start()
        try:
            from preserve import Manager
            follow(queue, Manager(queue, args.preserve_rules, args.binary))
        finally:
            control.shutdown()
            control.server_close()
    elif args.command == 'dashboard-token':
        from control import management_token
        print(management_token(queue.state))
    elif args.command in ('pause', 'resume'):
        # Live control is required so a pause cannot race a restoration in progress.
        from control import call
        print(json.dumps(call(args.socket, {'command': args.command, 'id': args.id})))
    elif args.command in ('approve', 'reject'):
        queue.decide(args.id, args.command == 'approve')
        print('Decision saved; the response service executes approved requests.')
    else:
        print(json.dumps(queue.rows(args.command == 'audit'), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
