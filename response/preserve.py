"""Bounded, descriptor-relative configuration baselines; never follow target symlinks."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import sys
import socket
from datetime import datetime, timezone
import uuid

MAX_ENTRIES = 10000
MAX_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 64


def parent(path):
    if not isinstance(path, str) or not path.startswith('/') or any(p in ('', '.', '..') for p in path.split('/')[1:]):
        raise ValueError('Preservation requires an absolute file/directory path other than /')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.split('/')[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def metadata(fd, info):
    attrs = {name: base64.b64encode(os.getxattr(fd, name)).decode() for name in os.listxattr(fd)}
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'mtime': info.st_mtime_ns, 'xattrs': attrs}


def snapshot(path, strict=True):
    tree, budget = {}, [0, 0]
    outer, name = parent(path)
    device = None
    def visit(directory, name, relative, depth):
        nonlocal device
        budget[0] += 1
        if budget[0] > MAX_ENTRIES or depth > MAX_DEPTH:
            raise ValueError('Preservation tree exceeds 10000 entries or 64 levels')
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            if strict:
                raise ValueError('Preservation target disappeared during capture')
            return
        if device is None:
            device = info.st_dev
            if device != os.fstat(outer).st_dev:
                raise ValueError('Preservation root must not be a mount point')
        if info.st_dev != device:
            raise ValueError('Preservation does not cross filesystem/mount boundaries')
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            if strict:
                raise ValueError('Baseline supports regular files/directories only; no symlinks or special files')
            tree[relative] = {'kind': 'other'}
            return
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (before.st_ino, before.st_dev) != (info.st_ino, info.st_dev):
                raise ValueError('Target changed during capture')
            entry = metadata(fd, before)
            if stat.S_ISDIR(before.st_mode):
                entry['kind'] = 'directory'
                tree[relative] = entry
                for child in sorted(os.listdir(fd)):
                    visit(fd, child, relative + '/' + child if relative else child, depth + 1)
            else:
                if before.st_nlink != 1:
                    if strict:
                        raise ValueError('Preservation does not support hard-linked files')
                    tree[relative] = {'kind': 'other'}
                    return
                budget[1] += before.st_size
                if budget[1] > MAX_BYTES:
                    raise ValueError('Preservation contents exceed 64 MiB')
                content = bytearray()
                while True:
                    chunk = os.read(fd, min(65536, MAX_BYTES - len(content) + 1))
                    if not chunk:
                        break
                    content.extend(chunk)
                    if len(content) > before.st_size or len(content) > MAX_BYTES:
                        raise ValueError('File grew during capture')
                entry.update(kind='file', content=base64.b64encode(content).decode())
                tree[relative] = entry
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Target changed during capture; retry when quiescent')
        finally:
            os.close(fd)
    try:
        visit(outer, name, '', 0)
        return tree
    finally:
        os.close(outer)


def restore(path, tree, observed=None):
    """Restore entries relative to pinned parent descriptors, including removal of additions."""
    outer, root = parent(path)
    budget = [0]
    device = os.fstat(outer).st_dev
    def remove(directory, name, depth=0):
        budget[0] += 1
        if budget[0] > MAX_ENTRIES * 2 or depth > MAX_DEPTH:
            raise ValueError('Removal traversal limit exceeded')
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if info.st_dev != device:
            raise ValueError('Refusing to remove a mount point')
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                for child in os.listdir(fd):
                    remove(fd, child, depth + 1)
            finally:
                os.close(fd)
            os.rmdir(name, dir_fd=directory)
        else:
            os.unlink(name, dir_fd=directory)
    def apply_metadata(fd, entry):
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (entry['uid'], entry['gid']):
            os.fchown(fd, entry['uid'], entry['gid'])
        os.fchmod(fd, entry['mode'])
        for name in os.listxattr(fd):
            if name not in entry['xattrs']:
                os.removexattr(fd, name)
        for name, value in entry['xattrs'].items():
            os.setxattr(fd, name, base64.b64decode(value))
        os.utime(fd, ns=(info.st_atime_ns, entry['mtime']))
    def put(directory, name, relative):
        entry = tree[relative]
        try:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if entry['kind'] == 'directory':
            if current is not None and not stat.S_ISDIR(current.st_mode):
                remove(directory, name)
                current = None
            if current is None:
                os.mkdir(name, mode=0o700, dir_fd=directory)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                if os.fstat(fd).st_dev != device:
                    raise ValueError('Preservation does not cross mount boundaries')
                prefix = relative + '/' if relative else ''
                children = {key[len(prefix):].split('/')[0] for key in tree if key.startswith(prefix) and key != relative}
                for child in os.listdir(fd):
                    if child not in children:
                        remove(fd, child)
                for child in sorted(children):
                    put(fd, child, prefix + child)
                apply_metadata(fd, entry)
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            if observed is not None and observed.get(relative) == entry:
                return
            if current is not None and stat.S_ISDIR(current.st_mode):
                remove(directory, name)
            temporary = '.chomp-preserve-' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                data = base64.b64decode(entry['content'])
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                apply_metadata(fd, entry)
                os.fsync(fd)
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        os.fsync(directory)
    try:
        put(outer, root, '')
    finally:
        os.close(outer)


def activate(state, request_id, path, refresh=False):
    state = Path(state).resolve()
    target = Path(path)
    if target == state or target in state.parents or state in target.parents:
        raise ValueError('Preservation target must not overlap response state')
    tree = snapshot(path)
    folder = state / 'baselines'
    folder.mkdir(mode=0o700, exist_ok=True)
    destination = folder / (request_id + '.json')
    # Only an explicit maintenance resume may replace an existing baseline.
    temporary = folder / (request_id + '.new-' + uuid.uuid4().hex) if refresh else destination
    with temporary.open('x') as output:
        os.chmod(temporary, 0o600)
        json.dump(tree, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    if refresh:
        os.replace(temporary, destination)
    directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return 'Preservation active; baseline captured for ' + path


class Manager:
    def __init__(self, queue, source, binary, loader=None):
        self.queue, self.source, self.binary = queue, Path(source), str(binary)
        self.loader = loader or self.load
        queue.db.execute('CREATE TABLE IF NOT EXISTS guards(key TEXT PRIMARY KEY, fingerprint TEXT, request_id TEXT)')
        queue.db.commit()
        saved = queue.db.execute("SELECT value FROM progress WHERE key='preserve_rules'").fetchone()
        self.last_rules = json.loads(saved[0]) if saved else []
        self.last_error = None
        self.last_observed = {}

    def load(self):
        if not self.source.exists():
            return []
        result = subprocess.run([self.binary, 'validate', '--format', 'json', '--rules', str(self.source)],
                                capture_output=True, text=True, timeout=10, check=True)
        return [json.loads(line) for line in result.stdout.splitlines()]

    @staticmethod
    def desired(rules):
        desired = {}
        for rule in rules:
            if not rule['enabled']:
                continue
            for index, response in enumerate(rule.get('response', [])):
                if response['action'] != 'preserve_file':
                    continue
                path = response['target']['path']
                key = json.dumps([rule['id'], index])
                desired[key] = (rule, response, path)
        # Validate the complete reload before releasing any existing guard.
        paths = [Path(item[2]) for item in desired.values()]
        for index, path in enumerate(paths):
            if any(path == other or path in other.parents or other in path.parents for other in paths[:index]):
                raise ValueError('Preservation targets must not overlap')
        return desired

    def tick(self):
        try:
            rules = self.loader()
            desired = self.desired(rules)
        except Exception as error:
            message = 'Preservation rule reload failed; retaining last valid rules: ' + str(error)
            if message != self.last_error:
                print(message, file=sys.stderr, flush=True)
            self.last_error = message
            if not self.last_rules:
                raise
            rules = self.last_rules
            desired = self.desired(rules)
        else:
            self.last_error = None
        q = self.queue
        self.last_rules = copy.deepcopy(rules)
        with q.db:
            q.db.execute('INSERT OR REPLACE INTO progress VALUES(?,?)', ('preserve_rules', json.dumps(rules)))
            saved = {row[0]: (row[1], row[2]) for row in q.db.execute('SELECT key,fingerprint,request_id FROM guards')}
            for key, (fingerprint, request_id) in saved.items():
                item = desired.get(key)
                current = json.dumps(item[1], sort_keys=True) if item else None
                if current != fingerprint:
                    q.transition(request_id, 'disabled', 'Preservation rule disabled/removed/changed; baseline released')
                    q.db.execute('DELETE FROM guards WHERE key=?', (key,))
            for key, (rule, response, path) in desired.items():
                fingerprint = json.dumps(response, sort_keys=True)
                if key in saved and saved[key][0] == fingerprint:
                    continue
                request_id = uuid.uuid4().hex + uuid.uuid4().hex
                mode = response.get('mode', 'dry_run')
                status = {'automatic': 'queued', 'approval_required': 'pending', 'dry_run': 'queued'}[mode]
                q.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)', (request_id, rule['id'], json.dumps(response), json.dumps({'path': path}), status, 'Preservation activation', time.time()))
                q.db.execute('INSERT INTO audit(id,status,detail,at) VALUES(?,?,?,?)', (request_id, status, 'Preservation activation; mode=' + mode, time.time()))
                q.db.execute('INSERT INTO guards VALUES(?,?,?)', (key, fingerprint, request_id))
        for key, (rule, response, path) in desired.items():
            row = q.db.execute('SELECT r.id,r.status FROM guards g JOIN requests r ON r.id=g.request_id WHERE g.key=?', (key,)).fetchone()
            if row is None or row[1] != 'active':
                continue
            try:
                self.enforce(rule, response, path, row[0])
            except Exception as error:
                detail = 'Preservation failed for ' + path + ': ' + str(error)
                print(detail, file=sys.stderr, flush=True)
                with q.db:
                    q.db.execute('INSERT INTO audit(id,status,detail,at) VALUES(?,?,?,?)', (row[0], 'preservation_error', detail, time.time()))

    def enforce(self, rule, response, path, request_id):
        q = self.queue
        baseline_path = q.state / 'baselines' / (request_id + '.json')
        baseline = json.loads(baseline_path.read_text())
        try:
            current = snapshot(path, strict=False)
        except (OSError, ValueError) as error:
            current = {"": {"kind": "unreadable", "error": str(error)}}
        if current == baseline:
            self.last_observed.pop(request_id, None)
            return
        fingerprint = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
        if response.get("mode", "dry_run") == "dry_run" and self.last_observed.get(request_id) == fingerprint:
            return
        self.last_observed[request_id] = fingerprint
        changed = sorted(p or path for p in set(current) | set(baseline) if current.get(p) != baseline.get(p))
        alert = {'rule_id': rule['id'], 'rule_name': rule['name'], 'severity': rule['severity'],
                 'event': {'timestamp': datetime.now(timezone.utc).isoformat(), 'host': socket.gethostname(),
                               'event': {'type': 'file_metadata_changed', 'action': 'preservation_violation'}, 'file': {'path': path}},
                 'preservation': {'request_id': request_id, 'changed_count': len(changed), 'changed_paths': changed[:100], 'mode': response.get('mode', 'dry_run')}}
        print(json.dumps(alert), flush=True)
        if response.get('mode', 'dry_run') != 'dry_run':
            restore(path, baseline, observed=current)
            if snapshot(path) != baseline:
                raise ValueError('Preservation restore could not be verified: ' + path)
            detail = 'Restored baseline after changes to ' + path
        else:
            detail = 'Dry run: detected changes to ' + path + '; no restoration'
        with q.db:
            q.db.execute('INSERT INTO audit(id,status,detail,at) VALUES(?,?,?,?)', (request_id, 'restored' if response.get('mode', 'dry_run') != 'dry_run' else 'dry_run', detail, time.time()))
