"""Bounded source-tree snapshots; never return matched secret values."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

PRIVATE = {'.ssh', '.gnupg', '.aws', '.azure', '.codex', '.docker', '.kube', '.pki', '.config', '.hermes'}
CONFIG = re.compile(r'(?i)\b(?:private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|pairing[_-]?secret|broker[_-]?(?:url|pin)|project[_-]?id|device[_-]?id)\b')
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:])[0-9A-Fa-f:]{2,}(?![\w:])')
PRIVATE_HOST = re.compile(r'(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+(?:local|lan|internal|localdomain)\b')
MAX_FILE = 8 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_FILES = 10000


def categories(line):
    found = []
    if CONFIG.search(line): found.append('credential or personal-configuration name')
    for pattern, version, label in ((IPV4,4,'private or local IP address'), (IPV6,6,'private or local IPv6 address')):
        for match in pattern.finditer(line):
            try:
                addr = ipaddress.ip_address(match.group())
                if addr.version == version and (addr.is_private or addr.is_loopback or addr.is_link_local):
                    found.append(label)
                    break
            except ValueError:
                pass
    if PRIVATE_HOST.search(line): found.append('possibly private hostname')
    return found


def scan_batch(files, cwd, max_output=16 * 1024**2, timeout=60):
    command = [sys.executable, '-I', '-m', 'detect_secrets', 'scan', '--all-files', '--disable-filter',
               'detect_secrets.filters.allowlist.is_line_allowlisted', *files]
    env = {'PATH': os.defpath, 'PYTHONNOUSERSITE': '1', 'LC_ALL': 'C.UTF-8'}
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=env, cwd=cwd, start_new_session=True)
        try:
            parts, size, deadline = [], 0, time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining): raise RuntimeError('Secret scanner timed out')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk: break
                    size += len(chunk)
                    if size > max_output: raise RuntimeError('Secret scanner report exceeds limit')
                    parts.append(chunk)
            if process.wait(timeout=max(0.1, deadline - time.monotonic())):
                raise RuntimeError('Secret scanner failed; scan is incomplete')
            return json.loads(b''.join(parts))
        finally:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
            process.stdout.close()
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Secret scanner could not complete') from exc


def resolve_source(value, profile_data=None, allow_profile_data=False, directory=False):
    if type(allow_profile_data) is not bool: raise ValueError('allow_profile_data must be boolean')
    original = Path(value).expanduser()
    if original.is_symlink() or any(x in PRIVATE - {'.hermes'} for x in original.parts):
        raise ValueError('Private paths and symlink roots are unsupported')
    resolved = original.resolve(strict=True)
    data = Path(profile_data).resolve() if profile_data is not None else None
    home = data.parent if data is not None and data.name == 'plugin-data' else None
    allowed = allow_profile_data and home is not None and resolved.is_relative_to(data)
    protected = '.hermes' in original.parts or '.hermes' in resolved.parts or (home is not None and resolved.is_relative_to(home))
    if any(x in PRIVATE - {'.hermes'} for x in resolved.parts) or protected and not allowed:
        raise ValueError('Private profile configuration is unsupported; selected plugin data requires explicit opt-in')
    if directory:
        if not resolved.is_dir() or resolved == Path('/') or resolved == Path.home().resolve():
            raise ValueError('Choose a specific source directory')
    elif not resolved.is_file():
        raise ValueError('Choose a regular file')
    return resolved


def staging_parent(source):
    for candidate in (Path('/tmp'), Path('/dev/shm')):
        if candidate.is_dir() and os.access(candidate, os.W_OK) and not candidate.resolve().is_relative_to(source):
            return candidate
    raise ValueError('No private staging location exists outside the selected tree')


def inspect_tree(source_dir, allow_profile_data=False, *, _profile_data=None):
    return _inspect_tree(source_dir, expose_generated_names=False, profile_data=_profile_data, allow_profile_data=allow_profile_data)


def _inspect_tree(source_dir, expose_generated_names=False, profile_data=None, allow_profile_data=False, deadline=None):
    p = resolve_source(source_dir, profile_data, allow_profile_data, directory=True)
    entries, mapping, omissions, config, snapshots, directories, submitted = [], {}, [], [], [], [], 0
    forced_hidden = set()
    total = 0
    deadline = min(deadline, time.monotonic() + 55) if deadline is not None else time.monotonic() + 55
    fingerprint = hashlib.sha256()
    with tempfile.TemporaryDirectory(dir=staging_parent(p)) as temporary:
        stage = Path(temporary)
        def add_entry(rel):
            if len(entries) >= MAX_FILES: raise ValueError('Tree exceeds 10,000-entry inspection limit')
            index = len(entries)
            entries.append(rel)
            try:
                rel.encode('utf-8')
                non_utf8 = False
            except UnicodeEncodeError:
                non_utf8 = True
                forced_hidden.add(index)
                omissions.append({'index': index, 'reason': 'non-UTF-8 path requires separate inspection'})
            if not expose_generated_names:
                name_file = f'{index:08d}-name.txt'
                (stage/name_file).write_text('path = ' + json.dumps(rel, ensure_ascii=non_utf8) + '\n', encoding='utf-8')
                mapping[name_file] = (index, 'name')
                found = categories(rel)
                if found: config.append({'index': index, 'component': 'name', 'line': 1, 'categories': found})
            return index
        def omit(index, reason): omissions.append({'index': index, 'reason': reason})
        for directory, dirs, names in os.walk(p, followlinks=False):
            if time.monotonic() >= deadline: raise RuntimeError('Inspection time limit exceeded; narrow the scope')
            directory_path = Path(directory)
            try:
                state = directory_path.lstat()
                if not stat.S_ISDIR(state.st_mode): raise OSError('Directory changed during inspection')
                directories.append((directory_path, (state.st_dev, state.st_ino, state.st_mtime_ns)))
            except OSError as exc:
                raise RuntimeError('Source directory changed during inspection') from exc
            dirs.sort(); names.sort()
            for name in list(dirs):
                item = Path(directory)/name
                index = add_entry(str(item.relative_to(p)))
                if name == '.git' or name in PRIVATE or item.is_symlink():
                    omit(index, 'Git metadata, private configuration or symlink not inspected')
                    dirs.remove(name)
            for name in names:
                item = Path(directory)/name
                rel = str(item.relative_to(p))
                index = add_entry(rel)
                try:
                    if not stat.S_ISREG(item.lstat().st_mode):
                        omit(index, 'symlink or special file requires separate inspection'); continue
                    fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode):
                            omit(index, 'special file requires separate inspection'); continue
                        if before.st_size > MAX_FILE or total + before.st_size > MAX_TOTAL:
                            omit(index, 'file exceeds bounded inspection limits'); continue
                        data = stream.read(MAX_FILE + 1)
                        after = os.fstat(stream.fileno())
                    if len(data) > MAX_FILE or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
                        omit(index, 'file changed or exceeded limits while reading'); continue
                except OSError:
                    omit(index, 'unreadable file or symlink requires separate inspection'); continue
                total += len(data)
                identity = (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
                snapshots.append((item, index, identity))
                fingerprint.update(rel.encode('utf-8', 'surrogateescape') + b'\0' + hashlib.sha256(data).digest())
                if b'\0' in data[:8192]:
                    omit(index, 'binary or archive requires separate inspection'); continue
                try: text = data.decode('utf-8')
                except UnicodeDecodeError:
                    omit(index, 'non-UTF-8 file requires separate inspection'); continue
                content_file = f'{index:08d}-content.txt'
                (stage/content_file).write_text(text, encoding='utf-8')
                mapping[content_file] = (index, 'content')
                submitted += 1
                for num, line in enumerate(text.splitlines(), 1):
                    if num % 1000 == 0 and time.monotonic() >= deadline: raise RuntimeError('Inspection time limit exceeded; narrow the scope')
                    found = categories(line)
                    if found:
                        config.append({'index': index, 'component': 'content', 'line': num, 'categories': found})
                        if len(config) > 10000: raise ValueError('Too many configuration indicators; narrow the scope')
        if not mapping: raise ValueError('No entries to scan')
        names = sorted(mapping)
        findings = []
        for start in range(0, len(names), 100):
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise RuntimeError('Inspection time limit exceeded; narrow the scope')
            try:
                parsed = scan_batch(['./'+x for x in names[start:start+100]], stage, timeout=min(remaining, 15))
                for filename, matches in parsed['results'].items():
                    key = Path(filename).name
                    if key not in mapping or Path(filename).is_absolute() or '..' in Path(filename).parts:
                        raise ValueError('Scanner returned an unexpected path')
                    index, component = mapping[key]
                    for match in matches:
                        findings.append({'index': index, 'component': component, 'line': match.get('line_number'), 'type': match.get('type')})
                        if len(findings) > 10000: raise ValueError('Too many secret indicators')
            except (ValueError, TypeError, KeyError) as exc:
                raise RuntimeError('Secret scanner returned an invalid or oversized report') from exc
        sensitive = forced_hidden | {x['index'] for x in findings if x['component'] == 'name'} | {x['index'] for x in config if x['component'] == 'name'}
        for item, index, expected in snapshots:
            try:
                current = item.lstat()
                actual = (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)
                if actual != expected: omit(index, 'source changed after snapshot')
            except OSError:
                omit(index, 'source disappeared after snapshot')
        changed_directories = 0
        for directory, expected in directories:
            try:
                current = directory.lstat()
                if (current.st_dev, current.st_ino, current.st_mtime_ns) != expected: changed_directories += 1
            except OSError:
                changed_directories += 1
    def public(record):
        index = record['index']
        return {'file_id': index, 'path': entries[index] if (expose_generated_names and index not in forced_hidden) or index not in sensitive else None,
                **{k: v for k, v in record.items() if k != 'index'}}
    return {'text_files_submitted': submitted, 'path_entries_submitted': len(entries), 'scanned_content_sha256': fingerprint.hexdigest(),
            'changed_directories_after_snapshot': changed_directories,
            'secret_indicators': [public(x) for x in findings], 'configuration_indicators': [public(x) for x in config],
            'omissions': [public(x) for x in omissions],
            'coverage': 'Bounded private snapshots of selected current UTF-8 text and entry names; scanner filters and explicit omissions apply. Git history, binary/archive content, screenshots, releases and remote state require separate inspection.',
            'notice': 'Sensitive filenames are hidden when detected. Results are a snapshot, not proof of current state or publication safety.'}
