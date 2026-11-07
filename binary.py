"""Bounded printable-string triage for a selected binary; not a binary audit."""
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from .core import _inspect_tree, resolve_source, staging_parent

MAX_BINARY = 32 * 1024 * 1024
MAX_TEXT = 4 * 1024 * 1024
MAX_STRINGS = 100_000
MAX_STRING = 16_384
ASCII = re.compile(rb'[\x20-\x7e]{6,}')
UTF16LE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')


def inspect_binary(artifact_path, allow_profile_data=False, *, _profile_data=None):
    path = resolve_source(artifact_path, _profile_data, allow_profile_data)
    deadline = time.monotonic() + 55
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BINARY:
            raise ValueError('Select a regular binary no larger than 32 MiB')
        raw = stream.read(MAX_BINARY + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    if len(raw) > MAX_BINARY or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError('Binary changed or was replaced during inspection')
    fingerprint = hashlib.sha256(raw).hexdigest()
    def verify_unchanged():
        check_fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(check_fd, 'rb') as stream:
            state = os.fstat(stream.fileno())
            if not stat.S_ISREG(state.st_mode) or (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError('Binary changed during inspection')
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                if time.monotonic() >= deadline: raise RuntimeError('Binary inspection time limit exceeded')
                digest.update(chunk)
            end = os.fstat(stream.fileno())
        current = path.lstat()
        if digest.hexdigest() != fingerprint or (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns) != (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns) or not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (end.st_dev, end.st_ino):
            raise ValueError('Binary changed or was replaced during inspection')
    entries, total, skipped = [], 0, 0
    for pattern, encoding in ((ASCII, 'ascii'), (UTF16LE, 'utf-16le')):
        for match in pattern.finditer(raw):
            if time.monotonic() >= deadline: raise RuntimeError('Binary inspection time limit exceeded')
            value = match.group().decode(encoding)
            size = len(value.encode('utf-8')) + 1
            if len(value) > MAX_STRING or len(entries) >= MAX_STRINGS or total + size > MAX_TEXT:
                skipped += 1
                continue
            entries.append((match.start(), encoding, value)); total += size
    entries.sort(key=lambda item: item[0])
    if not entries:
        verify_unchanged()
        return {'sha256': fingerprint, 'strings_submitted': 0, 'strings_skipped': skipped,
                'secret_indicators': [], 'configuration_indicators': [], 'notice': NOTICE}
    with tempfile.TemporaryDirectory(dir=staging_parent(path.parent)) as tmp:
        staged = Path(tmp)/'strings.txt'
        staged.write_text('\n'.join(value for _, _, value in entries) + '\n', encoding='utf-8', newline='\n')
        result = _inspect_tree(tmp, expose_generated_names=True, deadline=deadline)
    verify_unchanged()
    def public(item):
        line = item.get('line')
        if type(line) is not int or not 1 <= line <= len(entries):
            raise RuntimeError('Unexpected scanner result; inspection incomplete')
        offset, encoding, _ = entries[line-1]
        return {'byte_offset': offset, 'encoding': encoding, **{k: v for k, v in item.items() if k not in ('path', 'file_id', 'component', 'line')}}
    return {'sha256': fingerprint, 'strings_submitted': len(entries), 'strings_skipped': skipped,
            'secret_indicators': [public(x) for x in result['secret_indicators']],
            'configuration_indicators': [public(x) for x in result['configuration_indicators']],
            'scanner_omissions': result['omissions'], 'notice': NOTICE}


NOTICE = ('Literal printable ASCII and UTF-16LE strings only; short, long, non-ASCII, compressed, encrypted, '
          'fragmented and image text may be missed. Scanner filters and limits apply. This does not certify '
          'a binary or release as safe; inspect artifacts and omissions separately.')
