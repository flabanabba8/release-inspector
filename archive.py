"""Bounded ZIP/APK inspection; no archive members are extracted by their names."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tempfile
import time
import zipfile
from .core import _inspect_tree, resolve_source

MAX_ARCHIVE = 512 * 1024**2
MAX_MEMBER = 8 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_MEMBERS = 5000
MAX_DEPTH = 2


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def inspect_archive(archive_path, allow_profile_data=False, *, _profile_data=None):
    path = resolve_source(archive_path, _profile_data, allow_profile_data)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Choose a regular archive at most 512 MiB')
    fingerprint = digest(path)
    deadline = time.monotonic() + 55
    omissions, unsafe_names, mapped = [], [], {}
    total, members = 0, 0
    with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
        staging = Path(tmp)
        def stage(identifier, kind, text):
            key = f'{len(mapped):08d}.txt'
            (staging / key).write_text(text, encoding='utf-8')
            mapped[key] = {'member': identifier, 'component': kind}
        def visit(z, parent, depth):
            nonlocal total, members
            for index, info in enumerate(z.infolist()):
                if time.monotonic() >= deadline: raise RuntimeError('Archive inspection time limit exceeded; narrow the scope')
                members += 1
                if members > MAX_MEMBERS: raise ValueError('Archive exceeds 5,000-member inspection limit')
                identifier = parent + [index]
                name = info.filename
                stage(identifier, 'name', 'archive_member = ' + json.dumps(name, ensure_ascii=False))
                if name.startswith('/') or '\\' in name or '..' in PurePosixPath(name).parts:
                    unsafe_names.append(identifier)
                if info.is_dir(): continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    omissions.append({'member': identifier, 'reason': 'symlink content requires separate review'})
                    continue
                if info.flag_bits & 1:
                    omissions.append({'member': identifier, 'reason': 'encrypted entry requires separate review'})
                    continue
                if info.file_size > MAX_MEMBER or total + info.file_size > MAX_TOTAL:
                    omissions.append({'member': identifier, 'reason': 'member exceeds bounded inspection limits'})
                    continue
                try:
                    data = z.read(info)
                except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    omissions.append({'member': identifier, 'reason': 'unreadable or corrupt entry'})
                    continue
                total += len(data)
                if zipfile.is_zipfile(io.BytesIO(data)):
                    if depth >= MAX_DEPTH:
                        omissions.append({'member': identifier, 'reason': 'nested archive exceeds depth limit'})
                    else:
                        try:
                            with zipfile.ZipFile(io.BytesIO(data)) as nested: visit(nested, identifier, depth+1)
                        except zipfile.BadZipFile:
                            omissions.append({'member': identifier, 'reason': 'invalid nested archive'})
                    continue
                if b'\0' in data[:8192]:
                    omissions.append({'member': identifier, 'reason': 'binary content requires separate inspection'})
                    continue
                try: text = data.decode('utf-8')
                except UnicodeDecodeError:
                    omissions.append({'member': identifier, 'reason': 'non-UTF-8 content requires separate inspection'})
                    continue
                stage(identifier, 'content', text)
        try:
            with zipfile.ZipFile(path) as archive: visit(archive, [], 0)
        except zipfile.BadZipFile as exc:
            raise ValueError('Not a readable ZIP or APK archive') from exc
        if not mapped: raise ValueError('Archive contains no entries')
        result = _inspect_tree(str(staging), expose_generated_names=True, deadline=deadline)
    if digest(path) != fingerprint: raise ValueError('Archive changed during inspection')
    def transform(item):
        return {**mapped[Path(item['path']).name], **{k: v for k, v in item.items() if k not in ('path', 'file_id', 'component')}}
    return {'archive_sha256': fingerprint, 'members': members, 'text_components_submitted': len(mapped),
            'secret_indicators': [transform(x) for x in result['secret_indicators']],
            'configuration_indicators': [transform(x) for x in result['configuration_indicators']],
            'unsafe_name_indexes': unsafe_names, 'omissions': omissions + result['omissions'],
            'notice': 'Member indexes are zero-based at each nesting level. Binary code, images, non-ZIP formats, release history and all omissions need separate review; a clean result is not proof of safety.'}
