"""Bounded read-only Git object scan; never claims a complete publication audit."""
import json
import os
from pathlib import Path
import re
import selectors
import time
import subprocess
import tempfile
from .core import _inspect_tree, resolve_source

MAX_OBJECTS = 2000
MAX_SINGLE = 8 * 1024**2
MAX_TOTAL = 128 * 1024**2
ENV = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1'}


def git(repo, args, input_bytes=None, timeout=10):
    # Bound stdout while streaming; a large or hostile repository must fail closed.
    try:
        with tempfile.TemporaryFile() as stdin_file:
            if input_bytes:
                stdin_file.write(input_bytes)
                stdin_file.seek(0)
            process = subprocess.Popen(['git', '-C', str(repo), '--no-pager', *args], stdin=stdin_file,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
            try:
                chunks, size = [], 0
                deadline = time.monotonic() + timeout
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise RuntimeError('Git inspection timed out')
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk: break
                        size += len(chunk)
                        if size > 16 * 1024**2: raise RuntimeError('Git output exceeds inspection limit')
                        chunks.append(chunk)
                if process.wait(timeout=max(0.1, deadline - time.monotonic())):
                    raise RuntimeError('Git inspection failed; history coverage is incomplete')
                return b''.join(chunks)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Git inspection did not complete') from exc


def tree_names(raw, digest_bytes):
    names, omitted, gitlinks, position = [], 0, 0, 0
    while position < len(raw):
        separator = raw.find(b' ', position)
        end = raw.find(b'\0', separator + 1) if separator >= 0 else -1
        if separator < 0 or end < 0 or end + 1 + digest_bytes > len(raw):
            raise RuntimeError('Malformed Git tree object')
        mode, name = raw[position:separator], raw[separator+1:end]
        if not mode or not name or b'/' in name: raise RuntimeError('Malformed Git tree entry')
        if mode == b'160000': gitlinks += 1
        try: names.append('tree_entry = ' + json.dumps(name.decode('utf-8'), ensure_ascii=False))
        except UnicodeDecodeError: omitted += 1
        position = end + 1 + digest_bytes
    return ('\n'.join(names) + ('\n' if names else '')).encode(), omitted, gitlinks


def tree_edges(raw, digest_bytes):
    edges, position = [], 0
    while position < len(raw):
        separator = raw.find(b' ', position)
        end = raw.find(b'\0', separator + 1) if separator >= 0 else -1
        if separator < 0 or end < 0 or end + 1 + digest_bytes > len(raw):
            raise RuntimeError('Malformed Git tree object')
        mode, name = raw[position:separator], raw[separator + 1:end]
        if not mode or not name or b'/' in name:
            raise RuntimeError('Malformed Git tree entry')
        edges.append((mode, name, raw[end + 1:end + 1 + digest_bytes].hex()))
        position = end + 1 + digest_bytes
    return edges


def full_tree_paths(trees):
    # Enumerate from every reachable tree: this includes direct tree refs and
    # shared subtrees, while bounding repeated paths and malicious deep graphs.
    paths, incomplete, total, visits = set(), False, 0, 0
    for root in trees:
        stack = [(root, b'', frozenset())]
        while stack:
            tree, prefix, ancestors = stack.pop()
            visits += 1
            if visits > 100000:
                return b'', True
            if tree in ancestors or len(ancestors) >= 100 or tree not in trees:
                incomplete = True
                continue
            for mode, name, child in trees[tree]:
                path = prefix + name
                try: text = path.decode('utf-8')
                except UnicodeDecodeError:
                    incomplete = True
                    continue
                if text not in paths:
                    paths.add(text)
                    total += len(path)
                if len(paths) > 10000 or total > 4_000_000:
                    return b'', True
                if mode in (b'40000', b'040000'):
                    stack.append((child, path + b'/', ancestors | {tree}))
    return (''.join('git_path = ' + json.dumps(path, ensure_ascii=False) + '\n' for path in sorted(paths))).encode(), incomplete


def inspect_git(repo_path, allow_profile_data=False, *, _profile_data=None):
    repo = resolve_source(repo_path, _profile_data, allow_profile_data, directory=True)
    deadline = time.monotonic() + 55
    def run(args, input_bytes=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise RuntimeError('History inspection time limit exceeded; narrow the scope')
        return git(repo, args, input_bytes, timeout=min(remaining, 10))
    if run(['rev-parse', '--is-shallow-repository']).strip() != b'false':
        raise ValueError('Shallow history is incomplete; use a complete repository')
    object_format = run(['rev-parse', '--show-object-format']).strip()
    if object_format not in (b'sha1', b'sha256'): raise ValueError('Unsupported Git object format')
    digest_bytes = 20 if object_format == b'sha1' else 32
    refs = run(['for-each-ref', '--format=%(objectname)%09%(refname)']).splitlines()
    head = run(['rev-parse', 'HEAD']).strip()
    output = run(['rev-list', '--objects', '--all', 'HEAD'])
    object_ids = []
    for line in output.splitlines():
        identifier = line.split(b' ', 1)[0].decode('ascii', 'strict')
        if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', identifier): raise RuntimeError('Invalid Git object identifier')
        object_ids.append(identifier)
    object_ids = list(dict.fromkeys(object_ids))
    if len(object_ids) > MAX_OBJECTS: raise ValueError('History exceeds the 2,000-object inspection limit')
    if not object_ids: raise ValueError('No reachable objects found')
    detail = run(['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], ('\n'.join(object_ids)+'\n').encode())
    records = []
    for line in detail.decode('ascii').splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] not in object_ids or parts[1] not in ('blob','tree','commit','tag') or not parts[2].isdigit():
            raise RuntimeError('Git returned incomplete object metadata')
        records.append((parts[0], parts[1], int(parts[2])))
    if len(records) != len(object_ids) or {x[0] for x in records} != set(object_ids): raise RuntimeError('Git object enumeration was incomplete')
    omissions, types, total = [], {}, 0
    with tempfile.TemporaryDirectory(dir='/tmp') as temp:
        root = Path(temp)
        names = []
        trees = {}
        for index, line in enumerate(refs):
            _, separator, name = line.partition(b'\t')
            if not separator: raise RuntimeError('Git returned invalid reference metadata')
            try: names.append('git_ref = ' + json.dumps(name.decode('utf-8'), ensure_ascii=False))
            except UnicodeDecodeError:
                omissions.append({'type': 'ref_names', 'index': index, 'reason': 'non-UTF-8 ref name requires separate inspection'})
        if names:
            (root/'refnames.txt').write_text('\n'.join(names)+'\n', encoding='utf-8')
            types['refnames'] = 'ref_names'
        for identifier, kind, size in records:
            if size > MAX_SINGLE or total + size > MAX_TOTAL:
                omissions.append({'object_id': identifier, 'type': kind, 'reason': 'object exceeds bounded scan limits'})
                continue
            raw = run(['cat-file', kind, identifier])
            if len(raw) != size: raise RuntimeError('Git object size changed during inspection')
            total += size
            if kind == 'tree':
                trees[identifier] = tree_edges(raw, digest_bytes)
                raw, missing, gitlinks = tree_names(raw, digest_bytes)
                if missing:
                    omissions.append({'object_id': identifier, 'type': kind, 'reason': 'non-UTF-8 tree names require separate inspection', 'count': missing})
                if gitlinks:
                    omissions.append({'object_id': identifier, 'type': kind, 'reason': 'submodule histories require separate inspection', 'count': gitlinks})
                if not raw: continue
                kind = 'tree_names'
            if kind == 'blob' and raw.startswith(b'version https://git-lfs.github.com/spec/v1\n'):
                omissions.append({'object_id': identifier, 'type': kind, 'reason': 'Git LFS payload requires separate inspection'})
            if b'\0' in raw[:8192]:
                omissions.append({'object_id': identifier, 'type': kind, 'reason': 'binary or archive requires separate inspection'})
                continue
            try: raw.decode('utf-8')
            except UnicodeDecodeError:
                omissions.append({'object_id': identifier, 'type': kind, 'reason': 'non-UTF-8 object requires separate inspection'})
                continue
            (root / (identifier + '.txt')).write_bytes(raw)
            types[identifier] = kind
        paths, incomplete = full_tree_paths(trees)
        if incomplete:
            omissions.append({'type': 'full_paths', 'reason': 'full path enumeration incomplete or exceeded bounds'})
        if paths:
            (root/'fullpaths.txt').write_bytes(paths)
            types['fullpaths'] = 'full_paths'
        if not types: raise ValueError('No supported text objects to scan')
        scan = _inspect_tree(str(root), expose_generated_names=True, deadline=deadline)
    refs_changed = refs != run(['for-each-ref', '--format=%(objectname)%09%(refname)']).splitlines() or head != run(['rev-parse', 'HEAD']).strip()
    def transform(item):
        stem = Path(item['path']).stem
        return {'object_id': None if types[stem] in ('ref_names', 'full_paths') else stem, 'object_type': types[stem],
                **{k: v for k, v in item.items() if k not in ('path', 'file_id', 'component')}}
    return {'refs_count': len(refs), 'refs_changed_during_scan': refs_changed, 'reachable_objects': len(object_ids), 'text_components_submitted': len(types),
            'secret_indicators': [transform(x) for x in scan['secret_indicators']],
            'configuration_indicators': [transform(x) for x in scan['configuration_indicators']], 'omissions': omissions + scan['omissions'],
            'coverage': 'Reachable text blobs, commits, tags, UTF-8 tree entry names, reconstructed relative paths and local ref names enumerated by git rev-list --all HEAD, subject to explicit omissions and scanner filters.',
            'notice': 'This is not a full audit: Binary/archive contents, screenshots, remote refs and release assets require separate inspection. No findings do not establish safety.'}
