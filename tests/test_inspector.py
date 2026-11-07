import importlib.util
import ipaddress
import json
import os
import sys
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inspector_core_fixture', root/'__init__.py', submodule_search_locations=[str(root)])
plugin = importlib.util.module_from_spec(spec);sys.modules[spec.name]=plugin;spec.loader.exec_module(plugin)
core = plugin.core

class InspectorTests(unittest.TestCase):
    def test_crlf_finding_keeps_original_line_number(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            token='AKIA'+'Z3XY7QWERTYUIOP2'
            (Path(tmp)/'source.txt').write_bytes(('header\r\nAWS_ACCESS_KEY_ID = "'+token+'"\r\n').encode())
            result=core.inspect_tree(tmp)
            self.assertEqual(result['secret_indicators'][0]['line'],2)
            self.assertFalse(token in str(result))

    def test_scanner_and_config_indicators_do_not_expose_value(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            token = 'AKIA' + 'Z3XY7QWERTYUIOP2'
            local_ip = '.'.join(map(str, (192, 168, 1, 50)))
            local_ipv6 = str(ipaddress.IPv6Address(1))
            private_host = 'fixture' + '.internal'
            (root / 'source.txt').write_text('AWS_ACCESS_KEY_ID = "' + token + '" # pragma: allowlist secret\nendpoint=' + local_ip + '\n' + local_ipv6 + '\n' + private_host + '\n')
            (root / 'bundle.zip').write_bytes(b'PK\x00binary')
            result = core.inspect_tree(str(root))
            self.assertTrue(result['secret_indicators'])
            self.assertTrue(result['configuration_indicators'])
            self.assertTrue(result['omissions'])
            self.assertNotIn(token, str(result))
            self.assertNotIn(local_ip, str(result))
            self.assertNotIn(local_ipv6, str(result))
            self.assertNotIn(private_host, str(result))
            categories = [c for x in result['configuration_indicators'] for c in x['categories']]
            self.assertIn('private or local IPv6 address', categories)
            self.assertIn('possibly private hostname', categories)

    def test_sensitive_filename_is_hidden_and_private_directory_omitted(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            token = 'AKIA' + 'Z3XY7QWERTYUIOP2'
            (root / ('AWS_ACCESS_KEY_ID=' + token)).write_text('fixture')
            private = root/'.CoDeX'
            private.mkdir()
            (private/'fixture.txt').write_text('not read')
            (root/'.GiT').mkdir()
            result = core.inspect_tree(str(root))
            self.assertFalse(token in str(result))
            self.assertTrue(any(x['component'] == 'name' and x['path'] is None for x in result['secret_indicators']))
            self.assertTrue(any('private configuration' in x['reason'] for x in result['omissions']))
            self.assertGreaterEqual(sum('Git metadata' in x['reason'] for x in result['omissions']), 2)

    def test_scanner_child_does_not_inherit_credentials(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            (root/'source.txt').write_text('ordinary text')
            original = core.subprocess.Popen
            seen = []
            def start(*args, **kwargs):
                seen.append(kwargs['env'])
                return original(*args, **kwargs)
            with patch.dict(os.environ, {'INWORLD_API_KEY':'fixture-only-value'}), patch.object(core.subprocess, 'Popen', side_effect=start):
                core.inspect_tree(str(root))
            self.assertTrue(seen)
            self.assertTrue(all('INWORLD_API_KEY' not in env for env in seen))

    def test_changed_source_and_new_file_are_reported(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            source = root/'source.txt'
            source.write_text('initial')
            original = core.scan_batch
            def mutate(files, cwd, **kwargs):
                result = original(files, cwd, **kwargs)
                source.write_text('changed size')
                (root/'new.txt').write_text('new')
                return result
            with patch.object(core, 'scan_batch', side_effect=mutate):
                result = core.inspect_tree(str(root))
            self.assertTrue(any('changed after snapshot' in x['reason'] for x in result['omissions']))
            self.assertGreater(result['changed_directories_after_snapshot'], 0)

    def test_scanner_output_is_bounded(self):
        original = core.subprocess.Popen
        def noisy(_command, **kwargs):
            return original([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 2048)'], **kwargs)
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp, patch.object(core.subprocess, 'Popen', side_effect=noisy):
            with self.assertRaisesRegex(RuntimeError, 'exceeds limit'):
                core.scan_batch([], tmp, max_output=1024)

    def test_scanner_timeout_stops_its_process(self):
        original = core.subprocess.Popen; children=[]
        def slow(_command, **kwargs):
            process=original([sys.executable,'-c','import time; time.sleep(30)'], **kwargs)
            children.append(process);return process
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp, patch.object(core.subprocess,'Popen',side_effect=slow):
            with self.assertRaisesRegex(RuntimeError,'timed out'):core.scan_batch([],tmp,timeout=.2)
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].poll())

    def test_non_utf8_filename_is_hidden_and_reported(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            filename = os.fsencode(root) + b'/bad-' + bytes([255]) + b'.txt'
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(b'ordinary text')
            result = core.inspect_tree(str(root))
            self.assertTrue(any('non-UTF-8 path' in x['reason'] and x['path'] is None for x in result['omissions']))
            json.dumps(result)

    def test_staging_is_outside_selected_tree(self):
        shm = Path('/dev/shm')
        if not shm.is_dir() or not os.access(shm, os.W_OK):
            self.skipTest('Alternative staging directory unavailable')
        self.assertFalse(core.staging_parent(Path('/tmp').resolve()).resolve().is_relative_to(Path('/tmp').resolve()))

    def test_private_and_symlink_roots_rejected(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            link = root / 'link'
            link.symlink_to(root)
            with self.assertRaises(ValueError):
                core.inspect_tree(str(link))

if __name__ == '__main__':
    unittest.main()
