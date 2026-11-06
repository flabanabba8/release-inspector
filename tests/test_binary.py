import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('inspector_binary_fixture', root/'__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class BinaryTests(unittest.TestCase):
    def test_ascii_and_utf16_findings_do_not_disclose_values(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            path = Path(tmp)/'fixture.bin'
            token = 'AKIA' + 'Z3XY7QWERTYUIOP2'
            private_ip = '.'.join(map(str, (192, 168, 1, 50)))
            path.write_bytes(b'\x00\xff' + ('AWS_ACCESS_KEY_ID = "' + token + '"').encode() + b'\x00\xff' + ('host=' + private_ip).encode('utf-16le') + b'\x00\xff')
            result = module.inspect_binary(str(path))
            self.assertTrue(result['secret_indicators'])
            self.assertTrue(any(x['encoding'] == 'utf-16le' for x in result['configuration_indicators']))
            self.assertNotIn(token, str(result))
            self.assertNotIn(private_ip, str(result))
            self.assertIn('does not certify', result['notice'])

    def test_oversized_strings_are_reported_as_skipped(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            path = Path(tmp)/'fixture.bin'
            path.write_bytes(b'X' * (module.binary.MAX_STRING + 1))
            result = module.inspect_binary(str(path))
            self.assertEqual(result['strings_submitted'], 0)
            self.assertGreater(result['strings_skipped'], 0)


if __name__ == '__main__': unittest.main()
