import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('inspector_archive_fixture', root/'__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class ArchiveTests(unittest.TestCase):
    def test_nested_archive_findings_and_omissions(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root = Path(tmp)
            token = 'AKIA' + 'Z3XY7QWERTYUIOP2'
            private_ip = '.'.join(map(str, (192, 168, 1, 50)))
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, 'w') as z:
                z.writestr('inside.txt', 'AWS_ACCESS_KEY_ID = "' + token + '"\n')
            archive = root/'fixture.apk'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('AWS_ACCESS_KEY_ID=' + token, 'fixture')
                z.writestr('nested.zip', nested.getvalue())
                z.writestr('settings.txt', 'host=' + private_ip)
                z.writestr('image.bin', b'\x00binary')
                z.writestr('../unsafe.txt', 'fixture')
            result = module.inspect_archive(str(archive))
            self.assertTrue(any(len(x['member']) == 2 for x in result['secret_indicators']))
            self.assertTrue(any(x['component'] == 'name' for x in result['secret_indicators']))
            self.assertTrue(result['configuration_indicators'])
            self.assertTrue(result['unsafe_name_indexes'])
            self.assertTrue(any('binary' in x['reason'] for x in result['omissions']))
            self.assertNotIn(token, str(result))
            self.assertNotIn(private_ip, str(result))

if __name__ == '__main__': unittest.main()
