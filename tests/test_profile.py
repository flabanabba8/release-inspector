import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('inspector_profile_fixture', root/'__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class ProfileTests(unittest.TestCase):
    def test_explicit_profile_data_only_and_no_scope_override(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            profile = Path(tmp)/'custom-profile'
            data = profile/'plugin-data'
            demo = data/'tutorial'
            demo.mkdir(parents=True)
            (demo/'caption.srt').write_text('ordinary caption')
            archive = demo/'artifact.zip'
            with zipfile.ZipFile(archive,'w') as z: z.writestr('content.txt','ordinary text')
            private = profile/'private'
            private.mkdir()
            (private/'secret.txt').write_text('fixture')
            with patch('plugins.plugin_storage.plugin_data_dir',return_value=data/'release-inspector'):
                blocked = json.loads(module.invoke('release_inspect_tree', {'source_dir':str(demo)}))
                self.assertIn('error',blocked)
                allowed = json.loads(module.invoke('release_inspect_tree', {'source_dir':str(demo),'allow_profile_data':True}))
                self.assertNotIn('error',allowed)
                self.assertGreater(allowed['text_files_submitted'],0)
                other = json.loads(module.invoke('release_inspect_tree', {'source_dir':str(private),'allow_profile_data':True}))
                self.assertIn('error',other)
                archive_result = json.loads(module.invoke('release_inspect_archive', {'archive_path':str(archive),'allow_profile_data':True}))
                self.assertNotIn('error',archive_result)
                override = json.loads(module.invoke('release_inspect_tree', {'source_dir':str(private),'allow_profile_data':True,'_profile_data':str(profile)}))
                self.assertIn('error',override)

if __name__=='__main__': unittest.main()
