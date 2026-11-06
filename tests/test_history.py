import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('inspector_history_fixture', root / '__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class GitTests(unittest.TestCase):
    def test_removed_secret_detected_in_reachable_history(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            repo = Path(tmp) / 'repo'
            repo.mkdir()
            env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
            def git(*args):
                subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.com',*args],
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=env,timeout=10)
            git('init','-q')
            token = 'AKIA' + 'Z3XY7QWERTYUIOP2'
            (repo / 'data.txt').write_text('AWS_ACCESS_KEY_ID = "' + token + '"\n')
            (repo / ('AWS_ACCESS_KEY_ID=' + token)).write_text('fixture')
            git('add','--all')
            git('commit','-q','-m','first')
            git('branch','archive')
            git('branch','AWS_ACCESS_KEY_ID=' + token)
            git('tag','old')
            git('tag','-a','annotated','-m','AWS_ACCESS_KEY_ID = ' + token)
            (repo / 'data.txt').write_text('No credential here.\n')
            git('add','data.txt')
            git('commit','-q','-m','remove')
            raw_file = repo / 'uncommitted.txt'
            raw_file.write_text('AWS_ACCESS_KEY_ID = "' + 'AKIA' + 'Q9P8N7M6L5K4J3H2' + '"\n')
            blob_id = subprocess.check_output(['git','-C',str(repo),'hash-object','-w',str(raw_file)], env=env, timeout=10).decode().strip()
            git('update-ref', 'refs/tags/raw-blob', blob_id)
            result = module.inspect_git(str(repo))
            self.assertGreaterEqual(result['refs_count'], 3)
            self.assertTrue(result['secret_indicators'])
            self.assertTrue(any(x['object_type'] == 'tag' for x in result['secret_indicators']))
            self.assertTrue(any(x['object_type'] == 'tree_names' for x in result['secret_indicators']))
            self.assertTrue(any(x['object_type'] == 'ref_names' for x in result['secret_indicators']))
            self.assertFalse(result['refs_changed_during_scan'])
            self.assertTrue(any(x['object_id'] == blob_id for x in result['secret_indicators']))
            self.assertNotIn(token, str(result))

    def test_reference_change_during_scan_is_reported(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            repo = Path(tmp)/'repo'
            repo.mkdir()
            env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':os.devnull}
            def git(*args):
                subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.com',*args],
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=env,timeout=10)
            git('init','-q')
            (repo/'file.txt').write_text('ordinary text')
            git('add','file.txt'); git('commit','-q','-m','first')
            original = module.history._inspect_tree
            def change_ref(*args, **kwargs):
                result = original(*args, **kwargs)
                git('branch','new-branch')
                return result
            with patch.object(module.history, '_inspect_tree', side_effect=change_ref):
                result = module.inspect_git(str(repo))
            self.assertTrue(result['refs_changed_during_scan'])

    def test_external_git_content_is_reported_as_uninspected(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            repo = Path(tmp)/'repo'
            repo.mkdir()
            env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', *args], env=env, stderr=subprocess.DEVNULL, timeout=10).decode().strip()
            git('init', '-q')
            (repo/'large.bin').write_text('version https://git-lfs.github.com/spec/v1\noid sha256:' + 'a'*64 + '\nsize 100\n')
            git('add', 'large.bin'); git('commit', '-q', '-m', 'first')
            commit = git('rev-parse', 'HEAD')
            git('update-index', '--add', '--cacheinfo', '160000,' + commit + ',nested')
            git('commit', '-q', '-m', 'add submodule entry')
            reasons = [x['reason'] for x in module.inspect_git(str(repo))['omissions']]
            self.assertIn('Git LFS payload requires separate inspection', reasons)
            self.assertIn('submodule histories require separate inspection', reasons)

if __name__ == '__main__': unittest.main()
