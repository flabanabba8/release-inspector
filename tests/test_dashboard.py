import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient

root=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('release_dashboard_fixture',root/'dashboard'/'plugin_api.py')
dashboard=importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)

class DashboardTests(unittest.TestCase):
    def test_profile_opt_in_and_sensitive_filename_redaction(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            profile=Path(tmp)/'custom-profile'
            data=profile/'plugin-data'
            source=data/'candidate'
            source.mkdir(parents=True)
            token='AKIA'+'Z3XY7QWERTYUIOP2'
            (source/('AWS_ACCESS_KEY_ID='+token)).write_text('fixture')
            app=FastAPI();app.include_router(dashboard.router);client=TestClient(app)
            with patch('plugins.plugin_storage.plugin_data_dir',return_value=data/'release-inspector'):
                args={'source_dir':str(source)}
                blocked=client.post('/action',json={'operation':'release_inspect_tree','arguments':args})
                self.assertEqual(blocked.status_code,400)
                args['allow_profile_data']=True
                response=client.post('/action',json={'operation':'release_inspect_tree','arguments':args})
                self.assertEqual(response.status_code,200)
                self.assertFalse(token in response.text)
                self.assertTrue(any(x['component']=='name' and x['path'] is None for x in response.json()['secret_indicators']))
                args['_profile_data']=str(profile)
                self.assertEqual(client.post('/action',json={'operation':'release_inspect_tree','arguments':args}).status_code,400)
                self.assertEqual(client.post('/action',json={'operation':'not_allowed','arguments':{}}).status_code,400)

if __name__=='__main__': unittest.main()
