"""Regressions from the four-host pilot: source embedding and Nginx include masks."""
import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import collect_linux as collect
class PilotRegressionTests(unittest.TestCase):
    def test_wrapper_transfers_collector_as_base64_not_nested_here_string(self):
        source=(Path(__file__).resolve().parents[1]/'tasks/windows.yml').read_text()
        self.assertNotIn("$scriptText = @'",source)
        self.assertIn("lookup('ansible.builtin.file', playbook_dir ~ '/scripts/collect_windows.ps1') | b64encode",source)
        self.assertIn('`$config',source)
    def scan(self,path):
        c=collect.Collector({'checks':['php'],'scan_seconds':5,'command_timeout':1,'run_php_version':False,'php_config_paths':[str(path)]})
        c.php_inventory={'status':'completado_en_fuentes','sources':[]}
        c.command=lambda *a,**k:''
        with patch.object(collect.glob,'glob',return_value=[]): c.php_runtime([],[])
        return [e for e in c.php_web['errors'] if e['location']==str(path)]
    def test_empty_nginx_mask_is_not_missing_explicit_file(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'nginx';root.mkdir();path=root/'nginx.conf'
            path.write_text('include /viko_fixture_nonexistent/*.conf;\n')
            self.assertEqual(self.scan(path),[])
            path.write_text('include /viko_fixture_nonexistent/required.conf;\n')
            self.assertTrue(any(e['reason']=='include_explicito_sin_coincidencia' for e in self.scan(path)))
if __name__=='__main__':unittest.main()
