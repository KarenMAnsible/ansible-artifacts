"""Regression: host PHP services with a private mount namespace must remain observable."""
import sys,unittest,types
from pathlib import Path
from unittest.mock import patch,mock_open
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import collect_linux as collect
import report
class NamespaceTests(unittest.TestCase):
    def proof(self,cgroup='0::/system.slice/php8.2-fpm.service\n',root_matches=True,pid_matches=True):
        def readlink(p):
            kind=p.rsplit('/',1)[1]
            if '/self/' in p:return kind+'-host'
            if kind=='mnt':return 'mnt-private'
            if kind=='pid' and not pid_matches:return 'pid-container'
            return kind+'-host'
        def stat(p):return types.SimpleNamespace(st_dev=1,st_ino=1 if p=='/' or root_matches else 2)
        with patch.object(collect.os,'readlink',side_effect=readlink),patch.object(collect.os,'stat',side_effect=stat),patch('builtins.open',mock_open(read_data=cgroup)):
            return collect.Collector.runtime_process_scope(123)
    def test_host_service_mount_namespace_is_accepted_with_matching_root_pid_user(self):
        p=self.proof();self.assertTrue(p['accepted']);self.assertEqual(p['service_units'],['php8.2-fpm.service'])
    def test_container_cgroup_is_not_accepted_even_with_same_root(self):
        self.assertFalse(self.proof('0::/docker/abc/system.slice/php8.2-fpm.service\n')['accepted'])
    def test_chroot_and_other_pid_namespace_not_accepted(self):
        self.assertFalse(self.proof(root_matches=False)['accepted'])
        self.assertFalse(self.proof(pid_matches=False)['accepted'])
    def test_unknown_mount_scope_is_pending(self):
        self.assertFalse(self.proof('0::/unrecognized.service\n')['accepted'])
    def test_support_packages_do_not_get_core_cve_rows(self):
        payload={'checks':['php'],'hosts':[{'host':'fixture','raw':{'status':'recolectado','coverage':{'families':{'php':{'status':'completado_en_fuentes'}}},'observations':[
            {'component':'php','path':'package:php-common','version':'','version_source':'package_db','package_role':'supporting_package','package':'php-common'},
            {'component':'php','path':'package:php8.2-fpm','version':'8.2.35','version_source':'package_db','package_role':'runtime','package':'php8.2-fpm'}]}}]}
        r=report.build_report(payload)
        own=[f for f in r['findings'] if f.get('package')=='php-common']
        self.assertEqual(len(own),1);self.assertEqual(own[0]['cve'],'')
        self.assertEqual(sum(bool(f.get('cve')) for f in r['findings']),2)
if __name__=='__main__':unittest.main()
