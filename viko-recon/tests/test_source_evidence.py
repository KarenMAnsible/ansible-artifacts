import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import report
class SourceEvidenceTests(unittest.TestCase):
    def observation(self):
        return {'component':'php','path':'/usr/sbin/php-fpm8.1','version':'8.1.34','version_source':'observed_executable',
                'package':'php8.1-fpm','package_version':'8.1.34-9+ubuntu24.04.1+deb.sury.org+1',
                'runtime_state':'proceso_php_observado','provenance':{'source_package':'php8.1',
                'source_version':'8.1.34-9+ubuntu24.04.1+deb.sury.org+1','origin_hosts':['ppa.launchpadcontent.net']}}
    def test_source_patch_is_pending_not_fixed_or_unqualified_vulnerable(self):
        p={'checks':['php'],'hosts':[{'host':'fixture','raw':{'status':'recolectado','coverage':{'families':{'php':{'status':'completado_en_fuentes'}}},'observations':[self.observation()]}}]}
        r=report.build_report(p)
        self.assertTrue(all(f['status']=='backport_identificado_validacion_pendiente' for f in r['findings']))
        self.assertEqual(r['hosts'][0]['php_result'],'pendiente_no_evaluado')
        self.assertEqual(report.php_visible_status(r['hosts'][0]),'PENDIENTE DE VALIDACIÓN')
        self.assertTrue(r['hosts'][0]['review_required'])
    def test_revision_mismatch_and_other_origin_do_not_inherit_source_patch(self):
        o=self.observation();self.assertIsNotNone(report.package_source_evidence(o))
        o['package_version']+='X';self.assertIsNone(report.package_source_evidence(o))
        o=self.observation();o['provenance']['origin_hosts']=['unrelated.example'];self.assertIsNone(report.package_source_evidence(o))
    def test_replaced_loaded_file_does_not_inherit_source_patch(self):
        o=self.observation();o['host_file_identity_verified']=False
        self.assertIsNone(report.package_source_evidence(o))
if __name__=='__main__':unittest.main()
