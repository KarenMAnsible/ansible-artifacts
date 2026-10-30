"""Offline regressions for coverage, provenance, runtime correlations and inventory."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import report
import collect_linux as collect

class EvidenceTests(unittest.TestCase):
    def base(self, **kw):
        r = dict(status='recolectado', platform='linux', observations=[], coverage={
            'families': {'php': {'status': 'completado_en_fuentes', 'runtime_web': 'sin_runtime_detectado_en_fuentes'}}, 'limits': {'checks': ['php']}})
        r.update(kw)
        return {'checks': ['php'], 'hosts': [{'host': 'fixture', 'customer': 'VIKO', 'raw': r}]}
    def test_no_observation_is_scoped_not_clean(self):
        r=report.build_report(self.base())
        self.assertEqual(r['hosts'][0]['php_result'], 'sin_hallazgo_en_alcance_consultado')
        self.assertIn('no acredita ausencia global', report.render_text(r).decode('utf-8-sig'))
    def test_new_version_without_provenance_does_not_certify_backport(self):
        o={'component':'php','path':'/php','version':'8.2.35','version_source':'php_cli_no_ini'}
        r=report.build_report(self.base(observations=[o]))
        self.assertEqual(r['findings'][0]['status'], 'fuera_rango_version')
        self.assertEqual(r['hosts'][0]['php_result'], 'pendiente_no_evaluado')
    def test_changelog_mention_alone_is_not_verified(self):
        o={'component':'php','path':'package:php7.4-fpm','version':'7.4.33','version_source':'package_db',
           'package':'php7.4-fpm','package_version':'7.4.33-custom',
           'provenance': {'provider':'tercero_declarado','changelog':[{'cves':['CVE-2026-109618']}]}}
        r=report.build_report(self.base(observations=[o]))
        self.assertTrue(all(f['result']=='afectacion_potencial' for f in r['findings']))
    def test_ppa_does_not_inherit_ubuntu_advisory(self):
        obs={'component':'php','package':'php8.1-fpm','package_version':'8.1.2-1ubuntu2.28',
             'version':'8.1.2','version_source':'package_db', 'provenance':{'provider':'tercero_declarado','origin_hosts':['ppa.launchpadcontent.net']}}
        e={'component':'php','package':obs['package'],'installed_version':obs['package_version'],
           'status':'fixed','cves':['CVE-2026-109618'], 'advisory':'https://ubuntu.com/security/notices/USN-8948-1'}
        rule=next(r for r in report.RULESET['rules'] if r['cve']=='CVE-2026-109618')
        self.assertIsNone(report.vendor_match(obs,rule,[e]))
        obs['provenance']={'provider':'ubuntu_declarado','origin_hosts':['security.ubuntu.com']}
        self.assertIsNotNone(report.vendor_match(obs,rule,[e]))
        e['installed_version']='different'; self.assertIsNone(report.vendor_match(obs,rule,[e]))
    def test_inventory_ports_and_unknown_vault_are_explicit(self):
        p=self.base();p.update(access_records_count=201, inventory_audit=[
            {'host':'key','in_aap':True,'in_access_records':True,'prepared_port':1024,'inventory_port':22,'prepared_status':'listo','mode':'key'},
            {'host':'unknown','in_aap':True,'in_access_records':False,'prepared_status':'vault_no_cargado'}])
        r=report.build_report(p)
        self.assertEqual(r['inventory_audit'][0]['audit_result'], 'puerto_discrepante')
        self.assertEqual(r['inventory_audit'][1]['audit_result'], 'no_evaluado_vault_no_cargado')
        self.assertEqual(r['summary']['access_port_1024_records'],1)
    def test_runtime_reports_multiple_workers_and_no_raw_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf=Path(tmp)/'nginx.conf';conf.write_text('fastcgi_param SECRET do_not_export;\nfastcgi_pass unix:/run/php/php8.2-fpm.sock;\n')
            c=collect.Collector({'checks':['php'],'scan_seconds':5,'command_timeout':1,'run_php_version':False})
            c.php_inventory={'status':'completado_en_fuentes','sources':[]}
            c.command=lambda *a,**k:''
            def fakeglob(pattern): return [str(conf)] if pattern=='/etc/nginx/conf.d/*.conf' else []
            with patch.object(collect.glob,'glob',side_effect=fakeglob): c.php_runtime([],[])
            encoded=json.dumps(c.php_web)
            self.assertNotIn('do_not_export',encoded)
            self.assertIn('/run/php/php8.2-fpm.sock',encoded)
            self.assertEqual(c.php_web['config'][0]['state'],'configurada_en_disco')
    def test_partial_php_not_hidden_by_auxiliary_success(self):
        p=self.base();p['hosts'][0]['raw']['coverage']['families']['php']['status']='parcial'
        r=report.build_report(p)
        self.assertEqual(r['hosts'][0]['php_result'],'pendiente_no_evaluado')
    def test_csv_has_one_summary_row_and_two_cve_rows(self):
        r=report.build_report(self.base())
        with tempfile.TemporaryDirectory() as d:
            report.write_reports(r,d)
            import csv
            with open(Path(d)/'resumen.csv',encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
            self.assertEqual(len(rows),1);self.assertIn('evidence',rows[0]);self.assertIn('next_action',rows[0])
            with open(Path(d)/'hallazgos.csv',encoding='utf-8-sig',newline='') as f: self.assertEqual(len(list(csv.DictReader(f))),2)
if __name__=='__main__': unittest.main()
