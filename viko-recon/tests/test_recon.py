import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import collect_linux as collect
import report


def jar(artifact='log4j-core', version='2.14.1', group='org.apache.logging.log4j', jndi=True, metadata=True):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        if artifact == 'log4j-core':
            z.writestr('org/apache/logging/log4j/core/Logger.class', b'fixture')
            if jndi:
                z.writestr('org/apache/logging/log4j/core/lookup/JndiLookup.class', b'fixture')
        if metadata:
            z.writestr('META-INF/maven/' + group + '/' + artifact + '/pom.properties',
                       'groupId=' + group + '\nartifactId=' + artifact + '\nversion=' + version + '\n')
    return b.getvalue()


def config(**overrides):
    c = dict(checks=['php', 'log4j', 'struts'], linux_roots=[], linux_excludes=[], scan_seconds=10,
             max_files=1000, max_archives=50, max_archive_mb=2, max_nested_mb=1,
             max_total_nested_mb=4, max_entries=1000, archive_depth=2, max_observations=100,
             command_timeout=1, run_php_version=False, container_inventory=False)
    c.update(overrides)
    return c


class RuleTests(unittest.TestCase):
    def rule(self, cve):
        return next(r for r in report.RULESET['rules'] if r['cve'] == cve)

    def state(self, cve, version, **extra):
        o = dict(component=self.rule(cve)['component'], version=version, version_source='maven_pom')
        o.update(extra)
        return report.classify(o, self.rule(cve), [])[0]

    def test_log4j_branch_exceptions_and_incomplete_original_fix(self):
        for version, shell, related in [('2.0-beta8', False, False), ('2.0-beta9', True, True),
                                        ('2.3.0', True, True), ('2.3.1', False, False),
                                        ('2.12.1', True, True), ('2.12.2', False, True),
                                        ('2.12.3', False, False), ('2.14.1', True, True),
                                        ('2.15.0', False, True), ('2.16.0', False, False),
                                        ('2.17.1', False, False)]:
            with self.subTest(version=version):
                self.assertEqual(self.state('CVE-2021-44228', version) == 'potencialmente_afectado', shell)
                self.assertEqual(self.state('CVE-2021-45046', version) == 'potencialmente_afectado', related)

    def test_php_all_fixed_boundaries_and_unsupported_branch(self):
        for fixed, old in [('8.2.35', '8.2.34'), ('8.3.36', '8.3.35'), ('8.4.27', '8.4.26'), ('8.5.12', '8.5.11')]:
            for cve in ('CVE-2026-109618', 'CVE-2026-109619'):
                self.assertEqual(self.state(cve, fixed), 'fuera_rango_version')
                self.assertEqual(self.state(cve, old), 'potencialmente_afectado')
        self.assertEqual(self.state('CVE-2026-109618', '8.6.0RC4'), 'requiere_validacion')
        self.assertEqual(self.state('CVE-2026-109618', '8.1.33'), 'potencialmente_afectado')

    def test_vendor_exact_package_evidence(self):
        rule = self.rule('CVE-2026-109618')
        o = dict(component='php', version='8.1.33', version_source='package_db', package='php-fpm', package_version='0:8.1.33-9.vendor')
        self.assertEqual(report.classify(o, rule, [])[0], 'requiere_validacion_proveedor')
        e = dict(component='php', package='php-fpm', installed_version=o['package_version'],
                 cves=[rule['cve']], status='fixed', advisory='https://example.test/vendor/errata')
        self.assertEqual(report.classify(o, rule, [e])[0], 'corregido_segun_evidencia_proveedor')
        e['installed_version'] += 'X'
        self.assertEqual(report.classify(o, rule, [e])[0], 'requiere_validacion_proveedor')

    def test_filename_and_modified_version_never_safe(self):
        self.assertEqual(self.state('CVE-2021-44228', '2.17.1', version_source='filename'), 'requiere_validacion')
        self.assertEqual(self.state('CVE-2021-44228', '2.17.1.vendor-3'), 'requiere_validacion')

    def test_struts_four_part_versions_and_upload_migration(self):
        self.assertEqual(self.state('CVE-2017-12611', '2.5.10.1'), 'potencialmente_afectado')
        self.assertEqual(self.state('CVE-2017-12611', '2.5.12'), 'fuera_rango_version')
        self.assertEqual(self.state('CVE-2018-11776', '2.5.16'), 'potencialmente_afectado')
        self.assertEqual(self.state('CVE-2018-11776', '2.5.17'), 'fuera_rango_version')
        self.assertEqual(self.state('CVE-2024-53677', '6.3.0.2'), 'potencialmente_afectado')
        self.assertEqual(self.state('CVE-2024-53677', '6.4.0'), 'requiere_validar_migracion_upload')


class CollectorTests(unittest.TestCase):
    def test_nested_sap_and_instana_wrapper(self):
        c = collect.Collector(config())
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as z:
            z.writestr('WEB-INF/lib/log4j-core-2.14.1.jar', jar())
        c.archive(io.BytesIO(outer.getvalue()), '/usr/sap/application.war')
        c.archive(io.BytesIO(jar(version='2.17.1')), '/opt/instana/pax-logging-log4j2-1.11.15.jar')
        self.assertEqual([o['version'] for o in c.observations], ['2.14.1', '2.17.1'])
        self.assertTrue(c.observations[0]['jndi_lookup'])
        self.assertIn('!', c.observations[0]['path'])
        self.assertEqual(report.classify(c.observations[1], report.RULESET['rules'][2], [])[0], 'fuera_rango_version')

    def test_wrapper_version_not_used_for_embedded_log4j(self):
        c = collect.Collector(config())
        c.archive(io.BytesIO(jar(metadata=False)), '/opt/instana/pax-logging-log4j2-1.11.15.jar')
        self.assertEqual(c.observations[0]['version'], '')
        self.assertEqual(c.observations[0]['version_source'], 'embedded_classes')

    def test_api_does_not_imply_core(self):
        c = collect.Collector(config())
        c.archive(io.BytesIO(jar(artifact='log4j-api')), '/opt/app/log4j-api-2.14.1.jar')
        self.assertEqual([o['component'] for o in c.observations], ['log4j-api'])

    def test_depth_and_corrupt_archive_record_incomplete_coverage(self):
        c = collect.Collector(config(archive_depth=0))
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as z:
            z.writestr('lib/core.jar', jar())
        c.archive(io.BytesIO(outer.getvalue()), '/usr/sap/app.war')
        c.archive(io.BytesIO(b'corrupt'), '/opt/broken.jar')
        self.assertEqual(c.error_count, 2)
        self.assertEqual(c.observations, [])

    def test_deadline_interrupts_blocked_work_and_keeps_evidence(self):
        c = collect.Collector(config(checks=['log4j'], scan_seconds=1))
        def blocked():
            c.add('log4j-core', '/usr/sap/a.jar', '2.14.1', 'maven_pom')
            time.sleep(4)
        c.context = lambda: ([], [], {}, [])
        c.walk = blocked
        start = time.monotonic()
        raw = c.run()
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertTrue(raw['coverage']['budget_exhausted'])
        self.assertEqual(len(raw['observations']), 1)
        self.assertEqual(raw['coverage']['file_search'], 'parcial')


class ReportTests(unittest.TestCase):
    def test_unreachable_and_partial_do_not_disappear(self):
        payload = {'checks': ['log4j'], 'hosts': [
            {'host': 'offline', 'raw': {'status': 'no_evaluado'}},
            {'host': 'partial', 'raw': {'status': 'recolectado', 'coverage': {'file_search': 'parcial'}, 'observations': []}},
            {'host': 'api-only', 'security_coverage': 'no_cubierto', 'raw': {
                'status': 'recolectado', 'coverage': {'file_search': 'completado_en_rutas'},
                'observations': [{'component': 'log4j-api', 'version': '2.14.1', 'path': '/opt/api.jar'}]}}]}
        r = report.build_report(payload)
        self.assertEqual(r['summary']['hosts'], 3)
        self.assertEqual(r['summary']['hosts_not_evaluated'], 1)
        self.assertEqual(r['hosts'][2]['security_coverage'], 'desconocido')
        states = {f['host']: f['status'] for f in r['findings'] if f.get('cve')}
        self.assertEqual(states['offline'], 'no_evaluado')
        self.assertEqual(states['partial'], 'no_detectado_busqueda_parcial')
        self.assertEqual(states['api-only'], 'no_detectado_en_rutas_revisadas')

    def test_report_zip_and_html_csv_escaping(self):
        payload = {'checks': ['php'], 'hosts': [{'host': '=HYPERLINK("x")', 'customer': '<script>alert(1)</script>', 'raw': {'status': 'no_evaluado'}}]}
        r = report.build_report(payload)
        with tempfile.TemporaryDirectory() as tmp:
            encoded = report.write_reports(r, tmp)
            import base64
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded))) as z:
                self.assertEqual(len(z.namelist()), 6)
                self.assertIn('resultados.txt', z.namelist())
                self.assertEqual(json.loads(z.read('reporte.json'))['summary']['hosts'], 1)
            h = (Path(tmp) / 'reporte.html').read_text()
            self.assertNotIn('<script>', h)
            self.assertIn('&lt;script&gt;', h)
            self.assertIn("'=HYPERLINK", (Path(tmp) / 'resumen.csv').read_text())

    def test_text_includes_findings_paths_and_timeout_pending(self):
        payload = {'checks': ['log4j'], 'hosts': [
            {'host': 'sap-test', 'address': '192.0.2.10', 'customer': 'QA', 'raw': {
                'status': 'recolectado', 'coverage': {'file_search': 'parcial', 'budget_exhausted': True,
                    'elapsed_seconds': 180, 'roots_requested': ['/usr/sap', '/opt/instana'],
                    'roots_completed': ['/usr/sap'], 'errors_count': 1,
                    'errors': [{'location': '/opt/instana', 'reason': 'tiempo_maximo_recolector'}]},
                'observations': [{'component': 'log4j-core', 'path': '/usr/sap/app.war!lib/log4j-core.jar',
                    'version': '2.14.1', 'version_source': 'maven_pom', 'jndi_lookup': True}]}},
            {'host': 'offline-test', 'raw': {'status': 'no_evaluado', 'reason': 'Tiempo máximo de conexión'}}]}
        text = report.render_text(report.build_report(payload)).decode('utf-8-sig')
        for expected in ('SERVIDOR: sap-test', 'SERVIDOR: offline-test', 'CVE-2021-44228',
                         '/usr/sap/app.war!lib/log4j-core.jar', '2.14.1', 'potencialmente_afectado',
                         'tiempo_maximo_recolector', 'Tiempo máximo de conexión', 'Presupuesto agotado: sí',
                         'Estado de recolección: no_evaluado'):
            self.assertIn(expected, text)

    def test_text_actual_hostname_ip_and_mexico_date(self):
        r = report.build_report({'checks': ['php'], 'hosts': [
            {'host': 'alias-db', 'address': 'sapprd.interna', 'raw': {
                'status': 'recolectado', 'system': {'hostname': 'SAPPRD', 'ip_addresses': ['192.0.2.10']},
                'timestamp_utc': '2026-10-24T01:45:30.1234567Z',
                'coverage': {'file_search': 'completado_en_rutas'}, 'observations': []}}]})
        r['generated_utc'] = '2026-10-23T16:00:00.123456+00:00'
        text = report.render_text(r).decode('utf-8-sig')
        for expected in ('SERVIDOR: SAPPRD', 'Nombre en inventario: alias-db',
                         'IP(s) del servidor: 192.0.2.10', 'Destino de conexión (inventario): sapprd.interna',
                         '2026-10-23 19:45:30 -0600', '2026-10-23 10:00:00 -0600'):
            self.assertIn(expected, text)
        files = report.per_server_texts(r)
        self.assertEqual(len(files), 1)
        name = next(iter(files))
        self.assertEqual(name, 'por_servidor/SAPPRD_192.0.2.10_20261023_100000.txt')

    def test_offline_text_dates_and_distinct_safe_filenames(self):
        r = report.build_report({'checks': ['php'], 'hosts': [
            {'host': '../same', 'address': '192.0.2.10', 'raw': {'status': 'no_evaluado'}},
            {'host': '..\\same', 'address': '192.0.2.10', 'raw': {'status': 'no_evaluado'}}]})
        files = report.per_server_texts(r)
        self.assertEqual(len(files), 2)
        self.assertEqual(len({name.rsplit('/', 1)[-1] for name in files}), 1)
        for name, content in files.items():
            self.assertNotIn('..', name)
            self.assertIn(name.count('/'), (1, 2))
            self.assertRegex(name.rsplit('/', 1)[-1], r'^same_192\.0\.2\.10_\d{8}_\d{6}\.txt$')
            text = content.decode('utf-8-sig')
            self.assertIn('IP(s) del servidor: 192.0.2.10', text)
            self.assertIn('Fecha y hora de recolección (CDMX): no registrada', text)
            self.assertNotIn('Fecha y hora del informe (CDMX): no registrada', text)
            self.assertIn('Servidores incluidos: 1', text)


if __name__ == '__main__':
    unittest.main()
