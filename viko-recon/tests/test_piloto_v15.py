"""Regressions for assessment pilot 1.5; uses existing offline fixtures."""
import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_linux as collect
import report

def config(**overrides):
    c = dict(checks=['php', 'log4j', 'struts'], linux_roots=[], linux_excludes=[], scan_seconds=10,
             max_files=1000, max_archives=50, max_archive_mb=2, max_nested_mb=1,
             max_total_nested_mb=4, max_entries=1000, archive_depth=2, max_observations=100,
             command_timeout=1, run_php_version=False, container_inventory=False)
    c.update(overrides)
    return c


class PilotTests(unittest.TestCase):
    def test_php_package_version_does_not_parse_ubuntu_metapackage(self):
            c = collect.Collector(config(checks=['php']))
            c.command = lambda argv: ('installed\tphp-common\t2:101~+ubuntu24.04.1+deb.sury.org+1\tall\n'
                                      'installed\tphp8.1-cli\t8.1.2-1ubuntu2.24\tamd64\n')
            with patch.object(collect.shutil, 'which', side_effect=lambda name: None if name == 'rpm' else '/usr/bin/dpkg-query'):
                c.packages()
            self.assertEqual(c.observations[0]['version'], '')
            self.assertEqual(c.observations[1]['version'], '8.1.2')
            self.assertEqual(c.observations[0]['package_version'], '2:101~+ubuntu24.04.1+deb.sury.org+1')

    def test_php_inventory_skips_broad_walk_and_records_limited_scope(self):
            c = collect.Collector(config(checks=['php'], php_inventory_only=True))
            c.context = lambda: ([], [], {}, [])
            c.command = lambda *a, **k: ''
            c.walk = lambda: self.fail('PHP inventory must not walk general SAP/Java roots')
            with patch.object(collect.glob, 'glob', return_value=[]), patch.object(collect.shutil, 'which', return_value=None):
                raw = c.run()
            self.assertEqual(raw['coverage']['file_search'], 'no_solicitado')
            self.assertEqual(raw['coverage']['families']['php']['runtime_web'], 'pendiente_de_correlacion')
            # No package manager is a real missing source, not a clean inventory.
            self.assertEqual(raw['coverage']['families']['php']['status'], 'parcial')

    def test_php_coverage_is_independent_of_java_search_but_web_pending(self):
            r = report.build_report({'checks': ['php', 'log4j'], 'hosts': [{'host': 'fixture', 'raw': {
                'status': 'recolectado', 'coverage': {'file_search': 'parcial', 'families': {
                    'php': {'status': 'completado_en_fuentes', 'runtime_web': 'pendiente_de_correlacion'},
                    'log4j': {'status': 'parcial'}}}, 'observations': []}}]})
            h = r['hosts'][0]
            self.assertEqual(h['family_status']['php'], 'no_detectado_en_fuentes_consultadas')
            self.assertEqual(h['family_status']['log4j'], 'no_detectado_busqueda_parcial')
            self.assertTrue(h['review_required'])
            self.assertEqual(r['summary']['hosts_partial'], 1)

    def test_php_inventory_does_not_claim_complete_web_assessment(self):
            r = report.build_report({'checks': ['php'], 'hosts': [{'host': 'fixture', 'raw': {
                'status': 'recolectado', 'coverage': {'file_search': 'no_solicitado', 'families': {
                    'php': {'status': 'completado_en_fuentes', 'runtime_web': 'pendiente_de_correlacion'}}},
                'observations': [{'component': 'php', 'version': '8.2.35', 'version_source': 'php_cli_no_ini', 'path': '/php'}]}}]})
            self.assertEqual(r['summary']['hosts_partial'], 0)
            self.assertTrue(r['hosts'][0]['review_required'])
            text = report.render_text(r).decode('utf-8-sig')
            self.assertIn('PHP utilizado por la aplicación web: pendiente_de_correlacion', text)

    def test_diagnostics_and_services_are_present_in_text(self):
            r = report.build_report({'checks': ['php'], 'hosts': [{'host': 'fixture', 'raw': {
                'status': 'no_evaluado', 'diagnostics': {'stage': 'script_parse', 'code': 'powershell_parse_failed', 'line': 8},
                'services': [{'name': 'php-fpm', 'state': 'active'}],
                'processes': [{'name': 'php-fpm', 'pid': 123, 'executable': '/usr/sbin/php-fpm'}]}}]})
            text = report.render_text(r).decode('utf-8-sig')
            for expected in ('script_parse', 'powershell_parse_failed', 'line: 8', 'php-fpm | active', '/usr/sbin/php-fpm'):
                self.assertIn(expected, text)
