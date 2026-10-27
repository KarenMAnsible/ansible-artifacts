#!/usr/bin/env python3
"""Shared rule engine and offline report renderer. Python >=3.8 on controller.
Can restore complete reports from the ZIP/base64 AAP artifact; see README.
"""
import argparse
import base64
import collections
import csv
import datetime
import gzip
import hashlib
import html
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import zipfile

HERE = Path(__file__).resolve().parent
RULESET = json.loads((HERE / 'rules.json').read_text(encoding='utf-8'))
try:
    from zoneinfo import ZoneInfo
    MEXICO_TZ = ZoneInfo('America/Mexico_City')
except (ImportError, KeyError):
    # Python 3.8 / runtimes without tzdata: explicit fixed reference offset.
    MEXICO_TZ = datetime.timezone(datetime.timedelta(hours=-6), 'UTC-06:00')


def report_datetime(value):
    try:
        value = re.sub(r'(\.\d{6})\d+', r'\1', str(value).replace('Z', '+00:00'))
        result = datetime.datetime.fromisoformat(value)
        return result if result.tzinfo else result.replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


def mexico_datetime(value):
    instant = report_datetime(value)
    return instant.astimezone(MEXICO_TZ).strftime('%Y-%m-%d %H:%M:%S %z') if instant else 'no registrada'


def server_ips(host):
    values = [host.get('address', '')] + list(host.get('system', {}).get('ip_addresses') or [])
    result = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(value))
            if address not in result:
                result.append(address)
        except ValueError:
            pass
    return result


def version_key(value):
    """Narrow numeric/Maven prerelease subset. Unknown suffix => human review."""
    m = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?(alpha|beta|rc)(\d+))?', str(value).strip(), re.I)
    if not m:
        return None
    nums = tuple(int(x or 0) for x in m.groups()[:4])
    stage = {'alpha': 0, 'beta': 1, 'rc': 2, None: 3}[m.group(5).lower() if m.group(5) else None]
    return nums + (stage, int(m.group(6) or 0))


def in_range(v, spec):
    if 'min' in spec and v < version_key(spec['min']):
        return False
    if 'max_exclusive' in spec and v >= version_key(spec['max_exclusive']):
        return False
    if 'max_inclusive' in spec and v > version_key(spec['max_inclusive']):
        return False
    return True


def vendor_match(observation, rule, evidence):
    for e in evidence:
        if (e.get('component') == observation.get('component')
            and observation.get('package') and e.get('package') == observation['package']
            and e.get('installed_version') == observation.get('package_version')
            and rule['cve'] in e.get('cves', [])
            and e.get('status') == 'fixed'
            and str(e.get('advisory', '')).startswith('https://')):
            return e
    return None


def classify(observation, rule, evidence):
    checked = vendor_match(observation, rule, evidence)
    if checked:
        return 'corregido_segun_evidencia_proveedor', 'Declaración validada externamente para este paquete exacto: ' + checked['advisory']
    v = version_key(observation.get('version', ''))
    if v is None:
        return 'requiere_validacion', 'Versión desconocida, modificada o formato no reconocido.'
    if observation.get('version_source') in ('filename', 'conflict'):
        return 'requiere_validacion', 'La versión se infiere del nombre; confirmar metadatos y procedencia.'
    if rule['family'] == 'php':
        branch = str(v[0]) + '.' + str(v[1])
        if branch in rule['branch_minimums']:
            affected = v < version_key(rule['branch_minimums'][branch])
        elif v[:2] < (8, 2):
            affected = True
        else:
            return 'requiere_validacion', 'Rama PHP fuera de la matriz comprobada; consultar aviso del proveedor.'
        if affected and observation.get('version_source') == 'package_db':
            return 'requiere_validacion_proveedor', 'Versión upstream anterior al mínimo; verificar errata y backport del paquete exacto.'
        if affected:
            return 'potencialmente_afectado', 'Versión en rango; falta validar uso, exposición y posibles correcciones del proveedor.'
        return 'fuera_rango_version', 'Fuera del rango numérico de este CVE; comprobar runtime web y correcciones efectivamente cargadas.'
    affected = any(in_range(v, r) for r in rule['ranges'])
    if affected:
        return 'potencialmente_afectado', 'Versión en rango; la configuración, backports y uso efectivo requieren validación.'
    if rule['cve'] == 'CVE-2024-53677' and v >= version_key('6.4.0'):
        return 'requiere_validar_migracion_upload', 'Verificar que la aplicación migró desde el interceptor antiguo; versión sola no acredita remediación.'
    return 'fuera_rango_version', 'Fuera del rango de este CVE; no significa ausencia de otras vulnerabilidades.'


def build_report(payload):
    checks = payload.get('checks', ['php', 'log4j', 'struts'])
    rules = [r for r in RULESET['rules'] if r['family'] in checks]
    hosts = []
    findings = []
    for host in payload.get('hosts', []):
        raw = host.get('raw', {})
        available = raw.get('status') == 'recolectado'
        coverage = raw.get('coverage', {})
        host_checks = coverage.get('limits', {}).get('checks', checks)
        hs = {k: host.get(k, '') for k in ('host', 'address', 'customer', 'security_coverage', 'security_coverage_source')}
        hs['security_coverage'] = hs['security_coverage'] or 'desconocido'
        if hs['security_coverage'] not in ('cubierto', 'no_cubierto', 'desconocido') or (hs['security_coverage'] != 'desconocido' and not hs['security_coverage_source']):
            hs['security_coverage'] = 'desconocido'
        hs.update(platform=raw.get('platform', ''), system=raw.get('system', {}),
                  collection_status=raw.get('status', 'no_evaluado'),
                  collection_reason=raw.get('reason', ''), coverage=coverage,
                  trend_local=raw.get('trend_local', {}), services=raw.get('services', []),
                  processes=raw.get('processes', []), containers=raw.get('containers', []),
                  family_status={}, timestamp_utc=raw.get('timestamp_utc', ''))
        obs = raw.get('observations', [])
        for rule in rules:
            if rule['family'] not in host_checks:
                continue
            candidates = [o for o in obs if o.get('component') == rule['component']] if available else []
            if not candidates:
                state = 'no_evaluado' if not available else 'no_detectado_en_rutas_revisadas'
                if available and coverage.get('file_search') != 'completado_en_rutas':
                    state = 'no_detectado_busqueda_parcial'
                candidates = [{'component': rule['component'], 'path': '', 'version': '', 'version_source': ''}]
            else:
                state = None
            for o in candidates:
                if state:
                    status, note = state, 'Ausencia de hallazgo no prueba ausencia global; revisar cobertura y contenido no inspeccionado.'
                else:
                    status, note = classify(o, rule, host.get('vendor_evidence', []))
                finding = {k: hs[k] for k in ('host', 'address', 'customer', 'security_coverage')}
                finding.update(family=rule['family'], cve=rule['cve'], severity=rule['severity'],
                               component=o['component'], version=o.get('version', ''), path=o.get('path', ''),
                               version_source=o.get('version_source', ''), package=o.get('package', ''),
                               package_version=o.get('package_version', ''), jndi_lookup=o.get('jndi_lookup'),
                               status=status, note=note, action=rule['action'], source=rule['source'],
                               runtime_exposure='no_evaluada', application_owner='por_identificar')
                identity = '\0'.join(str(finding.get(k, '')) for k in ('host', 'cve', 'component', 'path', 'version', 'package_version', 'version_source'))
                finding['id'] = hashlib.sha256(identity.encode()).hexdigest()[:20]
                findings.append(finding)
        for o in obs:
            if o.get('component') not in ('log4j-api', 'log4j1', 'xwork-core'):
                continue
            family = 'struts' if o['component'] == 'xwork-core' else 'log4j'
            if family not in checks:
                continue
            f = {k: hs[k] for k in ('host', 'address', 'customer', 'security_coverage')}
            f.update(family=family, cve='', severity='informational', component=o['component'],
                     version=o.get('version', ''), path=o.get('path', ''), version_source=o.get('version_source', ''),
                     status='componente_informativo', note='No se atribuye automáticamente un CVE de core a este componente.',
                     action='Identificar aplicación y revisar aviso del proveedor.', source='', runtime_exposure='no_evaluada')
            findings.append(f)
        own = [f for f in findings if f['host'] == hs['host']]
        for family in checks:
            states = [f['status'] for f in own if f['family'] == family and f.get('cve')]
            priority = ['potencialmente_afectado', 'requiere_validacion_proveedor', 'requiere_validacion',
                        'requiere_validar_migracion_upload', 'no_evaluado', 'no_detectado_busqueda_parcial',
                        'no_detectado_en_rutas_revisadas', 'fuera_rango_version', 'corregido_segun_evidencia_proveedor']
            hs['family_status'][family] = next((s for s in priority if s in states), 'no_evaluado')
        hs['observations_count'] = len(obs)
        hs['review_required'] = (any(f['status'].startswith(('potencialmente', 'requiere_', 'no_evaluado')) for f in own)
                                 or coverage.get('file_search') != 'completado_en_rutas'
                                 or any(c.get('running') or c.get('status') == 'no_evaluado' for c in hs['containers']))
        hosts.append(hs)
    counts = dict(collections.Counter(f['status'] for f in findings if f.get('cve')))
    return {'schema_version': 1, 'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'rules_reviewed_on': RULESET['reviewed_on'], 'checks': checks,
            'scope_note': RULESET['scope_note'], 'summary': {'hosts': len(hosts),
                'hosts_not_evaluated': sum(h['collection_status'] != 'recolectado' for h in hosts),
                'hosts_partial': sum(h['collection_status'] == 'recolectado' and h['coverage'].get('file_search') != 'completado_en_rutas' for h in hosts),
                'hosts_requiring_review': sum(h['review_required'] for h in hosts),
                'cve_observation_rows': sum(bool(f.get('cve')) for f in findings), 'statuses': counts},
            'hosts': hosts, 'findings': findings}


def csv_safe(value):
    if value is None:
        return ''
    text = str(value).replace('\x00', '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def csv_bytes(rows, fields):
    stream = io.StringIO(newline='')
    w = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for row in rows:
        w.writerow({k: csv_safe(row.get(k, '')) for k in fields})
    return ('\ufeff' + stream.getvalue()).encode('utf-8')


def render_html(report):
    esc = lambda x: html.escape(str(x if x is not None else ''), quote=True)
    headers = ['Cliente', 'Servidor', 'Familia', 'CVE', 'Componente', 'Versión', 'Estado', 'Ruta / paquete']
    rows = []
    for f in report['findings']:
        values = [f.get(k, '') for k in ('customer', 'host', 'family', 'cve', 'component', 'version', 'status', 'path')]
        rows.append('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in values) + '</tr>')
    cover = []
    for h in report['hosts']:
        cov = h['coverage']
        cover.append('<details><summary>' + esc(h['host']) + ' · ' + esc(h['collection_status']) + ' · ' + esc(cov.get('file_search', 'no_evaluado')) + '</summary><pre>' + esc(json.dumps({'reason': h['collection_reason'], 'coverage': cov, 'containers': h['containers']}, ensure_ascii=False, indent=2)) + '</pre></details>')
    return ('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>VIKO · Reconocimiento de vulnerabilidades</title><style>body{font:15px system-ui;margin:32px;color:#163044;background:#f4f7fa}h1{color:#07556b}table{border-collapse:collapse;background:white;width:100%}td,th{padding:10px;border-bottom:1px solid #dde5ed;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#07556b;color:white}pre{white-space:pre-wrap}details{background:white;padding:12px;margin:8px 0}.table{overflow:auto}.note{padding:16px;background:#fff3d5;border-left:4px solid #d08a00}</style>'
            '<h1>VIKO · Reconocimiento de vulnerabilidades</h1><p>' + esc(report['generated_utc']) + ' · Reglas revisadas: ' + esc(report['rules_reviewed_on']) + '</p>'
            '<p class="note">Reconocimiento de solo lectura. Los hallazgos son candidatos para validación; no se confirma explotación ni exposición pública. “Fuera de rango” corresponde solo al CVE indicado. Una búsqueda parcial o limitada a rutas no acredita ausencia global. Contenedores: inventario sin inspección de su contenido.</p>'
            '<pre>' + esc(json.dumps(report['summary'], ensure_ascii=False, indent=2)) + '</pre><div class="table"><table><thead><tr>'
            + ''.join('<th>' + esc(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(rows)
            + '</tbody></table></div><h2>Cobertura por servidor</h2>' + ''.join(cover) + '</html>').encode('utf-8')


def render_text(report):
    """Human-readable evidence, including negative/partial/failed checks."""
    def clean(value):
        return re.sub(r'[\x00-\x1f\x7f]', ' ', str(value if value is not None else ''))

    summary = report['summary']
    lines = [
        'VIKO | RESULTADOS DEL RECONOCIMIENTO DE VULNERABILIDADES',
        'Fecha y hora del informe (CDMX): ' + mexico_datetime(report['generated_utc']),
        'Generado (UTC): ' + clean(report['generated_utc']),
        'Reglas revisadas: ' + clean(report['rules_reviewed_on']),
        'Familias solicitadas: ' + ', '.join(report['checks']),
        '', 'RESUMEN GENERAL',
        'Servidores incluidos: ' + str(summary['hosts']),
        'Servidores no evaluados: ' + str(summary['hosts_not_evaluated']),
        'Servidores con cobertura parcial: ' + str(summary['hosts_partial']),
        'Servidores que requieren revisión: ' + str(summary['hosts_requiring_review']),
        'Filas de evaluación por componente/CVE: ' + str(summary['cve_observation_rows']),
    ]
    for status, count in sorted(summary['statuses'].items()):
        lines.append('  ' + status + ': ' + str(count))
    lines += [
        '', 'ALCANCE DE LOS RESULTADOS',
        'Reconocimiento de solo lectura. No se aplicaron parches.',
        'Una versión en rango indica afectación potencial; falta validar configuración, proveedor y uso efectivo.',
        'Fuera de rango se refiere solo al CVE indicado. No detectado no acredita ausencia global.',
        'La cobertura de TrendAI requiere cruce con Seguridad; la exposición pública no se evaluó.',
        'Las imágenes y el contenido interno de contenedores no se inspeccionaron.',
    ]
    for host in report['hosts']:
        coverage = host['coverage']
        lines += [
            '', 'SERVIDOR: ' + clean(host['system'].get('hostname') or host['host']),
            'Nombre en inventario: ' + clean(host['host']),
            'Cliente: ' + clean(host['customer']),
            'IP(s) del servidor: ' + clean(', '.join(server_ips(host)) or 'no registrada'),
            'Destino de conexión (inventario): ' + clean(host['address']),
            'Sistema: ' + clean(host['system'].get('PRETTY_NAME', host['platform'])),
            'Fecha y hora del informe (CDMX): ' + mexico_datetime(report['generated_utc']),
            'Fecha y hora de recolección (CDMX): ' + mexico_datetime(host['timestamp_utc']),
            'Fecha de recolección (UTC): ' + clean(host['timestamp_utc'] or 'no registrada; equipo no evaluado'),
            'Estado de recolección: ' + clean(host['collection_status']),
            'Cobertura del recorrido: ' + clean(coverage.get('file_search', 'no_evaluado')),
            'Tiempo de recolección (s): ' + clean(coverage.get('elapsed_seconds', 'sin dato')),
            'Presupuesto agotado: ' + ('sí' if coverage.get('budget_exhausted') else 'no / sin dato'),
            'Cobertura TrendAI declarada: ' + clean(host['security_coverage']),
            'Fuente de cobertura TrendAI: ' + clean(host['security_coverage_source']),
        ]
        if host['collection_reason']:
            lines.append('Motivo de recolección pendiente: ' + clean(host['collection_reason']))
        for label, key in [('Raíces solicitadas', 'roots_requested'), ('Raíces recorridas', 'roots_completed'),
                           ('Raíces ausentes', 'roots_absent'), ('Exclusiones', 'excluded')]:
            lines.append(label + ':')
            lines.extend('  ' + clean(p) for p in coverage.get(key, []))
            if not coverage.get(key):
                lines.append('  Sin dato / ninguna registrada.')
        lines.append('Estado por familia:')
        lines.extend('  ' + clean(k) + ': ' + clean(v) for k, v in host['family_status'].items())
        lines.append('Detalle de resultados:')
        for finding in report['findings']:
            if finding['host'] != host['host']:
                continue
            lines += [
                '  ' + clean(finding.get('cve') or 'INFORMATIVO') + ' | ' + clean(finding['component']),
                '    Estado: ' + clean(finding['status']),
                '    Versión: ' + clean(finding.get('version') or 'no identificada'),
            ]
            if finding.get('path'):
                lines += ['    Ruta / archivo: ' + clean(finding['path']),
                          '    Fuente de versión: ' + clean(finding.get('version_source', ''))]
            if finding.get('package'):
                lines.append('    Paquete: ' + clean(finding['package']) + ' | versión instalada: ' + clean(finding.get('package_version', '')))
            if finding.get('jndi_lookup') is not None:
                lines.append('    JndiLookup.class presente: ' + ('sí' if finding['jndi_lookup'] else 'no'))
            lines.append('    Interpretación: ' + clean(finding.get('note', '')))
            if finding.get('path'):
                lines.append('    Siguiente acción: ' + clean(finding.get('action', '')))
            if finding.get('source'):
                lines.append('    Aviso oficial: ' + clean(finding['source']))
        lines.append('Errores / omisiones registrados: ' + str(coverage.get('errors_count', 0)))
        for error in coverage.get('errors', []):
            lines.append('  ' + clean(error.get('location', '')) + ': ' + clean(error.get('reason', '')))
        if coverage.get('errors_count', 0) > len(coverage.get('errors', [])):
            lines.append('  Se alcanzó el límite de ejemplos de errores; el total incluye las omisiones restantes.')
        for container in host['containers']:
            lines.append('Contenedores ' + clean(container.get('engine', '')) + ': ' + clean(container.get('status', '')) + '; contenido interno pendiente.')
            for running in container.get('running', []):
                lines.append('  ' + clean(running.get('name', '')) + ' | imagen: ' + clean(running.get('image', '')))
        for limitation in coverage.get('limitations', []):
            lines.append('Límite de cobertura: ' + clean(limitation))
    # BOM + CRLF for straightforward opening in Windows Notepad.
    return ('\ufeff' + '\r\n'.join(lines) + '\r\n').encode('utf-8')


def per_server_texts(report):
    """Safe, distinct filenames carrying host identity, IP and report date."""
    def slug(value, limit):
        value = re.sub(r'[^A-Za-z0-9._-]+', '_', str(value)).strip('._-')
        return value[:limit] or 'sin_dato'

    instant = report_datetime(report['generated_utc'])
    stamp = instant.astimezone(MEXICO_TZ).strftime('%Y%m%d_%H%M%S') if instant else 'fecha_no_registrada'
    files = {}
    for host in report['hosts']:
        identity = host['system'].get('hostname') or host['host']
        ips = server_ips(host)
        basename = '{}_{}_{}.txt'.format(slug(identity, 48), slug(ips[0] if ips else 'IP_no_registrada', 42), stamp)
        name = 'por_servidor/' + basename
        if name in files:
            folder = hashlib.sha256((host['host'] + '\0' + host.get('address', '')).encode()).hexdigest()
            name = 'por_servidor/{}/{}'.format(folder, basename)
            if name in files:
                raise ValueError('Objetivo duplicado: ' + host['host'])
        findings = [f for f in report['findings'] if f['host'] == host['host']]
        single = dict(report, hosts=[host], findings=findings)
        single['summary'] = {
            'hosts': 1,
            'hosts_not_evaluated': int(host['collection_status'] != 'recolectado'),
            'hosts_partial': int(host['collection_status'] == 'recolectado' and host['coverage'].get('file_search') != 'completado_en_rutas'),
            'hosts_requiring_review': int(host['review_required']),
            'cve_observation_rows': sum(bool(f.get('cve')) for f in findings),
            'statuses': dict(collections.Counter(f['status'] for f in findings if f.get('cve')))
        }
        files[name] = render_text(single)
    return files


def write_reports(report, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    hosts = []
    for h in report['hosts']:
        row = dict(h)
        row['coverage_status'] = h['coverage'].get('file_search', 'no_evaluado')
        row['coverage_errors'] = h['coverage'].get('errors_count', '')
        for family in ('php', 'log4j', 'struts'):
            row[family] = h['family_status'].get(family, 'no_solicitado')
        hosts.append(row)
    files = {
        'resultados.txt': render_text(report),
        'reporte.json': json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'),
        'resumen.csv': csv_bytes(hosts, ['customer', 'host', 'address', 'platform', 'security_coverage', 'collection_status', 'coverage_status', 'coverage_errors', 'observations_count', 'php', 'log4j', 'struts', 'review_required']),
        'hallazgos.csv': csv_bytes(report['findings'], ['customer', 'host', 'address', 'security_coverage', 'family', 'cve', 'severity', 'component', 'version', 'version_source', 'package', 'package_version', 'path', 'jndi_lookup', 'status', 'note', 'action', 'source']),
        'reporte.html': render_html(report)
    }
    files.update(per_server_texts(report))
    for name, data in files.items():
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.chmod(str(p), 0o600)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    bundle = buffer.getvalue()
    p = out / 'resultados.zip'
    p.write_bytes(bundle)
    os.chmod(str(p), 0o600)
    return base64.b64encode(bundle).decode('ascii')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--input', help='Entrada consolidada privada producida por Ansible')
    g.add_argument('--restore-artifacts', help='JSON exportado del Job AAP o su objeto artifacts')
    p.add_argument('--out', required=True)
    p.add_argument('--artifact-limit', type=int, default=700000)
    args = p.parse_args()
    os.umask(0o077)
    if args.restore_artifacts:
        a = json.loads(Path(args.restore_artifacts).read_text(encoding='utf-8-sig'))
        a = a.get('artifacts', a)
        value = a.get('viko_vuln_report_zip_base64', '')
        if not value:
            p.error('El Job no incluye el reporte completo. Recuperar desde almacenamiento persistente configurado.')
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        data = base64.b64decode(value, validate=True)
        if len(data) > 50 * 1024 * 1024:
            p.error('Paquete excede 50 MiB')
        # Only known basenames; do not extract arbitrary paths from external ZIPs.
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in ('reporte.json', 'resumen.csv', 'hallazgos.csv', 'reporte.html'):
                i = z.getinfo(name)
                if i.file_size > 100 * 1024 * 1024:
                    p.error('Archivo descomprimido excede límite')
                (out / name).write_bytes(z.read(i))
            if 'resultados.txt' in z.namelist():
                i = z.getinfo('resultados.txt')
                if i.file_size > 100 * 1024 * 1024:
                    p.error('TXT descomprimido excede límite')
                (out / 'resultados.txt').write_bytes(z.read(i))
            else:
                # Preserve compatibility with artifacts generated by v1.0.
                old_report = json.loads((out / 'reporte.json').read_text(encoding='utf-8'))
                (out / 'resultados.txt').write_bytes(render_text(old_report))
        restored_report = json.loads((out / 'reporte.json').read_text(encoding='utf-8'))
        for name, content in per_server_texts(restored_report).items():
            target = out / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        print('Reportes recuperados en ' + str(out))
        return
    payload = json.loads(Path(args.input).read_text(encoding='utf-8'))
    report = build_report(payload)
    encoded = write_reports(report, args.out)
    include = len(encoded.encode('ascii')) <= args.artifact_limit
    artifact = {'viko_vuln_summary': report['summary'], 'viko_vuln_rules_reviewed_on': RULESET['reviewed_on'],
                'viko_vuln_report_dir': str(args.out),
                'viko_vuln_bundle_status': 'completo' if include else 'excede_limite_configurado_recuperar_resultados_zip_desde_directorio_persistente',
                'viko_vuln_report_zip_base64': encoded if include else '',
                'viko_vuln_bundle_bytes_base64': len(encoded)}
    print(json.dumps(artifact, separators=(',', ':')))


if __name__ == '__main__':
    main()
