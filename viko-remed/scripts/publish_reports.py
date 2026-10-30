"""Publish sanitized remediation evidence, per-host TXT and recoverable AAP artifact."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
import zipfile

try:
    from zoneinfo import ZoneInfo
    CDMX = ZoneInfo('America/Mexico_City')
except (ImportError, KeyError):
    CDMX = timezone(timedelta(hours=-6))


def slug(value, limit):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', str(value)).strip('._-')[:limit] or 'sin_dato'


def identity(host):
    validation = host.get('validation', {})
    system = next(iter(validation.get('hosts', [])), {}).get('system', {})
    name = system.get('hostname') or host['host']
    candidates = [host.get('address', '')] + system.get('ip_addresses', [])
    address = 'IP_no_registrada'
    for candidate in candidates:
        try:
            address = str(ipaddress.ip_address(candidate))
            break
        except (ValueError, TypeError):
            pass
    return slug(name, 48), slug(address, 42)


def text_report(host, instant):
    def clean(value):
        return str(value).replace('\r', ' ').replace('\n', ' ')
    lines = ['VIKO | REMEDIACION PHP Y VALIDACION LOG4J / STRUTS',
             'Equipo: ' + clean(host['host']),
             'Destino: ' + clean(host.get('address', 'sin_dato')),
             'Sistema: ' + clean(host.get('os', 'sin_identificar')),
             'Informe CDMX: ' + instant.isoformat(),
             'Modo: ' + clean(host.get('mode', 'sin_dato')),
             'Estado: ' + clean(host.get('status', 'no_evaluado')),
             'Motivo: ' + clean(host.get('reason', '')), '', 'PHP | EJECUCION']
    for blocker in host.get('php_planning', {}).get('blockers', []):
        lines.append('Bloqueo: ' + clean(blocker))
    for action in host.get('actions', []):
        lines += ['Accion: ' + clean(action['id']) + ' | ' + clean(action['status']),
                  '  Antes: ' + clean(action.get('before', 'sin evidencia')),
                  '  Despues: ' + clean(action.get('after', 'no ejecutado')),
                  '  Alcance: ' + clean(action.get('validation_scope', 'consultar plan'))]
    if not host.get('actions'):
        lines.append('No se ejecutaron acciones. Consultar seleccion, cobertura y bloqueos; no implica correccion.')
    for key, title in [('validation', 'VALIDACION PREVIA'), ('php_post_validation', 'PHP | VALIDACION POSTERIOR')]:
        report = host.get(key)
        if not report:
            continue
        lines += ['', title]
        for item in report.get('hosts', []):
            coverage = item.get('coverage', {})
            lines += ['Recoleccion: ' + clean(item.get('collection_status', 'no_evaluado')),
                      'Cobertura: ' + clean(coverage.get('file_search', 'sin_dato')),
                      'Tiempo: ' + clean(coverage.get('elapsed_seconds', 'sin_dato')),
                      'Rutas solicitadas: ' + clean(', '.join(coverage.get('roots_requested', []))),
                      'Rutas completadas: ' + clean(', '.join(coverage.get('roots_completed', []))),
                      'Errores/omisiones: ' + clean(coverage.get('errors_count', 0))]
            for error in coverage.get('errors', []):
                lines.append('  ' + clean(error.get('location', '')) + ': ' + clean(error.get('reason', '')))
        for finding in report.get('findings', []):
            lines += [clean(finding.get('cve') or 'INFORMATIVO') + ' | ' + clean(finding['component']),
                      '  Version: ' + clean(finding.get('version') or 'no identificada'),
                      '  Ruta: ' + clean(finding.get('path', '')),
                      '  Fuente version: ' + clean(finding.get('version_source', '')),
                      '  Estado: ' + clean(finding.get('status', '')),
                      '  Decision: ' + clean(finding.get('remediation_decision', '')),
                      '  Accion posterior: ' + clean(finding.get('action', ''))]
    lines += ['', 'AGENTE | SOLO DIAGNOSTICO', json.dumps(host.get('agent_diagnostic', {}), ensure_ascii=False),
              '', 'Log4j/Struts no se modificaron. PHP requiere verificar runtime web y cierre de Seguridad.',
              'Ausencia de hallazgo en rutas parciales no demuestra ausencia global. Sin rollback automatico.']
    return ('\ufeff' + '\r\n'.join(lines) + '\r\n').encode('utf-8')


def write_exclusive(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, prefix='.viko-report-') as stream:
        temporary = Path(stream.name)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        try:
            os.link(str(temporary), str(path))
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != data:
                raise ValueError('Colision de nombre; no se sobrescribio un TXT existente')
    finally:
        temporary.unlink()


def shared_mount(path):
    """Do not silently advertise an arbitrary EE-local directory as persistent."""
    if not path or not Path(path).is_dir():
        return False
    resolved = Path(path).resolve()
    try:
        lines = Path('/proc/self/mountinfo').read_text().splitlines()
        for line in lines:
            point = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), line.split()[4]))
            if str(point) != '/' and (resolved == point or point in resolved.parents):
                return True
    except OSError:
        pass
    return False


def publish(payload, directory, shared_root='', job_id='sin_job', limit=700000):
    out = Path(directory)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    reports = {}
    reports_by_host = {}
    for host in payload['hosts']:
        name, address = identity(host)
        try:
            instant = datetime.fromisoformat(host.get('report_utc', '').replace('Z', '+00:00')).astimezone(CDMX)
        except ValueError:
            instant = datetime.now(CDMX)
        stamp = instant.strftime('%Y%m%d_%H%M%S')
        filename = '{}_{}_{}.txt'.format(name, address, stamp)
        # A duplicate destination is kept in a separate host folder, preserving basename format.
        key = filename
        if key in reports:
            key = hashlib.sha256(host['host'].encode()).hexdigest()[:16] + '/' + filename
        data = text_report(host, instant)
        reports[key] = data
        reports_by_host[host['host']] = [key]
        write_exclusive(out / 'por_servidor' / key, data)
    full = json.dumps(payload, ensure_ascii=False, indent=2).encode()
    write_exclusive(out / 'remediacion.json', full)
    mounted = shared_mount(shared_root)
    shared_status = 'montaje_no_confirmado_recuperar_desde_artifacts'
    if mounted:
        try:
            destination = Path(shared_root) / 'remediacion' / ('job_' + slug(job_id, 40))
            for name, data in reports.items():
                write_exclusive(destination / 'por_servidor' / name, data)
            write_exclusive(destination / ('consolidado_' + hashlib.sha256(full).hexdigest()[:16] + '.json'), full)
            shared_status = 'guardado_en_montaje'
        except (OSError, ValueError):
            shared_status = 'error_de_publicacion_recuperar_desde_artifacts'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr('remediacion.json', full)
        for name, data in reports.items():
            zipped.writestr('por_servidor/' + name, data)
    encoded = base64.b64encode(archive.getvalue()).decode()
    if len(encoded) > int(limit):
        encoded = ''
        if shared_status != 'guardado_en_montaje':
            raise ValueError('Evidencia excede limite y no hay copia persistente; usar lote mas pequeno')
    return {
        'viko_remediacion': [{'host': h['host'], 'status': h['status'], 'os': h.get('os', ''),
                             'php_actions': len(h.get('actions', [])),
                             'report_names': reports_by_host[h['host']]} for h in payload['hosts']],
        'viko_remediacion_reportes_zip_base64': encoded,
        'viko_remediacion_reportes_sha256': hashlib.sha256(archive.getvalue()).hexdigest(),
        'viko_remediacion_publicacion': shared_status,
        'viko_remediacion_txt': len(reports),
        'viko_remediacion_job_id': str(job_id)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--shared-root', default='')
    parser.add_argument('--job-id', default='sin_job')
    args = parser.parse_args()
    print(json.dumps(publish(json.loads(Path(args.input).read_text()), args.out, args.shared_root, args.job_id)))
