"""Read-only Debian PHP package checks and loaded-file generation audit.
No phpinfo, configuration dumps, exploits, HTTP endpoints or credentials.
An inode match proves file generation only, never the complete contents of memory.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import time


def run(argv, timeout=15):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, env=dict(os.environ, LC_ALL='C'))
    if len(result.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('Salida excesiva')
    return result


def audit():
    deadline = time.monotonic() + 120
    result = {'scope': 'Integridad segun metadatos dpkg e inode de archivos PHP mapeados; no prueba funcional web ni cierre CVE',
              'packages': [], 'mapped_php_files': [], 'errors': [], 'status': 'evaluado',
              'migration_context': {'cli_extensions': [], 'apache_php_modules': [], 'config_references': [],
              'scope': 'Solo inventario de compatibilidad; no cambia handlers ni acredita funcionamiento de la aplicacion'}}
    inventory = run(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Package}\t${Version}\n'])
    if inventory.returncode:
        raise RuntimeError('Inventario dpkg no disponible')
    for line in inventory.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 3 or fields[0] != 'installed' or not re.match(r'^(php|libapache2-mod-php)', fields[1]):
            continue
        if len(result['packages']) >= 120 or time.monotonic() >= deadline:
            result['errors'].append('Limite de paquetes o tiempo alcanzado'); break
        check = run(['dpkg', '--verify', fields[1]], min(10, max(1, deadline-time.monotonic())))
        deviations = len(check.stdout.splitlines())
        result['packages'].append({'name': fields[1], 'version': fields[2],
            'status': 'sin_diferencias_segun_metadatos_dpkg' if not deviations and check.returncode == 0 else 'diferencias_o_verificacion_incompleta',
            'deviations': deviations, 'returncode': check.returncode})
    # Extension names and active configuration references help prepare an explicit
    # migration. Never emit raw configuration lines, environment or phpinfo.
    for branch in ('7.4', '8.1', '8.2', '8.3', '8.4', '8.5'):
        binary = '/usr/bin/php' + branch
        if not Path(binary).is_file() or time.monotonic() >= deadline:
            continue
        try:
            probe = run([binary, '-d', 'auto_prepend_file=', '-d', 'auto_append_file=', '-r',
                         'echo "VIKO_EXT:".json_encode(get_loaded_extensions());'], 10)
            match = re.search(r'VIKO_EXT:(\[[^\r\n]*\])', probe.stdout)
            names = json.loads(match.group(1)) if match else []
            result['migration_context']['cli_extensions'].append({'branch': branch,
                'extensions': sorted(n for n in names if isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9_ .-]{1,80}', n)),
                'scope': 'CLI; extensiones web pueden diferir', 'returncode': probe.returncode})
        except (OSError, ValueError, subprocess.TimeoutExpired):
            result['errors'].append('Extensiones CLI no evaluadas: ' + branch)
    apache = Path('/etc/apache2')
    if apache.is_dir():
        for module in sorted((apache/'mods-enabled').glob('php*.load')):
            result['migration_context']['apache_php_modules'].append(module.name)
        count = 0
        for directory in ('sites-enabled', 'conf-enabled', 'mods-enabled'):
            for path in sorted((apache/directory).glob('*')):
                if time.monotonic() >= deadline or count >= 2000:
                    result['errors'].append('Cobertura de configuracion Apache incompleta'); break
                count += 1
                try:
                    resolved = path.resolve()
                    if apache not in resolved.parents or not resolved.is_file() or resolved.stat().st_size > 1024*1024:
                        continue
                    text = '\n'.join(line for line in resolved.read_text(errors='replace').splitlines()
                                     if not line.lstrip().startswith('#'))
                    branches = sorted(set(re.findall(r'php(?:-fpm)?([578]\.[0-9]+)', text)))
                    handler = bool(re.search(r'(?im)^\s*(?:SetHandler|ProxyPassMatch|AddHandler|Action)\s', text))
                    if branches or handler:
                        result['migration_context']['config_references'].append({'file': str(path),
                            'php_branches_referenced': branches, 'handler_directive_present': handler})
                except (OSError, ValueError):
                    result['errors'].append('Configuracion Apache no evaluada: ' + path.name)

    pids = sorted((p for p in Path('/proc').iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    for process in pids[:10000]:
        if time.monotonic() >= deadline:
            result['errors'].append('Tiempo de procesos agotado'); break
        try:
            # Host processes only: no container root/namespace inference.
            if not os.path.samefile(str(process / 'root'), '/'):
                continue
            if any(os.readlink(str(process / 'ns' / ns)) != os.readlink('/proc/self/ns/' + ns)
                   for ns in ('pid', 'user', 'net')):
                continue
            executable = os.readlink(str(process / 'exe'))
            if not re.search(r'/(?:php-fpm[0-9.]*|apache2|httpd)(?: \(deleted\))?$', executable):
                continue
            with (process/'maps').open() as stream:
                for index, line in enumerate(stream):
                    if index > 20000 or len(result['mapped_php_files']) >= 1000:
                        result['errors'].append('Limite de mapas alcanzado'); break
                    parts = line.split(None, 5)
                    if len(parts) != 6:
                        continue
                    mapped = parts[5].strip()
                    if not (re.match(r'^/usr/lib/(?:php/|apache2/modules/libphp)', mapped)
                            or re.match(r'^/usr/sbin/php-fpm[0-9.]*', mapped)):
                        continue
                    deleted = mapped.endswith(' (deleted)')
                    clean = mapped.removesuffix(' (deleted)') if hasattr(mapped, 'removesuffix') else mapped[:-10] if deleted else mapped
                    try:
                        current = os.stat(clean)
                        major, minor = (int(n,16) for n in parts[3].split(':'))
                        matches = not deleted and current.st_ino == int(parts[4]) and os.major(current.st_dev) == major and os.minor(current.st_dev) == minor
                    except OSError:
                        matches = False
                    item = {'pid': int(process.name), 'path': clean, 'generation': 'archivo_actual' if matches else 'obsoleta_o_no_verificable'}
                    if item not in result['mapped_php_files']:
                        result['mapped_php_files'].append(item)
        except FileNotFoundError:
            continue  # process exited during collection
        except (PermissionError, OSError, ValueError):
            result['errors'].append('Proceso no verificable: ' + process.name)
    if len(pids) > 10000:
        result['errors'].append('Cobertura parcial: mas de 10000 procesos')
    if result['errors'] or any(p['status'] != 'sin_diferencias_segun_metadatos_dpkg' for p in result['packages']):
        result['status'] = 'revision_requerida'
    if not result['mapped_php_files']:
        result['errors'].append('No se observaron archivos PHP web mapeados; no acredita ausencia')
        result['status'] = 'revision_requerida'
    return result


if __name__ == '__main__':
    try:
        value = audit()
    except Exception as error:
        value = {'status': 'no_evaluado', 'errors': [type(error).__name__], 'scope': 'No se pudo completar auditoria local'}
    print('VIKO_PHP_AUDIT:' + json.dumps(value))
