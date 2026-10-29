#!/usr/bin/env python3
"""VIKO read-only Linux collector, Python >=3.6, standard library only.
No CVE verdicts here: report.py applies the same rules to both platforms.
"""
import base64
import datetime
import glob
import io
import ipaddress
import json
import os
import platform
import re
import signal
import shutil
import stat
import struct
import subprocess
import sys
import time
import zipfile


class ScanDeadline(Exception):
    pass


class Collector:
    def __init__(self, config):
        self.c = config
        self.started = time.monotonic()
        self.deadline = self.started + max(1, int(config.get('scan_seconds', 180)))
        self.observations = []
        self.errors = []
        self.error_count = 0
        self.files = self.archives = self.nested_bytes = 0
        self.seen_files = set()
        self.completed_roots = []
        self.missing_roots = []
        self.budget_exhausted = False
        self.php_inventory = None

    def problem(self, location, reason):
        self.error_count += 1
        if len(self.errors) < 100:
            self.errors.append({'location': str(location), 'reason': reason})

    def expired(self):
        if time.monotonic() >= self.deadline:
            self.budget_exhausted = True
            return True
        return False

    def command(self, argv, optional=False):
        if self.expired():
            return None
        if not shutil.which(argv[0]):
            if not optional:
                self.problem(argv[0], 'herramienta_no_disponible')
            return None
        try:
            # These inventory commands have bounded runtime; discard unexpectedly
            # large output rather than incorporating it into evidence.
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=max(.1, min(float(self.c.get('command_timeout', 10)),
                                                   self.deadline - time.monotonic())),
                               env=dict(os.environ, LC_ALL='C'), universal_newlines=True,
                               errors='replace')
            if p.returncode:
                self.problem(argv[0], 'consulta_fallida_rc_' + str(p.returncode))
                return None
            if len(p.stdout) > 4 * 1024 * 1024:
                self.problem(argv[0], 'salida_excede_limite')
                return None
            return p.stdout
        except (OSError, subprocess.TimeoutExpired):
            self.problem(argv[0], 'error_o_timeout')
            return None

    def add(self, component, path, version='', source='', **extra):
        family = 'php' if component == 'php' else 'struts' if component in ('struts2-core', 'xwork-core') else 'log4j'
        if family not in self.c.get('checks', ['php', 'log4j', 'struts']):
            return
        if len(self.observations) >= int(self.c.get('max_observations', 2000)):
            self.problem(path, 'limite_componentes')
            return
        item = dict(component=component, path=path, version=version, version_source=source)
        item.update(extra)
        if item not in self.observations:
            self.observations.append(item)

    @staticmethod
    def properties(text):
        result = {}
        for line in text.splitlines():
            m = re.match(r'^\s*([^#!\s=:]+)\s*[=:]\s*(.*?)\s*$', line)
            if m:
                result[m.group(1)] = m.group(2)
        return result

    def read_entry(self, z, entry, limit=131072):
        if entry.file_size > limit:
            self.problem(entry.filename, 'entrada_excede_limite')
            return None
        if entry.compress_size and entry.file_size / entry.compress_size > 300:
            self.problem(entry.filename, 'ratio_compresion_excesivo')
            return None
        with z.open(entry) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            self.problem(entry.filename, 'lectura_excede_limite')
            return None
        return data

    def archive(self, source, path, depth=0):
        if self.expired():
            return
        self.archives += 1
        if self.archives > int(self.c.get('max_archives', 1500)):
            self.problem(path, 'limite_archivos_comprimidos')
            return
        try:
            # Inspect the classic EOCD before ZipFile materializes every entry.
            # ZIP64/multivolume archives are deliberately left for a deeper scan.
            own_stream = isinstance(source, str)
            stream = open(source, 'rb') if own_stream else source
            try:
                stream.seek(0, 2)
                length = stream.tell()
                stream.seek(max(0, length - 65557))
                tail = stream.read(65557)
                pos = tail.rfind(b'PK\x05\x06')
                if pos < 0 or len(tail) < pos + 22:
                    self.problem(path, 'zip_sin_directorio_clasico')
                    return
                count = struct.unpack_from('<H', tail, pos + 10)[0]
                disks = struct.unpack_from('<HH', tail, pos + 4)
                if count == 65535 or disks != (0, 0):
                    self.problem(path, 'zip64_o_multivolumen_no_inspeccionado')
                    return
                if count > int(self.c.get('max_entries', 50000)):
                    self.problem(path, 'demasiadas_entradas_zip')
                    return
                stream.seek(0)
            finally:
                if own_stream:
                    stream.close()
            with zipfile.ZipFile(source) as z:
                infos = z.infolist()
                if len(infos) > int(self.c.get('max_entries', 50000)):
                    self.problem(path, 'demasiadas_entradas_zip')
                    return
                names = [i.filename.replace('\\', '/') for i in infos]
                core = any(n.endswith('org/apache/logging/log4j/core/Logger.class') for n in names)
                jndi = any(n.endswith('org/apache/logging/log4j/core/lookup/JndiLookup.class') for n in names)
                struts = any(n.endswith('org/apache/struts2/dispatcher/Dispatcher.class') for n in names)
                log1 = any(n.endswith('org/apache/log4j/Logger.class') for n in names)
                found = set()
                for info, name in zip(infos, names):
                    if self.expired():
                        return
                    if name.endswith('/pom.properties') and '/META-INF/' not in '/' + name:
                        continue
                    if name.endswith('/pom.properties'):
                        data = self.read_entry(z, info)
                        if data is None:
                            continue
                        p = self.properties(data.decode('utf-8', 'replace'))
                        group, artifact = p.get('groupId'), p.get('artifactId')
                        valid = ((group == 'org.apache.logging.log4j' and artifact in ('log4j-core', 'log4j-api'))
                                 or (group == 'org.apache.struts' and artifact == 'struts2-core')
                                 or (group == 'org.apache.struts.xwork' and artifact == 'xwork-core')
                                 or (group == 'log4j' and artifact == 'log4j'))
                        if valid:
                            component = 'log4j1' if artifact == 'log4j' else artifact
                            self.add(component, path, p.get('version', ''), 'maven_pom',
                                     jndi_lookup=jndi if component == 'log4j-core' else None,
                                     metadata_entry=name, archive_depth=depth)
                            found.add(component)
                base = path.rsplit('!', 1)[-1].rsplit('/', 1)[-1]
                matched = re.match(r'^(log4j-core|log4j-api|struts2-core|xwork-core|log4j)-(.+)\.jar$', base, re.I)
                component = ('log4j1' if matched and matched.group(1).lower() == 'log4j' else matched.group(1).lower()) if matched else None
                if component and component not in found:
                    version, vsource = matched.group(2), 'filename'
                    manifests = [i for i in infos if i.filename.upper() == 'META-INF/MANIFEST.MF']
                    if manifests:
                        data = self.read_entry(z, manifests[0])
                        if data:
                            m = re.search(r'^Implementation-Version:\s*(\S+)', data.decode('utf-8', 'replace'), re.M)
                            if m and m.group(1) == version:
                                vsource = 'manifest_and_filename'
                            elif m and m.group(1) != version:
                                self.problem(path, 'version_manifest_y_nombre_discrepan')
                                version, vsource = '', 'conflict'
                    self.add(component, path, version, vsource, jndi_lookup=jndi if component == 'log4j-core' else None, archive_depth=depth)
                    found.add(component)
                for flag, component in ((core, 'log4j-core'), (struts, 'struts2-core'), (log1, 'log4j1')):
                    if flag and component not in found:
                        self.add(component, path, '', 'embedded_classes', jndi_lookup=jndi if component == 'log4j-core' else None, archive_depth=depth)
                for info, name in zip(infos, names):
                    if not name.lower().endswith(('.jar', '.war', '.ear', '.zip')):
                        continue
                    if self.expired():
                        return
                    if depth >= int(self.c.get('archive_depth', 2)):
                        self.problem(path + '!' + name, 'profundidad_maxima')
                        continue
                    limit = int(self.c.get('max_nested_mb', 32)) * 1024 * 1024
                    if self.nested_bytes + info.file_size > int(self.c.get('max_total_nested_mb', 128)) * 1024 * 1024:
                        self.problem(path + '!' + name, 'presupuesto_total_anidados')
                        continue
                    data = self.read_entry(z, info, limit)
                    if data is not None:
                        self.nested_bytes += len(data)
                        self.archive(io.BytesIO(data), path + '!' + name, depth + 1)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError):
            self.problem(path, 'zip_no_legible_o_no_soportado')

    def file(self, path):
        try:
            s = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(s.st_mode):
                return
            key = (s.st_dev, s.st_ino)
            if key in self.seen_files:
                return
            self.seen_files.add(key)
            self.files += 1
            if re.match(r'^php(?:-fpm|[0-9.]+)?$', os.path.basename(path)) and os.access(path, os.X_OK):
                self.add('php', path, '', 'binary_without_version')
            if not path.lower().endswith(('.jar', '.war', '.ear', '.zip')):
                return
            if not set(self.c.get('checks', [])) & {'log4j', 'struts'}:
                return
            if s.st_size > int(self.c.get('max_archive_mb', 128)) * 1024 * 1024:
                self.problem(path, 'zip_excede_tamano')
                return
            self.archive(path, path)
        except OSError:
            self.problem(path, 'sin_permiso_o_error_lectura')

    def walk(self):
        excludes = [os.path.abspath(p).rstrip('/') for p in self.c.get('linux_excludes', [])]
        for root in self.c.get('linux_roots', []):
            if self.expired() or self.files >= int(self.c.get('max_files', 100000)):
                self.budget_exhausted = True
                break
            if not os.path.lexists(root):
                self.missing_roots.append(root)
                continue
            if os.path.islink(root):
                self.problem(root, 'raiz_symlink_no_seguida')
                continue
            try:
                rootdev = os.stat(root).st_dev
                def error(err):
                    self.problem(err.filename, 'directorio_no_legible')
                for directory, dirs, files in os.walk(root, onerror=error, followlinks=False):
                    if self.expired() or self.files >= int(self.c.get('max_files', 100000)):
                        self.budget_exhausted = True
                        break
                    keep = []
                    for d in sorted(dirs):
                        p = os.path.join(directory, d)
                        if any(p == e or p.startswith(e + '/') for e in excludes):
                            continue
                        try:
                            if os.path.islink(p):
                                self.problem(p, 'symlink_no_seguido')
                            elif not self.c.get('follow_mounts', False) and os.stat(p).st_dev != rootdev:
                                self.problem(p, 'montaje_no_recorrido')
                            else:
                                keep.append(d)
                        except OSError:
                            self.problem(p, 'directorio_no_legible')
                    dirs[:] = keep
                    for name in sorted(files):
                        if self.expired() or self.files >= int(self.c.get('max_files', 100000)):
                            self.budget_exhausted = True
                            break
                        self.file(os.path.join(directory, name))
                if not self.budget_exhausted:
                    self.completed_roots.append(root)
            except OSError:
                self.problem(root, 'raiz_no_legible')

    def packages(self):
        manager = 'rpm' if shutil.which('rpm') else 'dpkg' if shutil.which('dpkg-query') else None
        if manager == 'rpm':
            output = self.command(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'])
        elif manager == 'dpkg':
            output = self.command(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n'])
        else:
            self.problem('paquetes', 'gestor_no_soportado')
            return
        if output is None:
            return
        for line in output.splitlines():
            cols = line.split('\t')
            if manager == 'dpkg':
                if len(cols) != 4 or cols[0] != 'installed':
                    continue
                cols = cols[1:]
            if len(cols) != 3:
                continue
            name, version, arch = cols
            if re.match(r'^(?:php(?:\d+(?:\.\d+)*)?-)?php(?:\d+(?:\.\d+)*)?(?:-(?:cli|fpm|cgi|common))?$', name) or re.match(r'^libapache2-mod-php[\d.]*$', name):
                # Anchor after the epoch. A metapackage such as
                # 2:101~+ubuntu24.04.1 must never become PHP 24.04.1.
                m = re.match(r'(\d+\.\d+\.\d+)(?=$|[-+~.])', re.sub(r'^\d+:', '', version))
                self.add('php', 'package:' + name, m.group(1) if m else '', 'package_db', package=name, package_version=version, architecture=arch, package_manager=manager)

    def php(self):
        start_errors = self.error_count
        self.packages()
        candidates = []
        patterns = ('/usr/bin/php*', '/usr/local/bin/php*', '/opt/remi/php*/root/usr/bin/php',
                    '/opt/plesk/php/*/bin/php', '/opt/rh/rh-php*/root/usr/bin/php',
                    '/usr/local/php*/bin/php', '/opt/php*/bin/php')
        for pattern in patterns:
            candidates.extend(glob.glob(pattern))
        if shutil.which('php'):
            candidates.append(shutil.which('php'))
        seen = set()
        for p in candidates:
            # Never run phpize/php-config, FPM, CGI, or application scripts.
            if not re.match(r'^php(?:\d+(?:\.\d+)*)?$', os.path.basename(p)):
                continue
            p = os.path.realpath(p)
            if p in seen or not os.path.isfile(p) or not os.access(p, os.X_OK):
                continue
            seen.add(p)
            if len(seen) > 16:
                self.problem('php', 'limite_binarios_php')
                break
            version = ''
            if self.c.get('run_php_version', True):
                text = self.command([p, '-n', '-v'])
                m = re.search(r'^PHP\s+(\S+)', text or '', re.M)
                version = m.group(1) if m else ''
            self.add('php', p, version, 'php_cli_no_ini' if version else 'binary_without_version')
        self.php_inventory = {
            'status': 'parcial' if self.error_count > start_errors or self.expired() else 'completado_en_fuentes',
            'sources': ['base de paquetes instalada', 'PHP CLI en PATH y patrones configurados'],
            'binary_patterns': list(patterns), 'cli_binaries_checked': len(seen),
            'runtime_web': 'pendiente_de_correlacion',
            'note': 'El inventario de paquetes/CLI no acredita ausencia de PHP en aplicaciones, módulos Apache o contenedores.'}

    def context(self):
        services = []
        output = self.command(['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--plain', '--no-legend'], optional=True)
        for line in (output or '').splitlines():
            cols = line.split()
            if len(cols) >= 4 and re.search(r'php|apache|httpd|nginx|tomcat|instana|ds_agent|trend|cloudreset', cols[0], re.I):
                services.append({'name': cols[0], 'state': cols[2], 'substate': cols[3]})
        # Executable name/path only; no command lines, environments, or arguments.
        processes = []
        for pid in os.listdir('/proc') if os.path.isdir('/proc') else []:
            if not pid.isdigit() or self.expired():
                continue
            try:
                with open('/proc/' + pid + '/comm') as f:
                    name = f.read(100).strip()
                if re.search(r'php|apache|httpd|nginx|tomcat|java|instana|ds_agent|trend|cloudreset', name, re.I):
                    exe = ''
                    try:
                        exe = os.readlink('/proc/' + pid + '/exe')
                    except OSError:
                        pass
                    processes.append({'pid': int(pid), 'name': name, 'executable': exe})
            except OSError:
                pass
        trend = {'services': [s for s in services if re.search(r'ds_agent|trend', s['name'], re.I)],
                 'paths_present': [p for p in ('/opt/ds_agent', '/opt/TrendMicro') if os.path.exists(p)],
                 'note': 'Evidencia local; estado de protección y cobertura requieren consola de Seguridad.'}
        containers = []
        if self.c.get('container_inventory', True):
            for engine in ('docker', 'podman'):
                if not shutil.which(engine):
                    continue
                output = self.command([engine, 'ps', '--format', '{{.ID}}\t{{.Image}}\t{{.Names}}'])
                containers.append({'engine': engine, 'status': 'consultado' if output is not None else 'no_evaluado',
                                   'running': [dict(zip(('id', 'image', 'name'), l.split('\t', 2))) for l in (output or '').splitlines()],
                                   'contents_scanned': False})
        return services, processes, trend, containers

    def run(self):
        system = {'hostname': platform.node(), 'kernel': platform.release(), 'architecture': platform.machine(), 'ip_addresses': []}
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    k, _, v = line.strip().partition('=')
                    if k in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
                        system[k] = v.strip('"')
        except OSError:
            pass
        services, processes, trend, containers = [], [], {}, []
        def stop(_signum, _frame):
            raise ScanDeadline()
        previous_handler = signal.signal(signal.SIGALRM, stop)
        signal.setitimer(signal.ITIMER_REAL, max(.1, self.deadline - time.monotonic()))
        try:
            if 'php' in self.c.get('checks', []):
                self.php()
            addresses = self.command(['ip', '-o', 'addr', 'show'], optional=True)
            for value in re.findall(r'\binet6?\s+([^\s/]+)', addresses or ''):
                try:
                    address = ipaddress.ip_address(value)
                    if not address.is_loopback and not address.is_link_local and str(address) not in system['ip_addresses']:
                        system['ip_addresses'].append(str(address))
                except ValueError:
                    pass
            services, processes, trend, containers = self.context()
            if not self.c.get('php_inventory_only', False):
                self.walk()
        except ScanDeadline:
            self.budget_exhausted = True
            self.problem('servidor', 'tiempo_maximo_recolector')
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
        file_search = ('no_solicitado' if self.c.get('php_inventory_only', False) else
                       ('parcial' if self.error_count or self.budget_exhausted else
                        ('completado_en_rutas' if self.completed_roots else 'sin_rutas_revisadas')))
        families = {}
        for family in self.c.get('checks', []):
            if family == 'php':
                families[family] = self.php_inventory or {'status': 'no_evaluado', 'runtime_web': 'pendiente_de_correlacion'}
            else:
                families[family] = {'status': file_search, 'sources': ['archivos en raíces configuradas']}
        return {'schema_version': 1, 'collector_version': '1.5-piloto', 'status': 'recolectado', 'platform': 'linux', 'system': system,
                'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'observations': self.observations, 'services': services, 'processes': processes,
                'trend_local': trend, 'containers': containers,
                'coverage': {'file_search': file_search, 'families': families,
                             'roots_requested': [] if self.c.get('php_inventory_only', False) else self.c.get('linux_roots', []), 'roots_completed': self.completed_roots,
                             'roots_absent': self.missing_roots, 'excluded': self.c.get('linux_excludes', []),
                             'files_seen': self.files, 'archives_seen': self.archives, 'errors_count': self.error_count,
                             'errors': self.errors, 'budget_exhausted': self.budget_exhausted,
                             'elapsed_seconds': round(time.monotonic() - self.started, 2),
                             'limits': self.c,
                             'limitations': ['Solo rutas configuradas; no prueba ausencia global.',
                                             'Contenedores: solo inventario de ejecución; imágenes y contenido interno no inspeccionados.',
                                             'No correlaciona automáticamente biblioteca con aplicación en ejecución ni exposición pública.',
                                             'No evalúa condiciones de explotación ni configuraciones de Struts/PHP.']}}


if __name__ == '__main__':
    try:
        config = json.loads(base64.b64decode(sys.argv[1]).decode('utf-8'))
        result = Collector(config).run()
    except Exception as exc:
        result = {'status': 'no_evaluado', 'reason': 'Fallo interno del recolector: ' + type(exc).__name__}
    print('VIKO_VULN_JSON:' + json.dumps(result, separators=(',', ':'), ensure_ascii=True))
