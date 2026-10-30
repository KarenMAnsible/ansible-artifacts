"""Build exact Linux PHP package plans. Does not install or reconfigure anything."""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

MINIMUM = {'8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12'}
CVES = ['CVE-2026-109618', 'CVE-2026-109619']


def version(value):
    match = re.match(r'^(?:\d+:)?(\d+)\.(\d+)\.(\d+)(?:$|[-+~.])', str(value))
    return tuple(map(int, match.groups())) if match else None


class Planner:
    def __init__(self, config):
        self.c = config
        self.deadline = time.monotonic() + 180
        self.actions = []
        self.blockers = []
        self.checked = []
        self.zypper_candidates = None

    def run(self, argv):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Tiempo de consulta de repositorios agotado')
        process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=min(20, remaining), universal_newlines=True,
                                 env=dict(os.environ, LC_ALL='C'))
        if process.returncode != 0:
            raise RuntimeError('Consulta fallida: ' + argv[0])
        if len(process.stdout) > 8 * 1024 * 1024:
            raise RuntimeError('Consulta excede limite de salida')
        return process.stdout

    def owner(self, path):
        if self.c['manager'] == 'apt':
            result = self.run(['dpkg-query', '-S', path])
            names = {line.rsplit(': ', 1)[0].split(':')[0] for line in result.splitlines() if ': ' in line}
            if len(names) != 1:
                raise RuntimeError('Propietario de binario ambiguo')
            return names.pop()
        return self.run(['rpm', '-qf', '--qf', '%{NAME}', path]).strip()

    def candidate(self, name):
        manager = self.c['manager']
        if manager == 'apt':
            text = self.run(['apt-cache', 'policy', name])
            match = re.search(r'^\s*Candidate:\s*(\S+)', text, re.M)
            if not match or match.group(1) == '(none)':
                raise RuntimeError('Sin candidato apt: ' + name)
            return match.group(1)
        if manager == 'dnf':
            text = self.run(['dnf', '-q', 'repoquery', '--available', '--latest-limit', '1',
                             '--qf', '%{epoch}:%{version}-%{release}', name])
            values = {line.strip().replace('(none):', '0:') for line in text.splitlines()
                      if re.match(r'^(?:\d+|\(none\)):\d', line.strip())}
            if len(values) != 1:
                raise RuntimeError('Sin candidato dnf unico: ' + name)
            return values.pop()
        if manager == 'zypper':
            if self.zypper_candidates is None:
                text = self.run(['zypper', '--non-interactive', '--xmlout', '--no-refresh',
                                 'list-updates', '--type', 'package'])
                root = ET.fromstring(text)
                self.zypper_candidates = {}
                for node in root.iter('update'):
                    if node.get('kind') == 'package' and node.get('name') and node.get('edition'):
                        self.zypper_candidates.setdefault(node.get('name'), set()).add(node.get('edition'))
            values = self.zypper_candidates.get(name, set())
            if len(values) != 1:
                raise RuntimeError('Sin actualizacion zypper unica: ' + name)
            return next(iter(values))
        raise RuntimeError('Gestor no implementado: ' + manager)

    def build(self):
        packages = {p['key']: p['value'] for p in self.c.get('packages', [])}
        if not packages:
            try:
                if self.c['manager'] == 'apt':
                    inventory = self.run(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Package}\t${Version}\n'])
                    for line in inventory.splitlines():
                        columns = line.split('\t')
                        if len(columns) == 3 and columns[0] == 'installed' and re.match(r'^(php|libapache2-mod-php)', columns[1]):
                            packages.setdefault(columns[1], []).append({'version': columns[2]})
                elif self.c['manager'] in ('dnf', 'zypper'):
                    inventory = self.run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}\n'])
                    for line in inventory.splitlines():
                        columns = line.split('\t')
                        if len(columns) == 2 and re.match(r'^(php|libapache2-mod-php)', columns[0]):
                            packages.setdefault(columns[0], []).append({'version': columns[1]})
                else:
                    raise RuntimeError('Gestor PHP no implementado: ' + self.c['manager'])
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                self.blockers.append(str(error))
                return self.result()
        binaries = [o for o in self.c.get('observations', [])
                    if o.get('version_source') == 'php_cli_no_ini' and o.get('path', '').startswith('/')]
        if not binaries:
            if packages or self.c.get('observations'):
                self.blockers.append('PHP detectado sin runtime CLI verificable. Preparar plan especifico de esta instalacion.')
            return self.result()
        seen_groups = set()
        for binary in binaries:
            path = binary['path']
            observed = str(binary.get('version', ''))
            current = version(observed) if re.fullmatch(r'\d+\.\d+\.\d+', observed) else None
            if current is None:
                self.blockers.append(path + ': version desconocida o prerelease')
                continue
            branch = '.'.join(map(str, current[:2]))
            minimum = MINIMUM.get(branch)
            if minimum is None:
                self.blockers.append(path + ': rama ' + branch + ' requiere migracion o evidencia de backport del proveedor')
                continue
            if current >= version(minimum):
                self.checked.append({'path': path, 'version': binary['version'], 'status': 'version_en_minimo_o_superior_runtime_web_pendiente'})
                continue
            try:
                owner = self.owner(os.path.realpath(path))
                if not re.match(r'^(php\d*(?:\.\d+)?(?:-php)?)(?:-|$)', owner):
                    raise RuntimeError('Runtime sin paquete PHP reconocido')
                prefix = re.match(r'^(php\d*(?:\.\d+)?(?:-php)?)(?:-|$)', owner).group(1)
                key = (prefix, branch)
                if key in seen_groups:
                    continue
                seen_groups.add(key)
                selected = []
                for name, entries in packages.items():
                    eligible_name = name == prefix or name.startswith(prefix + '-') or name == 'libapache2-mod-' + prefix
                    if not eligible_name:
                        continue
                    if len(entries) != 1:
                        raise RuntimeError('Paquete multi-arquitectura requiere plan: ' + name)
                    installed = version(entries[0]['version'])
                    if installed and installed[:2] == current[:2]:
                        selected.append(name)
                if owner not in selected or len(selected) > 40:
                    raise RuntimeError('No se pudo delimitar el grupo de paquetes del runtime')
                exact = []
                candidate_versions = set()
                for name in selected:
                    candidate = self.candidate(name)
                    target = version(candidate)
                    if target is None or target[:2] != current[:2] or target < version(minimum):
                        raise RuntimeError('El candidato no contiene el minimo upstream en la misma rama: ' + name)
                    candidate_versions.add(target)
                    exact.append({'name': name, 'version': candidate})
                if len(candidate_versions) != 1:
                    raise RuntimeError('Candidatos PHP desalineados entre extensiones/runtime')
                target = '.'.join(map(str, candidate_versions.pop()))
                services = []
                for name, service in self.c.get('services', {}).items():
                    if service.get('state') != 'running':
                        continue
                    php_service = bool(re.search(r'php.*fpm', name, re.I)) and (
                        prefix == 'php' or prefix in name or branch in name or name in ('php-fpm', 'php-fpm.service'))
                    apache = any(n.startswith('libapache2-mod-php') or n == 'php' for n in selected) and name in ('apache2.service', 'httpd.service')
                    if php_service or apache:
                        services.append(name)
                self.actions.append({
                    'id': 'php_auto_' + re.sub(r'[^a-zA-Z0-9_]', '_', prefix),
                    'family': 'php', 'cves': CVES, 'os_family': self.c['os_family'],
                    'os_version': self.c['os_version'], 'method': 'linux_packages',
                    'vendor_advisory': 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
                    'backup_reference': self.c.get('backup_reference', ''),
                    'packages': exact, 'probe_argv': [path, '-n', '-r', 'echo PHP_VERSION;'],
                    'expected_output': target, 'services': sorted(set(services)),
                    'health_argv': [path, '-n', '-r', 'echo "VIKO_PHP_RUNTIME_OK";'],
                    'health_regex': '^VIKO_PHP_RUNTIME_OK$',
                    'validation_scope': 'PHP CLI y servicios identificados; falta prueba funcional de la aplicacion y posibles instalaciones paralelas',
                    'auto_generated': True})
            except (RuntimeError, OSError, subprocess.TimeoutExpired, ET.ParseError) as error:
                self.blockers.append(path + ': ' + str(error))
        return self.result()

    def result(self):
        return {'actions': self.actions, 'blockers': self.blockers, 'checked': self.checked,
                'status': 'bloqueado' if self.blockers else 'plan_generado' if self.actions else 'sin_cambios_propuestos'}


if __name__ == '__main__':
    config = json.loads(base64.b64decode(sys.argv[1]).decode())
    print('VIKO_PHP_PLAN:' + json.dumps(Planner(config).build()))
