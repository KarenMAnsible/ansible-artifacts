"""Read-only, bounded inventory of the standard CloudReset agent directories."""
import json
import os
import re
from pathlib import Path

roots = ['/CloudrResetPwdAgent', '/CloudResetPwdAgent', '/CloudResetPwdUpdateAgent']
out = []
for name in roots:
    root = Path(name)
    if not root.exists():
        continue
    record = {'path': name, 'version': '', 'log4j_files': [], 'errors': [],
              'coverage': 'standard_directories_only'}
    try:
        version_file = root / 'version'
        if version_file.is_file():
            with version_file.open() as stream:
                version = stream.read(128).strip()
            if re.fullmatch(r'\d+\.\d+\.\d+', version):
                record['version'] = version
            else:
                record['errors'].append('Version marker not recognized')
        count = 0
        def onerror(error):
            record['errors'].append(type(error).__name__)
        for folder, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            depth = len(Path(folder).relative_to(root).parts)
            dirs[:] = [] if depth >= 3 else [d for d in dirs if d not in ['logs', 'depend']]
            for file in files:
                count += 1
                if count > 3000:
                    record['errors'].append('File budget exceeded')
                    break
                if 'log4j' in file.lower() and file.lower().endswith('.jar'):
                    record['log4j_files'].append(str(Path(folder) / file))
            if count > 3000:
                break
    except OSError as error:
        record['errors'].append(type(error).__name__)
    out.append(record)
print(json.dumps({'agents': out, 'coverage': 'standard_directories_only'}))
