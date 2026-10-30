"""Classify collected evidence with the existing project's shared CVE rules."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def triage(raw, recon_dir, host):
    spec = importlib.util.spec_from_file_location('viko_recon_report', Path(recon_dir) / 'scripts/report.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = raw.get('coverage', {}).get('limits', {}).get('checks', ['php', 'log4j', 'struts'])
    report = module.build_report({'checks': checks, 'hosts': [
        {'host': host, 'raw': raw, 'vendor_evidence': []}]})
    for finding in report['findings']:
        status = finding['status']
        if status == 'potencialmente_afectado':
            decision = 'remediacion_recomendada_por_version_confirmar_aplicabilidad'
        elif status.startswith('requiere_'):
            decision = 'requiere_validacion_adicional'
        elif status == 'fuera_rango_version':
            decision = 'fuera_del_rango_de_este_CVE'
        elif status.startswith('no_detectado'):
            decision = 'no_detectado_en_alcance_no_acredita_ausencia'
        elif status == 'componente_informativo':
            decision = 'informativo_no_atribuir_CVE_de_core'
        else:
            decision = 'no_evaluado'
        finding['remediation_decision'] = decision
        finding['automatic_changes'] = False
        finding['automatic_remediation_allowed'] = finding['family'] == 'php'
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--recon-dir', required=True)
    parser.add_argument('--host', required=True)
    args = parser.parse_args()
    print(json.dumps(triage(json.loads(Path(args.input).read_text()), args.recon_dir, args.host)))
