# Piloto de reconocimiento PHP y diagnóstico — 29 de octubre de 2026

Este ajuste es de reconocimiento de solo lectura. No instala paquetes, no actualiza PHP,
no reinstala agentes ni modifica SAP, Instana, Struts, servicios o contenedores.

## Qué resuelve en esta primera etapa

- Amplía la detección de Python y distingue el fallo de conexión, de comprobación
  del intérprete y de ejecución del recolector Linux.
- Windows registra etapa, código de fallo, tipo de excepción y línea cuando están
  disponibles. No publica stderr, mensajes crudos ni texto del script.
- Conserva las observaciones Windows si un fallo posterior impide terminar.
- Corrige el análisis de metapaquetes PHP: `101~+ubuntu24.04.1` no es PHP 24.04.1.
- Muestra en TXT los servicios, procesos y rutas de ejecutables ya recolectados,
  sin argumentos de procesos ni variables de entorno.
- Distingue cobertura del inventario PHP de la búsqueda de bibliotecas Java.
- Genera el informe dentro del mismo play. El campo Límite contiene solamente
  los equipos a revisar; no se agrega localhost.

## Primera corrida

Sincronizar el proyecto Reconocimiento-Vulnerabilidades-VIKO después de publicar
el cambio. Duplicar la plantilla Password y llamarla `Reconocimiento PHP - Piloto Password`.
Conservar inventario, entorno de ejecución y encuesta de la plantilla original.
La copia SSH Key puede prepararse después conservando la credencial Machine y
la encuesta deshabilitada.

Playbook: `viko-recon/reconocimiento_universal.yml`.

En las copias de piloto conservar las variables de conexión y establecer:

```yaml
vuln_checks:
  - php
vuln_php_inventory_only: true
vuln_fail_no_evidence: true
vuln_scan_seconds: 180
vuln_task_timeout: 240
vuln_command_timeout: 10
vuln_container_inventory: false
vuln_report_dir: /viko-reportes/job_{{ awx_job_id }}
vuln_txt_dir: /viko-reportes/TXT
```

Lanzar por separado, con los accesos correspondientes:

1. Linux: `huawei_viko_new_pruebas_seguridad` (94.74.67.251).
2. Windows: `gcp_sin_definir_trend` (34.58.53.46), conexión WinRM del inventario.

El Límite de cada corrida es exactamente un alias. El tiempo de espera de la
plantilla puede mantenerse en 1800 segundos. El timeout de tarea es 240 segundos;
las consultas individuales tienen 10 segundos y el recolector tiene 180 segundos.

Los TXT se consultan por SFTP en `/home/cloud-user/reportes/`, con nombre
`EQUIPO_IP_AAAAMMDD_HHMMSS.txt` y fecha/hora CDMX. Se conservan los reportes anteriores.

## Interpretación y criterio del piloto

Comprobar un TXT nuevo por corrida, identificación del equipo, IP, fecha,
versión del recolector `1.5-piloto`, fuentes consultadas y resultados por CVE.
Si falla la recolección, debe mostrar diagnóstico. Con `vuln_fail_no_evidence: true`
el Job termina con fallo después de guardar el reporte si algún objetivo no
devolvió evidencia. Así una ejecución sin evidencia no pasa inadvertida.

Linux consulta la base de paquetes y PHP CLI en PATH/patrones conocidos; no hace
un recorrido general de SAP o Java en este modo. Windows consulta PHP en PATH,
metadatos de ejecutables en carpetas PHP conocidas y carpetas de procesos PHP
visibles. Las fuentes tienen alcances distintos y se describen en la evidencia.

`completado_en_fuentes` significa que terminaron esas consultas finitas; no significa
assessment web completo ni servidor libre de vulnerabilidades. `no_detectado_en_fuentes_consultadas`
no acredita ausencia de PHP fuera de esas fuentes. El runtime usado por cada
aplicación web queda explícitamente pendiente de correlación. Los paquetes con
posibles backports requieren la errata del proveedor para el paquete exacto.

Primero validar la recolección real en los dos pilotos. Después agregar la
correlación de PHP con la aplicación web y las rutas de aplicaciones faltantes.
Las búsquedas profundas de SAP/Instana se realizarán en corridas por rutas; este
piloto no aumenta los límites de las búsquedas Java ni sustituye ese trabajo.

Las plantillas actuales pueden conservar `vuln_checks: [php, log4j, struts]` y no
deben llevar `vuln_php_inventory_only: true`. La selección de familias controla
las comprobaciones; este ajuste no realiza remediación.

## Verificación realizada antes de entregar

21 pruebas unitarias de clasificación, archivos anidados SAP/Instana, límites,
conservación de evidencia, metapaquetes, cobertura por familia y exportación TXT.
Comprobación sintáctica Ansible y análisis sintáctico PowerShell con Tree-sitter.
Integración Ansible local con un objetivo accesible y otro sin conexión, y otra
corrida con todos los objetivos sin conexión: los objetivos se conservan en el
reporte sin agregarlos junto con localhost en el Límite.

El análisis sintáctico PowerShell no sustituye una ejecución con Windows PowerShell
5.1. No se ha ejecutado este cambio contra los Windows reales de VIKO desde aquí.
