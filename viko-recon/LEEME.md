# VIKO · Reconocimiento universal de PHP, Log4j y Struts

Versión 1.2 · TXT consolidado y por servidor, con nombre, IP y fecha/hora. Reglas revisadas el 23 de octubre de 2026.

## Primero: piloto de dos equipos

1. Copie **la carpeta completa** de este paquete al proyecto Git usado por AAP. No copie únicamente el YAML: depende de `tasks/`, `scripts/` y `vars/`.
2. Sincronice el proyecto. En su Execution Environment verifique `ansible.windows`; `collections/requirements.yml` declara la dependencia, pero no instala automáticamente la colección en el EE. Linux requiere SSH y Python 3.6+ ya instalado; el recolector no instala nada. Windows requiere PowerShell 5.1, .NET con ZipArchive, conexión WinRM/PSRP o SSH PowerShell configurada. Consolidador: Python 3.8+ en el controlador/EE. Probado aquí con ansible-core 2.19.14; consulte `VALIDACION.md` para los límites de la prueba.
3. En el inventario, seleccione **un Linux y un Windows de prueba** y registre sus rutas reales de SAP e Instana. Conserve sus credenciales habituales de AAP. No ponga contraseñas en este paquete.
4. Incluya el host de informes `localhost` en el inventario, con `ansible_connection: local` y `ansible_python_interpreter: '{{ ansible_playbook_python }}'`. El patrón por defecto lo excluye del reconocimiento remoto.
5. Cree una plantilla con `reconocimiento_universal.yml`, Job type **Run**, forks **5**, verbosity **0** y Timeout **1800 segundos**. Deje desactivada la división del Job (Job slicing). Use Limit: `NOMBRE_LINUX,NOMBRE_WINDOWS,localhost`. El segundo play consolida en localhost: si se omite de Limit no se genera el reporte.
6. Ejecute el piloto, compruebe el tiempo, los errores de cobertura y la detección en rutas conocidas. Después amplíe por lotes de aproximadamente 20 equipos; ajuste el Timeout global según el lote.

No se ha ejecutado este paquete contra servidores VIKO. Requiere el piloto antes de una ejecución amplia. Tampoco modifica el assessment universal existente: es un playbook independiente.

## Alcance real

| Familia | CVE evaluados |
|---|---|
| PHP2Shell | CVE-2026-109618, CVE-2026-109619 |
| Log4j core | CVE-2021-44228, CVE-2021-45046 |
| Apache Struts core | CVE-2017-12611, CVE-2018-11776, CVE-2024-53677 |

Struts se incluye como la segunda familia recuperada del trabajo previo; Ivonne debe contrastar los CVE históricos con su hallazgo original. La revisión no acredita ausencia de otros CVE del producto. Los límites históricos de corrección de las reglas **no son recomendaciones de versiones actuales**.

Reconocimiento de solo lectura sobre aplicaciones y servicios. Lee metadatos de paquetes, archivos comprimidos, procesos y servicios seleccionados. Opcionalmente ejecuta `php -n -v` sobre CLI conocidas y consulta `docker/podman ps`. No ejecuta solicitudes de explotación, no abre conexiones a los sitios web para probar fallos, no actualiza repositorios, no aplica parches, no reinicia servicios, no elimina clases y no reemplaza JAR. Ansible puede usar sus archivos temporales normales de transporte. Los reportes se escriben solamente en el controlador/EE.

PHP CLI y PHP web pueden ser instalaciones distintas. Se inventarían paquetes y procesos como contexto, pero no se determina automáticamente qué versión efectiva utiliza cada sitio, pool FPM o módulo Apache. No se inspecciona `php.ini`, el código de la aplicación ni el valor efectivo de `session.upload_progress.enabled`; se deja como validación previa a remediar. Consulte el aviso adicional PHP del 23-oct-2026.

## SAP, Instana y archivos anidados

Las raíces prioritarias Linux son `/usr/sap`, `/opt/instana` y `/opt/instana-agent`, antes del resto de rutas amplias. En Windows se priorizan las rutas SAP e Instana de `C:`. Después se revisan las rutas generales configuradas.

Se inspeccionan **todos los JAR/WAR/EAR/ZIP legibles en esas raíces**, sin limitarse a nombres `log4j*.jar`. También se buscan clases de Log4j/Struts y metadatos Maven en bibliotecas con otro nombre, por ejemplo wrappers de Instana. La versión del wrapper `pax-logging-log4j2` no se considera automáticamente la versión de Log4j.

Se revisan hasta dos niveles de archivos anidados: por ejemplo EAR → WAR → JAR. Límites de profundidad, tamaño, entradas, tiempo o permisos producen cobertura parcial y un motivo. ZIP64 y archivos multivolumen se dejan pendientes de una revisión especializada. No se extraen archivos al disco remoto. Una versión en el nombre del JAR queda como indicio que requiere validación; se prefieren metadatos Maven. `JndiLookup.class` se registra como evidencia; su presencia o ausencia por sí sola no define el estado del CVE.

Volúmenes distintos de `C:`, carpetas personalizadas, directorios de usuario, enlaces simbólicos y junctions necesitan atención explícita. No se siguen symlinks/reparse points. En Linux no se atraviesan dispositivos montados debajo de una raíz por defecto; especifique como raíz el punto de montaje autorizado que necesite revisar. No agregue shares remotos sin evaluar su alcance. El inventario de contenedores **no inspecciona imágenes ni su contenido interno**; registre esa cobertura pendiente con Seguridad.

## Variables

Los valores de `vars/defaults.yml` usan prefijo `vuln_defaults_`; para personalizar use nombres **sin `defaults_`**, desde inventario/grupo/host o Extra vars. Si reemplaza la lista de raíces debe incluir todas las rutas que quiera conservar. No use `--tags`: seleccione familias con `vuln_checks`.

Ejemplo de Extra vars de la plantilla (reemplace las rutas por las reales):

```yaml
vuln_checks: [php, log4j, struts]
vuln_scan_seconds: 180
vuln_task_timeout: 240
vuln_command_timeout: 10
vuln_run_php_version: true
vuln_container_inventory: true
```

Ejemplo de variables de un host Linux:

```yaml
vuln_customer: CLIENTE
vuln_linux_roots:
  - /usr/sap
  - /opt/instana
  - /opt/instana-agent
  - /opt/aplicaciones
  - /srv
vuln_become: true  # Solo si la credencial y los permisos lo permiten.
```

Ejemplo de variables de un host Windows:

```yaml
vuln_customer: CLIENTE
vuln_windows_roots:
  - 'C:\Program Files\SAP'
  - 'C:\Program Files (x86)\SAP'
  - 'C:\Program Files\Instana'
  - 'D:\usr\sap'
  - 'D:\SAP'
  - 'D:\Instana'
  - 'C:\inetpub'
  - 'C:\PHP'
```

La plataforma se selecciona por conexión `winrm`/`psrp` o `ansible_shell_type: powershell`; el resto se trata como Linux. En conexiones especiales puede declarar `vuln_platform: windows` o `vuln_platform: linux`. macOS, AIX, Solaris, equipos de red y appliances no forman parte de la compatibilidad declarada.

## Límites y continuidad

| Control | Predeterminado |
|---|---|
| Presupuesto de todo el recolector por host | 180 s |
| Consulta individual de procesos externos | 10 s |
| Prevalidación SSH/Python | Tarea de 30 s |
| Tarea de recolección en Ansible | 240 s |
| Proceso hijo de PowerShell | Presupuesto + 20 s; se termina si no acaba |
| Consolidación local | 90 s |
| Archivos recorridos | 100 000 |
| Archivos comprimidos inspeccionados | 1 500 |
| Tamaño máximo de archivo comprimido externo | 128 MiB |
| Cada archivo anidado descomprimido | 32 MiB |
| Total de contenido anidado leído | 128 MiB |
| Entradas por archivo ZIP/JAR | 50 000 |
| Profundidad de anidados | 2 |
| Componentes recogidos | 2 000 |

El tiempo de un host incluye prevalidación/transporte, por lo que 180 s no es un límite total de pared del Job. Configure también el Timeout de AAP indicado en el piloto. `vuln_task_timeout` debe superar `vuln_scan_seconds` al menos 40 s. Ajuste los timeouts de conexión SSH/WinRM según sus credenciales y red; el corte de una tarea no reemplaza esa configuración.

Linux utiliza un temporizador del proceso además de límites por consulta. En Windows el recolector tiene un presupuesto interno y se ejecuta en un proceso hijo con watchdog. En ambos casos los fallos y tiempos agotados quedan como parciales/no evaluados y el resto de hosts sigue. Un proceso del sistema bloqueado en E/S no interrumpible puede requerir intervención del SO; el Timeout global de AAP evita que el Job espere indefinidamente.

## TrendAI y backports

La evidencia local de servicios/carpetas de Trend no demuestra cobertura, licencia ni vigencia de protección. Cruce con la consola de Seguridad:

```yaml
vuln_security_coverage: no_cubierto  # cubierto / no_cubierto / desconocido
vuln_security_coverage_source: 'Exportación de consola validada por Seguridad, 2026-10-23'
```

Se examinan los hosts seleccionados y se etiqueta esa cobertura. No se excluyen hosts automáticamente por encontrar un agente. Si no hay fuente para la cobertura declarada se informa `desconocido`.

PHP distribuido mediante RPM/DEB puede estar corregido mediante backport. Si su versión upstream está en rango, se marca `requiere_validacion_proveedor`. Una errata se puede registrar por **nombre y versión exacta instalada** después de validarla externamente:

```yaml
vuln_vendor_evidence:
  - component: php
    package: NOMBRE_REAL_DEL_PAQUETE
    installed_version: VERSION_COMPLETA_EXACTA_REPORTADA
    cves: [CVE-2026-109618, CVE-2026-109619]
    status: fixed
    advisory: 'https://URL-REAL-DEL-AVISO-VALIDADO'
```

Esta declaración no descarga ni verifica el aviso y no aplica a otras instalaciones. El estado `corregido_segun_evidencia_proveedor` significa que la evidencia suministrada coincide exactamente con el paquete encontrado.

## Reportes y recuperación desde AAP

Se generan **`resultados.txt`**, `resumen.csv`, `hallazgos.csv`, `reporte.json`, `reporte.html` y `resultados.zip`. El TXT incluye resumen general y detalle por servidor: cliente, dirección, sistema, cobertura, tiempo, raíces SAP/Instana, hallazgos por CVE, versiones, rutas, errores y pendientes. Usa UTF-8 con BOM y saltos de línea Windows para abrirlo en Bloc de notas. También está incluido en el ZIP recuperable desde artefactos; al restaurar un artefacto antiguo de v1.0 se genera el TXT desde el JSON existente. Los CSV incluyen BOM para abrirlos en Excel y neutralizan celdas que podrían interpretarse como fórmulas. El JSON conserva cobertura, errores, procesos y servicios, con rutas pero sin líneas de comandos, variables de entorno ni contenido de configuraciones.

**Identificación visible:** cada bloque del TXT muestra nombre real del sistema (cuando responde), nombre en inventario, IP(s) locales detectadas, destino de conexión, fecha/hora del informe y fecha/hora de recolección. Se muestran hora CDMX con su desfase y el timestamp UTC original. Python 3.8 o un EE sin base de zonas utiliza como referencia explícita UTC-06:00. Un equipo no evaluado conserva nombre/dirección del inventario y fecha del informe; no se inventa una fecha de recolección ni una IP si el inventario solo tiene DNS y no se obtuvo la IP local.

Además del consolidado, se genera **un TXT por servidor** dentro de `por_servidor/`, con un nombre del tipo `recon_SERVIDOR_IP_FECHA_HORA_CDMX_ID.txt`. El timestamp incluye microsegundos y un identificador distingue nombres que coincidan al sanearlos. Estos TXT también viajan en `resultados.zip` y se reconstruyen al recuperar artefactos. Las IP locales pueden incluir interfaces de redes internas y contenedores; no acreditan exposición pública.

Por defecto, el directorio local es temporal. **No dependa de descargar después un archivo de `/tmp` dentro del EE.** El Job publica mediante `set_stats`:

- `viko_vuln_summary`: resumen compacto, siempre.
- `viko_vuln_report_zip_base64`: ZIP completo codificado si cabe en el límite configurado.
- `viko_vuln_bundle_status`: `completo` o un aviso explícito de exceso de tamaño.
- `viko_vuln_report_dir`: ruta del directorio en ese EE/controlador.

Descargue desde el detalle/API del Job el JSON que contiene `artifacts` (puede ser el JSON completo del Job) como `job.json`. Luego, en su equipo con el paquete completo:

```bash
python3 scripts/report.py --restore-artifacts job.json --out resultados-recuperados
```

Los artefactos están sujetos a límites y retención de su controlador; compruebe la recuperación en el piloto. Límite por defecto del base64: 700 000 bytes (`vuln_aap_artifact_max_bytes`). Para lotes grandes configure `vuln_report_dir` apuntando a almacenamiento que **realmente esté montado y autorizado como persistente** en el EE, o reduzca el lote. Escribir una ruta en Extra vars no crea un montaje persistente. Si el ZIP excede el límite, el resumen sigue disponible y el reporte completo permanece en `resultados.zip` dentro del directorio configurado; no se presenta como guardado permanentemente.

Los reportes son internos: contienen nombres de clientes, IP y rutas. Conserve permisos restringidos.

## Interpretación

- `potencialmente_afectado`: versión dentro de un rango; requiere validar configuración, proveedor y uso efectivo.
- `requiere_validacion`: sin versión confiable, solo nombre o formato modificado.
- `requiere_validacion_proveedor`: paquete PHP potencialmente corregido mediante backport.
- `requiere_validar_migracion_upload`: Struts requiere comprobar el cambio de mecanismo de carga.
- `fuera_rango_version`: fuera del rango de ese CVE, sin afirmar que todo el producto sea seguro.
- `corregido_segun_evidencia_proveedor`: coincide con una errata externa suministrada para un paquete exacto.
- `no_detectado_en_rutas_revisadas` / `no_detectado_busqueda_parcial`: no se encontró ese componente dentro de la cobertura indicada.
- `no_evaluado`: conectividad, requisito, fallo o timeout impidió evaluar.

`log4j-api`, Log4j 1 y `xwork-core` se registran informativamente; no se les atribuyen automáticamente CVE de Log4j core o de una versión de Struts no identificada. El resumen usa una fila por servidor; los detalles tienen una fila por observación y CVE. Varias filas pueden corresponder al mismo componente.

## Fuentes oficiales de las reglas

- PHP: https://www.php.net/archive/2026.php
- PHP OOM: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- PHP estado global: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- Apache Log4j: https://logging.apache.org/security.html
- Struts S2-053: https://struts.apache.org/docs/s2-053.html
- Struts S2-057: https://struts.apache.org/docs/s2-057.html
- Struts S2-067: https://cwiki.apache.org/confluence/spaces/WW/pages/327979397/S2-067

Antes del parcheo: autorización del cliente, compatibilidad de la aplicación, respaldo/snapshot con Infraestructura, ventana, prueba piloto, validación del servicio y rollback preparado. Este paquete no realiza esa etapa.
