# PHP VIKO: evidencia 1.6, candidata para cuatro pilotos

Estado: código preparado; aceptación pendiente en Linux, Windows, Ansible y Viko Web.
Reconocimiento de sólo lectura en destinos. El instalador sí modifica exclusivamente
los archivos de código listados, con respaldo previo. No modifica Vault, credenciales,
inventarios, puertos, servicios, paquetes ni el enlace SFTP.

## Instalación y publicación

Subir Mejorar_Evidencia_PHP_VIKO_v16.py a /home/cloud-user.

```bash
python3 /home/cloud-user/Mejorar_Evidencia_PHP_VIKO_v16.py
python3 /home/cloud-user/Mejorar_Evidencia_PHP_VIKO_v16.py --aplicar
```

El primer comando comprueba y muestra el plan. El segundo valida pruebas y sintaxis
en una copia temporal antes de respaldar e instalar. Si detecta archivos propios
modificados desde el ZIP, se detiene sin sobrescribirlos; permite cambios ajenos.
No instala dependencias ni modifica el índice de Git. Python del instalador >= 3.9.

Para que AAP reciba los cambios mediante su proyecto Git:

```bash
python3 /home/cloud-user/Mejorar_Evidencia_PHP_VIKO_v16.py --publicar
```

Publica sólo los archivos de esta mejora, en main y en el origin conocido.
Exige índice sin cambios preparados y comprueba que la copia coincide con el
payload. No agrega vars/, __pycache__ ni otros archivos. No hace pull, reset,
stash ni push forzado. Si el push falla, conserva el commit local.
Después sincronizar el proyecto en AAP y confirmar el nuevo commit.

## Los cuatro pilotos

Mantener vuln_checks: [php] y vuln_php_inventory_only: true. Este indicador sigue
limitando el recorrido general; 1.6 añade consultas acotadas de runtime, no activa
un recorrido completo. Mantener exactamente los límites actuales de cada plantilla.
Conservar vuln_fail_no_evidence: true si ya se usa. No poner localhost en Límite.
La delegación local interna que genera reportes se conserva.

Password, Vault VIKO - Vault Accesos, encuesta desactivada, vuln_use_vault: true:

```
huawei_viko_new_pruebas_seguridad,gcp_sin_definir_trend
```

SSH Key, encuesta desactivada, vuln_use_vault: false: ejecutar por separado si sus
llaves Machine son diferentes. No presuponer que una llave cubre ambos bloques.

```
alibaba_viko_ecs_ansible
```

```
huawei_viko_new_vikowebnew
```

Seleccionar la credencial Machine que ya corresponde a cada piloto. No modificar
ansible_port: se usa la integración ya existente. Los cuatro registros con 1024
se identifican en el cruce, sin conectar a ellos en estos pilotos.

1.6 restringe los objetivos de PHP a esos cuatro aliases. No incluye un interruptor
para lanzar a todo el inventario: los lotes se preparan después de la aceptación.

## Evidencia y límites

Linux registra paquetes exactos, metadatos de origen disponibles en caché,
propietario de archivos, menciones de changelog local y relación de procesos con
módulos PHP mapeados. Lee una lista acotada de configuraciones Apache/Nginx/FPM;
extrae sólo rutas, endpoints y números de línea. Para FastCGI correlaciona sockets
Unix/TCP con descriptores del proceso PHP cuando los permisos lo permiten.

Una ruta configurada puede diferir de la generación cargada. Un worker FPM activo
no prueba que todas las aplicaciones lo usen. No se envían solicitudes HTTP ni se
crean phpinfo.php, scripts temporales web o archivos en destinos.

Se pueden agregar archivos de configuración Linux concretos mediante
vuln_php_config_paths: ['/ruta/archivo.conf']. Includes con variables no resueltas,
upstreams indirectos, namespaces distintos, chroots y rutas alternativas no
descubiertas permanecen pendientes. Esta revisión no inspecciona el contenido de
contenedores. El inventario de contenedores depende de permisos y usuario.

Windows consulta servicios por ServiceController, con alternativas CIM y WMI en
procesos con límite. Los fallos de esas consultas quedan como auxiliares. Consulta
handlers efectivos IIS por sitio/aplicación y extrae scriptProcessor sin parámetros;
correlaciona rutas php-cgi con procesos observados. Consulta configuraciones
Apache/Nginx de ubicaciones comunes y derivadas de ejecutables en ejecución.
El hash y ProductVersion identifican el archivo; no certifican un backport.
No atribuye un worker IIS a una aplicación concreta únicamente por coincidir la
ruta del ejecutable. Aplicaciones no legibles se declaran pendientes.

No se publican argumentos de procesos, entorno, XML completo, configuración
completa ni URLs de repositorios con credenciales. Los informes conservan la
identidad técnica necesaria: IP, cliente, rutas, versiones y metadatos permitidos.
Los permisos pueden limitar /proc/maps, /proc/fd o la configuración de IIS.
No se elevan privilegios automáticamente; se conserva vuln_become.

Los límites son compartidos: si se agota el presupuesto, se conserva la evidencia
obtenida y la cobertura PHP queda parcial. Una consulta auxiliar que consume todo
el presupuesto sí puede impedir completar PHP; ese efecto no se oculta.

## CVE y backports

Fuentes primarias comprobadas el 29 de octubre de 2026:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://ubuntu.com/security/notices/USN-8948-1

Mínimos upstream por rama: 8.2.35, 8.3.36, 8.4.27 y 8.5.12. No se cambia esta
matriz. Los otros CVE conservan su revisión anterior.

La verificación automática de backport es deliberadamente acotada al aviso
USN-8948-1 y a coincidencias exactas de distribución, paquete, versión binaria,
paquete/versión fuente y origen Ubuntu declarado en los metadatos locales.
No extiende estos umbrales al PPA de Ondrej ni a versiones posteriores no incluidas
en la tabla. Los avisos de otros proveedores requieren revisión adicional.
La verificación es contra metadatos locales y el aviso; no es una auditoría de
integridad del sistema ni de memoria del proceso.

Un changelog que menciona un CVE es evidencia candidata; no cierra el hallazgo
por sí solo. Viko Web puede conservar afectación potencial hasta verificar el
backport de sus revisiones exactas del PPA. No cambiar reglas para forzar un positivo.
Se conserva el mecanismo de evidencia externa por paquete y versión exactos,
pero se exige además correspondencia de proveedor/origen con el dominio oficial.
Esa entrada sigue siendo una declaración revisada externamente, no una consulta
automática del contenido del aviso en tiempo de ejecución.

## Archivos y consolidación

Los TXT conservan EQUIPO_IP_AAAAMMDD_HHMMSS.txt y fecha CDMX. Conservar la
configuración existente de vuln_report_dir y vuln_txt_dir, y el montaje persistente
del EE que ya permite publicar en:

/home/cloud-user/aap/controller/data/projects/viko_reportes/TXT

El instalador no mueve ni reemplaza /home/cloud-user/reportes.
Un directorio existente en el host no implica por sí solo visibilidad desde el EE.

El paquete recuperable conserva TXT, JSON, HTML y CSV con BOM para Excel:

- resumen.csv: una fila por equipo, cliente/IP, versiones, runtime, cobertura,
  resultado, evidencia y siguiente acción.
- hallazgos.csv: una fila por observación/componente y CVE.
- cruce_inventario.csv: unión de aliases AAP y registros disponibles, estados,
  modo, puertos y discrepancias. Leer los 201 no prueba 201 conexiones.

El cruce se obtiene del inventario completo cargado en ese Job AAP; no puede
ver otros inventarios AAP ajenos al Job. En un piloto Password usa el diccionario
que ya carga vault_accesos.yml; no vuelve a descifrar el Vault. En Key no lo carga:
marca vault_no_cargado y no inventa que falten los 201 registros. La consolidación
elige el cruce que sí consultó la mayor cantidad de registros.

Para fusionar los reportes de los pilotos en un equipo con los scripts disponibles:

```bash
python3 viko-recon/scripts/consolidar_php.py \
  --report /ruta/password/reporte.json \
  --report /ruta/ansible/reporte.json \
  --report /ruta/vikoweb/reporte.json \
  --out /ruta/consolidado_php
```

Añadir --xlsx si openpyxl está instalado. No se instala automáticamente.
Elige la evidencia más reciente por alias; no cuenta al mismo equipo dos veces.
Una sola observación potencial mantiene el resultado del equipo en afectación
potencial, aunque existan otros componentes corregidos. Ausencia con cobertura
parcial queda pendiente. Los resultados no garantizan equipo libre de vulnerabilidades.

## Criterios para aceptar los pilotos

- Cuatro aliases con evidencia, versión 1.6-evidencia y TXT accesibles por SFTP.
- Linux/Windows sin hallazgos: cobertura y omisiones explícitas; ningún “no vulnerable” global.
- Windows: consulta de servicios resuelta o diagnóstico de las alternativas;
  un fallo auxiliar aislado no cambia por sí solo la cobertura de PHP.
- Viko Web: conservar todas las ramas instaladas y las activas; módulos, handlers
  y sockets/procesos relacionados, o motivo técnico concreto de lo pendiente.
- Backports: paquete/revisión/proveedor y fuente verificable para cada CVE;
  si falta algo, conservar pendiente o afectación potencial.
- Cruce Password: 201 registros consultados, estados listos/pendientes, huérfanos,
  aliases sin registro y los cuatro puertos 1024. Investigar discrepancias.
- Revisar elapsed_seconds, budget_exhausted y omisiones. Si 15 segundos no bastan,
  no declarar cobertura completa: decidir una segunda consulta dirigida.

Validaciones locales: suite offline, sintaxis Python compatible, YAML y análisis
sintáctico PowerShell. No sustituye pruebas reales en Windows Server 2016 o AAP.

## Restauración

El instalador imprime la carpeta de respaldo. Para restaurar sólo sus archivos:

```bash
python3 /home/cloud-user/Mejorar_Evidencia_PHP_VIKO_v16.py \
  --restaurar /home/cloud-user/viko_php_backups/RESPALDO_IMPRESO
```

Se detiene si los archivos propios cambiaron después. No revierte commits ni
reescribe historia Git. Si se publicó, habrá que publicar un commit de reversión
controlado antes de sincronizar AAP. No se incluyen operaciones automáticas de
borrado de reportes ni cambios en Vault.
