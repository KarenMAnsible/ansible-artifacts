# Remediación VIKO con el Vault ya existente

Reutiliza `viko-recon/tasks/vault_accesos.yml` del commit 72d1d20. No modifica el assessment, no importa Excel, no descifra/recrea `group_vars/all/vault.yml` y no abre `vars/vault.yml`. Las entradas del Vault con `!unsafe` conservan texto literal; los accesos permanecen bajo `no_log`. No confundir 192 listos por formato con 192 conexiones probadas.

## Instalar como cloud-user en ansible-viko

Guardar `Integrar_Vault_Remediacion_VIKO.py` en `/home/cloud-user/`. Ejecutar sin sudo:

```bash
python3 /home/cloud-user/Integrar_Vault_Remediacion_VIKO.py --diagnostico
python3 /home/cloud-user/Integrar_Vault_Remediacion_VIKO.py --aplicar --publicar
```

La segunda orden respalda únicamente archivos propios que cambien, aplica y valida Python/YAML/sintaxis Ansible. No contacta pilotos ni ejecuta remediaciones. Publica un commit limitado a esas rutas; conserva el staged ajeno. No hace pull, limpieza, stash, checkout, reset ni cambios en Vault. Si main y origin/main difieren, se detiene antes de escribir. Si falla una comprobación, restaura únicamente los archivos que alcanzó a cambiar, sin pisar cambios concurrentes. Un fallo posterior de commit/push conserva la integración validada para revisión.

Si el CLI no está en PATH, añadir `--ansible-playbook /ruta/ansible-playbook`. PyYAML y las colecciones requeridas deben estar disponibles para las comprobaciones del CLI. El EE de AAP también debe contener las dependencias de ejecución: reutilizar el EE del assessment y verificar `ansible.windows >=2.8` para MSI y `community.general` para SUSE. El instalador no cambia colecciones ni archivos de dependencias ajenos; añade la referencia propia en `viko-remed/collections/requirements.yml`.

Si se ejecutó primero `--aplicar` sin publicar, repetir `--aplicar --publicar` publica solo las diferencias de archivos propios que coinciden con el payload instalado. Cambios ajenos o commits locales previos no se publican automáticamente.

## Dos plantillas de remediación

Duplicar las plantillas que ya funcionan, sin modificar las de reconocimiento. En ambas:

- Proyecto: Reconocimiento-Vulnerabilidades-VIKO, sincronizado tras publicar.
- Playbook: `viko-remed/remediacion_universal.yml`.
- Inventario: el mismo de los pilotos, con sus alias exactos.
- No se requiere el grupo viko_pruebas. Seleccione explícitamente los destinos en Límite.
- Límite: alias exacto del equipo que desea ejecutar. No agregar un destino de procesamiento local.
- Tipo: Run. Forks: 1. Timeout: 5400 segundos. No usar Check.
- Desactivar encuestas de usuario/contraseña. Retirar extra vars antiguas `ansible_user`, `ansible_password`, `ansible_ssh_pass`, `ansible_host` y puertos que contradigan los datos vigentes. Conservar variables de transporte y configuración necesarias, como WinRM basic/5985 cuando corresponda.

### Password / Vault

Credencial: **VIKO - Vault Accesos**, tipo Vault, identificador vacío. No se utiliza una credencial Machine con un usuario/contraseña fijo para todos los hosts. Si se necesita una credencial Machine por elevación, comprobar que no contradiga el acceso por host. La conexión Linux necesita permisos de root/sudo según el plan; no se supone que la contraseña de conexión sea automáticamente la de sudo.

Variables iniciales:

```yaml
vuln_use_vault: true
remed_target: all
remed_mode: plan
remed_connect_timeout: 15
remed_scan_seconds: 600
remed_allow_service_restart: false
remed_agent_diagnostic: true
remed_shared_root: /viko-reportes
```

Cada alias obtiene dirección, usuario, cliente y puerto de su entrada. El campo `port` conserva los cuatro SSH 1024. Si un alias se clasificó como llave o está pendiente, esa plantilla falla de forma censurada en lugar de intentar una contraseña incorrecta. No asigna llaves según la referencia del Excel.

### SSH Key / Machine

Credencial Machine con la llave correcta para ese bloque. Retirar la credencial Vault de esta copia. Encuesta de contraseña desactivada. Mismas variables de arriba, cambiando:

```yaml
vuln_use_vault: false
```

Esta copia no abre el Vault ni selecciona credenciales a partir de referencias. Usuario, IP y puerto provienen de la credencial/inventario configurados para ese bloque. Conservar el puerto particular en el inventario cuando sea un host con llave; no se abre el Vault para buscarlo. No mezclar bloques que requieren llaves distintas en una misma ejecución con una sola Machine.

## Secuencia piloto

1. Password: limitar al alias Linux de pruebas y ejecutar `plan`. Comprobar acceso, SO, puerto, reporte y selección de paquetes. No instala paquetes ni reinicia servicios; puede refrescar índices.
2. Password: limitar al alias Windows de pruebas y ejecutar `plan`. Comprobar acceso WinRM, versión/ruta PHP y las decisiones de Log4j/Struts.
3. SSH Key: limitar al alias de ansible-viko con su Machine y `vuln_use_vault: false`. No debe solicitar contraseña de conexión ni de Vault.
4. Para corregir PHP Linux, registrar en variables del host `remed_backup_reference` con la referencia real del respaldo/snapshot. Cambiar a `remed_mode: apply` y `remed_allow_service_restart: true` para renovar los servicios previstos. Ejecutar primero un solo piloto.
5. Revisar acciones, versión previa/final, reevaluación PHP y salud de la aplicación. Un Job correcto en plan no es una remediación. No lanzar a los 201 registros por haber funcionado el Vault.

**Alcance conservado:** PHP tiene corrección por paquetes Linux y planes MSI compatibles explícitos. PHP Windows por ZIP/XAMPP/IIS aún requiere un método de actualización definido: el Vault habilita la conexión, no crea ese manejador faltante. Si detecta PHP Windows sin un plan compatible queda bloqueado, nunca corregido ficticiamente. Las ramas antiguas/backports y stacks personalizados requieren evidencia del proveedor. Log4j/Struts se validan con metadatos/versiones/rutas y se indica remediación posterior, sin modificar bibliotecas. CloudResetPwdAgent no se reinstala.

Se conservan búsqueda bajo SAP/Instana, 600 segundos por reconocimiento, 600 por transacción, 60 por sonda y 120 por reinicio de servicio. Los 15 segundos corresponden a conexión SSH; no se pretende instalar PHP en 15 segundos ni sustituir los timeouts WinRM ya configurados.

## TXT por equipo en /home/cloud-user/reportes/

Los nombres son `EQUIPO_IP_AAAAMMDD_HHMMSS.txt`, con fecha CDMX y hostname real cuando se obtuvo. El Job conserva un ZIP de evidencia en `artifacts.viko_remediacion_reportes_zip_base64`, con SHA256. Si existe un montaje `/viko-reportes`, también publica bajo `remediacion/job_ID/por_servidor`. No se presenta un directorio efímero del EE como persistente.

Tras cada Job, usar su número real:

```bash
python3 /home/cloud-user/Integrar_Vault_Remediacion_VIKO.py --recoger NUMERO_JOB
```

Primero busca los TXT en el montaje del host. Si no están, solicita un token AAP con permiso de lectura al Job, sin guardarlo, y recupera únicamente sus artefactos. Alternativamente permite `--artifact-json /ruta/job.json` para un Job/artifacts exportado, sin token. Con certificado autofirmado del AAP propio, añadir conscientemente `--sin-verificar-tls`; con certificado confiable no hace falta.

La carpeta común se conserva si ya existe, incluido su enlace simbólico. No sobrescribe TXT distintos. No contiene contraseñas ni el diccionario de accesos. Revisar que se recuperó el número esperado de equipos y consultar cobertura/bloqueos; `no detectado` en una búsqueda parcial no acredita ausencia global.

## Actualización V2

Consultar ACTUALIZACION_PHP_V2.md para revisiones de paquetes, backports mínimos, auditoría y selección sin grupo.
