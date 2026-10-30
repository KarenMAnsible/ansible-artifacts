# Actualización PHP V2

Se elimina la dependencia del grupo viko_pruebas. En ambas plantillas retirar
remed_target: viko_pruebas; usar remed_target: all (o alias exacto explícito).
Seleccionar el alias exacto en Límite. Un Límite vacío con target all selecciona
todo el inventario. La pertenencia al grupo de pruebas ya no se comprueba.

Password: credencial VIKO - Vault Accesos, vuln_use_vault: true.
Key: Machine correspondiente, sin Vault, vuln_use_vault: false.
No modificar group_vars/all/vault.yml ni vars/vault.yml. Mantener los alias.

PHP soportado: instala candidatos exactos de la misma rama que cumplen los
mínimos configurados. Incluye revisiones del paquete aunque PHP_VERSION no cambie.
En Debian/Ubuntu, para 7.4/8.1 permite actualizar en la misma rama únicamente
cuando el candidato corresponde exactamente a la fuente revisada en
viko-recon/scripts/php_vendor_sources.json y ésta identifica ambos CVE.
No extrapola evidencia de una revisión a otra. APT conserva validación de firma,
sin downgrade ni eliminación automática. Se verifican las revisiones instaladas
antes de reiniciar servicios y se comprueba configuración Apache/FPM.

IMPORTANTE: los backports mínimos EOL identificados NO equivalen al parche
integral. Aunque se actualice un paquete heredado, el Job mantiene revisión
requerida; no declara corregidos los CVE por esa actualización.
Si el candidato ya está instalado, no reinstala ni reinicia sin necesidad.
Para Viko Web, si las tres ramas conservan las revisiones de la última corrida,
no habrá actualización de paquetes propuesta; el cierre de las ramas heredadas
requiere migración compatible a PHP con parche completo y prueba funcional web.
No cambia handlers, módulos ni configuración de aplicaciones para forzar una
migración desconocida. Windows mantiene sólo los planes MSI explícitos previos.

Audita paquetes dpkg y las generaciones de archivos PHP mapeados por procesos
del host. No publica phpinfo/configuraciones/contraseñas. Coincidencia de inode
no acredita identidad de toda la memoria ni integridad criptográfica; dpkg usa
sus metadatos locales y no valida por sí solo la procedencia del binario.
La evidencia de fuente y su firma pendiente conservan su alcance original.
La cobertura incompleta se reporta. Una prueba funcional de la aplicación
sigue siendo necesaria; no se declara que el sitio esté sano sólo por PHP CLI.

Log4j y Struts sólo validan; se conservan SAP, Instana y tiempos límite.
TXT EQUIPO_IP_AAAAMMDD_HHMMSS.txt: recuperar con el instalador original
--recoger NUMERO_JOB hacia /home/cloud-user/reportes. Conserva el enlace existente.

Instalar como cloud-user:
python3 /home/cloud-user/Ajustar_Remediacion_PHP_VIKO.py --diagnostico
python3 /home/cloud-user/Ajustar_Remediacion_PHP_VIKO.py --aplicar --publicar

Sólo cambia archivos propios de viko-remed. Respalda, valida Python/YAML y
sintaxis; no ejecuta acciones contra equipos. Sin cambios a Vault, inventarios,
assessment, vars/, __pycache__ ni staged ajeno. Si detecta conflictos se detiene.
Después sincronizar el proyecto AAP con la revisión publicada y seleccionar
un solo alias en el Límite. apply puede instalar paquetes/reiniciar servicios;
plan consulta y propone, puede refrescar índices. No hay rollback automático.

Fuentes de alcance del parche:
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
