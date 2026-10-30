# Correlación PHP 1.6.2: servicios del host con montaje aislado

Los TXT del piloto 1.6.1 confirmaron recolección en los cuatro equipos. SUSE,
Windows y Ansible no mostraron PHP en las fuentes consultadas. Windows resolvió
servicios por ServiceController. Los tiempos observados fueron 4.16, 4.8, 1.61 y
1.43 segundos (SUSE, Windows, Viko Web y Ansible respectivamente).

Viko Web detectó PHP 7.4.33, 8.1.34 y 8.2.35. Apache y FPM 8.1/8.2 estaban activos.
La configuración en disco habilita mod_php 7.4 y un handler de un sitio dirige a
/run/php/php8.2-fpm.sock. Esto no confirma por sí solo qué versión atiende cada
sitio. La comprobación anterior omitió todos esos procesos al diferir únicamente
su namespace de montaje; quedaron 17 omisiones de correlación.

Esta corrección permite observar un proceso con montaje diferente sólo después
de comprobar misma raíz por dispositivo/inodo, mismo namespace PID y usuario y
cgroup de un servicio Apache/FPM del host conocido, sin marcadores de contenedor.
No entra en namespaces ni recorre el contenido de contenedores o chroots.
Si no puede comprobar esas condiciones, conserva el resultado pendiente.

Para atribuir un ejecutable o módulo observado al paquete del host, también
comprueba dispositivo/inodo del archivo observado y del archivo del host.
Los sockets se correlacionan sólo con namespace de red coincidente. Un archivo
eliminado o una generación de proceso no verificada siguen pendientes.

Se clasifican metapaquetes/paquetes de soporte como información: php-common,
php7.4, php8.1, php8.2 y paquetes -common no se cuentan directamente como motores
PHP ni reciben automáticamente dos filas de CVE de core. Los paquetes runtime,
ejecutables y módulos conservan su detalle. Las filas de evidencia no son una
cuenta de vulnerabilidades únicas.

No se cambian reglas de CVE ni se certifican backports PPA por la mención del
changelog. Viko Web tiene referencias locales a ambos CVE en las revisiones
7.4.33-31 y 8.1.34-9; la publicación exacta del proveedor aún requiere corroboración
primaria. PHP 8.2.35 cumple el mínimo numérico upstream, pero esto no prueba por sí
solo procedencia/integridad ni que cada aplicación use ese runtime.

Instalación en ansible-viko, como cloud-user:

```bash
python3 /home/cloud-user/Correlacionar_Runtime_PHP_VIKO_v162.py --aplicar
python3 /home/cloud-user/Correlacionar_Runtime_PHP_VIKO_v162.py --publicar
```

El instalador respalda sólo sus archivos, rechaza diferencias inesperadas y no
modifica Vault, accesos, inventarios, puertos, límites, servicios ni paquetes.
Mantiene la restricción de los cuatro pilotos. No repetir la actualización de
credenciales: Viko Web ya quedó publicado en a0fac3a.

Sincronizar el proyecto AAP y repetir únicamente Password, con Límite:

```
huawei_viko_new_vikowebnew
```

Conservar vuln_use_vault: true, vuln_checks: [php], vuln_php_inventory_only: true,
los límites existentes y la misma carpeta TXT. La versión Linux esperada es
1.6.2-evidencia; Windows conserva 1.6.1 porque no cambió.

Aceptar correlación sólo si aparecen módulos mapeados o el handler junto al
socket/worker observado, con sus pruebas de alcance. Si aparecen procesos pero
no vínculo del sitio, conservar correlación parcial. No ampliar la corrida hasta
revisar el nuevo TXT y la evidencia de backports. Para un consolidado exhaustivo
se necesitarán reporte.json y cruce_inventario.csv de los Jobs; los TXT individuales
no contienen todo el cruce de los 201 accesos.
