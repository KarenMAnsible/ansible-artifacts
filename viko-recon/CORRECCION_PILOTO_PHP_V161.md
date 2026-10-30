# Corrección del piloto PHP 1.6.1

La corrida Password del 29-oct-2026 tuvo tres objetivos y sólo uno con evidencia.
Se mantienen los cuatro aliases autorizados y todos los límites existentes.

Correcciones de código:

- El script PowerShell de transporte ahora incorpora el recolector codificado en
  base64. La versión 1.6 insertaba un here-string dentro de otro y su terminador
  cerraba antes de tiempo el script exterior. Se reprodujo el error sintáctico
  del envoltorio completo y se comprobó la corrección. La ejecución real queda
  pendiente en Windows Server 2016; no basta con analizar sólo el recolector.
- Un include Nginx con máscara sin archivos no se trata como archivo explícito
  faltante. Un include explícito no encontrado sigue siendo una omisión. Esto no
  implica que toda la configuración del Nginx del host o de contenedores se inspeccionó.
- El TXT separa el número de omisiones de correlación PHP del contador general.
- Los recolectores se identifican como 1.6.1-evidencia.

Subir Corregir_Piloto_PHP_VIKO_v161.py a /home/cloud-user y ejecutar:

```bash
python3 /home/cloud-user/Corregir_Piloto_PHP_VIKO_v161.py --aplicar
python3 /home/cloud-user/Corregir_Piloto_PHP_VIKO_v161.py --publicar
```

Sincronizar el proyecto AAP. Repetir Password únicamente con:

```
huawei_viko_new_pruebas_seguridad,gcp_sin_definir_trend
```

Y SSH Key únicamente con:

```
alibaba_viko_ecs_ansible
```

Viko Web debe ir por contraseña según la corrección de la usuaria. Sin embargo,
en el Job se omitió la tarea condicionada a mode=password, y SSH rechazó el acceso.
Esto muestra que su registro sigue como key en la integración utilizada. El parche
no cambia Vault, no inventa una contraseña ni prueba credenciales alternativas.

El modo de diagnóstico opcional descifra únicamente el Vault existente en memoria,
mediante ansible-vault, para mostrar campos técnicos permitidos del registro Viko Web.
No guarda texto descifrado ni revela valores de contraseñas. La clave del Vault se
introduce en el prompt local de ansible-vault; no debe compartirse aquí.

```bash
python3 /home/cloud-user/Corregir_Piloto_PHP_VIKO_v161.py --diagnosticar-vikoweb
```

La salida contiene modo, estado y si existe un campo password con valor. No cambia
ningún acceso. Corregir la clasificación y su fuente requiere una intervención
puntual posterior con el acceso real; no volver a importar con la regla anterior
que forzaba Viko Web como llave. Una vez corregido, repetir su piloto en Password.

El cruce del Job consultó 201 registros: 9 pendientes, 153 listos por contraseña
 y 39 referencias de llave listas; cuatro registros conservan puerto 1024.
Esos estados son preparación de acceso, no resultados de conectividad de todo el universo.
No ampliar la corrida hasta completar Windows y la detección positiva de Viko Web.

## Actualización autorizada de Viko Web desde la primera hoja

La usuaria confirmó que las credenciales actuales de la primera hoja funcionan.
El modo explícito siguiente toma exclusivamente esa fila del Excel local actualizado,
verifica alias e IP exactos, y actualiza usuario/password/modo de ese único registro:

```bash
python3 /home/cloud-user/Corregir_Piloto_PHP_VIKO_v161.py \
  --actualizar-vikoweb --publicar-acceso \
  --excel /home/cloud-user/inventario_ansible_actualizado.xlsx
```

Sólo solicita la clave actual del Vault en el terminal local; no solicita pegar la
contraseña del servidor aquí ni la imprime. Conserva otros 200 registros, puertos,
claves globales y formato 1.1 AES256. Comprueba cifrado mediante descifrado de retorno.
Respalda el Vault cifrado y el importador local antes de modificar. También elimina
exclusivamente Viko Web de la regla KEY_HOSTS del importador, para evitar que una
importación futura vuelva a forzar key. Ansible permanece como llave. Si el
importador local difiere de las versiones conocidas, se detiene sin tocar accesos.
--publicar-acceso publica sólo group_vars/all/vault.yml; exige índice Git vacío.
No modifica vars/vault.yml ni inventarios. Sin ese indicador, el cambio queda local.
El Excel debe ser la copia que contiene las credenciales actualizadas; se puede
indicar otra ruta con --excel. No usa copias antiguas de agosto como fuente.
