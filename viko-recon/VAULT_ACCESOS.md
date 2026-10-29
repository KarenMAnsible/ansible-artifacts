# Accesos de reconocimiento

Fuente vigente autorizada: hoja Busqueda AAP. IP, usuario, acceso, cliente y
sistema proceden de esa hoja. Los puertos explícitos de Detalle tecnico se
incorporan por alias exacto. Nunca se sustituyen IP o accesos con datos de Detalle.

El importador muestra un plan por defecto. --aplicar pide la clave del Vault
existente y respalda antes de escribir. --publicar agrega un commit con sólo los
cuatro archivos propios y lo envía a origin/main. No ejecuta jobs ni conecta a
servidores. vars/vault.yml se conserva sin abrirlo ni modificarlo.

Clasificación: referencias rotuladas Llave, Key, SSH Key, archivos .pem/.ppk o
llaves privadas se excluyen de contraseñas. Viko Web y Ansible conservan su modo
de llave conocido. Las demás celdas Password / Llave se interpretan como
contraseñas, salvo Tipo de acceso explícito (si existe). Validar el resumen; un
nombre de llave sin etiqueta necesita Tipo de acceso=key. No se importan llaves
privadas: siguen en credenciales Machine de AAP. Los registros con formato o
sistema pendiente quedan guardados con status=pendiente y no pueden conectarse.

En AAP, sincronizar Reconocimiento-Vulnerabilidades-VIKO. Usar primero la
plantilla piloto Password existente. Añadir credencial tipo Vault con la misma
clave del archivo group_vars/all/vault.yml; dejar Vault ID vacío (formato 1.1).
Desactivar encuesta de usuario/contraseña y quitar extra vars ansible_user,
ansible_password, ansible_ssh_user y ansible_ssh_pass. Quitar cualquier petición
obligatoria de contraseña SSH en la credencial Machine de esa plantilla.
Añadir vuln_use_vault: true y conservar el resto de variables, límites y reportes.
Probar sólo un Linux por contraseña y un Windows por contraseña. Limit contiene
los alias, sin localhost. Revisar TXT y evidencia antes de ampliar.

La plantilla SSH Key puede conservar vuln_use_vault=false (valor por defecto),
sus credenciales Machine y encuesta de contraseña desactivada. Si se habilita
Vault para metadatos de llave, adjuntar también la credencial Vault; el código
no instala llaves ni intenta seleccionar una credencial Machine por su nombre.

Con Vault activo: puerto explícito del Excel tiene prioridad; si no existe,
se mantiene ansible_port del inventario; sólo si tampoco existe se usan 22 para
SSH o 5985 para WinRM. No se cambia autenticación ni transporte de WinRM.
Los fallos de acceso se detectan durante el piloto; importar no prueba claves.
