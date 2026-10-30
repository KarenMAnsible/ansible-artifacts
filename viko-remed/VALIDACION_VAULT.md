# Verificación de la integración Vault

Base revisada: `VIKO_Remediacion_Piloto_20261029.zip`, versión 2. Tarea de acceso revisada: commit `72d1d2034e82ca8591520f49b14ca8088263407b` del repositorio existente.

Pruebas locales controladas:

- Instalación y repetición sin cambios: Vault cifrado, `vars/vault.yml` incluso con YAML inválido, staged ajeno y archivos de `__pycache__` permanecieron intactos.
- Fallo forzado de syntax-check: restauración únicamente de archivos propios; no se alteró el Vault.
- Publicación simulada a un repositorio bare local: commit limitado a `viko-remed/`, conservando un archivo ajeno staged.
- Fusión de cambios: se conservó una edición local no conflictiva en un archivo propio.
- Vault sintético cifrado con texto `!unsafe`: accesos Linux/Windows y cuatro registros con puerto 1024 conservaron la contraseña literal, sin mostrarla en stdout/stderr.
- Modo Machine/llave sin archivo Vault disponible: omitió el cargador y no solicitó contraseña de Vault.
- Recuperación offline de TXT: nombre EQUIPO_IP_AAAAMMDD_HHMMSS.txt, comprobación SHA256, copia idempotente y conservación del enlace simbólico de la carpeta común.
- Flujo completo local en modo plan, primero con un host y después con dos en serie: generó evidencia/artefactos sin instalar paquetes ni contactar servidores VIKO. La consolidación omite objetivos aún no iniciados para no marcarlos fallidos prematuramente. La fecha por equipo se conserva al consolidar de nuevo.

Entorno de prueba: ansible-core 2.17.14, ansible.windows 2.8.0, community.general 9.5.1. Las pruebas de acceso utilizaron registros y contraseñas ficticios; no acreditan conectividad real de los 192 registros listos por formato.

No se descifró el Vault de VIKO, no se importó Excel, no se publicó al origin de VIKO ni se ejecutaron remediaciones en sus servidores. Pendiente validar los pilotos reales con las credenciales de AAP. La actualización de PHP Windows ZIP/XAMPP/IIS sigue requiriendo su manejador específico; habilitar Vault no lo sustituye.
