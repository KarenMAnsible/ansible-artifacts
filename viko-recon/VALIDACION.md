# Validación de la versión 1.2

Realizada el 23 de octubre de 2026 en un entorno Linux local, con evidencia sintética.

## Comprobaciones completadas

- `ansible-playbook --syntax-check` con ansible-core **2.19.14** y colección **ansible.windows 3.9.1**.
- **15 pruebas automatizadas** mediante `python3 -m unittest discover -s tests -v`.
- Límites de versión por rama de PHP; excepciones de Log4j 2.3/2.12 y la diferencia entre CVE-2021-44228 y CVE-2021-45046.
- Rangos de Struts, versiones con cuatro números y validación pendiente de migración del mecanismo de carga.
- Backports: una declaración externa solo cierra la observación del paquete y versión exactos.
- Log4j anidado en un WAR en una ruta de prueba que representa SAP.
- Log4j dentro de un wrapper con nombre de Instana; se conserva la versión del componente Maven, no la del wrapper.
- Biblioteca con clases Log4j pero sin metadatos de versión: requiere validación.
- `log4j-api` por sí solo no genera una observación de Log4j core.
- Archivos corruptos, profundidad máxima y corte de tiempo: dejan cobertura parcial.
- Temporizador Linux: interrupción de una operación de prueba bloqueada, conservando evidencia ya recogida.
- Ejecución completa del playbook sobre un host Linux local y un host de prueba con transporte SSH no disponible: ambos se conservan en el reporte; el Job finaliza la consolidación.
- Las rutas declaradas en variables del host se respetan frente a los valores predeterminados.
- Reportes TXT/JSON/CSV/HTML y ZIP; recuperación desde un objeto de artefactos como el exportado por AAP, con comparación exacta de bytes. El TXT conserva hallazgos, rutas y motivos de timeout o evaluación pendiente.
- Exceso del límite de tamaño del artefacto: se informa explícitamente y no se presenta como reporte completo.
- Escape HTML y neutralización de fórmulas en CSV.
- TXT consolidado y por servidor: nombre real/inventario, IP y fecha/hora CDMX con timestamp UTC; conversión de fecha de Windows con siete decimales, equipos no evaluados y nombres de archivo seguros sin colisiones en los casos probados.
- Análisis estático de sintaxis PowerShell del recolector y de la plantilla de watchdog renderizada mediante tree-sitter-powershell. Esto no equivale a ejecutar PowerShell en Windows.

## Pendiente antes de ampliar el uso

1. Piloto real Linux y Windows con credenciales, versiones, permisos y rutas VIKO.
2. Ejecución real del recolector y watchdog Windows bajo PowerShell 5.1, .NET y el EE seleccionado. No hubo un Windows disponible en este entorno.
3. Confirmar en el controlador AAP de VIKO que los artefactos completos se guardan y se pueden recuperar; aquí se probó la generación y recuperación local, sin acceder a ese controlador.
4. Cruce con la consola TrendAI, revisión de backports y correspondencia con los CVE originales de Ivonne.
5. Completar rutas en volúmenes adicionales, symlinks/junctions y contenido de contenedores que quede fuera de la cobertura.

Este paquete no se conectó a servidores de clientes, no modificó el repositorio existente y no aplicó parches.
