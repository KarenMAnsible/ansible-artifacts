# Evidencia de backports PHP, revisión 29-oct-2026

Fuente de la evidencia: verificacion_backports_vikoweb.json generado con consulta
HTTPS al PPA ondrej/php y correspondencia exacta de Source/Version del DSC.
El empaquetado descargado coincide en SHA256 y tamaño con el DSC. La firma GPG
del DSC no se verificó; la fuente no prueba integridad de binarios instalados ni
contenido de memoria. Se conserva este límite en el reporte.

## Hechos observados

- php7.4, 1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1: el parche
  0164-Avoid-state-corruption-via-bailout.patch está incluido en debian/patches/series
  y su cabecera identifica ambos CVE. Se describe como backport/mitigación mínima EOL.
- php8.1, 8.1.34-9+ubuntu24.04.1+deb.sury.org+1: el parche
  0083-Avoid-state-corruption-via-bailout.patch está incluido en la serie y su
  cabecera identifica ambos CVE, también como mitigación mínima EOL.
- php8.2, 8.2.35-1+ubuntu24.04.1+deb.sury.org+1: empaquetado fuente exacto consultado.
  La ausencia de un parche adicional en debian/patches no prueba falta de la
  corrección upstream de PHP 8.2.35.

El changelog de la primera entrada puede corresponder al rebuild Ubuntu y no
mencionar CVE. La verificación usa también la serie de parches, no sólo esa entrada.

## Clasificación

php_vendor_sources.json registra las revisiones, URLs, hashes y parches mínimos.
Se aplica únicamente cuando coinciden exactamente el paquete/versión fuente,
la versión del paquete instalado asociado y el origen PPA declarado. No se
extrapola una rama completa ni se cambia el mínimo upstream de ningún CVE.

Cuando se identifica el backport mínimo, el detalle pasa a
backport_identificado_validacion_pendiente. El resultado general es pendiente,
y el título dice PENDIENTE DE VALIDACIÓN si no hay otro hallazgo potencial.
No se marca como corregido ni se certifica que el host no tenga vulnerabilidades.
Si otro componente conserva afectación potencial, ése sigue siendo el resultado
prioritario del equipo. Los equipos sin PHP en fuentes consultadas conservan el
encabezado negativo limitado al alcance consultado.

Fuentes primarias revisadas:
https://www.php.net/archive/2026.php
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

PHP publicó backports mínimos para EOL. El aviso de estado global recomienda
una versión con el parche completo como mitigación fiable. El aviso informativo
del 23 de octubre trata además session.upload_progress.enabled y la combinación
inusual de handlers de serialización; el reconocimiento actual no certifica ese
valor efectivo en cada aplicación ni extiende su veredicto a otros CVE.

## Aplicación

```bash
python3 /home/cloud-user/Integrar_Evidencia_Backports_PHP_VIKO.py --aplicar
python3 /home/cloud-user/Integrar_Evidencia_Backports_PHP_VIKO.py --publicar
```

Respalda y cambia sólo sus archivos. No modifica recolectores, Vault, inventarios,
puertos, servicios, paquetes, límites ni la restricción de los cuatro pilotos.
Sincronizar AAP y emitir un nuevo reporte sólo de huawei_viko_new_vikowebnew con
Password y las mismas variables. El cambio es del motor de reportes; no aplica
parches a Viko Web. Conservar los TXT previos como evidencia histórica.

Para consolidar en Excel, recuperar reporte.json de ambos Jobs de los cuatro
pilotos (Password y Key) y el reporte actualizado de Viko Web, junto con
cruce_inventario.csv del Job Password que consultó los 201 accesos. El consolidador
existente elige la recolección más reciente por alias. Los TXT individuales no
contienen el cruce íntegro de todos los accesos.
