# Cambios de Escudo Transparente 9.6.0

## Historial local y privado

- Nueva pantalla de historial accesible desde el popup.
- Filtros por verde, rojo preventivo, rojo crítico y análisis incompleto.
- Búsqueda local por dominio.
- Detalles de evidencias y estado de VirusTotal, Google Safe Browsing, PhishTank e IPQualityScore.
- Eliminación individual y opción para borrar todo.

## Privacidad y límites

- Los registros se almacenan únicamente en `chrome.storage.local`.
- Solo se conserva el dominio; no se guardan URL completas, rutas, credenciales, parámetros ni fragmentos.
- Tampoco se guarda el valor observado de las evidencias ni contenido de páginas o correos.
- Se mantienen como máximo 100 registros durante 7 días.
- Los análisis repetidos del mismo dominio dentro de diez minutos se actualizan en lugar de duplicarse.
- El historial no se sincroniza con el backend ni con Google Cloud.

## Verificación

- Se añadieron pruebas de privacidad, deduplicación, conservación del mejor estado de fuentes y borrado.
- El historial refleja si la verificación externa fue completa, parcial o únicamente local.
