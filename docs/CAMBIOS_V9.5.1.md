# Cambios de Escudo Transparente 9.5.1

## Incorporaciones

- Google Safe Browsing API v5 para coincidencias con phishing, malware y otras amenazas conocidas.
- PhishTank API para identificar URL reportadas, verificadas y válidas como phishing.
- IPQualityScore Malicious URL Scanner para riesgo, phishing, malware e indicadores sospechosos.
- Nuevo módulo `backend/threat_sources.py` que mantiene separada la integración con proveedores.
- Consultas externas paralelas, caché en memoria y límites conservadores por instancia.
- Cuatro secretos compatibles con variables locales y Google Secret Manager.
- Estado individual de cada fuente en `/health` y en el popup.
- Bloqueo temporal de URL exactas cuando el resultado combinado contiene una señal fuerte o al menos dos señales activas.
- Pruebas automáticas de respuestas de Google Safe Browsing, PhishTank e IPQualityScore sin consumir claves reales.

## Criterios añadidos al puntaje

| Evidencia | Puntos |
|---|---:|
| Google Safe Browsing: coincidencia | 40 |
| PhishTank: verificada y válida | 40 |
| PhishTank: reportada sin verificación completa | 10 |
| IPQualityScore: phishing, malware o riesgo alto | 35 |
| IPQualityScore: indicador sospechoso | 15 |

El modelo continúa siendo complementario y no cambia el color por sí solo. La decisión ya no depende de los intervalos 1–25 y 26–100: exactamente una evidencia débil produce rojo preventivo; una evidencia fuerte o dos evidencias activas producen rojo crítico. Los puntos se conservan como explicación y trazabilidad.

## Seguridad y privacidad

- Las claves nunca se incluyen en la extensión ni en el repositorio.
- Las consultas externas no reciben credenciales incrustadas, parámetros ni fragmentos de la URL.
- Las direcciones locales o privadas directas no se envían a terceros.
- Una fuente sin configurar o sin respuesta no se considera un resultado seguro.

## Consideración comercial

Google Safe Browsing solo permite uso no comercial. Para una versión destinada a la venta debe utilizarse Google Web Risk u otra alternativa con licencia comercial. También deben revisarse los planes y términos comerciales de las demás fuentes.
