# Catálogo de evidencias y validación de claridad

Este documento define las evidencias que puede mostrar Escudo Transparente. Una evidencia es un dato observable con origen, condición y aporte explícitos. El puntaje es orientativo: no confirma por sí solo que una página sea legítima o fraudulenta.

## Contrato de una evidencia

Cada elemento producido por el analizador contiene:

- `id`: identificador estable para pruebas y trazabilidad.
- `source`: `url`, `page`, `model`, `virustotal`, `google_safe_browsing`, `phishtank` o `ipqualityscore`.
- `title` y `description`: explicación legible para el usuario.
- `observedValue`: valor que activó la evidencia.
- `threshold`: condición de referencia.
- `scoreContribution`: puntos asignados.
- `severity`: `info`, `medium` o `high`.
- `contributesToDecision`: indica si modificó el resultado.

`reasons` se conserva como representación textual por compatibilidad, pero `evidence` es la fuente estructurada oficial.

## Regla de decisión

- 0 evidencias activas: verde.
- Exactamente 1 evidencia débil: rojo preventivo y opción de continuar.
- 2 o más evidencias activas: rojo crítico y bloqueo preventivo.
- 1 evidencia con severidad `high`: rojo crítico aunque sea la única señal.

Las evidencias informativas (`contributesToDecision: false`) no cuentan como señales. Los puntos explican el peso de cada evidencia y se muestran para trazabilidad, pero el color se decide por cantidad y severidad, no por intervalos de puntaje.

## Evidencias utilizadas

| ID | Fuente | Condición | Puntos |
|---|---|---|---:|
| `BRAND_IMPERSONATION` | URL | `viabcp` aparece fuera de `viabcp.com`, `viabcp.com.pe` o sus subdominios | 45 |
| `URL_CREDENTIALS` | URL | Usuario o contraseña antes del dominio | 45 |
| `PUNYCODE` | URL | Dominio que contiene `xn--` | 10 |
| `PUBLIC_IP` | URL | Host con IP pública | 15 |
| `LURE_COMBINATION` | URL | Palabra de señuelo combinada con otra señal | 10 |
| `MANY_HYPHENS` | URL | Tres o más guiones en el dominio | 10 |
| `EXTREME_LENGTH` | URL | Más de 200 caracteres y otra señal previa | 5 |
| `HTTP_PASSWORD_FORM` | Página | Formulario de contraseña servido por HTTP | 25 |
| `CROSS_ORIGIN_FORM` | Página | Formulario de contraseña enviado a otro origen | 15 |
| `VT_MALICIOUS` | VirusTotal | Una detección maliciosa | 15 |
| `VT_MALICIOUS` | VirusTotal | Dos o más detecciones maliciosas | 30 |
| `VT_SUSPICIOUS` | VirusTotal | Una o más detecciones sospechosas sin detecciones maliciosas | 10 |
| `GSB_THREAT` | Google Safe Browsing | Coincidencia con una amenaza conocida | 40 |
| `PHISHTANK_VERIFIED` | PhishTank | Reportada, verificada y válida | 40 |
| `PHISHTANK_REPORTED` | PhishTank | Reportada sin verificación completa | 10 |
| `IPQS_HIGH_RISK` | IPQualityScore | Phishing, malware o `unsafe` con riesgo ≥ 85 | 35 |
| `IPQS_SUSPICIOUS` | IPQualityScore | `suspicious`, `unsafe` o riesgo ≥ 60 | 15 |
| `MODEL_MEDIUM` | Modelo | Salida desde 60/100, corroborada por reputación | 5 |
| `MODEL_HIGH` | Modelo | Salida desde 80/100, corroborada por reputación | 10 |

El modelo sin una alerta independiente se muestra como evidencia informativa con cero puntos. `NO_URL_SIGNALS`, `INVALID_URL` y `UNSUPPORTED_PROTOCOL` también son informativas.

## Presentación

El popup presenta para cada evidencia: nombre, explicación, fuente, valor observado y aporte. Las alertas en página y correo usan el mismo objeto, con una versión compacta. El estado de cada fuente se informa por separado; una fuente no disponible nunca se interpreta como resultado limpio.

El backend no devuelve ninguna API key. Las fuentes externas reciben esquema, dominio, puerto y ruta, pero no reciben credenciales, parámetros de consulta ni fragmentos. Las direcciones locales o privadas no se consultan. Cada respuesta declara el alcance mediante `scope` y `query_parameters_shared`.

## Protocolo de validación de claridad

Probar con al menos cinco personas que no hayan participado en el desarrollo. Mostrar un caso verde, uno preventivo y uno de riesgo alto. Sin ayuda, cada participante debe responder:

1. ¿Cuál es el nivel de riesgo?
2. ¿Qué evidencia principal produjo el resultado?
3. ¿De qué fuente proviene?
4. ¿Cuántos puntos aportó?
5. ¿El modelo confirmó el fraude o solo aportó una señal?
6. ¿Un resultado verde garantiza que el sitio sea seguro?
7. ¿Qué acción recomienda el sistema?

La validación se aprueba cuando al menos cuatro de cinco personas responden correctamente las primeras cinco preguntas, nadie interpreta el verde como garantía y nadie interpreta el modelo aislado como confirmación. Registrar fecha, escenario, respuestas y observaciones; no registrar URLs privadas ni datos personales.

## Definición de terminado

- Todas las señales activas usan el contrato de evidencia.
- El puntaje puede rastrearse hasta sus evidencias.
- Popup, página y correo identifican fuente y aporte.
- Las fuentes no disponibles se distinguen de un resultado sin detecciones.
- Las pruebas automáticas verifican estructura, contribución y compatibilidad.
- La validación de claridad se ejecuta y documenta con el protocolo anterior.
