# Política de seguridad

Escudo Transparente es un prototipo académico (Proyecto para Computación II, USIL). Aun así, tomamos en serio cualquier reporte de seguridad.

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 9.6.x | Sí |
| Anteriores a 9.6 | No |

## Cómo reportar una vulnerabilidad

Por favor **no abras un Issue público** con detalles de una vulnerabilidad.

Usa el reporte privado de GitHub: pestaña **Security → Report a vulnerability**. Incluye:

- Descripción del problema y su impacto.
- Pasos para reproducirlo (versión de la extensión, navegador y, si aplica, la URL de prueba).
- Capturas o registros, sin datos personales ni claves reales.

Responderemos lo antes posible. Al ser un proyecto académico, no se garantizan plazos de corrección.

## Alcance

Incluye:

- La extensión de Chrome/Edge (carpeta `extension/`).
- El backend en Python (carpeta `backend/`) y su despliegue.
- La página de descarga de la extensión.

No incluye:

- Vulnerabilidades de los servicios externos que se consultan (VirusTotal, Google Safe Browsing, PhishTank, IPQualityScore).
- Resultados de detección incorrectos (falsos positivos o negativos). Para esos casos, abre un Issue normal.

## Manejo de datos y claves

- Las claves de las APIs externas se configuran **solo como variables de entorno del servidor**. Nunca van en la extensión ni en el repositorio (ver `.env.example`).
- Antes de consultar fuentes externas, el servidor elimina usuario, contraseña, parámetros de consulta y fragmento de la URL, y rechaza direcciones locales o privadas.
- El historial local de la extensión guarda solo el dominio, el resultado y las evidencias resumidas, durante 7 días y hasta 100 registros.
- La extensión no lee los valores de los campos de formularios ni el texto de las páginas o los correos.

Si encuentras una clave expuesta en este repositorio, repórtala por el canal privado para que la regeneremos.

## Limitaciones conocidas

- Una URL sin señales **no** es una URL segura: el resultado verde no es una garantía.
- El modelo de aprendizaje automático no está calibrado y se usa como evidencia de apoyo, no como decisión única.
- Antes de un uso comercial deben revisarse las licencias de las fuentes externas.
