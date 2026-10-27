# Configuración de fuentes de amenazas — versión 9.5.1

Escudo Transparente puede consultar cuatro fuentes externas. Todas son opcionales e independientes: si una no está configurada o no responde, las demás y las reglas locales continúan funcionando.

| Fuente | Variable secreta | Uso en el prototipo |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Detecciones de motores existentes |
| Google Safe Browsing v5 | `GOOGLE_SAFE_BROWSING_API_KEY` | Coincidencias con amenazas conocidas |
| PhishTank | `PHISHTANK_API_KEY` | URL reportada y verificada como phishing |
| IPQualityScore | `IPQS_API_KEY` | Riesgo, phishing, malware e indicadores sospechosos |

## 1. Obtener las claves

- Google Safe Browsing: habilita `Safe Browsing API` en el proyecto de Google Cloud y crea una clave en **APIs y servicios > Credenciales**. Restringe la clave a esa API. Documentación: <https://developers.google.com/safe-browsing/reference>.
- PhishTank: crea una cuenta gratuita, confirma el correo y consulta la clave de aplicación en la sección de API. Documentación: <https://phishtank.org/api_info.php>.
- IPQualityScore: crea una cuenta y copia la API key de tu panel. Documentación: <https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview>.
- VirusTotal: usa la clave de tu cuenta solo bajo las condiciones de su licencia.

No pegues ninguna clave en `server.py`, `config.js`, `manifest.json`, `Dockerfile`, GitHub, documentos ni capturas.

## 2. Probar localmente en PowerShell

Abre la terminal en la raíz del proyecto y configura únicamente las fuentes que utilizarás:

```powershell
$env:VT_API_KEY="TU_CLAVE_VIRUSTOTAL"
$env:GOOGLE_SAFE_BROWSING_API_KEY="TU_CLAVE_GOOGLE"
$env:PHISHTANK_API_KEY="TU_CLAVE_PHISHTANK"
$env:IPQS_API_KEY="TU_CLAVE_IPQS"
python .\backend\server.py
```

Las variables existen solo en esa terminal. Abre `http://127.0.0.1:8765/health` y comprueba cuáles aparecen con valor `true`.

Para borrar las variables manualmente:

```powershell
Remove-Item Env:VT_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:GOOGLE_SAFE_BROWSING_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:PHISHTANK_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:IPQS_API_KEY -ErrorAction SilentlyContinue
```

## 3. Guardarlas en Google Cloud

Para solicitar y guardar las cuatro claves de forma oculta en Secret Manager:

```powershell
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -Region "us-central1" -ConfigureAllApis
```

También puedes configurar una sola fuente:

```powershell
# Solo Google Safe Browsing
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -Region "us-central1" -ConfigureGoogleSafeBrowsing

# Solo PhishTank
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -Region "us-central1" -ConfigurePhishTank

# Solo IPQualityScore
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -Region "us-central1" -ConfigureIPQualityScore
```

El script reutiliza automáticamente los secretos que ya existan. Para reemplazar una clave, vuelve a ejecutar el parámetro correspondiente; se añadirá una versión nueva del secreto.

## 4. Privacidad y funcionamiento

- Las claves permanecen en el backend y nunca llegan a la extensión.
- Antes de consultar servicios externos se eliminan usuario, contraseña, parámetros de consulta y fragmento de la URL.
- No se envían direcciones locales, privadas ni reservadas.
- Las cuatro consultas se ejecutan en paralelo y se almacenan temporalmente en caché.
- Una fuente sin configurar, sin reporte, con cuota agotada o no disponible se muestra expresamente; nunca se interpreta como prueba de seguridad.

## 5. Restricciones comerciales

Google Safe Browsing está permitido únicamente para uso no comercial. Si la extensión se vende o genera ingresos, debe reemplazarse por Google Web Risk o por una alternativa con licencia comercial. Revisa también el plan y los términos aplicables de VirusTotal, PhishTank e IPQualityScore antes de distribuir el producto.
