# Guía de despliegue en Google Cloud Run

Esta versión puede ejecutarse localmente y también como un servicio HTTPS público en Google Cloud Run. El script de despliegue construye el contenedor, publica el backend, consulta la URL generada y configura automáticamente la extensión para usarla.

## 1. Requisitos

- Una cuenta y un proyecto de Google Cloud con facturación habilitada.
- Google Cloud CLI (`gcloud`) instalado.
- Python 3 instalado.
- La carpeta completa del proyecto abierta en VS Code.

Desde PowerShell, inicia sesión una sola vez:

```powershell
gcloud init
gcloud auth login
```

## 2. Publicar el backend

Abre la terminal de VS Code en la raíz del proyecto y ejecuta:

```powershell
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO"
```

Reemplaza `ID_DE_TU_PROYECTO` por el identificador real de Google Cloud, no por el nombre visible del proyecto.

Si utilizarás VirusTotal durante la demostración académica, usa:

```powershell
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -ConfigureVirusTotal
```

La clave se solicita de forma oculta y se guarda en Secret Manager. No se escribe en el código, en el ZIP ni en la extensión.

Para restringir CORS al identificador definitivo de la extensión:

```powershell
powershell -ExecutionPolicy Bypass -File .\cloud\deploy-cloud-run.ps1 -ProjectId "ID_DE_TU_PROYECTO" -ExtensionId "ID_DE_32_CARACTERES"
```

El identificador aparece en `chrome://extensions`. Si todavía estás trabajando con una extensión cargada manualmente, puedes omitirlo durante las pruebas.

## 3. Qué realiza el script

1. Habilita Cloud Run, Cloud Build, Artifact Registry y Secret Manager.
2. Crea una cuenta de servicio exclusiva para el backend.
3. Construye la imagen usando `backend/Dockerfile`.
4. Publica el servicio con cero instancias mínimas y una instancia máxima.
5. Obtiene la dirección HTTPS de Cloud Run.
6. Actualiza `extension/config.js` y el permiso exacto en `manifest.json`.
7. Comprueba la ruta pública `/health`.

Al terminar aparecerá una dirección similar a:

```text
https://escudo-transparente-api-xxxxx.run.app
```

## 4. Cargar y probar la extensión

1. Abre `chrome://extensions` o `edge://extensions`.
2. Activa **Modo desarrollador**.
3. Pulsa **Cargar descomprimida** y selecciona la carpeta `extension`.
4. Si ya estaba cargada, pulsa **Actualizar**.
5. Abre el popup y analiza una URL de demostración.

También puedes comprobar el servidor en el navegador:

```text
URL_DE_CLOUD_RUN/health
```

Debe responder con `"status": "ok"`.

## 5. Volver temporalmente al servidor local

```powershell
python .\tools\configure_extension.py http://127.0.0.1:8765
python .\backend\server.py
```

Después pulsa **Actualizar** en la página de extensiones.

## 6. Control de costos y alcance

El despliegue utiliza `min-instances=0` para que el servicio pueda reducirse a cero cuando no tenga tráfico, y `max-instances=1` para limitar el gasto y proteger la cuota académica de VirusTotal. Configura además un presupuesto y alertas de facturación en Google Cloud.

Este despliegue es adecuado para el prototipo académico. Antes de vender la extensión se debe incorporar autenticación por usuario, límites persistentes, monitoreo y una licencia comercial del servicio de reputación. CORS limita qué páginas pueden consumir la API desde un navegador, pero no reemplaza la autenticación. La API pública de VirusTotal no debe utilizarse como parte de un producto comercial.
