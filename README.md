# Escudo Transparente — versión 9.6.0

Prototipo funcional de extensión para Chrome y Edge con icono de escudo. La interfaz utiliza dos colores: verde cuando no se encuentran señales y rojo cuando existe algún indicio de riesgo. Internamente distingue entre rojo preventivo, que permite continuar, y rojo crítico, que bloquea preventivamente. Revisa automáticamente características de la URL y formularios de contraseña de la página; marca enlaces renderizados en Gmail y Outlook; conserva un historial local limitado; y consulta un modelo entrenado, VirusTotal, Google Safe Browsing, PhishTank e IPQualityScore mediante un backend local o publicado en Google Cloud Run. **Todas las fuentes externas son opcionales e independientes. Solo son resultados reales las fuentes que aparezcan como disponibles.** Una URL sin señales no es una URL segura.

## 1. Abrir en VS Code e instalar

1. Descomprime y abre la carpeta `Escudo-Transparente-v9.6.0` en VS Code.
2. En `chrome://extensions` o `edge://extensions`, activa **Modo desarrollador** y usa **Cargar descomprimida** para elegir `extension`.
3. Si actualizas una versión anterior, reemplaza sus archivos, pulsa **Actualizar** y recarga las pestañas ya abiertas. El navegador puede pedir aceptar un permiso adicional de bloqueo de solicitudes.
4. Abre una página y pulsa el icono. **Ver más detalles** explica las razones; **Comprobar otro enlace** permite pegar una URL sin visitarla.

## 2. Semáforo y análisis local

- 0 señales activas: verde; no se encontraron indicios en las reglas y fuentes disponibles.
- Exactamente 1 señal débil: rojo preventivo; permite continuar bajo responsabilidad del usuario.
- 2 o más señales activas, o 1 señal fuerte: rojo crítico; aplica bloqueo preventivo.

Los puntos se conservan para explicar cuánto aporta cada evidencia, pero ya no fijan el color por intervalos.

Las reglas son heurísticas provisionales. Una página `/login` normal o una IP local no generan alerta por sí solas. Los dominios que contienen `viabcp` se contrastan estrictamente con `viabcp.com`, `viabcp.com.pe` y sus subdominios para detectar intentos de suplantación como `alerta-viabcp.com` o `viabcp.com.ejemplo.com`. La longitud de una URL, incluso superior a 200 caracteres, no suma puntos sola: solo agrega cinco cuando ya hay otra señal en esa dirección. El aviso verde es breve y no impide navegar; el rojo preventivo muestra señales concretas y permite volver o continuar. Una predicción aislada del modelo sin calibrar queda como dato informativo. Se conserva un aviso en página si un formulario pide contraseña por HTTP. El script revisa si hay formularios de contraseña en HTTP o que envían datos a otro origen. **No lee valores de los campos ni el texto de la página/correo.** Una señal puede tener explicaciones legítimas; los pesos deben calibrarse con datos.

Cada señal se entrega como una evidencia trazable con identificador, fuente, valor observado, umbral y aporte al puntaje. El popup diferencia las evidencias que modificaron la decisión de las que solo son informativas. El catálogo y el protocolo de validación de claridad están en [`docs/EVIDENCIAS.md`](docs/EVIDENCIAS.md).

En páginas web normales, un clic en un enlace de riesgo alto queda detenido antes de abrirlo; el aviso rojo crítico solo permite volver. El rojo preventivo sí permite continuar bajo responsabilidad del usuario. En una página ya abierta, **Volver a un sitio seguro** usa el historial del navegador para regresar a la página anterior y, si no existe una página anterior, abre `about:blank`. La página anterior **no se comprueba ni se garantiza segura** por el mero hecho de regresar. Para URL escritas en la barra o redirecciones, el aviso aparece cuando se ejecuta el script, tras comenzar la navegación. Esto **no detiene la solicitud inicial**. Un resultado crítico —una señal fuerte o dos señales activas— registra un bloqueo de red temporal para esa URL exacta después de recibir el análisis del backend. Los intentos posteriores de abrirla durante la misma sesión muestran una página roja antes de solicitarla. El bloqueo temporal desaparece al cerrar el navegador; **Quitar bloqueos de URLs detectadas** también elimina los bloqueos persistentes creados por versiones anteriores. Una URL diferente en el mismo dominio no queda bloqueada automáticamente.

Para pruebas locales, ejecuta `python -m http.server 8000` en una carpeta de prueba. `http://127.0.0.1:8000/` queda verde. Para comprobar el rojo preventivo con una sola señal, pega en el popup `https://xn--fiq228c.example/`. Para comprobar el rojo crítico con dos señales débiles, pega `https://a-b-c-login.example/`; para una señal fuerte, usa `https://usuario@login-verificar.example/`. Son dominios reservados de demostración: pégalos en el popup, no los abras ni introduzcas credenciales.

### Historial local y privado

El botón **Ver historial local** del popup abre una página con filtros para resultados verdes, rojos preventivos, rojos críticos y análisis incompletos. El historial usa `chrome.storage.local`, guarda únicamente el dominio, resultado, evidencias resumidas y estado de las fuentes. Nunca conserva la URL completa, usuario, contraseña, ruta, parámetros, fragmentos ni contenido de páginas o correos. Mantiene como máximo 100 dominios durante 7 días, reemplaza duplicados recientes y permite eliminar un registro o borrar todo. No se sincroniza con Google Cloud ni con una cuenta del navegador.

## 3. Gmail y Outlook

Al abrir un mensaje en Gmail u Outlook web, la extensión marca junto a sus enlaces `⛔ Riesgo detectado` o `⛔ Enlace sospechoso` según la URL. Cuando hay un enlace crítico, muestra dentro del mensaje una tarjeta de alerta con **No abrir** y **Ver detalles**. El enlace crítico queda detenido al pulsarlo; los detalles muestran su URL y las señales concretas del análisis y, para hasta cuatro enlaces distintos por carga, actualiza la marca con el modelo y las fuentes externas disponibles. El límite evita gastar de golpe las cuotas gratuitas; los demás enlaces conservan únicamente el análisis local. Chrome/Edge restringen páginas internas, y las interfaces del correo pueden cambiar sus selectores. Los enlaces envueltos por servicios de redirección se evalúan por su URL visible para el navegador; no se desenrollan ni se lee el contenido del mensaje. Prueba ambas interfaces con correos de prueba antes de demostrar esta función.

## 4. Backend local, Google Cloud y fuentes externas opcionales

Desde la terminal de VS Code, en la raíz del proyecto:

```bash
python backend/server.py
```

Al abrir una página o el popup, la extensión consulta automáticamente `127.0.0.1:8765` si el servidor está encendido. El popup muestra primero las reglas locales y luego actualiza el puntaje y el estado de las fuentes. **Reintentar consulta** solo sirve si hubo un fallo. Sin una clave, esa fuente responde `not_configured`. Configura las claves únicamente como variables de entorno **en la terminal del servidor**, nunca en la extensión ni en Git:

- PowerShell: `$env:VT_API_KEY="TU_CLAVE"; $env:GOOGLE_SAFE_BROWSING_API_KEY="TU_CLAVE"; $env:PHISHTANK_API_KEY="TU_CLAVE"; $env:IPQS_API_KEY="TU_CLAVE"; python backend/server.py`
- bash: `VT_API_KEY="..." GOOGLE_SAFE_BROWSING_API_KEY="..." PHISHTANK_API_KEY="..." IPQS_API_KEY="..." python backend/server.py`

Consulta [`docs/CONFIGURACION_APIS.md`](docs/CONFIGURACION_APIS.md) para obtener, probar y proteger cada clave. Para dejar de depender de `localhost`, sigue [`docs/GUIA_GOOGLE_CLOUD.md`](docs/GUIA_GOOGLE_CLOUD.md). La versión 9.6.0 incluye un `Dockerfile`, compatibilidad con las variables `PORT` y `HOST`, una ruta `/health`, almacenamiento opcional de las cuatro claves en Secret Manager y un script de PowerShell que publica el backend y coloca automáticamente la URL HTTPS obtenida en `extension/config.js`. La extensión conserva el modo local como configuración inicial y nunca contiene claves privadas.

Las consultas a las cuatro fuentes se ejecutan en paralelo. Antes de enviarlas, el servidor **elimina usuario, contraseña, parámetros de consulta y fragmento** y rechaza destinos locales o privados. Aun así comparte el esquema, dominio, puerto y ruta; evita instalar este prototipo en un perfil con navegación confidencial. Esta normalización puede impedir encontrar un informe exacto si dependía de sus parámetros. Los resultados se guardan temporalmente en memoria y existen límites conservadores por instancia; alcanzar una cuota deja esa fuente como no disponible y nunca produce un bloqueo por sí mismo. Google Safe Browsing se integra mediante `urls.search` v5; PhishTank mediante `checkurl`; IPQualityScore mediante su analizador de URL con la clave en cabecera; y VirusTotal mediante el informe existente de URL.

**Licencias:** Google Safe Browsing es únicamente para uso no comercial y debe reemplazarse por Google Web Risk antes de vender el producto. La API pública de VirusTotal tampoco debe integrarse en un producto comercial. Revisa los términos y el plan contratado de todas las fuentes antes de distribuir la extensión.

## 5. Modelo de aprendizaje automático

No se incluye un modelo preentrenado sin procedencia. Consigue un CSV autorizado y etiquetado con columnas `url,label`, donde `0` es legítima y `1` phishing. El entrenador admite CSV UTF-8 y exportaciones habituales de Excel (Windows-1252/Latin-1, comas o punto y coma). Colócalo en `dataset/urls.csv` y ejecuta:

```bash
python backend/train.py dataset/urls.csv
```

El script necesita al menos 40 URLs y ambas clases. Entrena una regresión logística sobre atributos de URL sin dependencias externas y separa aproximadamente 20 % de los dominios para prueba, evitando evaluar exactamente los dominios vistos al entrenar. El entrenamiento nuevo añade longitud del dominio, profundidad de subdominios, números en la ruta y estructura de ruta/consulta. **El modelo anterior sigue funcionando sin reentrenar**; estas nuevas características solo se activan al ejecutar de nuevo `train.py` sobre tu CSV. Genera `backend/model.json` y `backend/evaluation.json` con precisión, recall, F1, verdaderos/falsos positivos y negativos. Guarda una copia de `model.json` y mide falsos positivos con un dataset externo antes y después de reentrenar. Reinicia el servidor para cargar el modelo nuevo. No subas datasets ajenos sin licencia ni contraseñas/tokens. TensorFlow puede estudiarse después; no es requisito para este clasificador inicial.

### Evaluación externa PhishStorm

Coloca `urlset.csv` descargado del repositorio original en `dataset/` y ejecuta `python backend/evaluate_phishstorm.py dataset/urlset.csv`. El evaluador lee `domain,label` (0 legítima, 1 phishing), acepta etiquetas numéricas como `0.0`/`1.0` e informa los motivos de omisión de filas. No modifica el modelo ni consulta enlaces. Si una URL no trae esquema, se supone HTTPS y se informa cuántas filas necesitaron esa suposición: sus resultados deben interpretarse con cautela. Los datos originales son de 2014, así que añade una prueba separada con URLs actuales. No incluyas `urlset.csv` en un repositorio sin comprobar primero sus condiciones de uso.

La combinación automática considera: VirusTotal (10–30 puntos), Google Safe Browsing (40), PhishTank (10 o 40) e IPQualityScore (15 o 35). Los valores exactos están en `docs/EVIDENCIAS.md` y deben validarse con casos reales autorizados. **El modelo no añade puntos por sí solo mientras no haya una validación externa aceptable**: su predicción se muestra como referencia. Cuando existe una alerta de reputación, el modelo puede añadir 10 puntos para una salida ≥ 0.8 y 5 para ≥ 0.6. Exactamente una señal débil queda como rojo preventivo; dos señales activas o una señal marcada como fuerte producen rojo crítico. Ninguna fuente prueba por sí sola que todo un dominio sea fraudulento.

La cifra del modelo es una **puntuación sin calibrar**, no el porcentaje real de probabilidad de phishing. El popup muestra el dominio y la URL completa por separado: el modelo recibe la URL completa, mientras que las fuentes externas reciben únicamente esquema, dominio, puerto y ruta. Si aparece verde aun con una salida alta del modelo, los detalles explican que la predicción aislada no contó. “Sin coincidencias” tampoco prueba que una página sea segura. La precisión medida en el CSV de entrenamiento no demuestra la tasa de falsos positivos en Google, LinkedIn o Facebook: pueden existir diferencias entre ese dataset y la navegación real. Valida un conjunto adicional de páginas legítimas y maliciosas ajenas al entrenamiento y ajusta/calibra el modelo antes de subir sus pesos. No se usan listas blancas de dominios, pues una página alojada en una plataforma conocida también puede ser fraudulenta.

### Validación externa del modelo

El proyecto incluye `backend/validate_external.py`. Para usarlo, conserva tu `backend/model.json` actual y prepara un CSV **independiente del entrenamiento**, con columnas `url,label` o `domain,label`; `0` indica legítima y `1` phishing. Ejecuta en PowerShell desde la raíz:

```powershell
python backend/validate_external.py dataset/validacion.csv dataset/urls.csv > research/results/validacion_resultado.json
```

El segundo CSV es opcional, pero permite avisar si hay dominios comunes con el entrenamiento. El informe muestra TP, FP, TN y FN a umbrales 0.4, 0.5 y 0.8; la tasa de falsos positivos; ejemplos legítimos puntuados ≥ 0.8; y grupos de calibración (salida media del modelo frente a proporción real de phishing). El apartado `independent` calcula las mismas métricas excluyendo dominios presentes en el CSV de entrenamiento; `thresholds` conserva las métricas de todas las URL para comparación. Las alertas se escriben en la terminal para que el archivo de salida sea JSON válido. Si solo aportas la muestra incluida de páginas legítimas, podrás medir falsos positivos, pero **no** sensibilidad ni calibración representativa. No se modifica el modelo al evaluar. Las URL sin esquema en la columna `domain` se interpretan como HTTPS y se cuentan por separado. Nunca presentes como validación externa un conjunto que comparta dominios con el entrenamiento.

## 6. Verificación y límites

Corre `node tests/analyzer.test.js`, `node tests/content.test.js`, `node tests/background.test.js`, `node tests/popup.test.js`, `node tests/mail.test.js`, `node tests/history.test.js`, `node tests/history_page.test.js` y `python -m unittest discover -s tests -p 'test_*.py'` desde la raíz. Incluyen la regla de 0/1/2 señales y señal fuerte, URL largas, alertas, respuestas simuladas de las cuatro fuentes, privacidad e interfaz del historial, bloqueo automático y lectura de CSV. Sigue también la guía `docs/PRUEBAS_NAVEGADOR.md` para probarlo realmente en Chrome/Edge. Una prueba automatizada verifica la lógica sin consumir las cuotas reales; una prueba en navegador con claves propias sigue siendo necesaria antes de la presentación.

El despliegue de Cloud Run se prueba adicionalmente consultando `URL_DE_CLOUD_RUN/health`. En producción, configura `ALLOWED_EXTENSION_ORIGINS` con el origen exacto `chrome-extension://ID`; el comodín incluido en el despliegue sin `-ExtensionId` sirve únicamente para el prototipo. Un servicio público también necesita autenticación, cuotas persistentes y monitoreo antes de distribuirse comercialmente.
