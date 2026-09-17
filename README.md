# Escudo Transparente — versión 0.9.0

Prototipo funcional de extensión para Chrome y Edge con icono de escudo. El popup muestra los símbolos del prototipo: check verde, triángulo amarillo y señal roja; los avisos sobre páginas usan los símbolos correspondientes. Revisa automáticamente características de la URL y formularios de contraseña de la página; marca enlaces renderizados en Gmail y Outlook; consulta automáticamente un modelo entrenado y reputación de VirusTotal mediante un servidor local. **Solo son resultados reales las fuentes que aparezcan como disponibles.** Una URL sin señales no es una URL segura.

## 1. Abrir en VS Code e instalar

1. Descomprime y abre la carpeta `phishing-detection-extension` en VS Code.
2. En `chrome://extensions` o `edge://extensions`, activa **Modo desarrollador** y usa **Cargar descomprimida** para elegir `extension`.
3. Si actualizas una versión anterior, reemplaza sus archivos, pulsa **Actualizar** y recarga las pestañas ya abiertas. El navegador puede pedir aceptar un permiso adicional de bloqueo de solicitudes.
4. Abre una página y pulsa el icono. **Ver más detalles** explica las razones; **Comprobar otro enlace** permite pegar una URL sin visitarla.

## 2. Semáforo y análisis local

- 0 puntos: verde, sin señales en las reglas consultadas.
- 1 a 25: amarillo, revisar.
- 26 a 100: rojo, evitar.

Las reglas son heurísticas provisionales. Una página `/login` normal o una IP local no generan alerta por sí solas. La longitud de una URL, incluso superior a 200 caracteres, no suma puntos sola: solo agrega cinco cuando ya hay otra señal en esa dirección. El aviso verde es breve y no impide navegar; el amarillo muestra señales concretas y permite volver o continuar. Una predicción aislada del modelo sin calibrar queda como dato informativo. Se conserva un aviso en página si un formulario pide contraseña por HTTP. El script revisa si hay formularios de contraseña en HTTP o que envíen datos a otro origen. **No lee valores de los campos ni el texto de la página/correo.** Una señal puede tener explicaciones legítimas; los pesos deben calibrarse con datos.

En páginas web normales, un clic en un enlace rojo queda detenido antes de abrirlo; el aviso rojo solo permite volver. En una página ya abierta, **Volver a un sitio seguro** usa el historial del navegador para regresar a la página anterior y, si no existe una página anterior, abre `about:blank`. La página anterior **no se comprueba ni se garantiza segura** por el mero hecho de regresar. Para URL escritas en la barra o redirecciones, el aviso aparece cuando se ejecuta el script, tras comenzar la navegación. Esto **no detiene la solicitud inicial**. Cuando VirusTotal informa al menos dos detecciones maliciosas en una consulta real, la extensión registra automáticamente un bloqueo de red temporal para esa URL exacta. Los intentos posteriores de abrirla durante la misma sesión muestran una página roja antes de solicitarla. El bloqueo temporal desaparece al cerrar el navegador; **Quitar bloqueos de URLs detectadas** también elimina los bloqueos persistentes creados por versiones anteriores. Una URL diferente en el mismo dominio no queda bloqueada automáticamente.

Para pruebas locales, ejecuta `python -m http.server 8000` en una carpeta de prueba. `http://127.0.0.1:8000/` queda verde. Para comprobar amarillo sin ventana emergente, pega en el popup `https://a-b-c-login.example/`; para rojo, pega `https://usuario@login-verificar.example/` (dominio reservado de demostración). No abras ni introduzcas credenciales en sitios desconocidos.

## 3. Gmail y Outlook

Al abrir un mensaje en Gmail u Outlook web, la extensión marca junto a sus enlaces `⚠ Revisar enlace` o `⛔ Enlace sospechoso` según la URL. Cuando hay un enlace rojo, muestra dentro del mensaje una tarjeta de alerta con **No abrir** y **Ver detalles**. El enlace rojo queda detenido al pulsarlo; los detalles muestran su URL y las señales concretas del análisis y, para hasta cuatro enlaces distintos por carga, actualiza la marca con el modelo y VirusTotal si el servidor responde. El límite evita gastar de golpe la cuota gratuita; los demás enlaces conservan únicamente el análisis local. Chrome/Edge restringen páginas internas, y las interfaces del correo pueden cambiar sus selectores. Los enlaces envueltos por servicios de redirección se evalúan por su URL visible para el navegador; no se desenrollan ni se lee el contenido del mensaje. Prueba ambas interfaces con correos de prueba antes de demostrar esta función.

## 4. Servidor local y VirusTotal opcional

Desde la terminal de VS Code, en la raíz del proyecto:

```bash
python backend/server.py
```

Al abrir una página o el popup, la extensión consulta automáticamente `127.0.0.1:8765` si el servidor está encendido. El popup muestra primero las reglas locales y luego actualiza el puntaje y el estado de las fuentes. **Reintentar consulta** solo sirve si hubo un fallo. Sin clave, el servidor responde `not_configured` para VirusTotal. Para habilitar una clave propia, define `VT_API_KEY` como variable de entorno **en la terminal del servidor**, nunca en la extensión ni en Git:

- PowerShell: `$env:VT_API_KEY="TU_CLAVE"; python backend/server.py`
- bash: `VT_API_KEY="TU_CLAVE" python backend/server.py`

Se usa el informe existente `GET /api/v3/urls/{id}`; si no existe informe o hay límite de cuota, el resultado se informa como no disponible. Para consultas automáticas, el servidor **elimina usuario, contraseña, parámetros de consulta y fragmento** antes de enviarlo a VirusTotal. Aun así comparte dominio y ruta; evita instalar este prototipo en un perfil con navegación confidencial. Esta normalización puede impedir encontrar un informe de la URL completa si dependía de sus parámetros. Los resultados se guardan en memoria durante 30 minutos y el servidor limita las solicitudes a un máximo de 4 por minuto y 500 al día; alcanzar el límite deja la reputación como no disponible, sin bloquear por ese motivo. La extensión no guarda la clave. La API pública de VirusTotal no está autorizada para productos comerciales; la versión Premium planteada en el BMC requerirá condiciones/licencia apropiadas antes de venderse.

## 5. Modelo de aprendizaje automático

No se incluye un modelo preentrenado sin procedencia. Consigue un CSV autorizado y etiquetado con columnas `url,label`, donde `0` es legítima y `1` phishing. El entrenador admite CSV UTF-8 y exportaciones habituales de Excel (Windows-1252/Latin-1, comas o punto y coma). Colócalo en `dataset/urls.csv` y ejecuta:

```bash
python backend/train.py dataset/urls.csv
```

El script necesita al menos 40 URLs y ambas clases. Entrena una regresión logística sobre atributos de URL sin dependencias externas y separa aproximadamente 20 % de los dominios para prueba, evitando evaluar exactamente los dominios vistos al entrenar. El entrenamiento nuevo añade longitud del dominio, profundidad de subdominios, números en la ruta y estructura de ruta/consulta. **El modelo anterior sigue funcionando sin reentrenar**; estas nuevas características solo se activan al ejecutar de nuevo `train.py` sobre tu CSV. Genera `backend/model.json` y `backend/evaluation.json` con precisión, recall, F1, verdaderos/falsos positivos y negativos. Guarda una copia de `model.json` y mide falsos positivos con un dataset externo antes y después de reentrenar. Reinicia el servidor para cargar el modelo nuevo. No subas datasets ajenos sin licencia ni contraseñas/tokens. TensorFlow puede estudiarse después; no es requisito para este clasificador inicial.

### Evaluación externa PhishStorm

Coloca `urlset.csv` descargado del repositorio original en `dataset/` y ejecuta `python backend/evaluate_phishstorm.py dataset/urlset.csv`. El evaluador lee `domain,label` (0 legítima, 1 phishing), acepta etiquetas numéricas como `0.0`/`1.0` e informa los motivos de omisión de filas. No modifica el modelo ni consulta enlaces. Si una URL no trae esquema, se supone HTTPS y se informa cuántas filas necesitaron esa suposición: sus resultados deben interpretarse con cautela. Los datos originales son de 2014, así que añade una prueba separada con URLs actuales. No incluyas `urlset.csv` en un repositorio sin comprobar primero sus condiciones de uso.

La combinación automática suma 15 puntos si VirusTotal informa una detección maliciosa y 30 si informa dos o más; si no hay detecciones maliciosas pero sí sospechosas, suma 10. **El modelo no añade puntos por sí solo mientras no haya una validación externa aceptable**: su predicción se muestra como referencia en fuentes y detalles. Si VirusTotal informa alguna detección maliciosa o sospechosa, el modelo puede añadir 10 puntos para una salida ≥ 0.8 y 5 para ≥ 0.4. Si las reglas de URL y formularios por sí solas no alcanzan rojo (26 puntos), el resultado combinado queda como máximo en amarillo a menos que VirusTotal informe al menos dos detecciones maliciosas. Dos detecciones tampoco prueban por sí solas que un sitio sea fraudulento: revisa el contexto.

La cifra del modelo es una **puntuación sin calibrar**, no el porcentaje real de probabilidad de phishing. El popup muestra el dominio de la página y la URL completa por separado: el modelo recibe la URL completa, mientras que el servidor consulta en VirusTotal el dominio y la ruta sin parámetros de consulta ni fragmento. Analizar solo `https://www.google.com/` al estar en `/webhp?...` perdería información importante de la ruta de cualquier sitio. Si aparece verde aun con una salida alta del modelo, los detalles explican que la predicción aislada no contó. Cero detecciones de VirusTotal tampoco prueba que una página sea segura. La precisión medida en el CSV de entrenamiento no demuestra la tasa de falsos positivos en Google, LinkedIn o Facebook: pueden existir diferencias entre ese dataset y la navegación real. Valida un conjunto adicional de páginas legítimas y maliciosas ajenas al entrenamiento y ajusta/calibra el modelo antes de subir sus pesos. No se usan listas blancas de dominios, pues una página alojada en una plataforma conocida también puede ser fraudulenta. `0` en reglas locales no equivale a `0` detecciones de VirusTotal.

### Validación externa del modelo

El proyecto incluye `backend/validate_external.py`. Para usarlo, conserva tu `backend/model.json` actual y prepara un CSV **independiente del entrenamiento**, con columnas `url,label` o `domain,label`; `0` indica legítima y `1` phishing. Ejecuta en PowerShell desde la raíz:

```powershell
python backend/validate_external.py dataset/validacion.csv dataset/urls.csv > validacion_resultado.json
```

El segundo CSV es opcional, pero permite avisar si hay dominios comunes con el entrenamiento. El informe muestra TP, FP, TN y FN a umbrales 0.4, 0.5 y 0.8; la tasa de falsos positivos; ejemplos legítimos puntuados ≥ 0.8; y grupos de calibración (salida media del modelo frente a proporción real de phishing). El apartado `independent` calcula las mismas métricas excluyendo dominios presentes en el CSV de entrenamiento; `thresholds` conserva las métricas de todas las URL para comparación. Las alertas se escriben en la terminal para que el archivo de salida sea JSON válido. Si solo aportas la muestra incluida de páginas legítimas, podrás medir falsos positivos, pero **no** sensibilidad ni calibración representativa. No se modifica el modelo al evaluar. Las URL sin esquema en la columna `domain` se interpretan como HTTPS y se cuentan por separado. Nunca presentes como validación externa un conjunto que comparta dominios con el entrenamiento.

## 6. Verificación y límites

Corre `node tests/analyzer.test.js`, `node tests/content.test.js`, `node tests/background.test.js`, `node tests/popup.test.js`, `node tests/mail.test.js` y `python -m unittest discover -s tests -p 'test_*.py'` desde la raíz. Incluyen la escala 0/1–25/26–100, URL largas, alertas, consultas, bloqueo automático simulado y lectura de CSV. Sigue también la guía `PRUEBAS_NAVEGADOR.md` para probarlo realmente en Chrome/Edge. El bloqueo de red necesita un informe existente de VirusTotal con al menos dos detecciones. Las páginas internas, iframes y ciertos enlaces abiertos desde otras aplicaciones quedan fuera del script. El correo y el bloqueo de red necesitan comprobación en el navegador antes de presentarlos como validados.
