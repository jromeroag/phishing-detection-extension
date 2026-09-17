# Pruebas en Chrome o Edge — versión 0.9.0

Antes de empezar, guarda una copia de `backend/model.json` y de tu CSV. Abre la carpeta en VS Code, ejecuta `python backend/server.py`, reemplaza los archivos de `extension/` y pulsa **Actualizar** en `chrome://extensions`. Recarga las pestañas abiertas. Para verificar VirusTotal, inicia el servidor con `VT_API_KEY` en el entorno como explica el README.

| Caso | Pasos | Resultado esperado |
| --- | --- | --- |
| Verde | Navega a `https://www.google.com/` y abre el popup | 0 si las fuentes disponibles no dan señales; aviso verde breve en la página. Anota el estado de VirusTotal y del modelo. |
| URL larga legítima | Navega a una URL larga de una plataforma conocida que uses | La longitud sola no genera amarillo. |
| Amarillo local | En el popup pega `https://a-b-c-login.example/` | 20/100. Es un dominio reservado: no hay que abrirlo. |
| Rojo por enlace local | Crea una página de prueba en `http://127.0.0.1:8000/` con un enlace a `https://usuario@login-verificar.example/` y púlsalo | Se cancela el clic, aparece la alerta roja con el motivo de `@`, sin opción de continuar; **Volver** mantiene la página origen. No se visita el dominio de prueba. |
| Regreso de página roja | Con historial previo, navega a una URL que efectivamente dé resultado rojo según las fuentes disponibles y pulsa **Volver a un sitio seguro** | Regresa a la página anterior; esa página anterior no queda validada automáticamente. |
| VirusTotal sin informe | Analiza una URL que no tenga reporte | Muestra «sin informe»; nunca se convierte en rojo por la ausencia de informe. |
| Servidor apagado | Detén `server.py`, abre una URL normal y el popup | Continúa el análisis local y se indica que el servidor no está disponible. |
| Bloqueo automático confirmado | Con el servidor y la clave activos, consulta una URL **de prueba autorizada** cuyo informe ya tenga ≥2 detecciones maliciosas; vuelve a abrir exactamente esa URL | La primera consulta muestra aviso rojo después de iniciar la navegación; la segunda navegación se redirige a la página roja de bloqueo. Una ruta o consulta distinta no se bloquea por esa regla. No uses sitios reales ni introduzcas credenciales. |
| Quitar reglas | En detalles del popup pulsa **Quitar bloqueos de URLs detectadas** | Se eliminan las reglas creadas por la extensión y las de versiones anteriores. |
| Correo | Envía un mensaje de prueba con enlaces benignos y URLs `.example` a Gmail web y Outlook web | Comprueba que un enlace rojo muestra tarjeta dentro del mensaje, que Ver detalles enseña URL y motivos reales, y que pulsar el enlace no lo abre. Comprueba que un correo sin enlaces rojos no muestra tarjeta y el resto sigue utilizable. |

En modo desarrollador, Chrome ofrece `chrome.declarativeNetRequest.testMatchOutcome()` para comprobar si una regla recién instalada coincide con una URL de prueba. El botón de bloqueo automático no necesita un clic manual; solo puede activarse tras una respuesta de reputación con las detecciones exigidas. Guarda captura de las alertas, las razones y la salida del evaluador externo para presentar resultados verificables.
