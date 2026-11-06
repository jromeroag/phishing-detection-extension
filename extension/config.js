// Este archivo no contiene secretos. El script de despliegue actualiza únicamente
// la dirección pública de Cloud Run. El valor inicial conserva el modo local.
globalThis.ESCUDO_CONFIG = Object.freeze({
  API_BASE_URL: "https://phishing-detection-extension-ax0o.onrender.com"
});
