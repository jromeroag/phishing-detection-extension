// Este archivo no contiene secretos. El script de despliegue actualiza únicamente
// la dirección pública de Cloud Run. El valor inicial conserva el modo local.
globalThis.ESCUDO_CONFIG = Object.freeze({
  API_BASE_URL: "http://127.0.0.1:8765"
});
