// La URL del backend se mantiene en config.js; nunca se guarda aquí una API key.
// Los bloqueos automáticos son de sesión y se aplican a futuras navegaciones.
if (typeof importScripts === "function") {
  importScripts(
    chrome.runtime.getURL("config.js"),
    chrome.runtime.getURL("services/analyzer.js")
  );
}
const API_BASE_URL = globalThis.ESCUDO_CONFIG?.API_BASE_URL || "http://127.0.0.1:8765";

function analysisEndpoint(rawURL) {
  const base = API_BASE_URL.endsWith("/") ? API_BASE_URL : API_BASE_URL + "/";
  const endpoint = new URL("analyze", base);
  endpoint.searchParams.set("url", rawURL);
  return endpoint.href;
}

let ruleQueue = Promise.resolve();
function exactRule(url, id) {
  const target = new URL(url);
  target.hash = "";
  if (!["http:", "https:"].includes(target.protocol) || target.href.length > 1024) return null;
  const escaped = target.href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return { id, priority: 1, action: { type: "redirect", redirect: { extensionPath: "/pages/blocked.html" } },
    condition: { regexFilter: "^" + escaped + "$", resourceTypes: ["main_frame"] } };
}
function recordVerifiedURL(url) {
  const job = ruleQueue.then(async () => {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const candidate = exactRule(url, 1);
    if (!candidate || rules.some((rule) => rule.condition.regexFilter === candidate.condition.regexFilter) || rules.length >= 100) return;
    candidate.id = Math.max(0, ...rules.map((rule) => rule.id)) + 1;
    await chrome.declarativeNetRequest.updateSessionRules({ addRules: [candidate] });
  });
  ruleQueue = job.catch(() => {});
  return job;
}
function hasStrongExternalFinding(data) {
  const virustotal = data?.reputation?.status === "found" && data.reputation.malicious >= 2;
  const google = data?.google_safe_browsing?.status === "match";
  const phishtank = data?.phishtank?.status === "found" &&
    data.phishtank.in_database && data.phishtank.verified && data.phishtank.valid;
  const ipqs = data?.ipqualityscore?.status === "found" && (
    data.ipqualityscore.phishing || data.ipqualityscore.malware ||
    (data.ipqualityscore.unsafe && data.ipqualityscore.risk_score >= 85)
  );
  return virustotal || google || phishtank || ipqs;
}
function shouldBlockURL(url, data) {
  // El mismo criterio se usa en el popup y en la página: una señal fuerte
  // o dos señales activas producen rojo crítico. El respaldo conserva el
  // bloqueo de coincidencias fuertes si el analizador no pudiera cargarse.
  if (!globalThis.EscudoAnalyzer) return hasStrongExternalFinding(data);
  const local = globalThis.EscudoAnalyzer.analyzeURL(url);
  const remote = globalThis.EscudoAnalyzer.scoreRemote(data);
  return globalThis.EscudoAnalyzer.combine(local, remote).level === "high";
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "REMOTE_LOOKUP") return;
  try {
    const url = new URL(message.url);
    if (!["http:", "https:"].includes(url.protocol) || message.url.length > 2048) {
      sendResponse({ error: "URL no válida" }); return;
    }
    fetch(analysisEndpoint(message.url), {
      signal: AbortSignal.timeout(10000)
    }).then(async (response) => {
      if (!response.ok) throw new Error("HTTP " + response.status);
      const data = await response.json();
      if (shouldBlockURL(message.url, data)) {
        try { await recordVerifiedURL(message.url); }
        catch { /* La alerta de la página aún puede mostrarse sin bloqueo de red. */ }
      }
      sendResponse(data);
    }).catch(() => sendResponse({ error: "Servicio de análisis no disponible" }));
  } catch { sendResponse({ error: "URL no válida" }); }
  return true;
});
