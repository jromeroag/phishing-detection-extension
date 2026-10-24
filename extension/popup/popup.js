const $ = (id) => document.getElementById(id);
let tabURL = "";
let tabId = null;
let selectedURL = "";
let pageSignals = null;
let remoteData = null;
const presentation = {
  low: { badge: "Verde", title: "Sin señales evidentes", description: "Sin indicios en las reglas y reportes disponibles.", icon: "status-green.svg" },
  medium: { badge: "Rojo", title: "Riesgo detectado", description: "Se encontró una señal sospechosa; revisa el dominio antes de continuar.", icon: "status-red.svg" },
  high: { badge: "Rojo", title: "Enlace sospechoso", description: "Evita abrir el enlace e introducir tus datos.", icon: "status-red.svg" },
  unknown: { badge: "Sin análisis", title: "Página no analizable", description: "Introduce una URL HTTP o HTTPS.", icon: "escudo-48.png" }
};
const sourceNames = { url: "Reglas de URL", page: "Inspección de la página", model: "Modelo", virustotal: "VirusTotal", unknown: "No disponible" };
function evidenceCard(item) {
  const card = document.createElement("article");
  card.className = "evidence-card " + (item.severity || "info");
  const source = sourceNames[item.source] || item.source || "No especificada";
  const observed = item.observedValue !== null && item.observedValue !== undefined ? "\nValor observado: " + item.observedValue : "";
  const contribution = item.contributesToDecision
    ? "Aporte al resultado: " + (item.scoreContribution > 0 ? "+" : "") + item.scoreContribution + " puntos"
    : "Aporte al resultado: informativa (0 puntos)";
  card.textContent = item.title + "\n" + item.description + "\nFuente: " + source + observed + "\n" + contribution;
  return card;
}
function compactEvidenceCard(item) {
  const card = document.createElement("article");
  card.className = "compact-evidence " + (item.severity || "info");
  const source = sourceNames[item.source] || item.source || "No especificada";
  const contribution = item.contributesToDecision
    ? (item.scoreContribution > 0 ? "+" : "") + item.scoreContribution + " puntos"
    : "Informativa · 0 puntos";
  card.textContent = item.title + "\n" + item.description + "\n" + source + " · " + contribution;
  return card;
}
function sourceDescription() {
  if (!remoteData) return "Consultando fuentes disponibles…";
  const reputation = remoteData.reputation;
  const bits = [];
  if (reputation?.status === "found") bits.push("VirusTotal: " + reputation.malicious + " maliciosas y " + reputation.suspicious + " sospechosas, " + reputation.total + " resultados (ruta sin parámetros)");
  else if (reputation?.status === "not_found") bits.push("VirusTotal: sin informe para la URL consultada");
  else if (reputation?.status === "rate_limited") bits.push("VirusTotal: cuota temporal alcanzada");
  else if (reputation?.status === "not_configured") bits.push("VirusTotal: clave sin configurar");
  else bits.push("VirusTotal: no disponible");
  const independentFinding = reputation?.status === "found" && (reputation.malicious > 0 || reputation.suspicious > 0);
  bits.push(remoteData.model ? "Modelo: salida " + Math.round(remoteData.model.probability * 100) + "/100 (sin calibrar" + (independentFinding ? "" : "; no puntúa por sí sola") + ")" : "Modelo: sin entrenar");
  return bits.join(" · ");
}
function render() {
  const urlResult = EscudoAnalyzer.analyzeURL(selectedURL);
  const local = EscudoAnalyzer.combine(urlResult, pageSignals);
  const remote = EscudoAnalyzer.scoreRemote(remoteData);
  const result = EscudoAnalyzer.combine(local, remote);
  const view = presentation[result.level];
  $("result").className = "risk " + result.level;
  $("symbol").src = "../icons/" + view.icon;
  $("badge").textContent = view.badge;
  $("status").textContent = view.title;
  $("summary").textContent = view.description;
  $("score").textContent = result.level === "unknown" ? "Sin puntaje" : result.score + "/100";
  $("domain").textContent = result.level === "unknown" ? "No disponible" : new URL(selectedURL).hostname;
  $("detail-domain").textContent = $("domain").textContent;
  $("url").textContent = selectedURL || "Sin URL disponible";
  $("detail-url").textContent = selectedURL || "Sin URL disponible";
  $("detail-score").textContent = $("score").textContent;
  $("source").textContent = "URL" + (pageSignals?.score ? ", formularios" : "") + (remoteData?.model ? ", modelo" : "") + (remoteData?.reputation?.status === "found" ? ", VirusTotal" : "");
  $("source-status").textContent = sourceDescription();
  $("remote-status").textContent = sourceDescription();
  const evidence = result.evidence || result.reasons.map((description) => ({
    title: "Señal observada", description, source: "unknown", severity: "info",
    scoreContribution: 0, contributesToDecision: false
  }));
  const primaryEvidence = [...evidence].sort((a, b) =>
    Number(b.contributesToDecision) - Number(a.contributesToDecision) ||
    (b.scoreContribution || 0) - (a.scoreContribution || 0)).slice(0, 2);
  $("overview-evidence").replaceChildren(...primaryEvidence.map(compactEvidenceCard));
  $("reasons").replaceChildren(...evidence.map(evidenceCard));
}
function analyzeAutomatically() {
  const requested = selectedURL;
  remoteData = null;
  render();
  if (EscudoAnalyzer.analyzeURL(requested).level === "unknown") return;
  chrome.runtime.sendMessage({ type: "REMOTE_LOOKUP", url: requested }, (data) => {
    if (selectedURL !== requested) return;
    if (chrome.runtime.lastError || !data || data.error) {
      $("source-status").textContent = "Servidor local no disponible; resultado basado en reglas locales.";
      $("remote-status").textContent = $("source-status").textContent;
      return;
    }
    remoteData = data;
    render();
  });
}
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  tabURL = tabs?.[0]?.url || "";
  tabId = tabs?.[0]?.id ?? null;
  selectedURL = tabURL;
  render();
  analyzeAutomatically();
  if (tabId !== null) chrome.tabs.sendMessage(tabId, { type: "PAGE_SIGNALS" }, (signals) => {
    if (!chrome.runtime.lastError && selectedURL === tabURL && signals) { pageSignals = signals; render(); }
  });
});
$("check-form").addEventListener("submit", (event) => {
  event.preventDefault();
  pageSignals = null;
  selectedURL = $("candidate").value.trim();
  analyzeAutomatically();
});
$("current").addEventListener("click", () => {
  $("candidate").value = "";
  selectedURL = tabURL;
  pageSignals = null;
  analyzeAutomatically();
  if (tabId !== null) chrome.tabs.sendMessage(tabId, { type: "PAGE_SIGNALS" }, (signals) => {
    if (!chrome.runtime.lastError && selectedURL === tabURL && signals) { pageSignals = signals; render(); }
  });
});
$("show-details").addEventListener("click", () => { $("overview").hidden = true; $("diagnosis").hidden = false; $("back").focus(); });
$("back").addEventListener("click", () => { $("diagnosis").hidden = true; $("overview").hidden = false; $("show-details").focus(); });
$("remote").addEventListener("click", analyzeAutomatically);
$("clear-blocks").addEventListener("click", async () => {
  try {
    const [session, dynamic] = await Promise.all([
      chrome.declarativeNetRequest.getSessionRules(), chrome.declarativeNetRequest.getDynamicRules()
    ]);
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: session.map((rule) => rule.id) });
    // Limpia también bloqueos persistentes de versiones anteriores.
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: dynamic.map((rule) => rule.id) });
    $("remote-status").textContent = "Bloqueos eliminados: " + (session.length + dynamic.length) + ".";
  } catch { $("remote-status").textContent = "No se pudieron quitar los bloqueos."; }
});
