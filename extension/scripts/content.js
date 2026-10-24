// Revisa la página automáticamente al abrirse. La advertencia no detiene
// la petición HTTP inicial: actúa cuando el script puede ejecutarse.
let latestPageResult = { score: 0, reasons: [], evidence: [] };
let remoteResult = { score: 0, reasons: [], evidence: [] };
let lastWarnedScore = -1;
let inspected = false;
let remoteFinished = false;
let notificationShown = false;
let analyzedURL = "";
let analysisGeneration = 0;
if (window === window.top) {
  analyzeCurrentPage();
  // popstate/hashchange cubren Atrás, Adelante y cambios de fragmento. El
  // comprobador también detecta history.pushState/replaceState usado por SPA,
  // que no genera esos eventos en el mundo aislado de una extensión.
  window.addEventListener("popstate", checkForNavigation);
  window.addEventListener("hashchange", checkForNavigation);
  setInterval(checkForNavigation, 500);
}

function checkForNavigation() {
  if (location.href !== analyzedURL) analyzeCurrentPage();
}

function analyzeCurrentPage() {
  const requestedURL = location.href;
  if (requestedURL === analyzedURL) return;
  analyzedURL = requestedURL;
  const generation = ++analysisGeneration;
  latestPageResult = { score: 0, reasons: [], evidence: [] };
  remoteResult = { score: 0, reasons: [], evidence: [] };
  lastWarnedScore = -1;
  inspected = false;
  remoteFinished = false;
  notificationShown = false;
  document.getElementById("escudo-warning-root")?.remove();

  const stillCurrent = () => generation === analysisGeneration &&
    requestedURL === analyzedURL && location.href === requestedURL;
  const currentResult = EscudoAnalyzer.analyzeURL(requestedURL);
  if (currentResult.level === "high") {
    const displayOnArrival = () => {
      if (stillCurrent()) showWarning(requestedURL, currentResult, true);
    };
    if (document.documentElement) displayOnArrival();
    else {
      const observer = new MutationObserver(() => {
        if (!stillCurrent()) { observer.disconnect(); return; }
        if (document.documentElement) { observer.disconnect(); displayOnArrival(); }
      });
      observer.observe(document, { childList: true });
    }
  }
  const inspect = () => {
    if (!stillCurrent()) return;
    latestPageResult = inspectPage();
    inspected = true;
    updatePageAlert(requestedURL, generation);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", inspect, { once: true });
  else inspect();
  chrome.runtime.sendMessage({ type: "REMOTE_LOOKUP", url: requestedURL }, (data) => {
    // Una respuesta de una URL anterior nunca actualiza ni alerta la página
    // actual, aunque termine después que la consulta más reciente.
    if (!stillCurrent()) return;
    if (!chrome.runtime.lastError && data && !data.error) remoteResult = EscudoAnalyzer.scoreRemote(data);
    remoteFinished = true;
    updatePageAlert(requestedURL, generation);
  });
}

function updatePageAlert(expectedURL = analyzedURL, expectedGeneration = analysisGeneration) {
  if (!inspected || expectedGeneration !== analysisGeneration ||
      expectedURL !== analyzedURL || location.href !== expectedURL) return;
  const local = EscudoAnalyzer.combine(EscudoAnalyzer.analyzeURL(expectedURL), latestPageResult);
  const final = EscudoAnalyzer.combine(local, remoteResult);
  const unsafePasswordForm = latestPageResult.evidence?.some((item) => item.id === "HTTP_PASSWORD_FORM") ||
    latestPageResult.reasons.some((reason) => reason.includes("HTTP sin cifrado"));
  if (final.level === "high" && (local.level === "high" || !remoteResult.needsCorroboration)) {
    if (final.score > lastWarnedScore) showWarning(expectedURL, final, true);
    return;
  }
  if (unsafePasswordForm && final.score > lastWarnedScore) {
    showWarning(expectedURL, final, true);
    return;
  }
  // Esperar ambas fuentes evita mostrar verde justo antes de recibir un resultado rojo.
  if (!remoteFinished || notificationShown || lastWarnedScore >= 0) return;
  if (final.level === "medium" && final.reasons.length) {
    notificationShown = true;
    showWarning(expectedURL, final, true);
  } else if (final.level === "low") {
    notificationShown = true;
    showWarning(expectedURL, final, true);
  }
}

// Se revisa la estructura del formulario, nunca los valores escritos.
function inspectPage() {
  let score = 0;
  const evidence = [];
  const forms = [...document.querySelectorAll("form")].filter((form) => form.querySelector('input[type="password"]'));
  if (forms.length && location.protocol === "http:") {
    score += 25;
    evidence.push(EscudoAnalyzer.createEvidence("HTTP_PASSWORD_FORM", {
      description: "La página pide contraseña mediante HTTP sin cifrado.",
      observedValue: forms.length + " formulario(s) sobre HTTP", threshold: "HTTPS",
      scoreContribution: 25, severity: "high", contributesToDecision: true
    }));
  }
  if (forms.some((form) => {
    try { return new URL(form.action || location.href, location.href).origin !== location.origin; }
    catch { return false; }
  })) {
    score += 15;
    evidence.push(EscudoAnalyzer.createEvidence("CROSS_ORIGIN_FORM", {
      description: "Un formulario de contraseña envía datos a otro origen; comprueba el destino.",
      observedValue: "Origen diferente", threshold: "Mismo origen",
      scoreContribution: 15, severity: "medium", contributesToDecision: true
    }));
  }
  return { score, evidence, reasons: evidence.map((item) => item.description) };
}
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PAGE_SIGNALS") sendResponse(latestPageResult);
});

// Al hacer clic en un enlace rojo, detiene el clic antes de navegar.
// Los indicios preventivos se muestran en rojo, pero solo el riesgo alto
// detiene el clic. Así una señal débil no bloquea por sí sola.
document.addEventListener("click", (event) => {
  const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
  if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || link.hasAttribute("download")) return;
  const result = EscudoAnalyzer.analyzeURL(link.href);
  if (result.level !== "high") return;
  event.preventDefault();
  event.stopImmediatePropagation();
  showWarning(link.href, result, false);
}, true);

function showWarning(destination, result, onArrival) {
  if (onArrival && result.level === "high") lastWarnedScore = result.score;
  const prior = document.getElementById("escudo-warning-root");
  if (prior) prior.remove();
  const host = document.createElement("div");
  host.id = "escudo-warning-root";
  const isLow = result.level === "low";
  host.style.cssText = "position:fixed!important;inset:0!important;z-index:2147483647!important;pointer-events:" + (isLow ? "none" : "auto") + "!important";
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = ":host{all:initial} .shade{position:fixed;inset:0;background:#101b2acc;display:grid;place-items:center;padding:20px;font:16px/1.5 system-ui,Arial,sans-serif}.box{width:min(100%,480px);background:white;color:#192437;border-radius:18px;padding:26px;box-shadow:0 20px 70px #0006}.heading{display:flex;align-items:center;gap:16px}.status-icon{width:72px;height:72px;flex:none}.box h2{color:#b42828;margin:0 0 8px}.box h3{font-size:16px;margin:16px 0 6px}.heading p{margin:0}.address{overflow-wrap:anywhere;background:#f3f5f7;padding:10px;border-radius:8px}.recommendations{background:#fff3f3;border-left:4px solid #cf2032;border-radius:8px;padding:10px 14px}.recommendations ul{margin:6px 0;padding-left:20px}button{cursor:pointer;border:0;border-radius:8px;padding:11px 15px;font:inherit}#back{background:#183960;color:#fff}#continue{background:#fff;color:#9f1725;border:1px solid #c92a38}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.small{font-size:12px;color:#556}";
  style.textContent += ".shade.low{background:transparent;display:block;pointer-events:none}.shade.medium{background:#7d1018cc}.shade.high{background:#b61b24}.box.low{position:fixed;right:18px;top:18px;width:min(350px,calc(100vw - 76px));padding:16px;pointer-events:auto;border:1px solid #a5ddba}.box.low .status-icon{width:48px;height:48px}.box.low h2{color:#087a45}.box.medium{background:#fff5f6;border:2px solid #d52a39}.box.medium #back{background:#b61b24;color:#fff}.box.medium #continue{background:#fff;color:#9f1725;border:1px solid #c92a38;font-weight:700}.box.high{box-shadow:none}.high #back{background:#b61b24}.low #continue{background:#13844b;color:white}.risk-label{display:inline-block;margin:0 0 5px;padding:3px 10px;border-radius:999px;font-size:13px;font-weight:700}.risk-label.low{background:#d9f5e2;color:#087a45}.risk-label.medium,.risk-label.high{background:#ffd7dc;color:#a61a2a}.close{float:right;background:transparent;padding:0 5px}";
  const shade = document.createElement("div"); shade.className = "shade";
  const box = document.createElement("div"); box.className = "box " + result.level; box.setAttribute("role", "alertdialog"); box.setAttribute("aria-modal", "true");
  if (isLow) box.setAttribute("aria-modal", "false");
  const riskLabel = document.createElement("span"); riskLabel.className = "risk-label " + result.level;
  riskLabel.textContent = result.level === "low" ? "Verde" : "Rojo";
  const heading = document.createElement("h2"); heading.textContent = result.level === "high" ? (onArrival ? "Sitio con riesgo alto" : "Enlace de riesgo alto bloqueado") : result.level === "medium" ? "Riesgo detectado" : "Sin señales evidentes";
  const explanation = document.createElement("p"); explanation.textContent = result.level === "high" ? "Se encontraron evidencias suficientes para aplicar un bloqueo preventivo:" : result.level === "medium" ? "Se encontró una señal sospechosa. Revisa la información antes de decidir si continúas:" : "No se observaron señales en las fuentes disponibles. Esto no garantiza que la página sea segura.";
  // SVG dentro de la alerta: permanece visible aunque la página limite imágenes externas.
  const ns = "http://www.w3.org/2000/svg";
  const statusIcon = document.createElementNS(ns, "svg");
  statusIcon.setAttribute("class", "status-icon");
  statusIcon.setAttribute("viewBox", "0 0 96 96");
  statusIcon.setAttribute("aria-hidden", "true");
  const emblem = document.createElementNS(ns, "path");
  emblem.setAttribute("d", result.level === "low" ? "M48 2a46 46 0 1 1 0 92a46 46 0 0 1 0-92z" : "M29 4h38l25 25v38L67 92H29L4 67V29z");
  emblem.setAttribute("fill", result.level === "low" ? "#13844b" : "#cf2032");
  const mark = document.createElementNS(ns, "path");
  mark.setAttribute("d", isLow ? "M23 48l16 16 34-36" : result.level === "high" ? "M48 26v34" : "M48 36v28");
  mark.setAttribute("fill", "none");
  mark.setAttribute("stroke", "#fff");
  mark.setAttribute("stroke-width", "9");
  mark.setAttribute("stroke-linecap", "round");
  const dot = document.createElementNS(ns, "circle");
  dot.setAttribute("cx", "48"); dot.setAttribute("cy", result.level === "high" ? "73" : "75");
  dot.setAttribute("r", "5"); dot.setAttribute("fill", "#fff");
  statusIcon.append(emblem, mark);
  if (!isLow) statusIcon.append(dot);
  const banner = document.createElement("div"); banner.className = "heading";
  const wording = document.createElement("div"); wording.append(riskLabel, heading, explanation); banner.append(statusIcon, wording);
  const address = document.createElement("p"); address.className = "address"; address.textContent = destination;
  const sourceNames = { url: "URL", page: "Página", model: "Modelo", virustotal: "VirusTotal" };
  const list = document.createElement("ul");
  (result.evidence || result.reasons.map((description) => ({ description }))).forEach((item) => {
    const li = document.createElement("li");
    const contribution = item.contributesToDecision ? " (" + (item.scoreContribution > 0 ? "+" : "") + item.scoreContribution + " puntos)" : " (informativa)";
    li.textContent = item.description + (item.source ? " Fuente: " + (sourceNames[item.source] || item.source) + contribution : "");
    list.append(li);
  });
  const recommendations = document.createElement("section"); recommendations.className = "recommendations";
  const recommendationsTitle = document.createElement("h3"); recommendationsTitle.textContent = "Recomendaciones";
  const recommendationsList = document.createElement("ul");
  [
    "No introduzcas contraseñas, códigos ni datos bancarios.",
    "Sal de esta página y entra al servicio escribiendo su dirección oficial.",
    "Si ya compartiste datos, cambia tu contraseña y contacta a la entidad."
  ].forEach((recommendation) => { const li = document.createElement("li"); li.textContent = recommendation; recommendationsList.append(li); });
  recommendations.append(recommendationsTitle, recommendationsList);
  const actions = document.createElement("div"); actions.className = "actions";
  const back = document.createElement("button"); back.id = "back"; back.textContent = onArrival ? "Volver a un sitio seguro" : "Volver"; back.addEventListener("click", () => {
    if (!onArrival) { host.remove(); return; }
    if (window.history?.length > 1) window.history.back();
    else window.location.replace("about:blank");
  });
  if (!isLow) actions.append(back);
  const proceed = document.createElement("button"); proceed.id = "continue";
  proceed.textContent = isLow ? "Entendido, continuar" : "Continuar bajo mi responsabilidad";
  proceed.addEventListener("click", () => { if (onArrival) host.remove(); else window.location.assign(destination); });
  if (result.level !== "high") actions.append(proceed);
  const limitation = document.createElement("p"); limitation.className = "small"; limitation.textContent = "Las señales son orientativas; comprueba el dominio antes de introducir datos.";
  if (result.level !== "high") {
    const close = document.createElement("button"); close.className = "close"; close.textContent = "×"; close.setAttribute("aria-label", "Cerrar aviso"); close.addEventListener("click", () => host.remove()); box.append(close);
  }
  box.append(banner);
  if (!isLow) box.append(address, list);
  if (result.level === "high") box.append(recommendations);
  box.append(actions);
  if (!isLow) box.append(limitation);
  shade.className = "shade " + result.level; shade.append(box); shadow.append(style, shade);
  (document.documentElement || document).append(host);
  if (isLow) setTimeout(() => host.remove(), 5000);
  else back.focus();
}
