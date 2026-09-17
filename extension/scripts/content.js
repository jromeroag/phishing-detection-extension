// Revisa la página automáticamente al abrirse. La advertencia no detiene
// la petición HTTP inicial: actúa cuando el script puede ejecutarse.
let latestPageResult = { score: 0, reasons: [] };
let remoteResult = { score: 0, reasons: [] };
let lastWarnedScore = -1;
let inspected = false;
let remoteFinished = false;
let notificationShown = false;
if (window === window.top) {
  const currentResult = EscudoAnalyzer.analyzeURL(location.href);
  if (currentResult.level === "high") {
    const displayOnArrival = () => showWarning(location.href, currentResult, true);
    if (document.documentElement) displayOnArrival();
    else {
      const observer = new MutationObserver(() => {
        if (document.documentElement) { observer.disconnect(); displayOnArrival(); }
      });
      observer.observe(document, { childList: true });
    }
  }
  const inspect = () => {
    latestPageResult = inspectPage();
    inspected = true;
    updatePageAlert();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", inspect, { once: true });
  else inspect();
  const initialURL = location.href;
  chrome.runtime.sendMessage({ type: "REMOTE_LOOKUP", url: initialURL }, (data) => {
    if (location.href !== initialURL) return;
    if (!chrome.runtime.lastError && data && !data.error) remoteResult = EscudoAnalyzer.scoreRemote(data);
    remoteFinished = true;
    updatePageAlert();
  });
}

function updatePageAlert() {
  if (!inspected) return;
  const local = EscudoAnalyzer.combine(EscudoAnalyzer.analyzeURL(location.href), latestPageResult);
  const final = EscudoAnalyzer.combine(local, remoteResult);
  const unsafePasswordForm = latestPageResult.reasons.some((reason) => reason.includes("HTTP sin cifrado"));
  if (final.level === "high" && (local.level === "high" || !remoteResult.needsCorroboration)) {
    if (final.score > lastWarnedScore) showWarning(location.href, final, true);
    return;
  }
  if (unsafePasswordForm && final.score > lastWarnedScore) {
    showWarning(location.href, final, true);
    return;
  }
  // Esperar ambas fuentes evita mostrar verde justo antes de recibir un resultado rojo.
  if (!remoteFinished || notificationShown || lastWarnedScore >= 0) return;
  if (final.level === "medium" && final.reasons.length) {
    notificationShown = true;
    showWarning(location.href, final, true);
  } else if (final.level === "low") {
    notificationShown = true;
    showWarning(location.href, final, true);
  }
}

// Se revisa la estructura del formulario, nunca los valores escritos.
function inspectPage() {
  let score = 0;
  const reasons = [];
  const forms = [...document.querySelectorAll("form")].filter((form) => form.querySelector('input[type="password"]'));
  if (forms.length && location.protocol === "http:") {
    score += 25;
    reasons.push("La página pide contraseña mediante HTTP sin cifrado.");
  }
  if (forms.some((form) => {
    try { return new URL(form.action || location.href, location.href).origin !== location.origin; }
    catch { return false; }
  })) {
    score += 15;
    reasons.push("Un formulario de contraseña envía datos a otro origen; comprueba el destino.");
  }
  return { score, reasons };
}
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PAGE_SIGNALS") sendResponse(latestPageResult);
});

// Al hacer clic en un enlace rojo, detiene el clic antes de navegar.
// Los indicios amarillos se consultan en el popup sin interrumpir la página.
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
  style.textContent = ":host{all:initial} .shade{position:fixed;inset:0;background:#101b2acc;display:grid;place-items:center;padding:20px;font:16px/1.5 system-ui,Arial,sans-serif}.box{width:min(100%,480px);background:white;color:#192437;border-radius:18px;padding:26px;box-shadow:0 20px 70px #0006}.heading{display:flex;align-items:center;gap:16px}.status-icon{width:72px;height:72px;flex:none}.box h2{color:#b42828;margin:0 0 8px}.box.medium h2{color:#a56b00}.heading p{margin:0}.address{overflow-wrap:anywhere;background:#f3f5f7;padding:10px;border-radius:8px}button{cursor:pointer;border:0;border-radius:8px;padding:11px 15px;font:inherit}#back{background:#183960;color:#fff}#continue{background:#fff1d0;color:#5b4200}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.small{font-size:12px;color:#556}";
  style.textContent += ".shade.low{background:transparent;display:block;pointer-events:none}.shade.high{background:#b61b24}.box.low{position:fixed;right:18px;top:18px;width:min(350px,calc(100vw - 76px));padding:16px;pointer-events:auto;border:1px solid #a5ddba}.box.low .status-icon{width:48px;height:48px}.box.low h2{color:#087a45}.box.high{box-shadow:none}.high #back{background:#b61b24}.low #continue{background:#13844b;color:white}.close{float:right;background:transparent;padding:0 5px}";
  const shade = document.createElement("div"); shade.className = "shade";
  const box = document.createElement("div"); box.className = "box " + result.level; box.setAttribute("role", "alertdialog"); box.setAttribute("aria-modal", "true");
  if (isLow) box.setAttribute("aria-modal", "false");
  const heading = document.createElement("h2"); heading.textContent = result.level === "high" ? (onArrival ? "Sitio con riesgo alto" : "Enlace de riesgo alto bloqueado") : result.level === "medium" ? "Sitio con riesgo medio" : "Sin señales evidentes";
  const explanation = document.createElement("p"); explanation.textContent = result.level === "high" ? "Se observaron las siguientes señales en el análisis disponible:" : result.level === "medium" ? "Revisa estas señales antes de continuar:" : "No se observaron señales en las fuentes disponibles. Esto no garantiza que la página sea segura.";
  // SVG dentro de la alerta: permanece visible aunque la página limite imágenes externas.
  const ns = "http://www.w3.org/2000/svg";
  const statusIcon = document.createElementNS(ns, "svg");
  statusIcon.setAttribute("class", "status-icon");
  statusIcon.setAttribute("viewBox", "0 0 96 96");
  statusIcon.setAttribute("aria-hidden", "true");
  const emblem = document.createElementNS(ns, "path");
  emblem.setAttribute("d", result.level === "high" ? "M29 4h38l25 25v38L67 92H29L4 67V29z" : result.level === "medium" ? "M41 12a8 8 0 0 1 14 0l39 66a9 9 0 0 1-8 14H10a9 9 0 0 1-8-14z" : "M48 2a46 46 0 1 1 0 92a46 46 0 0 1 0-92z");
  emblem.setAttribute("fill", result.level === "high" ? "#cf2032" : result.level === "medium" ? "#f2ad00" : "#13844b");
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
  const wording = document.createElement("div"); wording.append(heading, explanation); banner.append(statusIcon, wording);
  const address = document.createElement("p"); address.className = "address"; address.textContent = destination;
  const list = document.createElement("ul"); result.reasons.forEach((reason) => { const li = document.createElement("li"); li.textContent = reason; list.append(li); });
  const actions = document.createElement("div"); actions.className = "actions";
  const back = document.createElement("button"); back.id = "back"; back.textContent = onArrival ? "Volver a un sitio seguro" : "Volver"; back.addEventListener("click", () => {
    if (!onArrival) { host.remove(); return; }
    if (window.history?.length > 1) window.history.back();
    else window.location.replace("about:blank");
  });
  if (!isLow) actions.append(back);
  const proceed = document.createElement("button"); proceed.id = "continue";
  proceed.textContent = isLow ? "Entendido, continuar" : "Continuar";
  proceed.addEventListener("click", () => { if (onArrival) host.remove(); else window.location.assign(destination); });
  if (result.level !== "high") actions.append(proceed);
  const limitation = document.createElement("p"); limitation.className = "small"; limitation.textContent = "Las señales son orientativas; comprueba el dominio antes de introducir datos.";
  if (result.level !== "high") {
    const close = document.createElement("button"); close.className = "close"; close.textContent = "×"; close.setAttribute("aria-label", "Cerrar aviso"); close.addEventListener("click", () => host.remove()); box.append(close);
  }
  box.append(banner);
  if (!isLow) box.append(address, list);
  box.append(actions);
  if (!isLow) box.append(limitation);
  shade.className = "shade " + result.level; shade.append(box); shadow.append(style, shade);
  (document.documentElement || document).append(host);
  if (isLow) setTimeout(() => host.remove(), 5000);
  else back.focus();
}
