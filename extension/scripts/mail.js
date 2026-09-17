// Los avisos se insertan en el cuerpo del mensaje; solo se evalúan los enlaces.
let scheduled = false;
let remoteBudget = 4;
let lastViewURL = location.href;
const pending = new Map();
const results = new WeakMap();

function messageBody(link) {
  return link.closest(location.hostname === "mail.google.com" ? ".a3s" : '[role="main"]');
}

function setBadge(link, href, result, remoteStatus) {
  if (!link.isConnected || link.href !== href) return;
  const prior = link.nextElementSibling;
  if (prior?.classList.contains("escudo-mail-label")) prior.remove();
  results.set(link, result);
  if (result.level !== "medium" && result.level !== "high") { updateMessagePanel(link); return; }
  const badge = document.createElement("span");
  badge.className = "escudo-mail-label";
  badge.textContent = result.level === "high" ? " ⛔ Enlace sospechoso" : " ⚠ Revisar enlace";
  badge.title = result.reasons.join(" ") + (remoteStatus ? " Fuentes: " + remoteStatus : " Análisis local de URL.");
  badge.style.cssText = "display:inline-block;margin-left:4px;padding:2px 5px;border-radius:4px;background:" +
    (result.level === "high" ? "#ffe4e5;color:#9a1620" : "#fff3d5;color:#755000") + ";font:12px system-ui";
  link.after(badge);
  updateMessagePanel(link);
}

function updateMessagePanel(link) {
  const body = messageBody(link);
  if (!body) return;
  const links = [...body.querySelectorAll("a[href]")];
  const risk = links.map((item) => ({ link: item, result: results.get(item) }))
    .filter((item) => item.result?.level === "high")
    .sort((a, b) => b.result.score - a.result.score)[0];
  let panel = [...body.children].find((item) => item.classList?.contains("escudo-mail-panel"));
  if (!risk) { panel?.remove(); return; }
  if (panel?.dataset.escudoHref === risk.link.href && panel.dataset.escudoScore === String(risk.result.score) && panel.dataset.escudoReasons === risk.result.reasons.join("|")) return;
  panel?.remove();
  panel = document.createElement("section");
  panel.className = "escudo-mail-panel";
  panel.dataset.escudoHref = risk.link.href;
  panel.dataset.escudoScore = String(risk.result.score);
  panel.dataset.escudoReasons = risk.result.reasons.join("|");
  panel.setAttribute("role", "alert");
  // El DOM del correo no es de confianza: todo texto externo se escribe como texto.
  const icon = document.createElement("span"); icon.className = "escudo-mail-icon";
  icon.textContent = "!"; icon.setAttribute("aria-hidden", "true");
  const content = document.createElement("div"); content.className = "escudo-mail-content";
  const title = document.createElement("strong"); title.textContent = "¡Alerta de enlace sospechoso!";
  const description = document.createElement("p"); description.textContent = "El análisis detectó señales de riesgo en un enlace de este mensaje. Revisa el destino antes de abrirlo.";
  const actions = document.createElement("div"); actions.className = "escudo-mail-actions";
  const avoid = document.createElement("button"); avoid.type = "button"; avoid.className = "escudo-mail-avoid"; avoid.textContent = "No abrir";
  avoid.addEventListener("click", () => { description.textContent = "No se abrió el enlace. Los enlaces marcados en rojo en este correo quedan detenidos al hacer clic."; });
  const details = document.createElement("button"); details.type = "button"; details.className = "escudo-mail-details"; details.textContent = "Ver detalles";
  const info = document.createElement("div"); info.className = "escudo-mail-info"; info.hidden = true;
  const address = document.createElement("p"); address.textContent = "Destino: " + risk.link.href;
  const list = document.createElement("ul");
  for (const reason of risk.result.reasons) {
    const item = document.createElement("li"); item.textContent = reason; list.append(item);
  }
  info.append(address, list);
  details.addEventListener("click", () => { info.hidden = !info.hidden; details.textContent = info.hidden ? "Ver detalles" : "Ocultar detalles"; });
  actions.append(avoid, details); content.append(title, description, actions, info); panel.append(icon, content);
  body.append(panel);
}

function markMailLinks() {
  scheduled = false;
  if (lastViewURL !== location.href) { lastViewURL = location.href; remoteBudget = 4; pending.clear(); }
  const gmail = location.hostname === "mail.google.com";
  const selector = gmail ? ".a3s a[href]" : '[role="main"] a[href]';
  for (const link of [...document.querySelectorAll(selector)].slice(0, 300)) {
    const href = link.href;
    if (link.dataset.escudoChecked === href) continue;
    link.dataset.escudoChecked = href;
    const local = EscudoAnalyzer.analyzeURL(href);
    setBadge(link, href, local);
    if (local.level === "unknown") continue;
    if (!pending.has(href)) {
      if (remoteBudget <= 0) continue;
      remoteBudget--;
      const record = { links: [link], result: null, status: "" };
      const view = location.href;
      pending.set(href, record);
      chrome.runtime.sendMessage({ type: "REMOTE_LOOKUP", url: href }, (data) => {
        if (location.href !== view || pending.get(href) !== record || chrome.runtime.lastError || !data || data.error) return;
        const final = EscudoAnalyzer.combine(EscudoAnalyzer.analyzeURL(href), EscudoAnalyzer.scoreRemote(data));
        const sources = [data.model ? "modelo" : "modelo no disponible", data.reputation?.status === "found" ? "VirusTotal" : "VirusTotal sin informe"].join(", ");
        record.result = final; record.status = sources;
        record.links.forEach((item) => setBadge(item, href, final, sources));
      });
      continue;
    }
    const entry = pending.get(href); entry.links.push(link);
    if (entry.result) setBadge(link, href, entry.result, entry.status);
  }
}

// También detiene clics en enlaces rojos detectados por reputación, aunque la URL local parezca normal.
document.addEventListener("click", (event) => {
  const link = event.target?.closest?.("a[href]");
  if (!link || !messageBody(link) || results.get(link)?.level !== "high") return;
  if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault(); event.stopImmediatePropagation();
  updateMessagePanel(link);
  const panel = [...messageBody(link).children].find((item) => item.classList?.contains("escudo-mail-panel"));
  panel?.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
}, true);

const observer = new MutationObserver(() => {
  if (scheduled) return;
  scheduled = true; setTimeout(markMailLinks, 350);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
markMailLinks();
