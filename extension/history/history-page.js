const $ = (id) => document.getElementById(id);
const levelText = {
  low: "Verde · Sin señales",
  medium: "Rojo preventivo",
  high: "Rojo crítico"
};
const verificationText = {
  complete: "Verificación externa completa",
  partial: "Verificación externa parcial",
  local_only: "Solo análisis local"
};
const providerNames = {
  virustotal: "VirusTotal",
  google_safe_browsing: "Google Safe Browsing",
  phishtank: "PhishTank",
  ipqualityscore: "IPQualityScore"
};
const statusText = {
  found: "resultado recibido", not_found: "sin reporte", match: "coincidencia",
  no_match: "sin coincidencias", rate_limited: "cuota alcanzada",
  not_configured: "sin configurar", invalid_key: "clave rechazada",
  not_applicable: "no aplicable", unavailable: "no disponible", error: "error"
};
let entries = [];

function make(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function formatDate(timestamp) {
  return new Intl.DateTimeFormat("es", {
    dateStyle: "medium", timeStyle: "short"
  }).format(new Date(timestamp));
}

function visibleEntries() {
  const filter = $("filter").value;
  const search = $("search").value.trim().toLowerCase();
  return entries.filter((entry) => {
    const matchesLevel = filter === "all" || entry.level === filter ||
      (filter === "incomplete" && entry.verification !== "complete");
    return matchesLevel && (!search || entry.domain.includes(search));
  });
}

function evidenceList(entry) {
  const list = make("ul");
  if (!entry.evidence?.length) {
    list.append(make("li", "", "No se guardaron evidencias para este resultado."));
    return list;
  }
  entry.evidence.forEach((evidence) => {
    const suffix = evidence.contributesToDecision ? " Señal activa." : " Evidencia informativa.";
    list.append(make("li", "", evidence.title + ": " + evidence.description + suffix));
  });
  return list;
}

function providerGrid(entry) {
  const grid = make("div", "providers");
  Object.entries(providerNames).forEach(([key, name]) => {
    const status = entry.providers?.[key] || "unavailable";
    grid.append(make("div", "provider", name + ": " + (statusText[status] || status)));
  });
  return grid;
}

function historyCard(entry) {
  const card = make("article", "history-card " + entry.level);
  const header = make("div", "card-header");
  const identity = make("div");
  identity.append(make("span", "badge " + entry.level, levelText[entry.level]),
    make("h2", "domain", entry.domain));
  const date = make("time", "date", formatDate(entry.timestamp));
  date.dateTime = new Date(entry.timestamp).toISOString();
  header.append(identity, date);

  const metadata = make("div", "metadata");
  metadata.append(
    make("span", "", entry.signalCount + (entry.signalCount === 1 ? " señal" : " señales")),
    make("span", "", entry.score + "/100 puntos"),
    make("span", "verification " + entry.verification, verificationText[entry.verification] || "Análisis parcial")
  );

  const details = make("details", "details");
  details.append(make("summary", "", "Ver evidencias y fuentes"),
    make("h3", "", "Evidencias"), evidenceList(entry),
    make("h3", "", "Estado de las fuentes"), providerGrid(entry));

  const actions = make("div", "card-actions");
  const remove = make("button", "delete", "Eliminar registro");
  remove.type = "button";
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    await EscudoHistory.removeEntry(entry.id);
    await loadHistory();
  });
  actions.append(remove);
  card.append(header, metadata, details, actions);
  return card;
}

function renderHistory() {
  const visible = visibleEntries();
  $("history-list").replaceChildren(...visible.map(historyCard));
  $("empty").hidden = visible.length !== 0;
  $("summary").textContent = visible.length === entries.length
    ? entries.length + (entries.length === 1 ? " análisis guardado" : " análisis guardados")
    : visible.length + " de " + entries.length + " análisis";
  $("clear").disabled = entries.length === 0;
}

async function loadHistory() {
  entries = await EscudoHistory.getEntries();
  renderHistory();
}

$("filter").addEventListener("change", renderHistory);
$("search").addEventListener("input", renderHistory);
$("clear").addEventListener("click", async () => {
  if (!entries.length || !confirm("¿Borrar todo el historial local de Escudo Transparente?")) return;
  await EscudoHistory.clearEntries();
  await loadHistory();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[EscudoHistory.STORAGE_KEY]) loadHistory();
});
loadHistory();
