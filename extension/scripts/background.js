// Única ruta de consulta: la clave permanece en el servidor local.
// Los bloqueos automáticos son de sesión y se aplican a futuras navegaciones.
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
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "REMOTE_LOOKUP") return;
  try {
    const url = new URL(message.url);
    if (!["http:", "https:"].includes(url.protocol) || message.url.length > 2048) {
      sendResponse({ error: "URL no válida" }); return;
    }
    fetch("http://127.0.0.1:8765/analyze?url=" + encodeURIComponent(message.url), {
      signal: AbortSignal.timeout(5500)
    }).then(async (response) => {
      if (!response.ok) throw new Error("HTTP " + response.status);
      const data = await response.json();
      if (data?.reputation?.status === "found" && data.reputation.malicious >= 2) {
        try { await recordVerifiedURL(message.url); }
        catch { /* La alerta de la página aún puede mostrarse sin bloqueo de red. */ }
      }
      sendResponse(data);
    }).catch(() => sendResponse({ error: "Servidor local no disponible" }));
  } catch { sendResponse({ error: "URL no válida" }); }
  return true;
});
