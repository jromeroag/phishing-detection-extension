/* Motor local provisional: las ponderaciones deben validarse con datos reales. */
(function (root) {
  function classifyRisk(score) {
    if (score === 0) return "low";
    return score <= 25 ? "medium" : "high";
  }
  function analyzeURL(input) {
    let url;
    try { url = new URL(input); } catch { return { level: "unknown", score: 0, reasons: ["URL no válida."], url: input }; }
    if (!(["http:", "https:"].includes(url.protocol))) {
      return { level: "unknown", score: 0, reasons: ["Solo se analizan direcciones HTTP y HTTPS."], url: input };
    }
    let score = 0;
    const reasons = [];
    const add = (points, explanation) => { score += points; reasons.push(explanation); };
    if (url.username || url.password) add(45, "La dirección contiene datos antes del dominio (@).");
    if (url.hostname.includes("xn--")) add(10, "El dominio usa caracteres internacionales codificados; comprueba cómo se escribe.");
    const ip = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname.startsWith("192.168.") || url.hostname.startsWith("10.") || /^172\.(1[6-9]|2\d|3[01])\./.test(url.hostname);
    if (ip && !local) add(15, "La dirección usa una IP pública; verifica a quién pertenece.");
    // Una ruta como /login es habitual. La palabra en el dominio solo suma
    // puntos cuando aparece junto con otra señal de suplantación.
    const lure = /(?:login|verificar|actualizar|seguridad|cuenta|premio)/i.test(url.hostname);
    if (lure && (url.username || url.password || url.hostname.includes("xn--") || (ip && !local) || (url.hostname.match(/-/g) || []).length >= 3)) {
      add(10, "El dominio combina palabras de señuelo con otras señales inusuales.");
    }
    if ((url.hostname.match(/-/g) || []).length >= 3) add(10, "El dominio contiene muchos guiones.");
    // Los enlaces de sesiones, buscadores y redes sociales suelen ser largos.
    // Solo cuenta una longitud extrema si ya existe otra señal en la URL.
    if (url.href.length > 200 && score > 0) add(5, "La dirección es muy larga además de presentar otras señales.");
    score = Math.min(score, 100);
    const level = classifyRisk(score);
    if (!reasons.length) reasons.push("No se observaron señales sospechosas en la dirección. Esto no garantiza que el sitio sea seguro.");
    return { level, score, reasons, url: url.href };
  }
  function combine(base, extra) {
    if (base.level === "unknown") return base;
    if (!extra) return base;
    if (!extra.score) return extra.reasons?.length ? { ...base, reasons: [...base.reasons, ...extra.reasons] } : base;
    // URL y modelo usan rasgos relacionados. Sin evidencia independiente fuerte,
    // sumar ambos no basta para una alerta roja.
    const uncorroborated = extra.needsCorroboration && base.score <= 25;
    const score = Math.min(uncorroborated ? 25 : 100, base.score + extra.score);
    return { ...base, score, level: classifyRisk(score), reasons: [
      ...base.reasons.filter((r) => !r.startsWith("No se observaron señales")), ...extra.reasons
    ] };
  }
  function scoreRemote(data) {
    let score = 0;
    const reasons = [];
    let corroborated = false;
    if (data?.reputation?.status === "found") {
      if (data.reputation.malicious >= 2) { score += 30; corroborated = true; reasons.push("VirusTotal informa " + data.reputation.malicious + " detecciones maliciosas."); }
      else if (data.reputation.malicious === 1) { score += 15; reasons.push("VirusTotal informa una detección maliciosa; comprueba el enlace."); }
      else if (data.reputation.suspicious > 0) { score += 10; reasons.push("VirusTotal informa " + data.reputation.suspicious + " detección(es) sospechosa(s)."); }
    }
    const reputationAlert = data?.reputation?.status === "found" &&
      (data.reputation.malicious > 0 || data.reputation.suspicious > 0);
    if (data?.model?.probability >= .8) {
      if (reputationAlert) { score += 10; reasons.push("El modelo también detecta rasgos asociados con phishing."); }
      else reasons.push("El modelo aún no está validado para decidir el color por sí solo; su resultado se muestra como referencia.");
    } else if (data?.model?.probability >= .4) {
      if (reputationAlert) { score += 5; reasons.push("El modelo también detecta algunos rasgos asociados con phishing."); }
      else reasons.push("La predicción aislada del modelo no modifica el puntaje hasta validarlo externamente.");
    }
    return { score, reasons, needsCorroboration: !corroborated };
  }
  root.EscudoAnalyzer = { analyzeURL, classifyRisk, combine, scoreRemote };
})(typeof globalThis !== "undefined" ? globalThis : this);
