/* Motor explicable de riesgo. Las ponderaciones deben validarse con datos reales. */
(function (root) {
  const EVIDENCE_CATALOG = Object.freeze({
    INVALID_URL: { source: "url", title: "URL no válida" },
    UNSUPPORTED_PROTOCOL: { source: "url", title: "Protocolo no compatible" },
    BRAND_IMPERSONATION: { source: "url", title: "Posible suplantación de Vía BCP" },
    URL_CREDENTIALS: { source: "url", title: "Datos antes del dominio" },
    PUNYCODE: { source: "url", title: "Dominio internacional codificado" },
    PUBLIC_IP: { source: "url", title: "Dirección IP pública" },
    LURE_COMBINATION: { source: "url", title: "Señuelos combinados con señales inusuales" },
    MANY_HYPHENS: { source: "url", title: "Cantidad inusual de guiones" },
    EXTREME_LENGTH: { source: "url", title: "Dirección extremadamente larga" },
    NO_URL_SIGNALS: { source: "url", title: "Sin señales locales en la URL" },
    HTTP_PASSWORD_FORM: { source: "page", title: "Contraseña solicitada sin cifrado" },
    CROSS_ORIGIN_FORM: { source: "page", title: "Formulario enviado a otro origen" },
    VT_MALICIOUS: { source: "virustotal", title: "Detecciones maliciosas" },
    VT_SUSPICIOUS: { source: "virustotal", title: "Detecciones sospechosas" },
    MODEL_HIGH: { source: "model", title: "Coincidencia alta del modelo" },
    MODEL_MEDIUM: { source: "model", title: "Coincidencia media del modelo" }
  });
  function createEvidence(id, details = {}) {
    const definition = EVIDENCE_CATALOG[id] || {};
    return {
      id,
      source: details.source || definition.source || "unknown",
      title: details.title || definition.title || id,
      description: details.description || "",
      observedValue: details.observedValue ?? null,
      threshold: details.threshold ?? null,
      scoreContribution: details.scoreContribution || 0,
      severity: details.severity || "info",
      contributesToDecision: details.contributesToDecision === true
    };
  }
  function resultFromEvidence(url, evidence, score, level = classifyRisk(score)) {
    return { level, score, evidence, reasons: evidence.map((item) => item.description), url };
  }
  function classifyRisk(score) {
    if (score === 0) return "low";
    return score <= 25 ? "medium" : "high";
  }
  function analyzeURL(input) {
    let url;
    try { url = new URL(input); } catch {
      return resultFromEvidence(input, [createEvidence("INVALID_URL", {
        description: "URL no válida.", observedValue: input
      })], 0, "unknown");
    }
    if (!(["http:", "https:"].includes(url.protocol))) {
      return resultFromEvidence(input, [createEvidence("UNSUPPORTED_PROTOCOL", {
        description: "Solo se analizan direcciones HTTP y HTTPS.", observedValue: url.protocol,
        threshold: "http: o https:"
      })], 0, "unknown");
    }
    let score = 0;
    const evidence = [];
    const add = (id, points, description, observedValue, threshold, severity = "medium") => {
      score += points;
      evidence.push(createEvidence(id, { description, observedValue, threshold,
        scoreContribution: points, severity, contributesToDecision: points > 0 }));
    };
    const isDomainOrSubdomain = (hostname, domain) => hostname === domain || hostname.endsWith("." + domain);
    const protectedBrands = [
      { name: "Vía BCP", token: "viabcp", domains: ["viabcp.com", "viabcp.com.pe"] }
    ];
    for (const brand of protectedBrands) {
      const official = brand.domains.some((domain) => isDomainOrSubdomain(url.hostname, domain));
      if (url.hostname.includes(brand.token) && !official) {
        add("BRAND_IMPERSONATION", 45,
          "El dominio parece imitar a " + brand.name + ", pero no pertenece a sus dominios oficiales.",
          url.hostname, brand.domains.join(" o ") + " (o sus subdominios)", "high");
      }
    }
    if (url.username || url.password) add("URL_CREDENTIALS", 45,
      "La dirección contiene datos antes del dominio (@).", "Presente", "No debe contener credenciales", "high");
    if (url.hostname.includes("xn--")) add("PUNYCODE", 10,
      "El dominio usa caracteres internacionales codificados; comprueba cómo se escribe.", "xn--", "Dominio sin codificación sospechosa");
    const ip = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname.startsWith("192.168.") || url.hostname.startsWith("10.") || /^172\.(1[6-9]|2\d|3[01])\./.test(url.hostname);
    if (ip && !local) add("PUBLIC_IP", 15,
      "La dirección usa una IP pública; verifica a quién pertenece.", url.hostname, "Dominio identificable");
    // Una ruta como /login es habitual. La palabra en el dominio solo suma
    // puntos cuando aparece junto con otra señal de suplantación.
    const hyphenCount = (url.hostname.match(/-/g) || []).length;
    const lure = /(?:login|verificar|actualizar|seguridad|cuenta|premio)/i.test(url.hostname);
    if (lure && (url.username || url.password || url.hostname.includes("xn--") || (ip && !local) || hyphenCount >= 3)) {
      add("LURE_COMBINATION", 10, "El dominio combina palabras de señuelo con otras señales inusuales.",
        "Palabra de señuelo + otra señal", "Sin combinación de señales");
    }
    if (hyphenCount >= 3) add("MANY_HYPHENS", 10, "El dominio contiene muchos guiones.",
      hyphenCount + " guiones", "Menos de 3 guiones");
    // Los enlaces de sesiones, buscadores y redes sociales suelen ser largos.
    // Solo cuenta una longitud extrema si ya existe otra señal en la URL.
    if (url.href.length > 200 && score > 0) add("EXTREME_LENGTH", 5,
      "La dirección es muy larga además de presentar otras señales.", url.href.length + " caracteres", "Máximo 200 con otras señales");
    score = Math.min(score, 100);
    if (!evidence.length) evidence.push(createEvidence("NO_URL_SIGNALS", {
      description: "No se observaron señales sospechosas en la dirección. Esto no garantiza que el sitio sea seguro.",
      observedValue: "0 reglas activadas", threshold: "Solo fuentes consultadas"
    }));
    return resultFromEvidence(url.href, evidence, score);
  }
  function evidenceFromLegacy(result) {
    if (Array.isArray(result?.evidence)) return result.evidence;
    return (result?.reasons || []).map((description, index) => createEvidence("LEGACY_" + index, {
      source: "page", title: "Señal de la página", description,
      scoreContribution: index === 0 ? (result.score || 0) : 0,
      severity: result.score > 25 ? "high" : "medium",
      contributesToDecision: (result.score || 0) > 0
    }));
  }
  function combine(base, extra) {
    if (base.level === "unknown") return base;
    if (!extra) return base;
    const extraEvidence = evidenceFromLegacy(extra);
    if (!extra.score) return extraEvidence.length ? { ...base,
      evidence: [...(base.evidence || []), ...extraEvidence],
      reasons: [...base.reasons, ...extraEvidence.map((item) => item.description)] } : base;
    // URL y modelo usan rasgos relacionados. Sin evidencia independiente fuerte,
    // sumar ambos no basta para una alerta roja.
    const uncorroborated = extra.needsCorroboration && base.score <= 25;
    const score = Math.min(uncorroborated ? 25 : 100, base.score + extra.score);
    const baseEvidence = (base.evidence || []).filter((item) => item.id !== "NO_URL_SIGNALS");
    const evidence = [...baseEvidence, ...extraEvidence];
    return { ...base, score, level: classifyRisk(score), evidence,
      reasons: evidence.map((item) => item.description) };
  }
  function scoreRemote(data) {
    let score = 0;
    const evidence = [];
    let corroborated = false;
    const add = (id, points, description, observedValue, threshold, severity, contributes = points > 0) => {
      score += points;
      evidence.push(createEvidence(id, { description, observedValue, threshold,
        scoreContribution: points, severity, contributesToDecision: contributes }));
    };
    if (data?.reputation?.status === "found") {
      if (data.reputation.malicious >= 2) {
        corroborated = true;
        add("VT_MALICIOUS", 30, "VirusTotal informa " + data.reputation.malicious + " detecciones maliciosas.",
          data.reputation.malicious + " detecciones", "2 o más", "high");
      } else if (data.reputation.malicious === 1) {
        add("VT_MALICIOUS", 15, "VirusTotal informa una detección maliciosa; comprueba el enlace.",
          "1 detección", "1 detección", "medium");
      } else if (data.reputation.suspicious > 0) {
        add("VT_SUSPICIOUS", 10, "VirusTotal informa " + data.reputation.suspicious + " detección(es) sospechosa(s).",
          data.reputation.suspicious + " detección(es)", "1 o más", "medium");
      }
    }
    const reputationAlert = data?.reputation?.status === "found" &&
      (data.reputation.malicious > 0 || data.reputation.suspicious > 0);
    if (data?.model?.probability >= .8) {
      if (reputationAlert) add("MODEL_HIGH", 10, "El modelo también detecta rasgos asociados con phishing.",
        Math.round(data.model.probability * 100) + "/100", "80/100", "medium");
      else add("MODEL_HIGH", 0, "El modelo aún no está validado para decidir el color por sí solo; su resultado se muestra como referencia.",
        Math.round(data.model.probability * 100) + "/100", "80/100", "info", false);
    } else if (data?.model?.probability >= .6) {
      if (reputationAlert) add("MODEL_MEDIUM", 5, "El modelo también detecta algunos rasgos asociados con phishing.",
        Math.round(data.model.probability * 100) + "/100", "60/100", "medium");
      else add("MODEL_MEDIUM", 0, "La predicción aislada del modelo no modifica el puntaje hasta validarlo externamente.",
        Math.round(data.model.probability * 100) + "/100", "60/100", "info", false);
    }
    return { score, evidence, reasons: evidence.map((item) => item.description), needsCorroboration: !corroborated };
  }
  root.EscudoAnalyzer = { EVIDENCE_CATALOG, createEvidence, analyzeURL, classifyRisk, combine, scoreRemote };
})(typeof globalThis !== "undefined" ? globalThis : this);
