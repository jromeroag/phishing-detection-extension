/* Historial local y privado de análisis. Nunca almacena la URL completa. */
(function (root) {
  const STORAGE_KEY = "escudoAnalysisHistoryV1";
  const MAX_ENTRIES = 100;
  const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
  const DEDUPLICATION_MS = 10 * 60 * 1000;
  const LEVELS = new Set(["low", "medium", "high"]);
  const PROVIDERS = ["virustotal", "google_safe_browsing", "phishtank", "ipqualityscore"];
  const DEFINITIVE_STATUSES = {
    virustotal: new Set(["found", "not_found"]),
    google_safe_browsing: new Set(["match", "no_match"]),
    phishtank: new Set(["found", "not_found"]),
    ipqualityscore: new Set(["found", "not_found"])
  };
  let writeQueue = Promise.resolve();

  function boundedText(value, maximum = 240) {
    return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, maximum);
  }

  function providerStatuses(remoteData) {
    return {
      virustotal: boundedText(remoteData?.reputation?.status || "unavailable", 32),
      google_safe_browsing: boundedText(remoteData?.google_safe_browsing?.status || "unavailable", 32),
      phishtank: boundedText(remoteData?.phishtank?.status || "unavailable", 32),
      ipqualityscore: boundedText(remoteData?.ipqualityscore?.status || "unavailable", 32)
    };
  }

  function verificationState(statuses) {
    const completed = PROVIDERS.filter((provider) =>
      DEFINITIVE_STATUSES[provider].has(statuses[provider])).length;
    if (completed === PROVIDERS.length) return "complete";
    if (completed > 0) return "partial";
    return "local_only";
  }

  function compactEvidence(result) {
    const source = Array.isArray(result?.evidence) ? result.evidence : [];
    return source.slice(0, 6).map((item) => ({
      id: boundedText(item?.id || "UNKNOWN", 64),
      source: boundedText(item?.source || "unknown", 40),
      title: boundedText(item?.title || "Señal observada", 100),
      description: boundedText(item?.description || "", 240),
      severity: ["info", "medium", "high"].includes(item?.severity) ? item.severity : "info",
      contributesToDecision: item?.contributesToDecision === true
    }));
  }

  function createEntry(rawURL, result, remoteData = null, now = Date.now()) {
    let parsed;
    try { parsed = new URL(rawURL); } catch { return null; }
    if (!["http:", "https:"].includes(parsed.protocol) || !LEVELS.has(result?.level)) return null;
    const timestamp = Number.isFinite(Number(now)) ? Number(now) : Date.now();
    const providers = providerStatuses(remoteData);
    return {
      schemaVersion: 1,
      id: timestamp.toString(36) + "-" + Math.random().toString(36).slice(2, 9),
      timestamp,
      domain: boundedText(parsed.hostname.toLowerCase(), 253),
      level: result.level,
      signalCount: Math.max(0, Math.min(99, Number(result.signalCount) || 0)),
      score: Math.max(0, Math.min(100, Number(result.score) || 0)),
      strongSignal: result.strongSignal === true,
      verification: verificationState(providers),
      providers,
      evidence: compactEvidence(result)
    };
  }

  function storageArea() {
    return root.chrome?.storage?.local || null;
  }

  function readRaw() {
    return new Promise((resolve) => {
      const area = storageArea();
      if (!area) { resolve([]); return; }
      try {
        area.get({ [STORAGE_KEY]: [] }, (items) => {
          if (root.chrome?.runtime?.lastError) { resolve([]); return; }
          resolve(Array.isArray(items?.[STORAGE_KEY]) ? items[STORAGE_KEY] : []);
        });
      } catch { resolve([]); }
    });
  }

  function writeRaw(entries) {
    return new Promise((resolve) => {
      const area = storageArea();
      if (!area) { resolve(false); return; }
      try {
        area.set({ [STORAGE_KEY]: entries }, () =>
          resolve(!root.chrome?.runtime?.lastError));
      } catch { resolve(false); }
    });
  }

  function validEntries(entries, now = Date.now()) {
    const minimum = now - RETENTION_MS;
    return entries.filter((entry) => entry && LEVELS.has(entry.level) &&
      typeof entry.id === "string" && typeof entry.domain === "string" &&
      Number(entry.timestamp) >= minimum && Number(entry.timestamp) <= now + 60000)
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, MAX_ENTRIES);
  }

  async function getEntries(now = Date.now()) {
    const raw = await readRaw();
    const entries = validEntries(raw, now);
    if (entries.length !== raw.length) await writeRaw(entries);
    return entries;
  }

  function verificationRank(value) {
    return value === "complete" ? 2 : value === "partial" ? 1 : 0;
  }

  function saveAnalysis(rawURL, result, remoteData = null, now = Date.now()) {
    const entry = createEntry(rawURL, result, remoteData, now);
    if (!entry) return Promise.resolve(null);
    const job = writeQueue.then(async () => {
      const entries = validEntries(await readRaw(), entry.timestamp);
      const duplicateIndex = entries.findIndex((item) => item.domain === entry.domain &&
        entry.timestamp - item.timestamp <= DEDUPLICATION_MS);
      if (duplicateIndex >= 0) {
        const previous = entries.splice(duplicateIndex, 1)[0];
        if (verificationRank(previous.verification) > verificationRank(entry.verification)) {
          entry.verification = previous.verification;
          entry.providers = previous.providers;
        }
      }
      const next = [entry, ...entries].slice(0, MAX_ENTRIES);
      return await writeRaw(next) ? entry : null;
    });
    writeQueue = job.catch(() => null);
    return job;
  }

  function removeEntry(id) {
    const safeId = boundedText(id, 80);
    const job = writeQueue.then(async () => {
      const entries = await getEntries();
      return writeRaw(entries.filter((entry) => entry.id !== safeId));
    });
    writeQueue = job.catch(() => false);
    return job;
  }

  function clearEntries() {
    const job = writeQueue.then(() => writeRaw([]));
    writeQueue = job.catch(() => false);
    return job;
  }

  root.EscudoHistory = {
    STORAGE_KEY, MAX_ENTRIES, RETENTION_MS,
    providerStatuses, verificationState, createEntry,
    getEntries, saveAnalysis, removeEntry, clearEntries
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
