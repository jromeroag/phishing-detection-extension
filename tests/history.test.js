const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const storageData = {};
const chrome = {
  runtime: { lastError: null },
  storage: { local: {
    get(defaults, callback) { callback({ ...defaults, ...storageData }); },
    set(values, callback) { Object.assign(storageData, values); callback?.(); }
  } }
};
const context = { URL, chrome };
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/history.js', 'utf8'), context);
const history = context.EscudoHistory;

const weak = {
  level: 'medium', score: 15, signalCount: 1, strongSignal: false,
  evidence: [{ id: 'VT_MALICIOUS', source: 'virustotal', title: 'Detección',
    description: 'Una fuente observó una señal.', severity: 'medium', contributesToDecision: true }]
};
const remoteComplete = {
  reputation: { status: 'found' },
  google_safe_browsing: { status: 'no_match' },
  phishtank: { status: 'not_found' },
  ipqualityscore: { status: 'found' }
};
const privateURL = 'https://usuario:secreto@example.com/ruta/privada?token=MUY_SECRETO#cuenta';
const entry = history.createEntry(privateURL, weak, remoteComplete, 1_800_000_000_000);
assert.equal(entry.domain, 'example.com');
assert.equal(entry.verification, 'complete');
assert.doesNotMatch(JSON.stringify(entry), /usuario|secreto|ruta|token|cuenta/i);

(async () => {
  const now = Date.now();
  await history.saveAnalysis(privateURL, weak, remoteComplete, now);
  const critical = { ...weak, level: 'high', score: 30, signalCount: 2 };
  await history.saveAnalysis('https://example.com/otra-ruta?dato=privado', critical, null, now + 1000);
  let entries = await history.getEntries(now + 1000);
  assert.equal(entries.length, 1, 'el mismo dominio reciente debe actualizarse, no duplicarse');
  assert.equal(entries[0].level, 'high');
  assert.equal(entries[0].verification, 'complete', 'debe conservar el mejor estado de las fuentes');
  assert.doesNotMatch(JSON.stringify(entries), /otra-ruta|dato|privado/i);

  await history.saveAnalysis('https://otro.example/', { level: 'low', score: 0, signalCount: 0,
    strongSignal: false, evidence: [] }, null, now + 2000);
  entries = await history.getEntries(now + 2000);
  assert.equal(entries.length, 2);
  await history.removeEntry(entries[0].id);
  assert.equal((await history.getEntries()).length, 1);
  await history.clearEntries();
  assert.equal((await history.getEntries()).length, 0);
  storageData[history.STORAGE_KEY] = [{ ...entry, id: 'expired', timestamp: now - history.RETENTION_MS - 1 }];
  assert.equal((await history.getEntries(now)).length, 0);
  assert.equal(storageData[history.STORAGE_KEY].length, 0, 'los registros vencidos deben borrarse físicamente');
  console.log('Historial: privacidad, deduplicación, retención de estado y borrado correctos');
})().catch((error) => { console.error(error); process.exitCode = 1; });
