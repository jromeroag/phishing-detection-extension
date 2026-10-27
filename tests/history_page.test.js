const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function node(tag = 'div', id = '') {
  return {
    tag, id, className: '', textContent: '', value: '', hidden: false, disabled: false,
    children: [], listeners: {},
    append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = items; },
    addEventListener(type, callback) { this.listeners[type] = callback; }
  };
}
const elements = new Map();
for (const id of ['filter', 'search', 'clear', 'summary', 'history-list', 'empty']) {
  elements.set(id, node(id === 'filter' ? 'select' : id === 'search' ? 'input' : 'div', id));
}
elements.get('filter').value = 'all';
const now = Date.now();
const storageData = { escudoAnalysisHistoryV1: [
  { schemaVersion: 1, id: 'red', timestamp: now, domain: 'riesgo.example', level: 'high',
    signalCount: 2, score: 30, strongSignal: false, verification: 'partial',
    providers: { virustotal: 'found', google_safe_browsing: 'unavailable', phishtank: 'not_found', ipqualityscore: 'unavailable' },
    evidence: [{ title: 'Señal', description: 'Descripción segura.', contributesToDecision: true }] },
  { schemaVersion: 1, id: 'green', timestamp: now - 1000, domain: 'limpio.example', level: 'low',
    signalCount: 0, score: 0, strongSignal: false, verification: 'complete',
    providers: { virustotal: 'not_found', google_safe_browsing: 'no_match', phishtank: 'not_found', ipqualityscore: 'found' }, evidence: [] }
] };
const chrome = {
  runtime: { lastError: null },
  storage: {
    local: {
      get(defaults, callback) { callback({ ...defaults, ...storageData }); },
      set(values, callback) { Object.assign(storageData, values); callback?.(); }
    },
    onChanged: { addListener() {} }
  }
};
const document = {
  getElementById(id) { return elements.get(id); },
  createElement(tag) { return node(tag); }
};
const context = { URL, Date, Intl, Promise, document, chrome, confirm: () => true };
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/history.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('extension/history/history-page.js', 'utf8'), context);

const settle = () => new Promise((resolve) => setImmediate(resolve));
(async () => {
  await settle();
  assert.equal(elements.get('history-list').children.length, 2);
  assert.match(elements.get('summary').textContent, /2 análisis guardados/);

  elements.get('filter').value = 'high';
  elements.get('filter').listeners.change();
  assert.equal(elements.get('history-list').children.length, 1);
  assert.match(elements.get('history-list').children[0].children[0].children[0].children[1].textContent, /riesgo\.example/);

  elements.get('filter').value = 'all';
  elements.get('search').value = 'limpio';
  elements.get('search').listeners.input();
  assert.equal(elements.get('history-list').children.length, 1);

  elements.get('clear').listeners.click();
  await settle();
  await settle();
  assert.equal(storageData.escudoAnalysisHistoryV1.length, 0);
  assert.equal(elements.get('empty').hidden, false);
  console.log('Interfaz de historial: renderizado, filtros, búsqueda y borrado correctos');
})().catch((error) => { console.error(error); process.exitCode = 1; });
