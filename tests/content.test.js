const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const analyzerCode = fs.readFileSync('extension/services/analyzer.js', 'utf8');
const contentCode = fs.readFileSync('extension/scripts/content.js', 'utf8');

function createHarness(initialHref, { queued = false, response = { reputation: { status: 'not_found' } } } = {}) {
  const location = { href: initialHref };
  Object.defineProperties(location, {
    protocol: { get: () => new URL(location.href).protocol },
    origin: { get: () => new URL(location.href).origin }
  });
  const windowEvents = {};
  const documentEvents = {};
  const intervalCallbacks = [];
  const requests = [];
  const pending = [];
  const created = [];
  const overlays = [];
  let activeWarning = null;
  let wentBack = 0;

  function makeElement(tag) {
    const element = {
      tag, id: '', className: '', textContent: '', style: {}, children: [], attrs: {}, listeners: {},
      append(...children) { this.children.push(...children); children.forEach((child) => { child.parent = this; }); },
      setAttribute(name, value) { this.attrs[name] = value; },
      addEventListener(type, callback) { this.listeners[type] = callback; },
      attachShadow() { this.shadow = makeElement('shadow'); return this.shadow; },
      focus() {},
      remove() { if (activeWarning === this) activeWarning = null; }
    };
    created.push(element);
    return element;
  }

  const document = {
    readyState: 'complete',
    documentElement: {
      append(element) {
        overlays.push(element);
        if (element.id === 'escudo-warning-root') activeWarning = element;
      }
    },
    querySelectorAll() { return []; },
    getElementById(id) { return id === 'escudo-warning-root' ? activeWarning : null; },
    addEventListener(type, callback) { documentEvents[type] = callback; },
    createElement: makeElement,
    createElementNS(_namespace, tag) { return makeElement(tag); }
  };
  const window = {
    history: { length: 2, back() { wentBack++; } },
    location,
    addEventListener(type, callback) { windowEvents[type] = callback; }
  };
  window.top = window;
  const chrome = {
    runtime: {
      lastError: null,
      sendMessage(message, callback) {
        requests.push(message.url);
        if (queued) pending.push({ url: message.url, callback });
        else callback(response);
      },
      onMessage: { addListener() {} }
    }
  };
  const context = {
    URL, window, document, chrome, location,
    setTimeout() {},
    setInterval(callback) { intervalCallbacks.push(callback); return intervalCallbacks.length; }
  };
  vm.createContext(context);
  vm.runInContext(analyzerCode, context);
  vm.runInContext(contentCode, context);
  return {
    context, location, requests, pending, overlays, created, windowEvents, documentEvents,
    tick() { intervalCallbacks.forEach((callback) => callback()); },
    headings() { return created.filter((element) => element.tag === 'h2').map((element) => element.textContent); },
    warningCount() { return overlays.length; },
    wentBack() { return wentBack; }
  };
}

// La carga tradicional inicia la consulta sin abrir el popup.
const traditionalURL = 'https://www.facebook.com/' + 'a'.repeat(160);
const traditional = createHarness(traditionalURL, {
  response: { model: { probability: .96 }, reputation: { status: 'not_found' } }
});
assert.deepEqual(traditional.requests, [traditionalURL]);
assert.equal(traditional.warningCount(), 1);
assert.match(traditional.headings().at(-1), /Sin señales evidentes/);

// Los eventos y el comprobador periódico no duplican una URL ya analizada.
traditional.tick();
traditional.windowEvents.popstate();
traditional.windowEvents.hashchange();
assert.equal(traditional.requests.length, 1);

// Una SPA que cambia location.href dispara exactamente un análisis nuevo.
traditional.location.href = 'https://www.facebook.com/profile.php?id=123';
traditional.tick();
traditional.tick();
assert.equal(traditional.requests.length, 2);
assert.equal(traditional.requests[1], 'https://www.facebook.com/profile.php?id=123');

// Una respuesta atrasada de la URL anterior se ignora por completo.
const racing = createHarness('https://old.example/', { queued: true });
assert.equal(racing.requests.length, 1);
racing.location.href = 'https://current.example/';
racing.tick();
assert.equal(racing.requests.length, 2);
racing.pending[0].callback({ reputation: { status: 'found', malicious: 3, suspicious: 0 } });
assert.equal(racing.warningCount(), 0);
racing.pending[1].callback({ reputation: { status: 'not_found' } });
assert.equal(racing.warningCount(), 1);
assert.match(racing.headings().at(-1), /Sin señales evidentes/);

// Se conservan la alerta roja local, el bloqueo de continuar y Volver.
const red = createHarness('https://usuario@login-verificar.example/', {
  response: { error: 'offline' }
});
assert.match(red.headings().at(-1), /Sitio con riesgo alto/);
const redActions = red.created.find((element) => element.className === 'actions');
assert.equal(redActions.children.some((element) => element.id === 'continue'), false);
red.created.find((element) => element.id === 'back').listeners.click();
assert.equal(red.wentBack(), 1);

// Una señal preventiva se presenta en rojo, permite volver o continuar y no se confunde con bloqueo crítico.
const preventive = createHarness('https://example.com/', {
  response: { reputation: { status: 'found', malicious: 1, suspicious: 0 } }
});
assert.match(preventive.headings().at(-1), /Riesgo detectado/);
assert.match(preventive.created.find((element) => element.tag === 'li').textContent, /VirusTotal/);
const preventiveBox = preventive.created.find((element) => element.className === 'box medium');
const preventiveLabel = preventive.created.find((element) => element.className === 'risk-label medium');
const preventiveActions = preventive.created.find((element) => element.className === 'actions');
assert.ok(preventiveBox);
assert.equal(preventiveLabel.textContent, 'Rojo');
assert.equal(preventiveActions.children.some((element) => element.id === 'back'), true);
assert.equal(preventiveActions.children.some((element) => element.id === 'continue'), true);
assert.match(preventiveActions.children.find((element) => element.id === 'continue').textContent, /responsabilidad/);

console.log('Navegación: carga automática, SPA, deduplicación y respuestas atrasadas correctas');
console.log('Avisos existentes: verde, rojo preventivo con continuación y rojo crítico sin continuar');
