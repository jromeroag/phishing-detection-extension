const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const href = 'https://www.facebook.com/' + 'a'.repeat(160);
const window = {}; window.top = window;
let overlays = 0;
const callbacks = {};
const elements = [];
const document = {
  documentElement: { append() { overlays++; } }, readyState: 'loading',
  addEventListener(type, callback) { callbacks[type] = callback; },
  querySelectorAll() { return []; }, getElementById() { return null; },
  createElement: makeElement, createElementNS(_ns, tag) { return makeElement(tag); }
};
const chrome = { runtime: { lastError: null,
  sendMessage(_message, callback) { callback({ model: { probability: .96 }, reputation: { status: 'not_found' } }); },
  onMessage: { addListener() {} }
} };
const context = { URL, window, document, chrome, setTimeout() {},
  location: { href, protocol: 'https:', origin: 'https://www.facebook.com' } };
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js','utf8'), context);
vm.runInContext(fs.readFileSync('extension/scripts/content.js','utf8'), context);
callbacks.DOMContentLoaded();
assert.equal(overlays, 1); // Verde discreto después de recibir los resultados; no bloquea la página.
function makeElement(tag) {
  const el = { tag, style: {}, children: [], attrs: {}, listeners: {}, append(...children) { this.children.push(...children); },
    setAttribute(name, value) { this.attrs[name] = value; }, addEventListener(type, callback) { this.listeners[type] = callback; },
    attachShadow() { return makeElement('shadow'); }, focus() {}, remove() {} };
  elements.push(el);
  return el;
}
const redURL = 'https://usuario@login-verificar.example/';
elements.length = 0;
let wentBack = 0;
const redWindow = { history: { length: 2, back() { wentBack++; } } }; redWindow.top = redWindow;
const redDocument = { documentElement: makeElement('html'), readyState: 'loading',
  addEventListener() {}, createElement: makeElement,
  createElementNS(_ns, tag) { return makeElement(tag); }, getElementById() { return null; } };
const redChrome = { runtime: { getURL: (path) => 'chrome-extension://test/' + path,
  sendMessage(_message, callback) { callback({ error: 'offline' }); },
  onMessage: { addListener() {} } } };
const redContext = { URL, window: redWindow, document: redDocument, chrome: redChrome,
  location: { href: redURL, protocol: 'https:', origin: 'https://login-verificar.example' } };
vm.createContext(redContext);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js','utf8'),redContext);
vm.runInContext(fs.readFileSync('extension/scripts/content.js','utf8'),redContext);
const icon = elements.find((el) => el.tag === 'svg' && el.attrs.class === 'status-icon');
assert.equal(icon.children[0].attrs.fill, '#cf2032');
assert.equal(icon.children[0].tag, 'path');
assert.equal(elements.find((el) => el.className === 'actions').children.some((el) => el.id === 'continue'), false);
elements.find((el) => el.id === 'back').listeners.click();
assert.equal(wentBack, 1);
const yellowElements = [];
const yellowContext = { URL, window: { history: { length: 1 }, location: { replace(url) { yellowContext.fallback = url; } } },
  location: { href: 'https://example.com/', protocol: 'https:', origin: 'https://example.com' },
  document: { readyState: 'loading', documentElement: { append() {} }, querySelectorAll() { return []; },
    getElementById() { return null; }, addEventListener(type, cb) { if (type === 'DOMContentLoaded') yellowContext.inspect = cb; },
    createElement(tag) { const el = makeElement(tag); yellowElements.push(el); return el; },
    createElementNS(_ns, tag) { const el = makeElement(tag); yellowElements.push(el); return el; } },
  chrome: { runtime: { lastError: null, sendMessage(_msg, cb) { cb({ reputation: { status: 'found', malicious: 1, suspicious: 0 } }); }, onMessage: { addListener() {} } } } };
yellowContext.window.top = yellowContext.window;
vm.createContext(yellowContext);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js','utf8'), yellowContext);
vm.runInContext(fs.readFileSync('extension/scripts/content.js','utf8'), yellowContext);
yellowContext.inspect();
assert.equal(yellowElements.find((el) => el.tag === 'h2').textContent, 'Sitio con riesgo medio');
assert.match(yellowElements.find((el) => el.tag === 'li').textContent, /VirusTotal/);
yellowElements.find((el) => el.id === 'back').listeners.click();
assert.equal(yellowContext.fallback, 'about:blank');
console.log('Avisos según el análisis: verde discreto, rojo sin continuar y vuelta al historial');
