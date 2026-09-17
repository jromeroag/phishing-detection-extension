const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    id, textContent: '', hidden: false, value: '', className: '', listeners: {},
    addEventListener(type, fn) { this.listeners[type] = fn; },
    replaceChildren(...children) { this.children = children; }, focus() {}
  });
  return elements.get(id);
}
const document = { getElementById: element, createElement: () => ({ textContent: '' }) };
let lookups = 0;
const chrome = {
  tabs: { query(_options, callback) { callback([{ id: 1, url: 'https://example.com/' }]); },
    sendMessage(_id, _message, callback) { callback({ score: 0, reasons: [] }); } },
  runtime: { lastError: null, sendMessage(message, callback) {
    lookups++; assert.equal(message.type, 'REMOTE_LOOKUP');
    callback({ model: null, reputation: { status: 'found', malicious: 2, suspicious: 0, total: 70 } });
  } }
};
const context = { URL, document, chrome }; vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('extension/popup/popup.js', 'utf8'), context);
assert.equal(lookups, 1);
assert.equal(element('score').textContent, '30/100');
assert.equal(element('badge').textContent, 'Rojo');
assert.match(element('symbol').src, /status-red\.svg$/);
chrome.runtime.sendMessage = (_message, callback) => callback({
  model: { probability: .96 }, reputation: { status: 'not_found' }
});
element('candidate').value = 'https://www.linkedin.com/in/jromeroag/';
element('check-form').listeners.submit({ preventDefault() {} });
assert.equal(element('score').textContent, '0/100');
assert.equal(element('badge').textContent, 'Verde');
assert.match(element('symbol').src, /status-green\.svg$/);
assert.match(element('source-status').textContent, /sin calibrar/);
assert.match(element('source-status').textContent, /no puntúa por sí sola/);
assert.match(element('reasons').children.at(-1).textContent, /no está validado/);
chrome.runtime.sendMessage = (_message, callback) => callback({
  model: { probability: 1 }, reputation: { status: 'found', malicious: 0, suspicious: 0, total: 90 }
});
element('candidate').value = 'https://www.google.com/webhp?hl=es&sa=X';
element('check-form').listeners.submit({ preventDefault() {} });
assert.equal(element('domain').textContent, 'www.google.com');
assert.equal(element('detail-domain').textContent, 'www.google.com');
assert.equal(element('score').textContent, '0/100');
assert.match(element('source-status').textContent, /ruta sin parámetros/);
chrome.runtime.sendMessage = (_message, callback) => callback({
  model: null, reputation: { status: 'not_found' }
});
element('candidate').value = 'https://example.com/';
element('check-form').listeners.submit({ preventDefault() {} });
assert.equal(element('badge').textContent, 'Verde');
assert.match(element('symbol').src, /status-green\.svg$/);
console.log('Popup: consulta automática y resultado remoto correctos');
