const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function element(tag = 'div') {
  const node = { tag, children: [], dataset: {}, style: {}, isConnected: true, hidden: false,
    className: '', textContent: '', listeners: {},
    get classList() { return { contains: (name) => node.className.split(' ').includes(name) }; },
    append(...items) { this.children.push(...items); items.forEach(item => { item.parent = this; }); },
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(item => item !== this); },
    after(item) { this.nextElementSibling = item; },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    setAttribute() {}, focus() {}, blur() {}, scrollIntoView() {}
  };
  return node;
}
const body = element();
const links = [element('a'), element('a')];
links[0].href = 'https://www.linkedin.com/in/jromeroag/';
links[1].href = 'https://example.com/';
for (const link of links) link.closest = () => body;
body.querySelectorAll = () => links;
const listeners = {};
const document = { documentElement: {}, querySelectorAll() { return links; },
  createElement: element, addEventListener(type, fn) { listeners[type] = fn; } };
let calls = 0;
const chrome = { runtime: { lastError: null, sendMessage(message, callback) {
  calls++;
  callback(message.url.includes('linkedin')
    ? { model: { probability: .96 }, reputation: { status: 'not_found' } }
    : { model: null, reputation: { status: 'found', malicious: 2, suspicious: 0 } });
} } };
const context = { URL, document, chrome, location: { hostname: 'mail.google.com', href: 'https://mail.google.com/mail/u/0/#inbox/123' },
  MutationObserver: class { observe() {} }, setTimeout() {} };
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('extension/scripts/mail.js', 'utf8'), context);
assert.equal(calls, 2);
assert.equal(links[0].nextElementSibling, undefined);
assert.match(links[1].nextElementSibling.textContent, /Enlace sospechoso/);
const panel = body.children.find(item => item.className === 'escudo-mail-panel');
assert.ok(panel, 'Gmail must render a warning in the message');
assert.match(panel.children[1].children[0].textContent, /Alerta de enlace sospechoso/);
const actions = panel.children[1].children[2];
assert.equal(actions.children[0].textContent, 'No abrir');
assert.equal(actions.children[1].textContent, 'Ver detalles');
const info = panel.children[1].children[3];
assert.equal(info.hidden, true);
actions.children[1].listeners.click();
assert.equal(info.hidden, false);
assert.match(info.children[0].textContent, /https:\/\/example.com\//);
assert.match(info.children[1].children[0].textContent, /VirusTotal/);
let prevented = false;
listeners.click({ target: { closest() { return links[1]; } }, button: 0,
  preventDefault() { prevented = true; }, stopImmediatePropagation() {} });
assert.equal(prevented, true, 'red mail link must not open');
console.log('Correo: alerta dentro del mensaje, detalles reales, bloqueo y modelo aislado sin aviso');
