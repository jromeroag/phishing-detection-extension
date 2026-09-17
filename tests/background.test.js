const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const rules = [];
let lookup = { reputation: { status: 'found', malicious: 2, suspicious: 0 } };
let listener;
const chrome = {
  runtime: { onMessage: { addListener(callback) { listener = callback; } } },
  declarativeNetRequest: {
    async getSessionRules() { return [...rules]; },
    async updateSessionRules({ addRules }) { rules.push(...addRules); }
  }
};
const context = { URL, Promise, chrome, AbortSignal, fetch: async () => ({ ok: true, json: async () => lookup }) };
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/scripts/background.js', 'utf8'), context);
function send(url) {
  return new Promise((resolve) => listener({ type: 'REMOTE_LOOKUP', url }, {}, resolve));
}
(async () => {
  const target = 'https://example.com/login?x=1&y=2';
  await Promise.all([send(target), send(target)]);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].condition.resourceTypes[0], 'main_frame');
  assert.equal(rules[0].action.redirect.extensionPath, '/pages/blocked.html');
  assert.match(target, new RegExp(rules[0].condition.regexFilter));
  assert.doesNotMatch('https://example.com/login?x=other', new RegExp(rules[0].condition.regexFilter));
  assert.doesNotMatch('https://example.com/other', new RegExp(rules[0].condition.regexFilter));
  lookup = { reputation: { status: 'found', malicious: 1, suspicious: 0 } };
  await send('https://example.org/');
  assert.equal(rules.length, 1);
  lookup = { reputation: { status: 'not_found' } };
  await send('https://example.net/');
  assert.equal(rules.length, 1);
  console.log('Bloqueo automático: solo URL exacta confirmada, sin duplicados y sin bloquear evidencia débil');
})().catch((error) => { console.error(error); process.exitCode = 1; });
