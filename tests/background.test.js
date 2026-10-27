const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const rules = [];
let lookup = { reputation: { status: 'found', malicious: 2, suspicious: 0 } };
let listener;
let requestedEndpoint;
const chrome = {
  runtime: { onMessage: { addListener(callback) { listener = callback; } } },
  declarativeNetRequest: {
    async getSessionRules() { return [...rules]; },
    async updateSessionRules({ addRules }) { rules.push(...addRules); }
  }
};
const context = {
  URL, Promise, chrome, AbortSignal,
  ESCUDO_CONFIG: { API_BASE_URL: 'https://escudo-test.run.app' },
  fetch: async (url) => {
    requestedEndpoint = url;
    return { ok: true, json: async () => lookup };
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('extension/scripts/background.js', 'utf8'), context);
function send(url) {
  return new Promise((resolve) => listener({ type: 'REMOTE_LOOKUP', url }, {}, resolve));
}
(async () => {
  const target = 'https://example.com/login?x=1&y=2';
  await Promise.all([send(target), send(target)]);
  assert.ok(requestedEndpoint.startsWith('https://escudo-test.run.app/analyze?url='));
  assert.equal(new URL(requestedEndpoint).searchParams.get('url'), target);
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
  lookup = { google_safe_browsing: { status: 'match', threat_types: ['SOCIAL_ENGINEERING'] } };
  await send('https://google-confirmed.example/');
  assert.equal(rules.length, 2);
  lookup = { phishtank: { status: 'found', in_database: true, verified: true, valid: true } };
  await send('https://phishtank-confirmed.example/');
  assert.equal(rules.length, 3);
  lookup = { ipqualityscore: { status: 'found', risk_score: 92, unsafe: true, phishing: true, malware: false } };
  await send('https://ipqs-confirmed.example/');
  assert.equal(rules.length, 4);
  lookup = { ipqualityscore: { status: 'found', risk_score: 65, unsafe: false, suspicious: true, phishing: false, malware: false } };
  await send('https://ipqs-weak.example/');
  assert.equal(rules.length, 4);
  lookup = {
    reputation: { status: 'found', malicious: 1, suspicious: 0 },
    ipqualityscore: { status: 'found', risk_score: 65, unsafe: false, suspicious: true, phishing: false, malware: false }
  };
  await send('https://two-weak.example/');
  assert.equal(rules.length, 5);
  console.log('Bloqueo automático: una señal fuerte o dos señales débiles; una débil no bloquea');
})().catch((error) => { console.error(error); process.exitCode = 1; });
