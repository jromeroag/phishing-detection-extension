const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const context = { URL }; vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js', 'utf8'), context);
const analyzer = context.EscudoAnalyzer;
const weakSignal = analyzer.createEvidence('TEST_WEAK', {
  scoreContribution: 1, severity: 'medium', contributesToDecision: true
});
const secondWeakSignal = analyzer.createEvidence('TEST_WEAK_2', {
  scoreContribution: 1, severity: 'medium', contributesToDecision: true
});
const strongSignal = analyzer.createEvidence('TEST_STRONG', {
  scoreContribution: 1, severity: 'high', contributesToDecision: true
});
assert.equal(analyzer.classifyRisk(0, []), 'low');
assert.equal(analyzer.classifyRisk(15, [weakSignal]), 'medium');
assert.equal(analyzer.classifyRisk(2, [weakSignal, secondWeakSignal]), 'high');
assert.equal(analyzer.classifyRisk(1, [strongSignal]), 'high');
assert.equal(analyzer.analyzeURL('http://127.0.0.1:8000/').score, 0);
assert.equal(analyzer.analyzeURL('https://example.com/login').score, 0);
const oneLocalSignal = analyzer.analyzeURL('https://xn--fiq228c.example/');
assert.equal(oneLocalSignal.score, 10);
assert.equal(oneLocalSignal.signalCount, 1);
assert.equal(oneLocalSignal.level, 'medium');
const twoLocalSignals = analyzer.analyzeURL('https://a-b-c-login.example/');
assert.equal(twoLocalSignals.score, 20);
assert.equal(twoLocalSignals.signalCount, 2);
assert.equal(twoLocalSignals.level, 'high');
const fakeBcp = analyzer.analyzeURL('https://alerta-viabcp.com/en');
assert.equal(fakeBcp.level, 'high');
assert.equal(fakeBcp.score, 45);
assert.equal(fakeBcp.evidence[0].id, 'BRAND_IMPERSONATION');
assert.equal(fakeBcp.evidence[0].source, 'url');
assert.equal(fakeBcp.evidence[0].observedValue, 'alerta-viabcp.com');
assert.equal(fakeBcp.evidence[0].scoreContribution, 45);
for (const deceptive of ['https://viabcp-seguridad.com/', 'https://login-viabcp.net/', 'https://viabcp.com.ejemplo.com/']) {
  assert.equal(analyzer.analyzeURL(deceptive).level, 'high', deceptive);
  assert.ok(analyzer.analyzeURL(deceptive).evidence.some((item) => item.id === 'BRAND_IMPERSONATION'));
}
for (const official of ['https://viabcp.com/', 'https://www.viabcp.com/', 'https://seguridad.viabcp.com/', 'https://viabcp.com.pe/']) {
  assert.equal(analyzer.analyzeURL(official).score, 0, official);
}
const credentialRisk = analyzer.analyzeURL('https://usuario@login-verificar.example/');
assert.equal(credentialRisk.level, 'high');
assert.equal(credentialRisk.evidence[0].id, 'URL_CREDENTIALS');
assert.equal(credentialRisk.evidence[0].source, 'url');
assert.equal(credentialRisk.evidence[0].scoreContribution, 45);
assert.equal(credentialRisk.evidence[0].contributesToDecision, true);
assert.ok(credentialRisk.evidence[0].observedValue);
const combined = analyzer.combine(analyzer.analyzeURL('https://example.com/'), {score: 25,reasons:['Formulario HTTP']});
assert.equal(combined.level, 'medium');
assert.equal(combined.reasons[0], 'Formulario HTTP');
const modelOnly = analyzer.scoreRemote({model:{probability:.96}, reputation:{status:'not_found'}});
const linkedin = analyzer.combine(analyzer.analyzeURL('https://www.linkedin.com/in/jromeroag/'), modelOnly);
assert.equal(linkedin.score, 0);
assert.equal(linkedin.level, 'low');
assert.match(linkedin.reasons.at(-1), /no está validado/);
const longURL = 'https://www.facebook.com/' + 'a'.repeat(130);
assert.equal(analyzer.analyzeURL(longURL).score, 0);
assert.equal(analyzer.combine(analyzer.analyzeURL(longURL), modelOnly).score, 0);
assert.equal(analyzer.analyzeURL('https://www.facebook.com/' + 'a'.repeat(300)).score, 0);
assert.equal(analyzer.analyzeURL('https://a-b-c-login.example/' + 'a'.repeat(220)).score, 25);
const correlatedSignals = analyzer.analyzeURL('https://a-b-c-login.example/');
assert.equal(analyzer.combine(correlatedSignals, modelOnly).score, 20);
const google = analyzer.combine(analyzer.analyzeURL('https://www.google.com/webhp?hl=es&sa=X'),
  analyzer.scoreRemote({model:{probability:1},reputation:{status:'found',malicious:0,suspicious:0,total:90}}));
assert.equal(google.score, 0);
assert.equal(google.level, 'low');
const oneEngine = analyzer.scoreRemote({reputation:{status:'found',malicious:1,suspicious:0}, model:{probability:.96}});
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), oneEngine).level, 'high');
const belowThreshold = analyzer.scoreRemote({reputation:{status:'found',malicious:1,suspicious:0}, model:{probability:.59}});
assert.equal(belowThreshold.score, 15);
assert.doesNotMatch(belowThreshold.reasons.join(' '), /modelo también/i);
const atThreshold = analyzer.scoreRemote({reputation:{status:'found',malicious:1,suspicious:0}, model:{probability:.60}});
assert.equal(atThreshold.score, 20);
assert.match(atThreshold.reasons.join(' '), /modelo también/i);
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), atThreshold).level, 'high');
const twoEngines = analyzer.scoreRemote({reputation:{status:'found',malicious:2,suspicious:0}, model:null});
assert.equal(twoEngines.evidence[0].id, 'VT_MALICIOUS');
assert.equal(twoEngines.evidence[0].source, 'virustotal');
assert.equal(twoEngines.evidence[0].observedValue, '2 detecciones');
assert.equal(twoEngines.evidence[0].scoreContribution, 30);
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), twoEngines).level, 'high');
const googleThreat = analyzer.scoreRemote({
  google_safe_browsing:{status:'match',threat_types:['SOCIAL_ENGINEERING']}, model:null
});
assert.equal(googleThreat.score, 40);
assert.equal(googleThreat.evidence[0].id, 'GSB_THREAT');
assert.equal(googleThreat.evidence[0].source, 'google_safe_browsing');
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), googleThreat).level, 'high');
const phishtankThreat = analyzer.scoreRemote({
  phishtank:{status:'found',in_database:true,verified:true,valid:true,phish_id:42}, model:null
});
assert.equal(phishtankThreat.score, 40);
assert.equal(phishtankThreat.evidence[0].id, 'PHISHTANK_VERIFIED');
const ipqsThreat = analyzer.scoreRemote({
  ipqualityscore:{status:'found',risk_score:92,unsafe:true,suspicious:true,phishing:true,malware:false}, model:null
});
assert.equal(ipqsThreat.score, 35);
assert.equal(ipqsThreat.evidence[0].id, 'IPQS_HIGH_RISK');
const ipqsWeak = analyzer.scoreRemote({
  ipqualityscore:{status:'found',risk_score:65,unsafe:false,suspicious:true,phishing:false,malware:false}, model:null
});
assert.equal(ipqsWeak.score, 15);
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), ipqsWeak).level, 'medium');
const twoIndependentWeak = analyzer.scoreRemote({
  reputation:{status:'found',malicious:1,suspicious:0},
  ipqualityscore:{status:'found',risk_score:65,unsafe:false,suspicious:true,phishing:false,malware:false},
  model:null
});
assert.equal(twoIndependentWeak.needsCorroboration, false);
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), twoIndependentWeak).level, 'high');
assert.equal(analyzer.combine(analyzer.analyzeURL('https://usuario@example.com/'), modelOnly).level, 'high');
assert.equal(modelOnly.evidence[0].contributesToDecision, false);
assert.equal(modelOnly.evidence[0].scoreContribution, 0);
console.log('Analizador y combinación: correctos');
