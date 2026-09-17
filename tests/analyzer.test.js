const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const context = { URL }; vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/services/analyzer.js', 'utf8'), context);
const analyzer = context.EscudoAnalyzer;
for (const [score, expected] of [[0,'low'],[1,'medium'],[25,'medium'],[26,'high'],[100,'high']]) {
  assert.equal(analyzer.classifyRisk(score), expected);
}
assert.equal(analyzer.analyzeURL('http://127.0.0.1:8000/').score, 0);
assert.equal(analyzer.analyzeURL('https://example.com/login').score, 0);
assert.equal(analyzer.analyzeURL('https://a-b-c-login.example/').score, 20);
assert.equal(analyzer.analyzeURL('https://usuario@login-verificar.example/').level, 'high');
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
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), oneEngine).level, 'medium');
const twoEngines = analyzer.scoreRemote({reputation:{status:'found',malicious:2,suspicious:0}, model:null});
assert.equal(analyzer.combine(analyzer.analyzeURL('https://example.com/'), twoEngines).level, 'high');
assert.equal(analyzer.combine(analyzer.analyzeURL('https://usuario@example.com/'), modelOnly).level, 'high');
console.log('Analizador y combinación: correctos');
