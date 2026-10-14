const assert = require('node:assert/strict');
const fs = require('node:fs');

const active = JSON.parse(fs.readFileSync('backend/model.json', 'utf8'));
const candidate = JSON.parse(fs.readFileSync('backend/model_v2.json', 'utf8'));

assert.deepEqual(active, candidate, 'backend/model.json debe coincidir con model_v2.json');
assert.equal(active.features.length, 14, 'el modelo v2 activo debe usar sus 14 características');

console.log('Modelo activo: model_v2.json correctamente instalado como model.json');
