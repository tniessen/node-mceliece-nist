const { readFileSync } = require('fs');
const { join } = require('path');

const { createClass } = require('./impl');

const mod = new WebAssembly.Module(readFileSync(join(__dirname, 'mceliece.wasm')));
module.exports.McEliece = createClass(mod);
