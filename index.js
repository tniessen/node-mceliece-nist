const { randomBytes } = require('crypto');
const { McEliece, seed } = require('bindings')('node_mceliece');

seed(randomBytes(48));
module.exports.McEliece = McEliece;
