let McEliece;
try {
  // Try to load native bindings first.
  ({ McEliece } = require('bindings')('node_mceliece'));
} catch (err) {
  // If native bindings are not available, use WebAssembly instead.
  ({ McEliece } = require('./wasm'));
  process.emitWarning(`Using WebAssembly backend: ${err.message}`);
}

module.exports.McEliece = McEliece;
