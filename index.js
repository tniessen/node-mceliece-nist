'use strict';

let McEliece;
try {
  // Try to load native bindings first.
  ({ McEliece } = require('bindings')('node_mceliece'));
} catch (err) {
  // If native bindings are not available, use WebAssembly instead.
  ({ McEliece } = require('./wasm/main_thread'));
  process.emitWarning(`Using WebAssembly backend: ${err.message}`);
}

Object.defineProperty(module.exports, 'McEliece', { value: McEliece });
