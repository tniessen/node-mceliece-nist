const { parentPort, workerData } = require('worker_threads');

const { createClass } = require('./impl');

const { mod, algorithm, op, args } = workerData;
const me = new (createClass(mod))(algorithm);

let response;
try {
  response = {
    result: me[op](...args)
  };
} catch (err) {
  response = { err };
}
parentPort.postMessage(response);
