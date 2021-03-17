'use strict';

const assert = require('assert');

const { McEliece } = require('./');

assert(Array.isArray(McEliece.supportedAlgorithms));
assert(McEliece.supportedAlgorithms.length >= 2);
assert.throws(() => McEliece.supportedAlgorithms = []);
assert.throws(() => McEliece.supportedAlgorithms.shift());

for (const algorithm of McEliece.supportedAlgorithms) {
  console.log(`Testing ${algorithm}`);

  const kem = new McEliece(algorithm);
  const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

  console.log(`  Key size: ${keySize}`);
  console.log(`  Encrypted key size: ${encryptedKeySize}`);
  console.log(`  Public key size: ${publicKeySize}`);
  console.log(`  Private key size: ${privateKeySize}`);

  // Generate a key pair.
  const { publicKey, privateKey } = kem.keypair();
  assert(Buffer.isBuffer(publicKey));
  assert.strictEqual(publicKey.length, publicKeySize);
  assert(Buffer.isBuffer(privateKey));
  assert.strictEqual(privateKey.length, privateKeySize);

  // Encrypt and decrypt some keys.
  for (let i = 0; i < 10; i++) {
    const { key, encryptedKey } = kem.generateKey(publicKey);
    assert.strictEqual(key.length, keySize);
    assert.strictEqual(encryptedKey.length, encryptedKeySize);

    const receivedKey = kem.decryptKey(privateKey, encryptedKey);
    assert.deepStrictEqual(receivedKey, key);
  }
}

// Use static test vectors to make sure that the output is correct.
const vectors = require('./test_vectors');
for (const { algorithm, privateKey, encryptedKey, key } of vectors) {
  console.log(`Testing ${algorithm} with key ${key}`);
  const kem = new McEliece(algorithm);
  const receivedKey = kem.decryptKey(Buffer.from(privateKey, 'base64'),
                                     Buffer.from(encryptedKey, 'base64'));
  assert.strictEqual(receivedKey.toString('base64'), key);
}

// Keep track of algorithms that passed asynchronous tests.
const workingAsyncAlgorithms = [];
process.on('exit', () => {
  assert.strictEqual(workingAsyncAlgorithms.length,
                     McEliece.supportedAlgorithms.length);
});

for (const algorithm of McEliece.supportedAlgorithms) {
  console.log(`Testing async ${algorithm}`);

  const kem = new McEliece(algorithm);
  const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

  // This variable will be set to true synchronously in order to detect whether
  // the main thread was blocked.
  let wasAsync = false;

  kem.keypair((err, result) => {
    assert(wasAsync);
    assert.ifError(err);

    const { publicKey, privateKey } = result;

    assert(Buffer.isBuffer(publicKey));
    assert.strictEqual(publicKey.length, publicKeySize);
    assert(Buffer.isBuffer(privateKey));
    assert.strictEqual(privateKey.length, privateKeySize);

    const { key, encryptedKey } = kem.generateKey(publicKey);
    assert.strictEqual(key.length, keySize);
    assert.strictEqual(encryptedKey.length, encryptedKeySize);

    wasAsync = false;
    kem.decryptKey(privateKey, encryptedKey, (err, receivedKey) => {
      assert(wasAsync);

      assert.ifError(err);
      assert.deepStrictEqual(receivedKey, key);

      workingAsyncAlgorithms.push(algorithm);
    });

    wasAsync = true;
  });

  wasAsync = true;
}
