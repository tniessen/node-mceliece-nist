const assert = require('assert');

const { McEliece } = require('./');

assert(Array.isArray(McEliece.supportedAlgorithms));
assert(McEliece.supportedAlgorithms.length >= 2);

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
