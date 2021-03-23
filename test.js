'use strict';

const test = require('tape');

const { McEliece } = require('./');

test('McEliece constructor', (t) => {
  t.plan(1);

  t.throws(() => new McEliece('foo'),
           /No such implementation/,
           'should throw if the algorithm does not exist');
});

test('McEliece.supportedAlgorithms', (t) => {
  t.plan(4);

  t.ok(Array.isArray(McEliece.supportedAlgorithms),
       'supportedAlgorithms should be an array');

  t.ok(McEliece.supportedAlgorithms.length >= 2,
       'supportedAlgorithms should contain multiple algorithms');

  t.throws(() => McEliece.supportedAlgorithms = [],
           'supportedAlgorithms should not be writable');

  t.throws(() => McEliece.supportedAlgorithms.shift(),
           'supportedAlgorithms should not be modifiable');
});

for (const algorithm of McEliece.supportedAlgorithms) {
  test(`properties of ${algorithm}`, (st) => {
    const [, n, t] = /^mceliece(\d{4})(\d{2,3})f?$/.exec(algorithm);
    const m = Math.ceil(Math.log2(n));
    const k = n - m * t;
    st.ok(k > 0 && Number.isSafeInteger(k), 'n, k, t should be valid');

    const kem = new McEliece(algorithm);
    st.equal(kem.keySize, 32, 'keySize should be 32 bytes');
    st.equal(kem.encryptedKeySize, Math.ceil(m * t / 8) + 32,
             'encryptedKeySize should be ceil(m * t / 8) + 32 bytes');
    st.equal(kem.publicKeySize, m * t * Math.ceil(k / 8),
             'publicKeySize should be m * t * ceil(k / 8) bytes');
    st.equal(kem.privateKeySize,
             Math.ceil(n / 8) +                    // s
             t * Math.ceil(m / 8) +                // g_0, ..., g_(t-1)
             Math.ceil((2 * m - 1) * 2**(m - 4)),  // alpha_1, ..., alpha_n
             'privateKeySize should be ceil(n / 8) + t * ceil(m / 8) + ' +
             'ceil((2m - 1) * 2**(m - 4)) bytes');

    st.end();
  });

  test(`synchronous ${algorithm}`, (t) => {
    const kem = new McEliece(algorithm);
    const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

    // Generate a key pair.
    const { publicKey, privateKey } = kem.keypair();

    t.ok(Buffer.isBuffer(publicKey),
         'publicKey should be a Buffer');
    t.equal(publicKey.length, publicKeySize,
            `publicKey.length should be ${publicKeySize}`);
    t.ok(Buffer.isBuffer(privateKey),
         'privateKey should be a Buffer');
    t.equal(privateKey.length, privateKeySize,
            `privateKey.length should be ${privateKeySize}`);

    // Encrypt and decrypt.
    const { key, encryptedKey } = kem.generateKey(publicKey);
    t.equal(key.length, keySize,
            `key.length should be ${keySize}`);
    t.equal(encryptedKey.length, encryptedKeySize,
            `encryptedKey.length should be ${encryptedKeySize}`);

    const receivedKey = kem.decryptKey(privateKey, encryptedKey);
    t.deepEqual(receivedKey, key, 'decrypted key should match generated key');

    t.end();
  });

  test(`asynchronous ${algorithm}`, (t) => {
    const kem = new McEliece(algorithm);
    const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

    // This variable will be set to true synchronously in order to detect whether
    // the main thread was blocked.
    let wasAsync = false;

    kem.keypair((err, result) => {
      t.ok(wasAsync, 'keypair with callback should be async');
      t.error(err, 'decryptKey should not fail');

      const { publicKey, privateKey } = result;

      t.ok(Buffer.isBuffer(publicKey),
           'publicKey should be a Buffer');
      t.equal(publicKey.length, publicKeySize,
              `publicKey.length should be ${publicKeySize}`);
      t.ok(Buffer.isBuffer(privateKey),
           'privateKey should be a Buffer');
      t.equal(privateKey.length, privateKeySize,
              `privateKey.length should be ${privateKeySize}`);

      const { key, encryptedKey } = kem.generateKey(publicKey);
      t.equal(key.length, keySize,
              `key.length should be ${keySize}`);
      t.equal(encryptedKey.length, encryptedKeySize,
              `encryptedKey.length should be ${encryptedKeySize}`);

      wasAsync = false;
      kem.decryptKey(privateKey, encryptedKey, (err, receivedKey) => {
        t.ok(wasAsync, 'decryptKey with callback should be async');
        t.error(err, 'decryptKey should not fail');

        t.deepEqual(receivedKey, key,
                    'decrypted key should match generated key');
        t.end();
      });

      wasAsync = true;
    });

    wasAsync = true;
  });
}

// Use static test vectors to make sure that the output is correct.
test('KAT test vectors', (t) => {
  const vectors = require('./test_vectors');
  t.plan(vectors.length);

  for (const { algorithm, privateKey, encryptedKey, key } of vectors) {
    const kem = new McEliece(algorithm);
    const receivedKey = kem.decryptKey(Buffer.from(privateKey, 'base64'),
                                       Buffer.from(encryptedKey, 'base64'));
    t.equal(receivedKey.toString('base64'), key,
            `KAT vector for ${algorithm} should produce ${key}`);
  }
});
