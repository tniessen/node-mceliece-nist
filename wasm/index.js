const assert = require('assert');
const { createCipheriv, createHash, randomFillSync } = require('crypto');
const { readFileSync } = require('fs');
const { join } = require('path');

const constants = require('./mceliece_constants.js');

const mod = new WebAssembly.Module(readFileSync(join(__dirname, 'mceliece.wasm')));

function bytes(offset, length) {
  return Buffer.from(instance.exports.memory.buffer, offset, length);
}

const instance = new WebAssembly.Instance(mod, {
  env: {
    pqcrypto_mceliece_randombytes(ptr, count) {
      randomFillSync(bytes(ptr, count));
    },
    pqcrypto_mceliece_aes256ctr(outPtr, outlen, noncePtr, keyPtr) {
      const out = bytes(outPtr, outlen);
      const nonce = bytes(noncePtr, 16);
      const key = bytes(keyPtr, 32);

      createCipheriv('aes-256-ctr', key, nonce)
      .update(Buffer.alloc(outlen))
      .copy(out);
    },
    pqcrypto_mceliece_KeccakWidth1600_Sponge(rate, capacity, inputPtr, inputByteLen, suffix, outputPtr, outputByteLen) {
      assert.strictEqual(rate, 1088);
      assert.strictEqual(capacity, 512);
      assert.strictEqual(suffix, 0x1f);
      assert.strictEqual(outputByteLen, 32);

      const input = bytes(inputPtr, inputByteLen);
      const out = bytes(outputPtr, outputByteLen);

      createHash('shake256')
      .update(input)
      .digest()
      .copy(out);
    }
  }
});

function alg(name) {
  const ns = `crypto_kem_${name}_ref`;
  return {
    name,
    publicKeySize: constants[`${ns}_PUBLICKEYBYTES`],
    privateKeySize: constants[`${ns}_SECRETKEYBYTES`],
    keySize: constants[`${ns}_BYTES`],
    ciphertextSize: constants[`${ns}_CIPHERTEXTBYTES`],
    keypair: instance.exports[`${ns}_keypair`],
    encrypt: instance.exports[`${ns}_enc`],
    decrypt: instance.exports[`${ns}_dec`]
  };
}

const kems = Object.fromEntries([
  'mceliece348864',
  'mceliece348864f',
  'mceliece460896',
  'mceliece460896f',
  'mceliece6688128',
  'mceliece6688128f',
  'mceliece6960119',
  'mceliece6960119f',
  'mceliece8192128',
  'mceliece8192128f'
].map(name => [name, alg(name)]));

const kImpl = Symbol();

class McEliece {
  constructor(name) {
    if ((this[kImpl] = kems[name]) === undefined)
      throw new Error('No such implementation');
  }

  get keySize() {
    return this[kImpl].keySize;
  }

  get encryptedKeySize() {
    return this[kImpl].ciphertextSize;
  }

  get publicKeySize() {
    return this[kImpl].publicKeySize;
  }

  get privateKeySize() {
    return this[kImpl].privateKeySize;
  }

  keypair(callback) {
    const { publicKeySize, privateKeySize, keypair } = this[kImpl];

    const publicKeyPtr = instance.exports.malloc(publicKeySize);
    const privateKeyPtr = instance.exports.malloc(privateKeySize);

    const ret = keypair(publicKeyPtr, privateKeyPtr);
    try {
      if (ret !== 0)
        throw new Error('failed to generate keypair');

      const publicKey = Buffer.from(bytes(publicKeyPtr, publicKeySize));
      const privateKey = Buffer.from(bytes(privateKeyPtr, privateKeySize));
      if (callback)
        return callback(undefined, publicKey, privateKey);
      return { publicKey, privateKey };
    } catch (err) {
      if (callback)
        return callback(err);
      throw err;
    } finally {
      instance.exports.free(publicKeyPtr);
      instance.exports.free(privateKeyPtr);
    }
  }

  generateKey(publicKey) {
    const { publicKeySize, keySize, ciphertextSize, encrypt } = this[kImpl];

    if (publicKey.length !== publicKeySize)
      throw new TypeError('Invalid public key size');

    const publicKeyPtr = instance.exports.malloc(publicKeySize);
    const encryptedKeyPtr = instance.exports.malloc(ciphertextSize);
    const keyPtr = instance.exports.malloc(keySize);

    publicKey.copy(bytes(publicKeyPtr, publicKeySize));

    const ret = encrypt(encryptedKeyPtr, keyPtr, publicKeyPtr);
    try {
      if (ret !== 0)
        throw new Error('encryption failed');

      return {
        key: Buffer.from(bytes(keyPtr, keySize)),
        encryptedKey: Buffer.from(bytes(encryptedKeyPtr, ciphertextSize))
      };
    } finally {
      instance.exports.free(publicKeyPtr);
      instance.exports.free(encryptedKeyPtr);
      instance.exports.free(keyPtr);
    }
  }

  decryptKey(privateKey, encryptedKey, callback) {
    const { privateKeySize, ciphertextSize, keySize, decrypt } = this[kImpl];

    if (privateKey.length !== privateKeySize)
      throw new TypeError('Invalid private key size');

    if (encryptedKey.length !== ciphertextSize)
      throw new TypeError('Invalid ciphertext size');

    const privateKeyPtr = instance.exports.malloc(privateKeySize);
    const encryptedKeyPtr = instance.exports.malloc(ciphertextSize);
    const keyPtr = instance.exports.malloc(keySize);

    privateKey.copy(bytes(privateKeyPtr, privateKeySize));
    encryptedKey.copy(bytes(encryptedKeyPtr, ciphertextSize));

    const ret = decrypt(keyPtr, encryptedKeyPtr, privateKeyPtr);
    try {
      if (ret !== 0)
        throw new Error('decryption failed');

      const key = Buffer.from(bytes(keyPtr, keySize));
      if (callback)
        return callback(undefined, key);
      return key;
    } catch (err) {
      if (callback)
        return callback(err);
      throw err;
    } finally {
      instance.exports.free(privateKeyPtr);
      instance.exports.free(encryptedKeyPtr);
      instance.exports.free(keyPtr);
    }
  }
}

McEliece.supportedAlgorithms = Object.keys(kems);

module.exports.McEliece = McEliece;
