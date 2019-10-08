# mceliece-nist

This package provides Node.js bindings for the reference implementation that is
part of the [NIST submission](https://classic.mceliece.org/nist.html) by
Bernstein et al.

## Installation

Currently, installation requires `xsltproc` to compile XKCP. Apart from that,
install as usual:

```sh
npm i mceliece-nist
```

## Example

```javascript
const { McEliece } = require('mceliece-nist');

const kem = new McEliece('mceliece8192128');
const { publicKey, privateKey } = kem.keypair();

const { key, encryptedKey } = kem.generateKey(publicKey);
console.log(`Bob is using the key ${key.toString('hex')}`);

const receivedKey = kem.decryptKey(privateKey, encryptedKey);
console.log(`Alice is using the key ${receivedKey.toString('hex')}`);
```

## API

The package exports a single class, `McEliece`.

### Class `McEliece`

#### `new McEliece(algorithm)`

Creates a new instance using the specified algorithm. `algorithm` must be one of
the values contained in `McEliece.supportedAlgorithms`.

#### `McEliece.supportedAlgorithms`

This static field is an array of all supported algorithms.

#### `instance.keySize`

The (maximum) key size in bytes that this instance can encapsulate.

#### `instance.encryptedKeySize`

The size of the encapsulated key in bytes.

#### `instance.publicKeySize`

The size of the public key in bytes.

#### `instance.privateKeySize`

The size of the private key in bytes.

#### `instance.keypair()`

Creates and returns a new key pair `{ publicKey, privateKey }`. Both keys will
be returned as `Buffer`s.

#### `instance.generateKey(publicKey)`

Generates a new symmetric key and encrypts it using the given publicKey. Returns
`{ key, encryptedKey }`, both objects will be `Buffer`s.

#### `instance.decryptKey(privateKey, encryptedKey)`

Decrypts the `encryptedKey` that was returned by
`instance.generateKey(publicKey)` and returns the decrypted key as a `Buffer`.

## License

This project is distributed under the ISC license. However, the files contained
in the submodule `deps/KeccakCodePackage` are distributed under the terms
described in `deps/KeccakCodePackage/README.markdown`.
