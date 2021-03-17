# Reference implementation of Classic McEliece

The `kem` directory contains the reference implementation of the Classic
McEliece KEM that was provided by Bernstein et al. as part of the
[Classic McEliece NIST submission](https://classic.mceliece.org/nist.html).

- Source: Round-2 submission package
- Revision: `mceliece-20190331`
- File: [`mceliece-20190331.tar.gz`](https://classic.mceliece.org/nist/mceliece-20190331.tar.gz)
  - `e298f8bb1380a74d1f5990cb6e921f45` (md5)
  - `ec08d18f430601c6661a4d0cfe5f5592fb8d6edb` (sha1)
  - `3fa54e9139bb62338445047cb25ab73b0e1e576288f729d20ce4db8c2236f678` (sha256)

## Automatically applied patches

The `extract-kem-from-nist-submission` script was used to generate the contents
of the `kem` directory as well as the header file `mceliece.h` and the file
`binding.gyp`.

The contents of the `kem` directory correspond to the contents of the
`Reference_Implementation/kem` directory that is part of the submission package.
However, the `extract-kem-from-nist-submission` script applies the following
patches.

- The reference implementation uses libkeccak to implement SHAKE256. However,
  because Node.js uses OpenSSL by default, references to libkeccak header files
  are replaced with references to [`mceliece_externals.h`](mceliece_externals.h)
  that defines a compatible interface. The implementation of the interface
  uses OpenSSL.
- The reference implementation uses a random number generator that is based on
  AES256-CTR. Instead, we patch the implementation to use the AES implementation
  and the random number generator provided by OpenSSL via
  [`mceliece_externals.h`](mceliece_externals.h).
- Files that are not required for providing bindings for the reference
  implementation are removed (e.g., `KATNUM`).
