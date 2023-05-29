# Reference implementation of Classic McEliece

The `kem` directory contains the reference implementation of the Classic
McEliece KEM that was provided by Bernstein et al. as part of the
[Classic McEliece NIST submission](https://classic.mceliece.org/nist.html).

- Source: Round-4 submission package
- Revision: `mceliece-20221023`
- File: [`mceliece-20221023.tar.gz`](https://classic.mceliece.org/nist/mceliece-20221023.tar.gz)
  - `37bc7bddf9b061cb52992afe27f40f82` (md5)
  - `e939e24b0f840a1a78c474575b846c50986d4651` (sha1)
  - `sha256: 0428f1c9aeb3472ab580f21693d7fa26ccc92f29beee40a78cc88dab79dfb7a3` (sha256)

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
  AES256-CTR. Instead, we patch the implementation to use the random number
  generator provided by OpenSSL via
  [`mceliece_externals.h`](mceliece_externals.h).
- Files that are not required for providing bindings for the reference
  implementation are removed (e.g., `KATNUM`).
