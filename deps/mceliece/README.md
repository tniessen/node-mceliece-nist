# Reference implementation of Classic McEliece

The `kem` directory contains the reference implementation of the Classic
McEliece KEM that was provided by Bernstein et al. as part of the
[Classic McEliece NIST submission](https://classic.mceliece.org/nist.html).

- Source: Round-3 submission package
- Revision: `mceliece-20201010`
- File: [`mceliece-20201010.tar.gz`](https://classic.mceliece.org/nist/mceliece-20201010.tar.gz)
  - `3efe3af6b08c84743589d8bdb98e9c79` (md5)
  - `7095f7b5776e836a13d6e6d4b75d2704df1d412a` (sha1)
  - `1b8aca59430ca7a0569e4e918e1c0c165f67dd0ccde44760f314eaa40f75dafe` (sha256)

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
