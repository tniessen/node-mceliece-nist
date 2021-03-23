#ifndef _EXTERNALS_H
#define _EXTERNALS_H

#include <stddef.h>

#ifndef NO_SHORT_NAMES_FOR_EXTERNALS
# define randombytes            pqcrypto_mceliece_randombytes
# define SHAKE256               pqcrypto_mceliece_SHAKE256
#endif

#ifdef __EMSCRIPTEN__
# define WASM_EXTERN extern
#else
# define WASM_EXTERN
#endif

WASM_EXTERN
int pqcrypto_mceliece_randombytes(unsigned char*, size_t);

WASM_EXTERN
int pqcrypto_mceliece_SHAKE256(unsigned char*, size_t,
                               const unsigned char*, size_t);

#endif
