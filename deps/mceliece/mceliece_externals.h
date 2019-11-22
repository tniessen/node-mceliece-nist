#ifndef _EXTERNALS_H
#define _EXTERNALS_H

#include <stddef.h>

#ifndef NO_SHORT_NAMES_FOR_EXTERNALS
# define randombytes            pqcrypto_mceliece_randombytes
# define aes256ctr              pqcrypto_mceliece_aes256ctr
# define KeccakWidth1600_Sponge pqcrypto_mceliece_KeccakWidth1600_Sponge
#endif

#ifdef __EMSCRIPTEN__
# define WASM_EXTERN extern
#else
# define WASM_EXTERN
#endif

WASM_EXTERN
int pqcrypto_mceliece_randombytes(unsigned char*, size_t);

WASM_EXTERN
int pqcrypto_mceliece_aes256ctr(unsigned char*, size_t,
                                const unsigned char*, const unsigned char*);

WASM_EXTERN
int pqcrypto_mceliece_KeccakWidth1600_Sponge(unsigned int,
                                             unsigned int,
                                             const unsigned char*,
                                             size_t,
                                             unsigned char,
                                             unsigned char*,
                                             size_t);

#endif
