/* This file uses SHAKE256 implemented in the Keccak Code Package */

#include "../../mceliece_externals.h" 

#define crypto_hash_32b(out,in,inlen) \
  SHAKE256(out,32,in,inlen)

#define shake(out,outlen,in,inlen) \
  SHAKE256(out,outlen,in,inlen)

