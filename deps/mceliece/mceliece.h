#ifndef crypto_kem_mceliece348864_H
#define crypto_kem_mceliece348864_H

#define crypto_kem_mceliece348864_ref_PUBLICKEYBYTES 261120
#define crypto_kem_mceliece348864_ref_SECRETKEYBYTES 6452
#define crypto_kem_mceliece348864_ref_CIPHERTEXTBYTES 128
#define crypto_kem_mceliece348864_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece348864_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece348864_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece348864_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece348864_keypair crypto_kem_mceliece348864_ref_keypair
#define crypto_kem_mceliece348864_enc crypto_kem_mceliece348864_ref_enc
#define crypto_kem_mceliece348864_dec crypto_kem_mceliece348864_ref_dec
#define crypto_kem_mceliece348864_PUBLICKEYBYTES crypto_kem_mceliece348864_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece348864_SECRETKEYBYTES crypto_kem_mceliece348864_ref_SECRETKEYBYTES
#define crypto_kem_mceliece348864_BYTES crypto_kem_mceliece348864_ref_BYTES
#define crypto_kem_mceliece348864_CIPHERTEXTBYTES crypto_kem_mceliece348864_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece348864_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece348864_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece348864_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece348864_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece348864_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece348864_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece348864_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece348864f_H
#define crypto_kem_mceliece348864f_H

#define crypto_kem_mceliece348864f_ref_PUBLICKEYBYTES 261120
#define crypto_kem_mceliece348864f_ref_SECRETKEYBYTES 6452
#define crypto_kem_mceliece348864f_ref_CIPHERTEXTBYTES 128
#define crypto_kem_mceliece348864f_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece348864f_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece348864f_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece348864f_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece348864f_keypair crypto_kem_mceliece348864f_ref_keypair
#define crypto_kem_mceliece348864f_enc crypto_kem_mceliece348864f_ref_enc
#define crypto_kem_mceliece348864f_dec crypto_kem_mceliece348864f_ref_dec
#define crypto_kem_mceliece348864f_PUBLICKEYBYTES crypto_kem_mceliece348864f_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece348864f_SECRETKEYBYTES crypto_kem_mceliece348864f_ref_SECRETKEYBYTES
#define crypto_kem_mceliece348864f_BYTES crypto_kem_mceliece348864f_ref_BYTES
#define crypto_kem_mceliece348864f_CIPHERTEXTBYTES crypto_kem_mceliece348864f_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece348864f_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece348864f_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece348864f_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece348864f_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece348864f_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece348864f_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece348864f_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece460896_H
#define crypto_kem_mceliece460896_H

#define crypto_kem_mceliece460896_ref_PUBLICKEYBYTES 524160
#define crypto_kem_mceliece460896_ref_SECRETKEYBYTES 13568
#define crypto_kem_mceliece460896_ref_CIPHERTEXTBYTES 188
#define crypto_kem_mceliece460896_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece460896_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece460896_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece460896_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece460896_keypair crypto_kem_mceliece460896_ref_keypair
#define crypto_kem_mceliece460896_enc crypto_kem_mceliece460896_ref_enc
#define crypto_kem_mceliece460896_dec crypto_kem_mceliece460896_ref_dec
#define crypto_kem_mceliece460896_PUBLICKEYBYTES crypto_kem_mceliece460896_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece460896_SECRETKEYBYTES crypto_kem_mceliece460896_ref_SECRETKEYBYTES
#define crypto_kem_mceliece460896_BYTES crypto_kem_mceliece460896_ref_BYTES
#define crypto_kem_mceliece460896_CIPHERTEXTBYTES crypto_kem_mceliece460896_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece460896_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece460896_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece460896_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece460896_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece460896_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece460896_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece460896_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece460896f_H
#define crypto_kem_mceliece460896f_H

#define crypto_kem_mceliece460896f_ref_PUBLICKEYBYTES 524160
#define crypto_kem_mceliece460896f_ref_SECRETKEYBYTES 13568
#define crypto_kem_mceliece460896f_ref_CIPHERTEXTBYTES 188
#define crypto_kem_mceliece460896f_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece460896f_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece460896f_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece460896f_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece460896f_keypair crypto_kem_mceliece460896f_ref_keypair
#define crypto_kem_mceliece460896f_enc crypto_kem_mceliece460896f_ref_enc
#define crypto_kem_mceliece460896f_dec crypto_kem_mceliece460896f_ref_dec
#define crypto_kem_mceliece460896f_PUBLICKEYBYTES crypto_kem_mceliece460896f_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece460896f_SECRETKEYBYTES crypto_kem_mceliece460896f_ref_SECRETKEYBYTES
#define crypto_kem_mceliece460896f_BYTES crypto_kem_mceliece460896f_ref_BYTES
#define crypto_kem_mceliece460896f_CIPHERTEXTBYTES crypto_kem_mceliece460896f_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece460896f_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece460896f_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece460896f_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece460896f_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece460896f_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece460896f_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece460896f_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece6688128_H
#define crypto_kem_mceliece6688128_H

#define crypto_kem_mceliece6688128_ref_PUBLICKEYBYTES 1044992
#define crypto_kem_mceliece6688128_ref_SECRETKEYBYTES 13892
#define crypto_kem_mceliece6688128_ref_CIPHERTEXTBYTES 240
#define crypto_kem_mceliece6688128_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece6688128_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece6688128_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece6688128_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece6688128_keypair crypto_kem_mceliece6688128_ref_keypair
#define crypto_kem_mceliece6688128_enc crypto_kem_mceliece6688128_ref_enc
#define crypto_kem_mceliece6688128_dec crypto_kem_mceliece6688128_ref_dec
#define crypto_kem_mceliece6688128_PUBLICKEYBYTES crypto_kem_mceliece6688128_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece6688128_SECRETKEYBYTES crypto_kem_mceliece6688128_ref_SECRETKEYBYTES
#define crypto_kem_mceliece6688128_BYTES crypto_kem_mceliece6688128_ref_BYTES
#define crypto_kem_mceliece6688128_CIPHERTEXTBYTES crypto_kem_mceliece6688128_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece6688128_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece6688128_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece6688128_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece6688128_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece6688128_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece6688128_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece6688128_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece6688128f_H
#define crypto_kem_mceliece6688128f_H

#define crypto_kem_mceliece6688128f_ref_PUBLICKEYBYTES 1044992
#define crypto_kem_mceliece6688128f_ref_SECRETKEYBYTES 13892
#define crypto_kem_mceliece6688128f_ref_CIPHERTEXTBYTES 240
#define crypto_kem_mceliece6688128f_ref_BYTES 32

 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece6688128f_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece6688128f_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece6688128f_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece6688128f_keypair crypto_kem_mceliece6688128f_ref_keypair
#define crypto_kem_mceliece6688128f_enc crypto_kem_mceliece6688128f_ref_enc
#define crypto_kem_mceliece6688128f_dec crypto_kem_mceliece6688128f_ref_dec
#define crypto_kem_mceliece6688128f_PUBLICKEYBYTES crypto_kem_mceliece6688128f_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece6688128f_SECRETKEYBYTES crypto_kem_mceliece6688128f_ref_SECRETKEYBYTES
#define crypto_kem_mceliece6688128f_BYTES crypto_kem_mceliece6688128f_ref_BYTES
#define crypto_kem_mceliece6688128f_CIPHERTEXTBYTES crypto_kem_mceliece6688128f_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece6688128f_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece6688128f_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece6688128f_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece6688128f_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece6688128f_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece6688128f_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece6688128f_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece6960119_H
#define crypto_kem_mceliece6960119_H

#define crypto_kem_mceliece6960119_ref_PUBLICKEYBYTES 1047319
#define crypto_kem_mceliece6960119_ref_SECRETKEYBYTES 13908
#define crypto_kem_mceliece6960119_ref_CIPHERTEXTBYTES 226
#define crypto_kem_mceliece6960119_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece6960119_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece6960119_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece6960119_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece6960119_keypair crypto_kem_mceliece6960119_ref_keypair
#define crypto_kem_mceliece6960119_enc crypto_kem_mceliece6960119_ref_enc
#define crypto_kem_mceliece6960119_dec crypto_kem_mceliece6960119_ref_dec
#define crypto_kem_mceliece6960119_PUBLICKEYBYTES crypto_kem_mceliece6960119_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece6960119_SECRETKEYBYTES crypto_kem_mceliece6960119_ref_SECRETKEYBYTES
#define crypto_kem_mceliece6960119_BYTES crypto_kem_mceliece6960119_ref_BYTES
#define crypto_kem_mceliece6960119_CIPHERTEXTBYTES crypto_kem_mceliece6960119_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece6960119_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece6960119_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece6960119_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece6960119_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece6960119_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece6960119_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece6960119_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece6960119f_H
#define crypto_kem_mceliece6960119f_H

#define crypto_kem_mceliece6960119f_ref_PUBLICKEYBYTES 1047319
#define crypto_kem_mceliece6960119f_ref_SECRETKEYBYTES 13908
#define crypto_kem_mceliece6960119f_ref_CIPHERTEXTBYTES 226
#define crypto_kem_mceliece6960119f_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece6960119f_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece6960119f_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece6960119f_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece6960119f_keypair crypto_kem_mceliece6960119f_ref_keypair
#define crypto_kem_mceliece6960119f_enc crypto_kem_mceliece6960119f_ref_enc
#define crypto_kem_mceliece6960119f_dec crypto_kem_mceliece6960119f_ref_dec
#define crypto_kem_mceliece6960119f_PUBLICKEYBYTES crypto_kem_mceliece6960119f_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece6960119f_SECRETKEYBYTES crypto_kem_mceliece6960119f_ref_SECRETKEYBYTES
#define crypto_kem_mceliece6960119f_BYTES crypto_kem_mceliece6960119f_ref_BYTES
#define crypto_kem_mceliece6960119f_CIPHERTEXTBYTES crypto_kem_mceliece6960119f_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece6960119f_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece6960119f_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece6960119f_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece6960119f_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece6960119f_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece6960119f_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece6960119f_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece8192128_H
#define crypto_kem_mceliece8192128_H

#define crypto_kem_mceliece8192128_ref_PUBLICKEYBYTES 1357824
#define crypto_kem_mceliece8192128_ref_SECRETKEYBYTES 14080
#define crypto_kem_mceliece8192128_ref_CIPHERTEXTBYTES 240
#define crypto_kem_mceliece8192128_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece8192128_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece8192128_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece8192128_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece8192128_keypair crypto_kem_mceliece8192128_ref_keypair
#define crypto_kem_mceliece8192128_enc crypto_kem_mceliece8192128_ref_enc
#define crypto_kem_mceliece8192128_dec crypto_kem_mceliece8192128_ref_dec
#define crypto_kem_mceliece8192128_PUBLICKEYBYTES crypto_kem_mceliece8192128_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece8192128_SECRETKEYBYTES crypto_kem_mceliece8192128_ref_SECRETKEYBYTES
#define crypto_kem_mceliece8192128_BYTES crypto_kem_mceliece8192128_ref_BYTES
#define crypto_kem_mceliece8192128_CIPHERTEXTBYTES crypto_kem_mceliece8192128_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece8192128_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece8192128_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece8192128_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece8192128_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece8192128_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece8192128_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece8192128_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
#ifndef crypto_kem_mceliece8192128f_H
#define crypto_kem_mceliece8192128f_H

#define crypto_kem_mceliece8192128f_ref_PUBLICKEYBYTES 1357824
#define crypto_kem_mceliece8192128f_ref_SECRETKEYBYTES 14080
#define crypto_kem_mceliece8192128f_ref_CIPHERTEXTBYTES 240
#define crypto_kem_mceliece8192128f_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_mceliece8192128f_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_mceliece8192128f_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_mceliece8192128f_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_mceliece8192128f_keypair crypto_kem_mceliece8192128f_ref_keypair
#define crypto_kem_mceliece8192128f_enc crypto_kem_mceliece8192128f_ref_enc
#define crypto_kem_mceliece8192128f_dec crypto_kem_mceliece8192128f_ref_dec
#define crypto_kem_mceliece8192128f_PUBLICKEYBYTES crypto_kem_mceliece8192128f_ref_PUBLICKEYBYTES
#define crypto_kem_mceliece8192128f_SECRETKEYBYTES crypto_kem_mceliece8192128f_ref_SECRETKEYBYTES
#define crypto_kem_mceliece8192128f_BYTES crypto_kem_mceliece8192128f_ref_BYTES
#define crypto_kem_mceliece8192128f_CIPHERTEXTBYTES crypto_kem_mceliece8192128f_ref_CIPHERTEXTBYTES

#endif
#ifdef __cplusplus
extern "C" {
#endif
#undef rng_h
#undef RNG_SUCCESS
#undef RNG_BAD_MAXLEN
#undef RNG_BAD_OUTBUF
#undef RNG_BAD_REQ_LEN
#define AES_XOF_struct pqcrypto_kem_mceliece8192128f_impl_priv_AES_XOF_struct
#define AES256_CTR_DRBG_struct pqcrypto_kem_mceliece8192128f_impl_priv_AES256_CTR_DRBG_struct
#define AES256_CTR_DRBG_Update pqcrypto_kem_mceliece8192128f_impl_priv_AES256_CTR_DRBG_Update
#define seedexpander_init pqcrypto_kem_mceliece8192128f_impl_priv_seedexpander_init
#define seedexpander pqcrypto_kem_mceliece8192128f_impl_priv_seedexpander
#define randombytes_init pqcrypto_kem_mceliece8192128f_impl_priv_randombytes_init
#define randombytes pqcrypto_kem_mceliece8192128f_impl_priv_randombytes
/*
   rng.h
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/

#ifndef rng_h
#define rng_h

#include <stdio.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;


void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V);

int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen);

int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

int
randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
#undef AES_XOF_struct
#undef AES256_CTR_DRBG_struct
#undef AES256_CTR_DRBG_Update
#undef seedexpander_init
#undef seedexpander
#undef randombytes_init
#undef randombytes
#ifdef __cplusplus
}
#endif
