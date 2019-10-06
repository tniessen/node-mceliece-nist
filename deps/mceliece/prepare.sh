#!/bin/bash
set -e

# Extract the reference implementation.
archive=mceliece-20190331
tar -xf $archive.tar.gz $archive/Reference_Implementation/kem/ --strip-components=2

prepare_algorithm() {
  add_header $1
  add_makefile $1
}

add_header() {
  id=$1

  (
    cat kem/$id/crypto_kem_$id.h
    echo '#ifdef __cplusplus'
    echo 'extern "C" {'
    echo '#endif'
    echo '#undef rng_h'
    echo '#undef RNG_SUCCESS'
    echo '#undef RNG_BAD_MAXLEN'
    echo '#undef RNG_BAD_OUTBUF'
    echo '#undef RNG_BAD_REQ_LEN'
    echo "#define AES_XOF_struct pqcrypto_kem_${id}_impl_priv_AES_XOF_struct"
    echo "#define AES256_CTR_DRBG_struct pqcrypto_kem_${id}_impl_priv_AES256_CTR_DRBG_struct"
    echo "#define AES256_CTR_DRBG_Update pqcrypto_kem_${id}_impl_priv_AES256_CTR_DRBG_Update"
    echo "#define seedexpander_init pqcrypto_kem_${id}_impl_priv_seedexpander_init"
    echo "#define seedexpander pqcrypto_kem_${id}_impl_priv_seedexpander"
    echo "#define randombytes_init pqcrypto_kem_${id}_impl_priv_randombytes_init"
    echo "#define randombytes pqcrypto_kem_${id}_impl_priv_randombytes"
    cat kem/$id/nist/rng.h
    echo "#undef AES_XOF_struct"
    echo "#undef AES256_CTR_DRBG_struct"
    echo "#undef AES256_CTR_DRBG_Update"
    echo "#undef seedexpander_init"
    echo "#undef seedexpander"
    echo "#undef randombytes_init"
    echo "#undef randombytes"
    echo '#ifdef __cplusplus'
    echo '}'
    echo '#endif'
  ) >> mceliece.h
}

add_makefile() {
  id=$1

  files=`find kem/$id/ -type f -name '*.c' | grep -v 'nist/kat_kem.c' | tr '\n' ' '`

  (
    echo "$id.o: $files"
    for file in $files; do
      echo -ne '\t'
      echo gcc -O3 -fPIC -march=native -mtune=native  -L ../KeccakCodePackage/bin/generic64/ -Wall -Wno-misleading-indentation -I. -I../KeccakCodePackage/bin/generic64/ -D"apply_benes=pqcrypto_kem_${id}_impl_priv_apply_benes" -D"bitrev=pqcrypto_kem_${id}_impl_priv_bitrev" -D"bm=pqcrypto_kem_${id}_impl_priv_bm" -D"controlbits=pqcrypto_kem_${id}_impl_priv_controlbits" -D"decrypt=pqcrypto_kem_${id}_impl_priv_decrypt" -D"encrypt=pqcrypto_kem_${id}_impl_priv_encrypt" -D"eval=pqcrypto_kem_${id}_impl_priv_eval" -D"gf_add=pqcrypto_kem_${id}_impl_priv_gf_add" -D"gf_frac=pqcrypto_kem_${id}_impl_priv_gf_frac" -D"gf_inv=pqcrypto_kem_${id}_impl_priv_gf_inv" -D"gf_iszero=pqcrypto_kem_${id}_impl_priv_gf_iszero" -D"gf_mul=pqcrypto_kem_${id}_impl_priv_gf_mul" -D"GF_mul=pqcrypto_kem_${id}_impl_priv_GF_mul" -D"load2=pqcrypto_kem_${id}_impl_priv_load2" -D"load8=pqcrypto_kem_${id}_impl_priv_load8" -D"perm_conversion=pqcrypto_kem_${id}_impl_priv_perm_conversion" -D"pk_gen=pqcrypto_kem_${id}_impl_priv_pk_gen" -D"root=pqcrypto_kem_${id}_impl_priv_root" -D"sk_part_gen=pqcrypto_kem_${id}_impl_priv_sk_part_gen" -D"sort_63b=pqcrypto_kem_${id}_impl_priv_sort_63b" -D"store2=pqcrypto_kem_${id}_impl_priv_store2" -D"store8=pqcrypto_kem_${id}_impl_priv_store8" -D"support_gen=pqcrypto_kem_${id}_impl_priv_support_gen" -D"synd=pqcrypto_kem_${id}_impl_priv_synd" -D"syndrome=pqcrypto_kem_${id}_impl_priv_syndrome" -D"transpose_64x64=pqcrypto_kem_${id}_impl_priv_transpose_64x64" -D"aes256ctr=pqcrypto_kem_${id}_impl_priv_aes256ctr" -D"load4=pqcrypto_kem_${id}_impl_priv_load4" -D"AES256_CTR_DRBG_Update=pqcrypto_kem_${id}_impl_priv_AES256_CTR_DRBG_Update" -D"seedexpander=pqcrypto_kem_${id}_impl_priv_seedexpander" -D"handleErrors=pqcrypto_kem_${id}_impl_priv_handleErrors" -D"randombytes=pqcrypto_kem_${id}_impl_priv_randombytes" -D"randombytes_init=pqcrypto_kem_${id}_impl_priv_randombytes_init" -D"seedexpander_init=pqcrypto_kem_${id}_impl_priv_seedexpander_init" -D"perm_check=pqcrypto_kem_${id}_impl_priv_perm_check" -D"AES256_ECB=pqcrypto_kem_${id}_impl_priv_AES256_ECB" -D"genpoly_gen=pqcrypto_kem_${id}_impl_priv_genpoly_gen" -c $file -o ${file%.c}.o -lkeccak -lcrypto -ldl
    done
    echo -ne '\t'
    echo "ld -r -o $id.o `echo $files | sed 's/\.c/.o/g'`"
    echo
  ) >> Makefile
}

rm -f mceliece.h
rm -f Makefile

implementations=`ls -1 kem | while read id; do if [ -d "kem/$id" ]; then echo $id; fi; done`
for id in $implementations; do
  prepare_algorithm $id
done

(
  echo "mceliece.a: `echo $implementations | sed -E 's/( |$)/.o\1/g'`"
  echo -ne '\t'
  echo ar cr mceliece.a `echo $implementations | sed -E 's/( |$)/.o\1/g'`
) >> Makefile
