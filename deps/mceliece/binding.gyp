{
  'targets': [
    {
      'target_name': 'mceliece',
      'type': 'none',
      'dependencies': [
        'only_mceliece348864',
        'only_mceliece348864f',
        'only_mceliece460896',
        'only_mceliece460896f',
        'only_mceliece6688128',
        'only_mceliece6688128f',
        'only_mceliece6960119',
        'only_mceliece6960119f',
        'only_mceliece8192128',
        'only_mceliece8192128f',
      ]
    },
    {
      'target_name': 'only_mceliece348864',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece348864/operations.c',
        'kem/mceliece348864/encrypt.c',
        'kem/mceliece348864/controlbits.c',
        'kem/mceliece348864/decrypt.c',
        'kem/mceliece348864/pk_gen.c',
        'kem/mceliece348864/benes.c',
        'kem/mceliece348864/transpose.c',
        'kem/mceliece348864/synd.c',
        'kem/mceliece348864/bm.c',
        'kem/mceliece348864/gf.c',
        'kem/mceliece348864/root.c',
        'kem/mceliece348864/util.c',
        'kem/mceliece348864/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece348864_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece348864_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece348864_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece348864_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece348864_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece348864_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece348864_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece348864_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece348864_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece348864_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece348864_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece348864_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece348864_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece348864_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece348864_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece348864_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece348864_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece348864_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece348864_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece348864_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece348864_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece348864_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece348864_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece348864_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece348864_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece348864_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece348864_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece348864_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece348864_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece348864_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece348864f',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece348864f/operations.c',
        'kem/mceliece348864f/encrypt.c',
        'kem/mceliece348864f/controlbits.c',
        'kem/mceliece348864f/decrypt.c',
        'kem/mceliece348864f/pk_gen.c',
        'kem/mceliece348864f/benes.c',
        'kem/mceliece348864f/transpose.c',
        'kem/mceliece348864f/synd.c',
        'kem/mceliece348864f/bm.c',
        'kem/mceliece348864f/gf.c',
        'kem/mceliece348864f/root.c',
        'kem/mceliece348864f/util.c',
        'kem/mceliece348864f/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece348864f_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece348864f_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece348864f_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece348864f_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece348864f_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece348864f_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece348864f_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece348864f_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece348864f_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece348864f_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece348864f_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece348864f_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece348864f_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece348864f_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece348864f_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece348864f_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece348864f_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece348864f_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece348864f_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece348864f_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece348864f_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece348864f_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece348864f_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece348864f_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece348864f_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece348864f_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece348864f_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece348864f_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece348864f_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece348864f_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece460896',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece460896/operations.c',
        'kem/mceliece460896/encrypt.c',
        'kem/mceliece460896/controlbits.c',
        'kem/mceliece460896/decrypt.c',
        'kem/mceliece460896/pk_gen.c',
        'kem/mceliece460896/benes.c',
        'kem/mceliece460896/transpose.c',
        'kem/mceliece460896/synd.c',
        'kem/mceliece460896/bm.c',
        'kem/mceliece460896/gf.c',
        'kem/mceliece460896/root.c',
        'kem/mceliece460896/util.c',
        'kem/mceliece460896/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece460896_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece460896_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece460896_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece460896_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece460896_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece460896_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece460896_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece460896_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece460896_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece460896_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece460896_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece460896_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece460896_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece460896_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece460896_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece460896_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece460896_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece460896_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece460896_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece460896_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece460896_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece460896_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece460896_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece460896_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece460896_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece460896_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece460896_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece460896_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece460896_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece460896_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece460896f',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece460896f/operations.c',
        'kem/mceliece460896f/encrypt.c',
        'kem/mceliece460896f/controlbits.c',
        'kem/mceliece460896f/decrypt.c',
        'kem/mceliece460896f/pk_gen.c',
        'kem/mceliece460896f/benes.c',
        'kem/mceliece460896f/transpose.c',
        'kem/mceliece460896f/synd.c',
        'kem/mceliece460896f/bm.c',
        'kem/mceliece460896f/gf.c',
        'kem/mceliece460896f/root.c',
        'kem/mceliece460896f/util.c',
        'kem/mceliece460896f/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece460896f_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece460896f_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece460896f_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece460896f_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece460896f_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece460896f_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece460896f_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece460896f_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece460896f_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece460896f_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece460896f_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece460896f_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece460896f_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece460896f_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece460896f_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece460896f_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece460896f_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece460896f_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece460896f_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece460896f_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece460896f_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece460896f_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece460896f_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece460896f_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece460896f_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece460896f_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece460896f_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece460896f_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece460896f_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece460896f_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece6688128',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece6688128/operations.c',
        'kem/mceliece6688128/encrypt.c',
        'kem/mceliece6688128/controlbits.c',
        'kem/mceliece6688128/decrypt.c',
        'kem/mceliece6688128/pk_gen.c',
        'kem/mceliece6688128/benes.c',
        'kem/mceliece6688128/transpose.c',
        'kem/mceliece6688128/synd.c',
        'kem/mceliece6688128/bm.c',
        'kem/mceliece6688128/gf.c',
        'kem/mceliece6688128/root.c',
        'kem/mceliece6688128/util.c',
        'kem/mceliece6688128/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece6688128_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece6688128_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece6688128_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece6688128_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece6688128_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece6688128_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece6688128_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece6688128_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece6688128_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece6688128_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece6688128_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece6688128_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece6688128_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece6688128_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece6688128_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece6688128_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece6688128_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece6688128_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece6688128_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece6688128_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece6688128_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece6688128_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece6688128_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece6688128_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece6688128_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece6688128_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece6688128_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece6688128_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece6688128_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece6688128_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece6688128f',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece6688128f/operations.c',
        'kem/mceliece6688128f/encrypt.c',
        'kem/mceliece6688128f/controlbits.c',
        'kem/mceliece6688128f/decrypt.c',
        'kem/mceliece6688128f/pk_gen.c',
        'kem/mceliece6688128f/benes.c',
        'kem/mceliece6688128f/transpose.c',
        'kem/mceliece6688128f/synd.c',
        'kem/mceliece6688128f/bm.c',
        'kem/mceliece6688128f/gf.c',
        'kem/mceliece6688128f/root.c',
        'kem/mceliece6688128f/util.c',
        'kem/mceliece6688128f/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece6688128f_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece6688128f_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece6688128f_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece6688128f_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece6688128f_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece6688128f_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece6688128f_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece6688128f_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece6688128f_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece6688128f_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece6688128f_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece6688128f_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece6688128f_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece6688128f_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece6688128f_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece6688128f_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece6688128f_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece6688128f_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece6688128f_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece6688128f_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece6688128f_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece6688128f_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece6688128f_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece6688128f_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece6688128f_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece6688128f_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece6688128f_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece6688128f_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece6688128f_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece6688128f_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece6960119',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece6960119/operations.c',
        'kem/mceliece6960119/encrypt.c',
        'kem/mceliece6960119/controlbits.c',
        'kem/mceliece6960119/decrypt.c',
        'kem/mceliece6960119/pk_gen.c',
        'kem/mceliece6960119/benes.c',
        'kem/mceliece6960119/transpose.c',
        'kem/mceliece6960119/synd.c',
        'kem/mceliece6960119/bm.c',
        'kem/mceliece6960119/gf.c',
        'kem/mceliece6960119/root.c',
        'kem/mceliece6960119/util.c',
        'kem/mceliece6960119/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece6960119_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece6960119_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece6960119_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece6960119_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece6960119_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece6960119_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece6960119_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece6960119_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece6960119_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece6960119_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece6960119_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece6960119_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece6960119_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece6960119_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece6960119_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece6960119_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece6960119_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece6960119_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece6960119_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece6960119_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece6960119_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece6960119_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece6960119_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece6960119_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece6960119_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece6960119_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece6960119_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece6960119_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece6960119_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece6960119_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece6960119f',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece6960119f/operations.c',
        'kem/mceliece6960119f/encrypt.c',
        'kem/mceliece6960119f/controlbits.c',
        'kem/mceliece6960119f/decrypt.c',
        'kem/mceliece6960119f/pk_gen.c',
        'kem/mceliece6960119f/benes.c',
        'kem/mceliece6960119f/transpose.c',
        'kem/mceliece6960119f/synd.c',
        'kem/mceliece6960119f/bm.c',
        'kem/mceliece6960119f/gf.c',
        'kem/mceliece6960119f/root.c',
        'kem/mceliece6960119f/util.c',
        'kem/mceliece6960119f/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece6960119f_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece6960119f_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece6960119f_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece6960119f_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece6960119f_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece6960119f_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece6960119f_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece6960119f_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece6960119f_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece6960119f_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece6960119f_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece6960119f_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece6960119f_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece6960119f_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece6960119f_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece6960119f_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece6960119f_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece6960119f_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece6960119f_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece6960119f_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece6960119f_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece6960119f_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece6960119f_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece6960119f_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece6960119f_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece6960119f_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece6960119f_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece6960119f_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece6960119f_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece6960119f_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece8192128',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece8192128/operations.c',
        'kem/mceliece8192128/encrypt.c',
        'kem/mceliece8192128/controlbits.c',
        'kem/mceliece8192128/decrypt.c',
        'kem/mceliece8192128/pk_gen.c',
        'kem/mceliece8192128/benes.c',
        'kem/mceliece8192128/transpose.c',
        'kem/mceliece8192128/synd.c',
        'kem/mceliece8192128/bm.c',
        'kem/mceliece8192128/gf.c',
        'kem/mceliece8192128/root.c',
        'kem/mceliece8192128/util.c',
        'kem/mceliece8192128/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece8192128_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece8192128_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece8192128_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece8192128_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece8192128_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece8192128_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece8192128_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece8192128_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece8192128_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece8192128_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece8192128_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece8192128_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece8192128_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece8192128_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece8192128_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece8192128_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece8192128_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece8192128_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece8192128_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece8192128_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece8192128_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece8192128_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece8192128_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece8192128_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece8192128_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece8192128_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece8192128_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece8192128_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece8192128_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece8192128_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
    {
      'target_name': 'only_mceliece8192128f',
      'type': 'static_library',
      'include_dirs': ['../KeccakCodePackage/bin/generic64'],
      'sources': [
        'kem/mceliece8192128f/operations.c',
        'kem/mceliece8192128f/encrypt.c',
        'kem/mceliece8192128f/controlbits.c',
        'kem/mceliece8192128f/decrypt.c',
        'kem/mceliece8192128f/pk_gen.c',
        'kem/mceliece8192128f/benes.c',
        'kem/mceliece8192128f/transpose.c',
        'kem/mceliece8192128f/synd.c',
        'kem/mceliece8192128f/bm.c',
        'kem/mceliece8192128f/gf.c',
        'kem/mceliece8192128f/root.c',
        'kem/mceliece8192128f/util.c',
        'kem/mceliece8192128f/sk_gen.c',
      ],
      'defines': [
        'apply_benes=pqcrypto_kem_mceliece8192128f_impl_priv_apply_benes',
        'bitrev=pqcrypto_kem_mceliece8192128f_impl_priv_bitrev',
        'bm=pqcrypto_kem_mceliece8192128f_impl_priv_bm',
        'controlbits=pqcrypto_kem_mceliece8192128f_impl_priv_controlbits',
        'decrypt=pqcrypto_kem_mceliece8192128f_impl_priv_decrypt',
        'encrypt=pqcrypto_kem_mceliece8192128f_impl_priv_encrypt',
        'eval=pqcrypto_kem_mceliece8192128f_impl_priv_eval',
        'gf_add=pqcrypto_kem_mceliece8192128f_impl_priv_gf_add',
        'gf_frac=pqcrypto_kem_mceliece8192128f_impl_priv_gf_frac',
        'gf_inv=pqcrypto_kem_mceliece8192128f_impl_priv_gf_inv',
        'gf_iszero=pqcrypto_kem_mceliece8192128f_impl_priv_gf_iszero',
        'gf_mul=pqcrypto_kem_mceliece8192128f_impl_priv_gf_mul',
        'GF_mul=pqcrypto_kem_mceliece8192128f_impl_priv_GF_mul',
        'load2=pqcrypto_kem_mceliece8192128f_impl_priv_load2',
        'load8=pqcrypto_kem_mceliece8192128f_impl_priv_load8',
        'perm_conversion=pqcrypto_kem_mceliece8192128f_impl_priv_perm_conversion',
        'pk_gen=pqcrypto_kem_mceliece8192128f_impl_priv_pk_gen',
        'root=pqcrypto_kem_mceliece8192128f_impl_priv_root',
        'sk_part_gen=pqcrypto_kem_mceliece8192128f_impl_priv_sk_part_gen',
        'sort_63b=pqcrypto_kem_mceliece8192128f_impl_priv_sort_63b',
        'store2=pqcrypto_kem_mceliece8192128f_impl_priv_store2',
        'store8=pqcrypto_kem_mceliece8192128f_impl_priv_store8',
        'support_gen=pqcrypto_kem_mceliece8192128f_impl_priv_support_gen',
        'synd=pqcrypto_kem_mceliece8192128f_impl_priv_synd',
        'syndrome=pqcrypto_kem_mceliece8192128f_impl_priv_syndrome',
        'transpose_64x64=pqcrypto_kem_mceliece8192128f_impl_priv_transpose_64x64',
        'load4=pqcrypto_kem_mceliece8192128f_impl_priv_load4',
        'handleErrors=pqcrypto_kem_mceliece8192128f_impl_priv_handleErrors',
        'perm_check=pqcrypto_kem_mceliece8192128f_impl_priv_perm_check',
        'genpoly_gen=pqcrypto_kem_mceliece8192128f_impl_priv_genpoly_gen',
        'randombytes=pqcrypto_mceliece_randombytes',
        'aes256ctr=pqcrypto_mceliece_aes256ctr',
      ],
      'cflags': ['-fPIC']
    },
  ]
}
