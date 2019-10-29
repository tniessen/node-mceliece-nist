#include <napi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mceliece.h>

namespace {

typedef int (*keypair_fn_t)(unsigned char* public_key, unsigned char* private_key);
typedef int (*encrypt_fn_t)(unsigned char* ciphertext, unsigned char* key, const unsigned char* public_key);
typedef int (*decrypt_fn_t)(unsigned char* key, const unsigned char* ciphertext, const unsigned char* public_key);
typedef void (*seed_fn_t)(unsigned char* entropy_input, unsigned char* personalization_string, int security_strength);

typedef struct {
  const char* name;
  size_t public_key_size;
  size_t private_key_size;
  size_t key_size;
  size_t ciphertext_size;
  keypair_fn_t keypair;
  encrypt_fn_t encrypt;
  decrypt_fn_t decrypt;
  seed_fn_t seed;
} mceliece_t;

static const mceliece_t kems[] = {
  {
    "mceliece348864",
    crypto_kem_mceliece348864_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece348864_ref_SECRETKEYBYTES,
    crypto_kem_mceliece348864_ref_BYTES,
    crypto_kem_mceliece348864_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece348864_ref_keypair,
    crypto_kem_mceliece348864_ref_enc,
    crypto_kem_mceliece348864_ref_dec,
    pqcrypto_kem_mceliece348864_impl_priv_randombytes_init
  },
  {
    "mceliece348864f",
    crypto_kem_mceliece348864f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece348864f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece348864f_ref_BYTES,
    crypto_kem_mceliece348864f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece348864f_ref_keypair,
    crypto_kem_mceliece348864f_ref_enc,
    crypto_kem_mceliece348864f_ref_dec,
    pqcrypto_kem_mceliece348864f_impl_priv_randombytes_init
  },
  {
    "mceliece460896",
    crypto_kem_mceliece460896_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece460896_ref_SECRETKEYBYTES,
    crypto_kem_mceliece460896_ref_BYTES,
    crypto_kem_mceliece460896_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece460896_ref_keypair,
    crypto_kem_mceliece460896_ref_enc,
    crypto_kem_mceliece460896_ref_dec,
    pqcrypto_kem_mceliece460896_impl_priv_randombytes_init
  },
  {
    "mceliece460896f",
    crypto_kem_mceliece460896f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece460896f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece460896f_ref_BYTES,
    crypto_kem_mceliece460896f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece460896f_ref_keypair,
    crypto_kem_mceliece460896f_ref_enc,
    crypto_kem_mceliece460896f_ref_dec,
    pqcrypto_kem_mceliece460896f_impl_priv_randombytes_init
  },
  {
    "mceliece6688128",
    crypto_kem_mceliece6688128_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6688128_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6688128_ref_BYTES,
    crypto_kem_mceliece6688128_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6688128_ref_keypair,
    crypto_kem_mceliece6688128_ref_enc,
    crypto_kem_mceliece6688128_ref_dec,
    pqcrypto_kem_mceliece6688128_impl_priv_randombytes_init
  },
  {
    "mceliece6688128f",
    crypto_kem_mceliece6688128f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6688128f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6688128f_ref_BYTES,
    crypto_kem_mceliece6688128f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6688128f_ref_keypair,
    crypto_kem_mceliece6688128f_ref_enc,
    crypto_kem_mceliece6688128f_ref_dec,
    pqcrypto_kem_mceliece6688128f_impl_priv_randombytes_init
  },
  {
    "mceliece6960119",
    crypto_kem_mceliece6960119_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6960119_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6960119_ref_BYTES,
    crypto_kem_mceliece6960119_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6960119_ref_keypair,
    crypto_kem_mceliece6960119_ref_enc,
    crypto_kem_mceliece6960119_ref_dec,
    pqcrypto_kem_mceliece6960119_impl_priv_randombytes_init
  },
  {
    "mceliece6960119f",
    crypto_kem_mceliece6960119f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6960119f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6960119f_ref_BYTES,
    crypto_kem_mceliece6960119f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6960119f_ref_keypair,
    crypto_kem_mceliece6960119f_ref_enc,
    crypto_kem_mceliece6960119f_ref_dec,
    pqcrypto_kem_mceliece6960119f_impl_priv_randombytes_init
  },
  {
    "mceliece8192128",
    crypto_kem_mceliece8192128_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece8192128_ref_SECRETKEYBYTES,
    crypto_kem_mceliece8192128_ref_BYTES,
    crypto_kem_mceliece8192128_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece8192128_ref_keypair,
    crypto_kem_mceliece8192128_ref_enc,
    crypto_kem_mceliece8192128_ref_dec,
    pqcrypto_kem_mceliece8192128_impl_priv_randombytes_init
  },
  {
    "mceliece8192128f",
    crypto_kem_mceliece8192128f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece8192128f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece8192128f_ref_BYTES,
    crypto_kem_mceliece8192128f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece8192128f_ref_keypair,
    crypto_kem_mceliece8192128f_ref_enc,
    crypto_kem_mceliece8192128f_ref_dec,
    pqcrypto_kem_mceliece8192128f_impl_priv_randombytes_init
  }
};

static const mceliece_t* get_kem(const char* name) {
  for (unsigned int i = 0; i < sizeof(kems) / sizeof(mceliece_t); i++) {
    if (strcmp(kems[i].name, name) == 0)
      return &kems[i];
  }
  return NULL;
}

class McEliece : public Napi::ObjectWrap<McEliece> {
 public:
  McEliece(const Napi::CallbackInfo& info) : Napi::ObjectWrap<McEliece>(info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    this->impl = get_kem(name.c_str());

    if (this->impl == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
    }
  }

  Napi::Value Keypair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    Napi::Buffer<unsigned char> public_key = Napi::Buffer<unsigned char>::New(env, impl->public_key_size);
    Napi::Buffer<unsigned char> private_key = Napi::Buffer<unsigned char>::New(env, impl->private_key_size);
    int r = impl->keypair(public_key.Data(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "failed to generate keypair").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", public_key);
    obj.Set("privateKey", private_key);
    return obj;
  }

  Napi::Value GenerateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> public_key = info[0].As<Napi::Buffer<unsigned char>>();
    if (public_key.Length() != impl->public_key_size) {
      Napi::TypeError::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> encrypted_key = Napi::Buffer<unsigned char>::New(env, impl->ciphertext_size);
    Napi::Buffer<unsigned char> actual_key = Napi::Buffer<unsigned char>::New(env, impl->key_size);

    int r = impl->encrypt(encrypted_key.Data(), actual_key.Data(), public_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "encryption failed").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key", actual_key);
    obj.Set("encryptedKey", encrypted_key);
    return obj;
  }

  Napi::Value DecryptKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> private_key = info[0].As<Napi::Buffer<unsigned char>>();
    if (private_key.Length() != impl->private_key_size) {
      Napi::TypeError::New(env, "Invalid private key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> encrypted_key = info[1].As<Napi::Buffer<unsigned char>>();
    if (encrypted_key.Length() != impl->ciphertext_size) {
      Napi::TypeError::New(env, "Invalid ciphertext size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> actual_key = Napi::Buffer<unsigned char>::New(env, impl->key_size);

    int r = impl->decrypt(actual_key.Data(), encrypted_key.Data(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "decryption failed").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    
    return actual_key;
  }

  Napi::Value GetKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->key_size);
  }

  Napi::Value GetEncryptedKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->ciphertext_size);
  }

  Napi::Value GetPublicKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->public_key_size);
  }

  Napi::Value GetPrivateKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->private_key_size);
  }

 private:
  const mceliece_t* impl;
};

Napi::Value Seed(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  Napi::Buffer<unsigned char> entropy_input = info[0].As<Napi::Buffer<unsigned char>>();
  if (entropy_input.Length() != 48) {
    Napi::Error::New(env, "Entropy input must have 48 bytes").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  unsigned char entropy[48];
  memcpy(entropy, entropy_input.Data(), 48);

  for (unsigned int i = 0; i < sizeof(kems) / sizeof(*kems); i++) {
    kems[i].seed(entropy, nullptr, 256);
    entropy[0]++;
  }

  return env.Undefined();
}

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func = McEliece::DefineClass(env, "McEliece", {
      Napi::ObjectWrap<McEliece>::InstanceMethod("keypair", &McEliece::Keypair),
      Napi::ObjectWrap<McEliece>::InstanceMethod("generateKey", &McEliece::GenerateKey),
      Napi::ObjectWrap<McEliece>::InstanceMethod("decryptKey", &McEliece::DecryptKey),
      Napi::ObjectWrap<McEliece>::InstanceAccessor("keySize", &McEliece::GetKeySize, nullptr),
      Napi::ObjectWrap<McEliece>::InstanceAccessor("encryptedKeySize", &McEliece::GetEncryptedKeySize, nullptr),
      Napi::ObjectWrap<McEliece>::InstanceAccessor("publicKeySize", &McEliece::GetPublicKeySize, nullptr),
      Napi::ObjectWrap<McEliece>::InstanceAccessor("privateKeySize", &McEliece::GetPrivateKeySize, nullptr)
  });

  Napi::Array supported_algorithms = Napi::Array::New(env, sizeof(kems) / sizeof(*kems));
  for (unsigned int i = 0; i < sizeof(kems) / sizeof(*kems); i++) {
    supported_algorithms[i] = Napi::String::New(env, kems[i].name);
  }
  func.Set("supportedAlgorithms", supported_algorithms);

  exports.Set("McEliece", func);
  exports.Set("seed", Napi::Function::New(env, &Seed));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

}
