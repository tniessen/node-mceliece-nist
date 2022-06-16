#include <napi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

extern "C" {

#define NO_SHORT_NAMES_FOR_EXTERNALS
#include <mceliece.h>
#include <mceliece_externals.h>

#define CHECK(a, message) do {                                             \
                            if ((a) != 1) {                                \
                              napi_fatal_error(__FILE__, NAPI_AUTO_LENGTH, \
                                               message, NAPI_AUTO_LENGTH); \
                            }                                              \
                          } while (0)                                      \

int pqcrypto_mceliece_randombytes(unsigned char* x, size_t xlen) {
  CHECK(RAND_bytes(x, xlen), "RAND_bytes failed");
  return 0;
}

int pqcrypto_mceliece_SHAKE256(unsigned char *output, size_t outputByteLen,
                               const unsigned char *input, size_t inputByteLen) {
  EVP_MD_CTX* ctx;

  CHECK((ctx = EVP_MD_CTX_create()) != NULL,
        "EVP_MD_CTX_create failed");
  CHECK(EVP_DigestInit_ex(ctx, EVP_shake256(), NULL),
        "EVP_DigestInit_ex failed");
  CHECK(EVP_DigestUpdate(ctx, input, inputByteLen),
        "EVP_DigestUpdate failed");
  CHECK(EVP_DigestFinalXOF(ctx, output, outputByteLen),
        "EVP_DigestFinalXOF failed");

  EVP_MD_CTX_free(ctx);
  return 0;
}

}

namespace {

typedef int (*keypair_fn_t)(unsigned char* public_key, unsigned char* private_key);
typedef int (*encrypt_fn_t)(unsigned char* ciphertext, unsigned char* key, const unsigned char* public_key);
typedef int (*decrypt_fn_t)(unsigned char* key, const unsigned char* ciphertext, const unsigned char* public_key);

typedef struct {
  const char* name;
  size_t public_key_size;
  size_t private_key_size;
  size_t key_size;
  size_t ciphertext_size;
  keypair_fn_t keypair;
  encrypt_fn_t encrypt;
  decrypt_fn_t decrypt;
} mceliece_t;

const mceliece_t kems[] = {
  {
    "mceliece348864",
    crypto_kem_mceliece348864_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece348864_ref_SECRETKEYBYTES,
    crypto_kem_mceliece348864_ref_BYTES,
    crypto_kem_mceliece348864_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece348864_ref_keypair,
    crypto_kem_mceliece348864_ref_enc,
    crypto_kem_mceliece348864_ref_dec
  },
  {
    "mceliece348864f",
    crypto_kem_mceliece348864f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece348864f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece348864f_ref_BYTES,
    crypto_kem_mceliece348864f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece348864f_ref_keypair,
    crypto_kem_mceliece348864f_ref_enc,
    crypto_kem_mceliece348864f_ref_dec
  },
  {
    "mceliece460896",
    crypto_kem_mceliece460896_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece460896_ref_SECRETKEYBYTES,
    crypto_kem_mceliece460896_ref_BYTES,
    crypto_kem_mceliece460896_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece460896_ref_keypair,
    crypto_kem_mceliece460896_ref_enc,
    crypto_kem_mceliece460896_ref_dec
  },
  {
    "mceliece460896f",
    crypto_kem_mceliece460896f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece460896f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece460896f_ref_BYTES,
    crypto_kem_mceliece460896f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece460896f_ref_keypair,
    crypto_kem_mceliece460896f_ref_enc,
    crypto_kem_mceliece460896f_ref_dec
  },
  {
    "mceliece6688128",
    crypto_kem_mceliece6688128_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6688128_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6688128_ref_BYTES,
    crypto_kem_mceliece6688128_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6688128_ref_keypair,
    crypto_kem_mceliece6688128_ref_enc,
    crypto_kem_mceliece6688128_ref_dec
  },
  {
    "mceliece6688128f",
    crypto_kem_mceliece6688128f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6688128f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6688128f_ref_BYTES,
    crypto_kem_mceliece6688128f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6688128f_ref_keypair,
    crypto_kem_mceliece6688128f_ref_enc,
    crypto_kem_mceliece6688128f_ref_dec
  },
  {
    "mceliece6960119",
    crypto_kem_mceliece6960119_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6960119_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6960119_ref_BYTES,
    crypto_kem_mceliece6960119_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6960119_ref_keypair,
    crypto_kem_mceliece6960119_ref_enc,
    crypto_kem_mceliece6960119_ref_dec
  },
  {
    "mceliece6960119f",
    crypto_kem_mceliece6960119f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece6960119f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece6960119f_ref_BYTES,
    crypto_kem_mceliece6960119f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece6960119f_ref_keypair,
    crypto_kem_mceliece6960119f_ref_enc,
    crypto_kem_mceliece6960119f_ref_dec
  },
  {
    "mceliece8192128",
    crypto_kem_mceliece8192128_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece8192128_ref_SECRETKEYBYTES,
    crypto_kem_mceliece8192128_ref_BYTES,
    crypto_kem_mceliece8192128_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece8192128_ref_keypair,
    crypto_kem_mceliece8192128_ref_enc,
    crypto_kem_mceliece8192128_ref_dec
  },
  {
    "mceliece8192128f",
    crypto_kem_mceliece8192128f_ref_PUBLICKEYBYTES,
    crypto_kem_mceliece8192128f_ref_SECRETKEYBYTES,
    crypto_kem_mceliece8192128f_ref_BYTES,
    crypto_kem_mceliece8192128f_ref_CIPHERTEXTBYTES,
    crypto_kem_mceliece8192128f_ref_keypair,
    crypto_kem_mceliece8192128f_ref_enc,
    crypto_kem_mceliece8192128f_ref_dec
  }
};

const mceliece_t* get_kem(const char* name) {
  for (unsigned int i = 0; i < sizeof(kems) / sizeof(mceliece_t); i++) {
    if (strcmp(kems[i].name, name) == 0)
      return &kems[i];
  }
  return NULL;
}

template <typename T>
inline T* Malloc(size_t size) {
  return reinterpret_cast<T*>(malloc(size));
}

void Free(Napi::Env env, void* p) {
  free(p);
}

template <typename T>
inline T* Duplicate(const void* mem, size_t size) {
  T* copy = Malloc<T>(size);
  if (copy != nullptr)
    memcpy(copy, mem, size);
  return copy;
}

class KeygenWorker : public Napi::AsyncWorker {
 public:
  KeygenWorker(Napi::Function& callback, const mceliece_t* impl) : AsyncWorker(callback), impl(impl) {}

  ~KeygenWorker() {}

  void Execute() override {
    public_key = Malloc<unsigned char>(impl->public_key_size);
    private_key = Malloc<unsigned char>(impl->private_key_size);

    if (public_key == nullptr || private_key == nullptr) {
      free(public_key);
      free(private_key);
      return SetError("Failed to allocate memory");
    }

    if (impl->keypair(public_key, private_key) != 0) {
      free(public_key);
      free(private_key);
      return SetError("failed to generate keypair");
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto public_key_buf = Napi::Buffer<unsigned char>::New(env, public_key, impl->public_key_size, Free);
    const auto private_key_buf = Napi::Buffer<unsigned char>::New(env, private_key, impl->private_key_size, Free);

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", public_key_buf);
    obj.Set("privateKey", private_key_buf);
    return { env.Undefined(), obj };
  }

 private:
  const mceliece_t* impl;
  unsigned char* public_key;
  unsigned char* private_key;
};

class DecryptWorker : public Napi::AsyncWorker {
 public:
  DecryptWorker(Napi::Function& callback, const mceliece_t* impl, const void* private_key, const void* ciphertext) : AsyncWorker(callback), impl(impl) {
    this->private_key = Duplicate<unsigned char>(private_key, impl->private_key_size);
    this->ciphertext = Duplicate<unsigned char>(ciphertext, impl->ciphertext_size);
  }

  void Execute() override {
    if (private_key == nullptr || ciphertext == nullptr)
      return SetError("Failed to allocate memory");

    actual_key = Malloc<unsigned char>(impl->key_size);
    if (actual_key == nullptr)
      return SetError("Failed to allocate memory");

    if (impl->decrypt(actual_key, ciphertext, private_key) != 0) {
      free(actual_key);
      return SetError("decryption failed");
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto key = Napi::Buffer<unsigned char>::New(env, actual_key, impl->key_size, Free);
    return { env.Undefined(), key };
  }

  ~DecryptWorker() {
    free(private_key);
    free(ciphertext);
  }

 private:
  const mceliece_t* impl;
  unsigned char* private_key;
  unsigned char* ciphertext;
  unsigned char* actual_key;
};

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

    if (info[0].IsFunction()) {
      Napi::Function cb = info[0].As<Napi::Function>();
      KeygenWorker* worker = new KeygenWorker(cb, impl);
      worker->Queue();
      return env.Undefined();
    }

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

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray")
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

    if (info.Length() != 2 && info.Length() != 3) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[1].IsTypedArray()) {
      Napi::TypeError::New(env, "Second argument must be a TypedArray")
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

    if (info.Length() == 3 && info[2].IsFunction()) {
      Napi::Function cb = info[2].As<Napi::Function>();
      DecryptWorker* worker = new DecryptWorker(cb, impl, private_key.Data(), encrypted_key.Data());
      worker->Queue();
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

Napi::Object Init(Napi::Env env, Napi::Object exports) {
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
  func.DefineProperty(Napi::PropertyDescriptor::Value("supportedAlgorithms", supported_algorithms));

  exports.Set("McEliece", func);
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

}
