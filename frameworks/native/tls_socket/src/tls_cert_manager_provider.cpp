/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tls_cert_manager_provider.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <new>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_IS_BORINGSSL)
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

namespace OHOS::NetStack::TlsSocket {
namespace {
constexpr char PROVIDER_NAME[] = "netstack-certmanager";
struct ProviderContext {
    OSSL_LIB_CTX *libctx = nullptr;
    std::shared_ptr<AliasCredential> credential;
    std::shared_ptr<TlsConnectAttemptState> state;
};
struct ExternalKey {
    ProviderContext *provider = nullptr;
    std::shared_ptr<EVP_PKEY> publicKey;
    bool signing = false;
};
struct SignatureContext {
    ProviderContext *provider = nullptr;
    ExternalKey key;
    std::string digest;
    std::string mgfDigest;
    int padding = RSA_PKCS1_PADDING;
    int saltLength = RSA_PSS_SALTLEN_DIGEST;
};

void *KeyNew(void *ctx)
{
    auto key = new (std::nothrow) ExternalKey;
    if (key) {
        key->provider = static_cast<ProviderContext *>(ctx);
    }
    return key;
}
void KeyFree(void *key) { delete static_cast<ExternalKey *>(key); }
void *KeyDup(const void *key, int selection)
{
    auto copy = new (std::nothrow) ExternalKey(*static_cast<const ExternalKey *>(key));
    if (copy && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        copy->signing = false;
    }
    return copy;
}
int KeyHas(const void *ptr, int selection)
{
    const auto key = static_cast<const ExternalKey *>(ptr);
    return key && key->publicKey && (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) || key->signing);
}
int KeyMatch(const void *a, const void *b, int selection)
{
    auto left = static_cast<const ExternalKey *>(a);
    auto right = static_cast<const ExternalKey *>(b);
    return KeyHas(a, selection) && KeyHas(b, selection) &&
        EVP_PKEY_eq(left->publicKey.get(), right->publicKey.get()) == 1;
}
int KeyValidate(const void *ptr, int selection, int)
{
    auto key = static_cast<const ExternalKey *>(ptr);
    if (!KeyHas(ptr, selection)) {
        return 0;
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_pkey(key->provider->libctx, key->publicKey.get(), "provider=default"), EVP_PKEY_CTX_free);
    return ctx && EVP_PKEY_public_check(ctx.get()) == 1;
}
const OSSL_PARAM *KeyTypes(int)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0),
        OSSL_PARAM_END
    };
    return types;
}
int ImportKey(void *ptr, int selection, const OSSL_PARAM params[], const char *algorithm)
{
    auto key = static_cast<ExternalKey *>(ptr);
    if (!key || !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return 0;
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(key->provider->libctx, algorithm, "provider=default"), EVP_PKEY_CTX_free);
    EVP_PKEY *pub = nullptr;
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pub, EVP_PKEY_PUBLIC_KEY, const_cast<OSSL_PARAM *>(params)) <= 0) {
        return 0;
    }
    key->publicKey.reset(pub, EVP_PKEY_free);
    const auto &credential = key->provider->credential;
    // Only this connection's matching public key may be bound to its signing capability.
    key->signing = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && credential &&
        EVP_PKEY_eq(pub, credential->publicKey.get()) == 1;
    return !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) || key->signing;
}
int RsaImport(void *key, int selection, const OSSL_PARAM params[]) { return ImportKey(key, selection, params, "RSA"); }
int EcImport(void *key, int selection, const OSSL_PARAM params[]) { return ImportKey(key, selection, params, "EC"); }
int KeyExport(void *ptr, int selection, OSSL_CALLBACK *callback, void *arg)
{
    auto key = static_cast<ExternalKey *>(ptr);
    if (!key || !key->publicKey || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        return 0;
    }
    OSSL_PARAM *params = nullptr;
    if (EVP_PKEY_todata(key->publicKey.get(), selection, &params) <= 0) {
        return 0;
    }
    int result = callback(params, arg);
    OSSL_PARAM_free(params);
    return result;
}
int KeyGetParams(void *ptr, OSSL_PARAM params[])
{
    auto key = static_cast<ExternalKey *>(ptr);
    return key && key->publicKey && EVP_PKEY_get_params(key->publicKey.get(), params) > 0;
}
const OSSL_PARAM *KeyGettable(void *)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, nullptr),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, nullptr),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, nullptr),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0),
        OSSL_PARAM_END
    };
    return params;
}
const char *RsaOperation(int operation) { return operation == OSSL_OP_SIGNATURE ? "RSA" : nullptr; }
const char *EcOperation(int operation) { return operation == OSSL_OP_SIGNATURE ? "ECDSA" : nullptr; }

void *SignatureNew(void *provider, const char *)
{
    auto ctx = new (std::nothrow) SignatureContext;
    if (ctx) {
        ctx->provider = static_cast<ProviderContext *>(provider);
    }
    return ctx;
}
void SignatureFree(void *ctx) { delete static_cast<SignatureContext *>(ctx); }
void *SignatureDup(void *ctx) { return new (std::nothrow) SignatureContext(*static_cast<SignatureContext *>(ctx)); }

std::string CanonicalDigest(const char *name)
{
    if (!name) {
        return {};
    }
    const EVP_MD *md = EVP_get_digestbyname(name);
    switch (md ? EVP_MD_type(md) : NID_undef) {
        case NID_sha256: return "SHA256";
        case NID_sha384: return "SHA384";
        case NID_sha512: return "SHA512";
        default: return {};
    }
}
int Fail(SignatureContext *ctx)
{
    if (ctx && ctx->provider && ctx->provider->state) {
        ctx->provider->state->SetFirstError(TLS_ERR_SSL_NULL);
    }
    return 0;
}
bool ReadString(const OSSL_PARAM *param, std::string &output)
{
    const char *value = nullptr;
    if (!OSSL_PARAM_get_utf8_string_ptr(param, &value) || !value) {
        return false;
    }
    output = value;
    return true;
}

bool ReadPssSaltLength(const OSSL_PARAM *param, int &saltLength)
{
    if (param->data_type != OSSL_PARAM_UTF8_STRING) {
        return OSSL_PARAM_get_int(param, &saltLength) != 0;
    }
    std::string value;
    if (!ReadString(param, value)) {
        return false;
    }
    if (value == OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) {
        saltLength = RSA_PSS_SALTLEN_DIGEST;
        return true;
    }
    auto parsed = std::from_chars(value.data(), value.data() + value.size(), saltLength);
    return parsed.ec == std::errc() && parsed.ptr == value.data() + value.size() && saltLength >= 0;
}

bool ReadRsaPadding(const OSSL_PARAM *param, int &padding)
{
    if (param->data_type != OSSL_PARAM_UTF8_STRING) {
        return OSSL_PARAM_get_int(param, &padding) &&
            (padding == RSA_PKCS1_PADDING || padding == RSA_PKCS1_PSS_PADDING);
    }
    std::string value;
    if (!ReadString(param, value) || (value != OSSL_PKEY_RSA_PAD_MODE_PKCSV15 &&
        value != OSSL_PKEY_RSA_PAD_MODE_PSS)) {
        return false;
    }
    padding = value == OSSL_PKEY_RSA_PAD_MODE_PSS ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
    return true;
}

int SignatureSetParams(void *ptr, const OSSL_PARAM params[])
{
    auto ctx = static_cast<SignatureContext *>(ptr);
    if (!params) {
        return 1;
    }
    const auto *param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    std::string value;
    if (param) {
        if (!ReadString(param, value) || (ctx->digest = CanonicalDigest(value.c_str())).empty()) {
            return Fail(ctx);
        }
    }
    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (param && !ReadRsaPadding(param, ctx->padding)) {
        return Fail(ctx);
    }
    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (param && (!ReadString(param, value) || (ctx->mgfDigest = CanonicalDigest(value.c_str())).empty())) {
        return Fail(ctx);
    }
    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (param && !ReadPssSaltLength(param, ctx->saltLength)) {
        return Fail(ctx);
    }
    return 1;
}
const OSSL_PARAM *SignatureSettable(void *, void *)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nullptr, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nullptr, 0),
        OSSL_PARAM_END
    };
    return params;
}

int WriteSignatureIntParam(OSSL_PARAM *param, int value)
{
    if (param->data != nullptr && param->data_size == 0) {
        return 0;
    }
    return OSSL_PARAM_set_int(param, value);
}

int SignatureGetParams(void *ptr, OSSL_PARAM params[])
{
    auto ctx = static_cast<SignatureContext *>(ptr);
    auto param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (param && !OSSL_PARAM_set_utf8_string(param, ctx->digest.c_str())) {
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (param) {
        if (param->data_type == OSSL_PARAM_INTEGER) {
            if (!WriteSignatureIntParam(param, ctx->padding)) {
                return 0;
            }
        } else if (!OSSL_PARAM_set_utf8_string(param, ctx->padding == RSA_PKCS1_PSS_PADDING ?
            OSSL_PKEY_RSA_PAD_MODE_PSS : OSSL_PKEY_RSA_PAD_MODE_PKCSV15)) { return 0; }
    }
    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (param && !OSSL_PARAM_set_utf8_string(param,
        ctx->mgfDigest.empty() ? ctx->digest.c_str() : ctx->mgfDigest.c_str())) {
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (param) {
        if (param->data_type == OSSL_PARAM_INTEGER) {
            if (!WriteSignatureIntParam(param, ctx->saltLength)) {
                return 0;
            }
        } else if (!OSSL_PARAM_set_utf8_string(param, ctx->saltLength == RSA_PSS_SALTLEN_DIGEST ?
            OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST : std::to_string(ctx->saltLength).c_str())) {
            return 0;
        }
    }
    // ASN.1 algorithm identifiers are not advertised by this TLS-only implementation.
    return OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID) ? 0 : 1;
}
int DigestSignInit(void *ptr, const char *digest, void *key, const OSSL_PARAM params[])
{
    auto ctx = static_cast<SignatureContext *>(ptr);
    auto external = static_cast<ExternalKey *>(key);
    if (!external || !external->signing || !ctx->provider->credential || ctx->provider->state->IsCancelled()) {
        return Fail(ctx);
    }
    ctx->key = *external;
    ctx->digest = CanonicalDigest(digest);
    return !ctx->digest.empty() && SignatureSetParams(ctx, params) ? 1 : Fail(ctx);
}
bool VerifySignature(SignatureContext *ctx, const uint8_t *data, size_t size,
                     const std::vector<uint8_t> &signature)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX *pctx = nullptr;
    if (!md || EVP_DigestVerifyInit_ex(md.get(), &pctx, ctx->digest.c_str(), ctx->provider->libctx,
        "provider=default", ctx->key.publicKey.get(), nullptr) <= 0) {
        return false;
    }
    if (EVP_PKEY_is_a(ctx->key.publicKey.get(), "RSA")) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, ctx->padding) <= 0) { return false; }
        if (ctx->padding == RSA_PKCS1_PSS_PADDING &&
            (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
             EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_get_digestbyname(ctx->digest.c_str())) <= 0)) {
            return false;
        }
    }
    return EVP_DigestVerify(md.get(), signature.data(), signature.size(), data, size) == 1;
}
int DigestSign(void *ptr, unsigned char *signature, size_t *signatureSize, size_t capacity,
               const unsigned char *data, size_t size)
{
    auto ctx = static_cast<SignatureContext *>(ptr);
    if (!signatureSize || !ctx->key.signing || ctx->provider->state->IsCancelled()) {
        return Fail(ctx);
    }
    const size_t maxSize = EVP_PKEY_get_size(ctx->key.publicKey.get());
    if (!signature) {
        *signatureSize = maxSize;
        return 1; // A length query must never create a Cm session.
    }
    const EVP_MD *md = EVP_get_digestbyname(ctx->digest.c_str());
    bool rsa = EVP_PKEY_is_a(ctx->key.publicKey.get(), "RSA");
    if (!md || capacity < maxSize || (!ctx->mgfDigest.empty() && ctx->mgfDigest != ctx->digest) ||
        (rsa && ctx->padding == RSA_PKCS1_PSS_PADDING && ctx->saltLength != RSA_PSS_SALTLEN_DIGEST &&
         ctx->saltLength != EVP_MD_size(md))) {
        return Fail(ctx);
    }
    std::vector<uint8_t> result(maxSize);
    const auto &credential = ctx->provider->credential;
    auto error = credential->adapter->Sign(
        credential->keyUri, {ctx->digest, rsa ? ctx->padding : 0}, data, size, result);
    if (error != 0) {
        ctx->provider->state->SetFirstError(error);
        return 0;
    }
    if (result.empty() || result.size() > capacity || !VerifySignature(ctx, data, size, result)) {
        return Fail(ctx);
    }
    if (ctx->provider->state->IsCancelled()) {
        return Fail(ctx);
    }
    std::copy(result.begin(), result.end(), signature);
    *signatureSize = result.size();
    return 1;
}

template<typename Function>
OSSL_DISPATCH MakeDispatch(int id, Function function)
{
    return {id, reinterpret_cast<void (*)(void)>(function)};
}

auto MakeKeyDispatch(OSSL_FUNC_keymgmt_import_fn *importFn,
    OSSL_FUNC_keymgmt_query_operation_name_fn *operationFn)
{
    return std::array{
        MakeDispatch(OSSL_FUNC_KEYMGMT_NEW, KeyNew),
        MakeDispatch(OSSL_FUNC_KEYMGMT_FREE, KeyFree),
        MakeDispatch(OSSL_FUNC_KEYMGMT_DUP, KeyDup),
        MakeDispatch(OSSL_FUNC_KEYMGMT_HAS, KeyHas),
        MakeDispatch(OSSL_FUNC_KEYMGMT_MATCH, KeyMatch),
        MakeDispatch(OSSL_FUNC_KEYMGMT_VALIDATE, KeyValidate),
        MakeDispatch(OSSL_FUNC_KEYMGMT_GET_PARAMS, KeyGetParams),
        MakeDispatch(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, KeyGettable),
        MakeDispatch(OSSL_FUNC_KEYMGMT_IMPORT, importFn),
        MakeDispatch(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, KeyTypes),
        MakeDispatch(OSSL_FUNC_KEYMGMT_EXPORT, KeyExport),
        MakeDispatch(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, KeyTypes),
        MakeDispatch(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, operationFn),
        OSSL_DISPATCH{0, nullptr}
    };
}
const auto RSA_KEY_FUNCTIONS = MakeKeyDispatch(RsaImport, RsaOperation);
const auto EC_KEY_FUNCTIONS = MakeKeyDispatch(EcImport, EcOperation);
const OSSL_DISPATCH SIGNATURE_FUNCTIONS[] = {
    MakeDispatch(OSSL_FUNC_SIGNATURE_NEWCTX, SignatureNew),
    MakeDispatch(OSSL_FUNC_SIGNATURE_FREECTX, SignatureFree),
    MakeDispatch(OSSL_FUNC_SIGNATURE_DUPCTX, SignatureDup),
    MakeDispatch(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, DigestSignInit),
    MakeDispatch(OSSL_FUNC_SIGNATURE_DIGEST_SIGN, DigestSign),
    MakeDispatch(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, SignatureSetParams),
    MakeDispatch(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, SignatureSettable),
    MakeDispatch(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, SignatureGetParams),
    MakeDispatch(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, SignatureSettable),
    {0, nullptr}
};
const OSSL_ALGORITHM KEY_ALGORITHMS[] = {
    {"RSA:rsaEncryption", "provider=netstack-certmanager", RSA_KEY_FUNCTIONS.data(), "Certificate manager RSA key"},
    {"EC:id-ecPublicKey", "provider=netstack-certmanager", EC_KEY_FUNCTIONS.data(), "Certificate manager EC key"},
    {nullptr, nullptr, nullptr, nullptr}
};
const OSSL_ALGORITHM SIGNATURE_ALGORITHMS[] = {
    {"RSA", "provider=netstack-certmanager", SIGNATURE_FUNCTIONS, "Certificate manager RSA signature"},
    {"ECDSA", "provider=netstack-certmanager", SIGNATURE_FUNCTIONS, "Certificate manager EC signature"},
    {nullptr, nullptr, nullptr, nullptr}
};
const OSSL_ALGORITHM *ProviderQuery(void *, int operation, int *noCache)
{
    *noCache = 0;
    switch (operation) {
        case OSSL_OP_KEYMGMT: return KEY_ALGORITHMS;
        case OSSL_OP_SIGNATURE: return SIGNATURE_ALGORITHMS;
        default: return nullptr;
    }
}
void ProviderFree(void *ctx) { delete static_cast<ProviderContext *>(ctx); }
const OSSL_DISPATCH PROVIDER_FUNCTIONS[] = {
    MakeDispatch(OSSL_FUNC_PROVIDER_TEARDOWN, ProviderFree),
    MakeDispatch(OSSL_FUNC_PROVIDER_QUERY_OPERATION, ProviderQuery), {0, nullptr}
};
int ProviderInit(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **out, void **ctx)
{
    *ctx = new (std::nothrow) ProviderContext;
    *out = PROVIDER_FUNCTIONS;
    return *ctx ? 1 : 0;
}
} // namespace

struct AliasProviderRuntime::Impl {
    OSSL_LIB_CTX *libctx = nullptr;
    OSSL_PROVIDER *defaultProvider = nullptr;
    OSSL_PROVIDER *aliasProvider = nullptr;
    EVP_PKEY *key = nullptr;
    ~Impl()
    {
        EVP_PKEY_free(key);
        OSSL_PROVIDER_unload(aliasProvider);
        OSSL_PROVIDER_unload(defaultProvider);
        OSSL_LIB_CTX_free(libctx);
    }
};
AliasProviderRuntime::AliasProviderRuntime() : impl_(std::make_unique<Impl>()) {}
AliasProviderRuntime::~AliasProviderRuntime() = default;
bool AliasProviderRuntime::Initialize(const std::shared_ptr<AliasCredential> &credential,
    const std::shared_ptr<TlsConnectAttemptState> &state)
{
    if (!credential || !credential->publicKey || !state || impl_->libctx) {
        return false;
    }
    impl_->libctx = OSSL_LIB_CTX_new();
    if (!impl_->libctx || !OSSL_PROVIDER_add_builtin(impl_->libctx, PROVIDER_NAME, ProviderInit)) {
        state->SetFirstError(SYSTEM_INTERNAL_ERROR);
        return false;
    }
    impl_->defaultProvider = OSSL_PROVIDER_load(impl_->libctx, "default");
    impl_->aliasProvider = OSSL_PROVIDER_load(impl_->libctx, PROVIDER_NAME);
    if (!impl_->defaultProvider || !impl_->aliasProvider) {
        state->SetFirstError(TLS_ALIAS_UNSUPPORTED);
        return false;
    }
    auto provider = static_cast<ProviderContext *>(OSSL_PROVIDER_get0_provider_ctx(impl_->aliasProvider));
    provider->libctx = impl_->libctx;
    provider->credential = credential;
    provider->state = state;
    const char *algorithm = EVP_PKEY_base_id(credential->publicKey.get()) == EVP_PKEY_RSA ? "RSA" : "EC";
    OSSL_PARAM *params = nullptr;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(impl_->libctx, algorithm, "provider=netstack-certmanager"), EVP_PKEY_CTX_free);
    bool ok = ctx && EVP_PKEY_todata(credential->publicKey.get(), EVP_PKEY_PUBLIC_KEY, &params) > 0 &&
        EVP_PKEY_fromdata_init(ctx.get()) > 0 &&
        EVP_PKEY_fromdata(ctx.get(), &impl_->key, EVP_PKEY_KEYPAIR, params) > 0;
    OSSL_PARAM_free(params);
    if (!ok) {
        state->SetFirstError(TLS_ERR_SSL_NULL);
    }
    return ok;
}
SSL_CTX *AliasProviderRuntime::CreateClientContext() const
{
    return impl_->key ? SSL_CTX_new_ex(impl_->libctx, nullptr, TLS_client_method()) : nullptr;
}
EVP_PKEY *AliasProviderRuntime::GetKey() const { return impl_->key; }
} // namespace OHOS::NetStack::TlsSocket
#else
namespace OHOS::NetStack::TlsSocket {
struct AliasProviderRuntime::Impl {};
AliasProviderRuntime::AliasProviderRuntime() : impl_(std::make_unique<Impl>()) {}
AliasProviderRuntime::~AliasProviderRuntime() = default;
bool AliasProviderRuntime::Initialize(const std::shared_ptr<AliasCredential> &,
    const std::shared_ptr<TlsConnectAttemptState> &state)
{
    if (state) { state->SetFirstError(TLS_ALIAS_UNSUPPORTED); }
    return false;
}
SSL_CTX *AliasProviderRuntime::CreateClientContext() const { return nullptr; }
EVP_PKEY *AliasProviderRuntime::GetKey() const { return nullptr; }
} // namespace OHOS::NetStack::TlsSocket
#endif
