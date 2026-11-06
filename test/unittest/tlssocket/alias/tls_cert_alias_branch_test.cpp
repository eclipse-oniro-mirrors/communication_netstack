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

#include "tls_cert_alias_test_utils.h"
#include <array>
#include <gtest/gtest.h>
#include <openssl/core_dispatch.h>

namespace OHOS::NetStack::TlsSocket::Test {
namespace {
using namespace testing::ext;
constexpr size_t SIGNATURE_PARAM_BUFFER_SIZE = 32;

// Exercise the real registered provider dispatch, including contracts EVP normally filters.
class ProviderProbe {
public:
    explicit ProviderProbe(Fixture &fixture, bool ec = false)
    {
        provider_ = EVP_PKEY_get0_provider(fixture.runtime.GetKey());
        context = OSSL_PROVIDER_get0_provider_ctx(provider_);
        keys_ = Algorithms(OSSL_OP_KEYMGMT)[ec ? 1 : 0].implementation;
        signatures_ = Algorithms(OSSL_OP_SIGNATURE)[ec ? 1 : 0].implementation;
    }

    ~ProviderProbe()
    {
        OSSL_PROVIDER_unquery_operation(provider_, OSSL_OP_KEYMGMT, keyAlgorithms_);
        OSSL_PROVIDER_unquery_operation(provider_, OSSL_OP_SIGNATURE, signatureAlgorithms_);
    }

    template<class Function> Function *Key(int id) const { return Find<Function>(keys_, id); }
    template<class Function> Function *Signature(int id) const { return Find<Function>(signatures_, id); }

    auto NewKey() const
    {
        return std::unique_ptr<void, OSSL_FUNC_keymgmt_free_fn *>(
            Key<OSSL_FUNC_keymgmt_new_fn>(OSSL_FUNC_KEYMGMT_NEW)(context),
            Key<OSSL_FUNC_keymgmt_free_fn>(OSSL_FUNC_KEYMGMT_FREE));
    }

    auto NewSignature() const
    {
        return std::unique_ptr<void, OSSL_FUNC_signature_freectx_fn *>(
            Signature<OSSL_FUNC_signature_newctx_fn>(OSSL_FUNC_SIGNATURE_NEWCTX)(context, nullptr),
            Signature<OSSL_FUNC_signature_freectx_fn>(OSSL_FUNC_SIGNATURE_FREECTX));
    }

    bool Import(void *key, EVP_PKEY *publicKey, int selection = EVP_PKEY_KEYPAIR) const
    {
        OSSL_PARAM *params = nullptr;
        AliasCheck(EVP_PKEY_todata(publicKey, EVP_PKEY_PUBLIC_KEY, &params) > 0, __FILE__, __LINE__);
        int result = Key<OSSL_FUNC_keymgmt_import_fn>(OSSL_FUNC_KEYMGMT_IMPORT)(key, selection, params);
        OSSL_PARAM_free(params);
        return result == 1;
    }

    int Init(void *signature, void *key, const char *digest = "SHA256", const OSSL_PARAM *params = nullptr) const
    {
        return Signature<OSSL_FUNC_signature_digest_sign_init_fn>(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT)(
            signature, digest, key, params);
    }

    int Set(void *signature, const OSSL_PARAM *params) const
    {
        return Signature<OSSL_FUNC_signature_set_ctx_params_fn>(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS)(signature, params);
    }

    int Get(void *signature, OSSL_PARAM *params) const
    {
        return Signature<OSSL_FUNC_signature_get_ctx_params_fn>(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS)(signature, params);
    }

    int Sign(void *signature, unsigned char *output, size_t *size, size_t capacity) const
    {
        constexpr unsigned char message[] = "certificate verify original message";
        return Signature<OSSL_FUNC_signature_digest_sign_fn>(OSSL_FUNC_SIGNATURE_DIGEST_SIGN)(
            signature, output, size, capacity, message, sizeof(message));
    }

    void *context = nullptr;

private:
    template<class Function> static Function *Find(const OSSL_DISPATCH *table, int id)
    {
        for (; table->function_id != 0; ++table) {
            if (table->function_id == id) {
                return reinterpret_cast<Function *>(table->function);
            }
        }
        AliasCheck(false, __FILE__, __LINE__);
        return nullptr;
    }

    const OSSL_ALGORITHM *Algorithms(int operation)
    {
        int noCache = 1;
        const auto *algorithms = OSSL_PROVIDER_query_operation(provider_, operation, &noCache);
        AliasCheck(algorithms && noCache == 0, __FILE__, __LINE__);
        (operation == OSSL_OP_KEYMGMT ? keyAlgorithms_ : signatureAlgorithms_) = algorithms;
        return algorithms;
    }

    const OSSL_PROVIDER *provider_ = nullptr;
    const OSSL_DISPATCH *keys_ = nullptr;
    const OSSL_DISPATCH *signatures_ = nullptr;
    const OSSL_ALGORITHM *keyAlgorithms_ = nullptr;
    const OSSL_ALGORITHM *signatureAlgorithms_ = nullptr;
};

class TlsCertAliasBranchTest : public testing::Test {
public:
    void TearDown() override { ERR_clear_error(); }
};

HWTEST_F(TlsCertAliasBranchTest, AllErrorBoundariesAndDisabledBackend, TestSize.Level1)
{
    for (int error : {TLS_ALIAS_PERMISSION, TLS_ALIAS_INVALID, TLS_ALIAS_UNSUPPORTED,
        TLS_ALIAS_NOT_FOUND, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_UNAUTHORIZED}) {
        EXPECT_TRUE(IsCertAliasError(error));
        EXPECT_FALSE(CertAliasErrorMessage(error).empty());
        EXPECT_EQ(MakeSSLErrorString(error), CertAliasErrorMessage(error));
    }
    const int nonAliasErrors[] = {0, TLS_ALIAS_PERMISSION - 1, TLS_ALIAS_PERMISSION + 1, TLS_ALIAS_INVALID - 1,
        TLS_ALIAS_INVALID + 1, TLS_ALIAS_UNSUPPORTED - 1, TLS_ALIAS_UNSUPPORTED + 1,
        TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED, TLS_ALIAS_UNAUTHORIZED + 1, -1};
    for (int error : nonAliasErrors) {
        EXPECT_FALSE(IsCertAliasError(error));
        EXPECT_TRUE(CertAliasErrorMessage(error).empty());
    }
    auto adapter = CreateCertManagerAdapter();
    std::string uri;
    std::string pem;
    uint32_t count = 0;
    EXPECT_EQ(adapter->Load("valid", uri, pem, count), TLS_ALIAS_UNSUPPORTED);
    std::vector<uint8_t> signature(RSA_SIGNATURE_SIZE);
    EXPECT_EQ(adapter->Sign("uri", {"SHA256", 0}, nullptr, 0, signature), TLS_ALIAS_UNSUPPORTED);
}

HWTEST_F(TlsCertAliasBranchTest, FirstErrorAndCancellationAreAttemptLocal, TestSize.Level1)
{
    TlsConnectAttemptState first;
    TlsConnectAttemptState second;
    first.SetFirstError(0);
    first.SetFirstError(TLS_ALIAS_UNAUTHORIZED);
    first.SetFirstError(TLS_ALIAS_SERVICE_ERROR);
    EXPECT_EQ(first.GetError(), TLS_ALIAS_UNAUTHORIZED);
    EXPECT_EQ(second.GetError(), 0);
    EXPECT_FALSE(first.IsCancelled());
    first.Cancel();
    first.Cancel();
    EXPECT_TRUE(first.IsCancelled());
    EXPECT_FALSE(second.IsCancelled());
}

HWTEST_F(TlsCertAliasBranchTest, CredentialFailuresResetPreviousOutput, TestSize.Level1)
{
    auto adapter = std::make_shared<SigningAdapter>(false);
    std::shared_ptr<AliasCredential> credential;
    ASSERT_EQ(PrepareAliasCredential("valid", credential, adapter), 0);
    ASSERT_NE(credential, nullptr);
    for (int error : {TLS_ALIAS_PERMISSION, TLS_ALIAS_UNSUPPORTED, TLS_ALIAS_NOT_FOUND,
        TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_UNAUTHORIZED}) {
        adapter->loadError = error;
        EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), error);
        EXPECT_EQ(credential, nullptr);
    }
    adapter->loadError = 0;
    adapter->returnedUri.clear();
    EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), TLS_ALIAS_NOT_FOUND);
    adapter->returnedUri = "fake-owned-private-uri";
    adapter->certCount = 0;
    EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), TLS_ALIAS_NOT_FOUND);
    EXPECT_EQ(credential, nullptr);
}

HWTEST_F(TlsCertAliasBranchTest, PemFramingNulWhitespaceAndMalformedCertificates, TestSize.Level1)
{
    auto adapter = std::make_shared<SigningAdapter>(false);
    const auto original = adapter->pem;
    std::shared_ptr<AliasCredential> credential;
    for (const auto &pem : {std::string{}, std::string(" \r\n\t"), std::string("garbage"),
        std::string("-----BEGIN CERTIFICATE-----\nmissing end"),
        std::string("-----BEGIN CERTIFICATE-----\nbad base64\n-----END CERTIFICATE-----")}) {
        SCOPED_TRACE(pem);
        adapter->pem = pem;
        EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), TLS_ALIAS_NOT_FOUND);
        EXPECT_EQ(credential, nullptr);
    }
    adapter->pem = " \n\t" + original + "\r\n\t ";
    adapter->pem.push_back('\0');
    ASSERT_EQ(PrepareAliasCredential("valid", credential, adapter), 0);
    EXPECT_EQ(credential->certChain.size(), 1U);
    EXPECT_EQ(credential->keyUri, adapter->returnedUri);
}

HWTEST_F(TlsCertAliasBranchTest, UnsupportedCertificateKeyAlgorithm, TestSize.Level1)
{
    auto adapter = std::make_shared<SigningAdapter>(false);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    ASSERT_NE(key, nullptr);
    ASSERT_EQ(X509_set_pubkey(adapter->cert.get(), key.get()), 1);
    ASSERT_GT(X509_sign(adapter->cert.get(), key.get(), nullptr), 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    ASSERT_EQ(PEM_write_bio_X509(bio.get(), adapter->cert.get()), 1);
    char *data = nullptr;
    auto size = BIO_get_mem_data(bio.get(), &data);
    adapter->pem.assign(data, size);
    std::shared_ptr<AliasCredential> credential;
    EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), TLS_ALIAS_UNSUPPORTED);
    EXPECT_EQ(credential, nullptr);
}

HWTEST_F(TlsCertAliasBranchTest, CertificateWithUndecodablePublicKeyIsUnavailable, TestSize.Level1)
{
    auto adapter = std::make_shared<SigningAdapter>(false);
    auto algorithm = OBJ_txt2obj("1.2.3.4.5.6.7", 1);
    ASSERT_NE(algorithm, nullptr);
    ASSERT_EQ(X509_PUBKEY_set0_param(X509_get_X509_PUBKEY(adapter->cert.get()),
        algorithm, V_ASN1_UNDEF, nullptr, nullptr, 0), 1);
    ASSERT_GT(X509_sign(adapter->cert.get(), adapter->privateKey.get(), EVP_sha256()), 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    ASSERT_NE(bio, nullptr);
    ASSERT_EQ(PEM_write_bio_X509(bio.get(), adapter->cert.get()), 1);
    char *data = nullptr;
    auto size = BIO_get_mem_data(bio.get(), &data);
    adapter->pem.assign(data, size);
    std::shared_ptr<AliasCredential> credential;
    EXPECT_EQ(PrepareAliasCredential("valid", credential, adapter), TLS_ALIAS_NOT_FOUND);
    EXPECT_EQ(credential, nullptr);
}

HWTEST_F(TlsCertAliasBranchTest, RuntimeRejectsInvalidAndRepeatedInitialization, TestSize.Level1)
{
    AliasProviderRuntime runtime;
    auto state = std::make_shared<TlsConnectAttemptState>();
    EXPECT_EQ(runtime.GetKey(), nullptr);
    EXPECT_EQ(runtime.CreateClientContext(), nullptr);
    EXPECT_FALSE(runtime.Initialize(nullptr, state));
    EXPECT_FALSE(runtime.Initialize(std::make_shared<AliasCredential>(), state));
    Fixture fixture(false);
    EXPECT_FALSE(runtime.Initialize(fixture.credential, nullptr));
    EXPECT_TRUE(runtime.Initialize(fixture.credential, state));
    EXPECT_FALSE(runtime.Initialize(fixture.credential, state));
}

HWTEST_F(TlsCertAliasBranchTest, RuntimeRejectsUnimportablePublicKey, TestSize.Level1)
{
    AliasProviderRuntime runtime;
    auto credential = std::make_shared<AliasCredential>();
    credential->publicKey.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    ASSERT_NE(credential->publicKey, nullptr);
    auto state = std::make_shared<TlsConnectAttemptState>();
    EXPECT_FALSE(runtime.Initialize(credential, state));
    EXPECT_EQ(state->GetError(), TLS_ERR_SSL_NULL);
    EXPECT_EQ(runtime.GetKey(), nullptr);
    EXPECT_EQ(runtime.CreateClientContext(), nullptr);
}

HWTEST_F(TlsCertAliasBranchTest, InvalidPublicParametersAndUnsupportedOperation, TestSize.Level1)
{
    for (bool ec : {false, true}) {
        Fixture fixture(ec);
        ProviderProbe probe(fixture, ec);
        auto key = probe.NewKey();
        OSSL_PARAM empty[] = {OSSL_PARAM_END};
        EXPECT_EQ(probe.Key<OSSL_FUNC_keymgmt_import_fn>(OSSL_FUNC_KEYMGMT_IMPORT)(
            key.get(), EVP_PKEY_KEYPAIR, empty), 0);
        int bits = 0;
        OSSL_PARAM params[] = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, &bits), OSSL_PARAM_END};
        EXPECT_EQ(probe.Key<OSSL_FUNC_keymgmt_get_params_fn>(OSSL_FUNC_KEYMGMT_GET_PARAMS)(key.get(), params), 0);
        int noCache = 1;
        auto provider = EVP_PKEY_get0_provider(fixture.runtime.GetKey());
        EXPECT_EQ(OSSL_PROVIDER_query_operation(provider, OSSL_OP_CIPHER, &noCache), nullptr);
        EXPECT_EQ(noCache, 0);
    }
}

HWTEST_F(TlsCertAliasBranchTest, PublicValidationRejectsInvalidRsaKey, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto key = probe.NewKey();
    constexpr unsigned char invalidRsaModulus = 15;
    constexpr unsigned char invalidRsaExponent = 3;
    unsigned char modulus[] = {invalidRsaModulus};
    unsigned char exponent[] = {invalidRsaExponent};
    OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, modulus, sizeof(modulus)),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, exponent, sizeof(exponent)), OSSL_PARAM_END};
    ASSERT_EQ(probe.Key<OSSL_FUNC_keymgmt_import_fn>(OSSL_FUNC_KEYMGMT_IMPORT)(
        key.get(), EVP_PKEY_PUBLIC_KEY, params), 1);
    EXPECT_EQ(probe.Key<OSSL_FUNC_keymgmt_validate_fn>(OSSL_FUNC_KEYMGMT_VALIDATE)(
        key.get(), EVP_PKEY_PUBLIC_KEY, 0), 0);
    EXPECT_EQ(probe.Key<OSSL_FUNC_keymgmt_has_fn>(OSSL_FUNC_KEYMGMT_HAS)(
        key.get(), OSSL_KEYMGMT_SELECT_PRIVATE_KEY), 0);
}

HWTEST_F(TlsCertAliasBranchTest, KeyImportValidateDuplicateAndIdentityBinding, TestSize.Level1)
{
    for (bool ec : {false, true}) {
        Fixture fixture(ec);
        ProviderProbe probe(fixture, ec);
        auto key = probe.NewKey();
        auto has = probe.Key<OSSL_FUNC_keymgmt_has_fn>(OSSL_FUNC_KEYMGMT_HAS);
        auto validate = probe.Key<OSSL_FUNC_keymgmt_validate_fn>(OSSL_FUNC_KEYMGMT_VALIDATE);
        EXPECT_EQ(has(nullptr, EVP_PKEY_PUBLIC_KEY), 0);
        EXPECT_EQ(has(key.get(), EVP_PKEY_KEYPAIR), 0);
        EXPECT_EQ(validate(key.get(), EVP_PKEY_PUBLIC_KEY, 0), 0);
        EXPECT_FALSE(probe.Import(nullptr, fixture.credential->publicKey.get()));
        EXPECT_FALSE(probe.Import(key.get(), fixture.credential->publicKey.get(), OSSL_KEYMGMT_SELECT_PRIVATE_KEY));
        ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
        EXPECT_EQ(has(key.get(), EVP_PKEY_KEYPAIR), 1);
        EXPECT_EQ(validate(key.get(), EVP_PKEY_PUBLIC_KEY, 0), 1);
        auto duplicate = probe.NewKey();
        duplicate.reset(probe.Key<OSSL_FUNC_keymgmt_dup_fn>(OSSL_FUNC_KEYMGMT_DUP)(key.get(), EVP_PKEY_PUBLIC_KEY));
        ASSERT_NE(duplicate, nullptr);
        EXPECT_EQ(has(duplicate.get(), OSSL_KEYMGMT_SELECT_PRIVATE_KEY), 0);
        auto match = probe.Key<OSSL_FUNC_keymgmt_match_fn>(OSSL_FUNC_KEYMGMT_MATCH);
        EXPECT_EQ(match(nullptr, key.get(), EVP_PKEY_PUBLIC_KEY), 0);
        EXPECT_EQ(match(key.get(), duplicate.get(), EVP_PKEY_PUBLIC_KEY), 1);
        EXPECT_EQ(match(key.get(), duplicate.get(), EVP_PKEY_KEYPAIR), 0);
        auto signingCopy = probe.NewKey();
        signingCopy.reset(probe.Key<OSSL_FUNC_keymgmt_dup_fn>(
            OSSL_FUNC_KEYMGMT_DUP)(key.get(), EVP_PKEY_KEYPAIR));
        ASSERT_NE(signingCopy, nullptr);
        EXPECT_EQ(has(signingCopy.get(), EVP_PKEY_KEYPAIR), 1);
        EXPECT_EQ(match(key.get(), signingCopy.get(), EVP_PKEY_KEYPAIR), 1);
        SigningAdapter different(ec);
        EXPECT_FALSE(probe.Import(duplicate.get(), different.privateKey.get()));
        ASSERT_TRUE(probe.Import(duplicate.get(), different.privateKey.get(), EVP_PKEY_PUBLIC_KEY));
        EXPECT_EQ(match(key.get(), duplicate.get(), EVP_PKEY_PUBLIC_KEY), 0);
        auto operation = probe.Key<OSSL_FUNC_keymgmt_query_operation_name_fn>(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME);
        EXPECT_STREQ(operation(OSSL_OP_SIGNATURE), ec ? "ECDSA" : "RSA");
        EXPECT_EQ(operation(OSSL_OP_ASYM_CIPHER), nullptr);
    }
}

int PublicOnlyExport(const OSSL_PARAM params[], void *arg)
{
    ++*static_cast<int *>(arg);
    EXPECT_EQ(OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D), nullptr);
    EXPECT_EQ(OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY), nullptr);
    return 1;
}

HWTEST_F(TlsCertAliasBranchTest, KeyExportNeverExposesPrivateMaterial, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto key = probe.NewKey();
    auto exportKey = probe.Key<OSSL_FUNC_keymgmt_export_fn>(OSSL_FUNC_KEYMGMT_EXPORT);
    int callbacks = 0;
    EXPECT_EQ(exportKey(nullptr, EVP_PKEY_PUBLIC_KEY, PublicOnlyExport, &callbacks), 0);
    EXPECT_EQ(exportKey(key.get(), EVP_PKEY_PUBLIC_KEY, PublicOnlyExport, &callbacks), 0);
    ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
    EXPECT_EQ(exportKey(key.get(), EVP_PKEY_KEYPAIR, PublicOnlyExport, &callbacks), 0);
    EXPECT_EQ(callbacks, 0);
    EXPECT_EQ(exportKey(key.get(), EVP_PKEY_PUBLIC_KEY, PublicOnlyExport, &callbacks), 1);
    EXPECT_EQ(callbacks, 1);
    EXPECT_EQ(exportKey(key.get(), EVP_PKEY_PUBLIC_KEY, [](const OSSL_PARAM *, void *) { return 0; }, nullptr), 0);
    int bits = 0;
    OSSL_PARAM params[] = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, &bits), OSSL_PARAM_END};
    auto get = probe.Key<OSSL_FUNC_keymgmt_get_params_fn>(OSSL_FUNC_KEYMGMT_GET_PARAMS);
    EXPECT_EQ(get(nullptr, params), 0);
    EXPECT_EQ(get(key.get(), params), 1);
    EXPECT_EQ(bits, RSA_KEY_BITS);
    constexpr size_t invalidBitsBufferSize = 4;
    char invalidBits[invalidBitsBufferSize]{};
    OSSL_PARAM malformed[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_BITS, invalidBits, sizeof(invalidBits)), OSSL_PARAM_END};
    EXPECT_EQ(get(key.get(), malformed), 0);
    EXPECT_NE(probe.Key<OSSL_FUNC_keymgmt_gettable_params_fn>(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS)(probe.context), nullptr);
    EXPECT_NE(probe.Key<OSSL_FUNC_keymgmt_import_types_fn>(
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES)(EVP_PKEY_PUBLIC_KEY), nullptr);
}

HWTEST_F(TlsCertAliasBranchTest, MalformedSignatureStringParameters, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto signature = probe.NewSignature();
    EXPECT_EQ(probe.Set(signature.get(), nullptr), 1);
    const std::pair<const char *, std::vector<std::string>> inputs[] = {
        {OSSL_SIGNATURE_PARAM_DIGEST, {"", "SHA1", "unknown"}},
        {OSSL_SIGNATURE_PARAM_PAD_MODE, {"", "oaep", "none"}},
        {OSSL_SIGNATURE_PARAM_MGF1_DIGEST, {"", "SHA1", "unknown"}},
        {OSSL_SIGNATURE_PARAM_PSS_SALTLEN, {"", "-1", "auto", "32junk", "99999999999999999999"}},
    };
    for (const auto &[name, values] : inputs) {
        for (const auto &value : values) {
            SCOPED_TRACE(std::string(name) + "=" + value);
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(name, const_cast<char *>(value.c_str()), 0), OSSL_PARAM_END};
            EXPECT_EQ(probe.Set(signature.get(), params), 0);
        }
        OSSL_PARAM nullString[] = {OSSL_PARAM_utf8_string(name, nullptr, 0), OSSL_PARAM_END};
        EXPECT_EQ(probe.Set(signature.get(), nullString), 0);
    }
    EXPECT_EQ(fixture.state->GetError(), TLS_ERR_SSL_NULL);
}

HWTEST_F(TlsCertAliasBranchTest, MalformedSignatureParameterTypes, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto signature = probe.NewSignature();
    constexpr unsigned char invalidParamByte = 0xff;
    unsigned char value[] = {invalidParamByte};
    for (const char *name : {OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_PAD_MODE,
        OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_SIGNATURE_PARAM_PSS_SALTLEN}) {
        OSSL_PARAM params[] = {OSSL_PARAM_octet_string(name, value, sizeof(value)), OSSL_PARAM_END};
        EXPECT_EQ(probe.Set(signature.get(), params), 0);
    }
    int padding = RSA_NO_PADDING;
    OSSL_PARAM params[] = {OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding), OSSL_PARAM_END};
    EXPECT_EQ(probe.Set(signature.get(), params), 0);
}

HWTEST_F(TlsCertAliasBranchTest, SignatureParameterRoundTripAndContextDuplication, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto signature = probe.NewSignature();
    char digest[] = "sha256";
    char padding[] = "pss";
    char salt[] = "digest";
    OSSL_PARAM set[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, padding, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, salt, 0), OSSL_PARAM_END};
    ASSERT_EQ(probe.Set(signature.get(), set), 1);
    auto copy = probe.NewSignature();
    copy.reset(probe.Signature<OSSL_FUNC_signature_dupctx_fn>(OSSL_FUNC_SIGNATURE_DUPCTX)(signature.get()));
    ASSERT_NE(copy, nullptr);
    char digestOut[SIGNATURE_PARAM_BUFFER_SIZE]{};
    char mgfOut[SIGNATURE_PARAM_BUFFER_SIZE]{};
    char paddingOut[SIGNATURE_PARAM_BUFFER_SIZE]{};
    char saltOut[SIGNATURE_PARAM_BUFFER_SIZE]{};
    OSSL_PARAM get[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digestOut, sizeof(digestOut)),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, mgfOut, sizeof(mgfOut)),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, paddingOut, sizeof(paddingOut)),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, saltOut, sizeof(saltOut)), OSSL_PARAM_END};
    ASSERT_EQ(probe.Get(copy.get(), get), 1);
    EXPECT_STREQ(digestOut, "SHA256");
    EXPECT_STREQ(mgfOut, "SHA256");
    EXPECT_STREQ(paddingOut, "pss");
    EXPECT_STREQ(saltOut, "digest");
    EXPECT_NE(probe.Signature<OSSL_FUNC_signature_settable_ctx_params_fn>(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS)(signature.get(), probe.context), nullptr);
    int intPadding = RSA_PKCS1_PADDING;
    int intSalt = SHA256_DIGEST_LENGTH;
    OSSL_PARAM integers[] = {OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &intPadding),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, &intSalt), OSSL_PARAM_END};
    ASSERT_EQ(probe.Set(copy.get(), integers), 1);
    ASSERT_EQ(probe.Get(copy.get(), integers), 1);
    EXPECT_EQ(intPadding, RSA_PKCS1_PADDING);
    EXPECT_EQ(intSalt, SHA256_DIGEST_LENGTH);
    ASSERT_EQ(probe.Get(copy.get(), get), 1);
    EXPECT_STREQ(paddingOut, "pkcs1");
    EXPECT_STREQ(saltOut, "32");
}

HWTEST_F(TlsCertAliasBranchTest, ExplicitMgfAndNumericSaltAllowValidSignatures, TestSize.Level1)
{
    for (std::string padding : {"pkcs1", "pss"}) {
        Fixture fixture(false);
        ProviderProbe probe(fixture);
        auto key = probe.NewKey();
        ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
        auto signature = probe.NewSignature();
        char digest[] = "SHA256";
        char salt[] = "32";
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, padding.data(), 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, digest, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, salt, 0), OSSL_PARAM_END};
        ASSERT_EQ(probe.Init(signature.get(), key.get(), digest, params), 1);
        char mgf[SIGNATURE_PARAM_BUFFER_SIZE]{};
        OSSL_PARAM get[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, mgf, sizeof(mgf)),
            OSSL_PARAM_END};
        EXPECT_EQ(probe.Get(signature.get(), get), 1);
        EXPECT_STREQ(mgf, "SHA256");
        std::vector<unsigned char> output(EVP_PKEY_get_size(fixture.runtime.GetKey()));
        size_t size = output.size();
        EXPECT_EQ(probe.Sign(signature.get(), output.data(), &size, output.size()), 1);
        EXPECT_GT(size, 0U);
        EXPECT_EQ(fixture.adapter->signs, 1);
        EXPECT_EQ(fixture.state->GetError(), 0);
    }
}

HWTEST_F(TlsCertAliasBranchTest, SignatureGetRejectsSmallBuffersAndAlgorithmId, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto key = probe.NewKey();
    ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
    auto signature = probe.NewSignature();
    ASSERT_EQ(probe.Init(signature.get(), key.get()), 1);
    char small[1]{};
    for (const char *name : {OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_PAD_MODE,
        OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_SIGNATURE_PARAM_PSS_SALTLEN}) {
        OSSL_PARAM params[] = {OSSL_PARAM_utf8_string(name, small, sizeof(small)), OSSL_PARAM_END};
        EXPECT_EQ(probe.Get(signature.get(), params), 0);
    }
    unsigned char byte = 0;
    for (const char *name : {OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_SIGNATURE_PARAM_PSS_SALTLEN}) {
        OSSL_PARAM params[] = {OSSL_PARAM_int(name, nullptr), OSSL_PARAM_END};
        params[0].data_size = 0;
        // A null data pointer is a size query, even with a zero buffer size.
        EXPECT_EQ(probe.Get(signature.get(), params), 1);
        EXPECT_EQ(params[0].return_size, sizeof(int));
        params[0].data = &byte;
        EXPECT_EQ(probe.Get(signature.get(), params), 0);
    }
    OSSL_PARAM algorithmId[] = {OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, &byte, 1), OSSL_PARAM_END};
    EXPECT_EQ(probe.Get(signature.get(), algorithmId), 0);
}

HWTEST_F(TlsCertAliasBranchTest, SignatureInitRequiresBoundPrivateCapabilityAndAllowedDigest, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto signature = probe.NewSignature();
    EXPECT_EQ(probe.Init(signature.get(), nullptr), 0);
    auto key = probe.NewKey();
    ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get(), EVP_PKEY_PUBLIC_KEY));
    EXPECT_EQ(probe.Init(signature.get(), key.get()), 0);
    ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
    EXPECT_EQ(probe.Init(signature.get(), key.get(), nullptr), 0);
    EXPECT_EQ(probe.Init(signature.get(), key.get(), "SHA1"), 0);
    char invalidDigest[] = "SHA1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, invalidDigest, 0), OSSL_PARAM_END};
    EXPECT_EQ(probe.Init(signature.get(), key.get(), "SHA256", params), 0);
    fixture.state->Cancel();
    EXPECT_EQ(probe.Init(signature.get(), key.get()), 0);
    EXPECT_EQ(fixture.adapter->signs, 0);
}

HWTEST_F(TlsCertAliasBranchTest, SignatureSizeQueryBufferLimitAndCancellation, TestSize.Level1)
{
    Fixture fixture(false);
    ProviderProbe probe(fixture);
    auto signature = probe.NewSignature();
    size_t size = 0;
    EXPECT_EQ(probe.Sign(signature.get(), nullptr, &size, 0), 0);
    auto key = probe.NewKey();
    ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
    ASSERT_EQ(probe.Init(signature.get(), key.get()), 1);
    EXPECT_EQ(probe.Sign(signature.get(), nullptr, nullptr, 0), 0);
    ASSERT_EQ(probe.Sign(signature.get(), nullptr, &size, 0), 1);
    EXPECT_EQ(size, static_cast<size_t>(EVP_PKEY_get_size(fixture.runtime.GetKey())));
    EXPECT_EQ(fixture.adapter->signs, 0);
    std::vector<unsigned char> output(size, OUTPUT_FILL_BYTE);
    EXPECT_EQ(probe.Sign(signature.get(), output.data(), &size, output.size() - 1), 0);
    fixture.state->Cancel();
    EXPECT_EQ(probe.Sign(signature.get(), output.data(), &size, output.size()), 0);
    EXPECT_EQ(fixture.adapter->signs, 0);
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](auto c) { return c == OUTPUT_FILL_BYTE; }));
}

HWTEST_F(TlsCertAliasBranchTest, BackendErrorsArePreservedForEveryNewAttempt, TestSize.Level1)
{
    for (int error : {TLS_ALIAS_PERMISSION, TLS_ALIAS_UNSUPPORTED, TLS_ALIAS_NOT_FOUND,
        TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_UNAUTHORIZED}) {
        Fixture fixture(false);
        ProviderProbe probe(fixture);
        auto key = probe.NewKey();
        ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
        auto signature = probe.NewSignature();
        ASSERT_EQ(probe.Init(signature.get(), key.get()), 1);
        std::vector<unsigned char> output(EVP_PKEY_get_size(fixture.runtime.GetKey()));
        size_t size = output.size();
        fixture.adapter->signError = error;
        EXPECT_EQ(probe.Sign(signature.get(), output.data(), &size, output.size()), 0);
        EXPECT_EQ(fixture.state->GetError(), error);
        EXPECT_EQ(fixture.adapter->signs, 1);
    }
}

HWTEST_F(TlsCertAliasBranchTest, InvalidBackendSignatureAndCancellationDoNotPublishOutput, TestSize.Level1)
{
    for (int resultSize : {0, RSA_SIGNATURE_SIZE + 1, -1}) {
        Fixture fixture(false);
        ProviderProbe probe(fixture);
        auto key = probe.NewKey();
        ASSERT_TRUE(probe.Import(key.get(), fixture.credential->publicKey.get()));
        auto signature = probe.NewSignature();
        ASSERT_EQ(probe.Init(signature.get(), key.get()), 1);
        fixture.adapter->resultSize = resultSize;
        if (resultSize == -1) {
            fixture.adapter->onSign = [&fixture] { fixture.state->Cancel(); };
        }
        std::vector<unsigned char> output(RSA_SIGNATURE_SIZE, OUTPUT_FILL_BYTE);
        size_t size = output.size();
        EXPECT_EQ(probe.Sign(signature.get(), output.data(), &size, output.size()), 0);
        EXPECT_EQ(fixture.state->GetError(), TLS_ERR_SSL_NULL);
        EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](auto c) { return c == OUTPUT_FILL_BYTE; }));
    }
}
} // namespace
} // namespace OHOS::NetStack::TlsSocket::Test
