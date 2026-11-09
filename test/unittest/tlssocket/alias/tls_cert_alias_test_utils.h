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

#ifndef NETSTACK_TLS_CERT_ALIAS_TEST_UTILS_H
#define NETSTACK_TLS_CERT_ALIAS_TEST_UTILS_H

#include "tls_cert_manager_provider.h"
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/sha.h>

namespace OHOS::NetStack::TlsSocket::Test {
constexpr int RSA_KEY_BITS = 2048;
constexpr int RSA_SIGNATURE_SIZE = 256;
constexpr unsigned char OUTPUT_FILL_BYTE = 0x5a;

inline void AliasCheck(bool condition, const char *file, int line)
{
    if (!condition) {
        std::cerr << file << ":" << line << ": TLS alias test prerequisite failed\n";
        ERR_print_errors_fp(stderr);
        std::abort();
    }
}

class SigningAdapter final : public CertManagerAdapter {
public:
    explicit SigningAdapter(bool ec)
    {
        constexpr long certNotBeforeOffsetSeconds = -60;
        constexpr long certValiditySeconds = 3600;
        constexpr long x509V3Version = 2;
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new_from_name(nullptr, ec ? "EC" : "RSA", nullptr), EVP_PKEY_CTX_free);
        AliasCheck(ctx && EVP_PKEY_keygen_init(ctx.get()) > 0, __FILE__, __LINE__);
        if (ec) {
            AliasCheck(EVP_PKEY_CTX_set_group_name(ctx.get(), "prime256v1") > 0, __FILE__, __LINE__);
        } else {
            AliasCheck(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), RSA_KEY_BITS) > 0, __FILE__, __LINE__);
        }
        EVP_PKEY *key = nullptr;
        AliasCheck(EVP_PKEY_generate(ctx.get(), &key) > 0, __FILE__, __LINE__);
        privateKey.reset(key, EVP_PKEY_free);
        cert.reset(X509_new(), X509_free);
        AliasCheck(cert && X509_set_version(cert.get(), x509V3Version) == 1, __FILE__, __LINE__);
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert.get()), certNotBeforeOffsetSeconds);
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), certValiditySeconds);
        AliasCheck(X509_set_pubkey(cert.get(), key) == 1, __FILE__, __LINE__);
        auto name = X509_get_subject_name(cert.get());
        AliasCheck(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>("localhost"), -1, -1, 0) == 1, __FILE__, __LINE__);
        AliasCheck(X509_set_issuer_name(cert.get(), name) == 1, __FILE__, __LINE__);
        AliasCheck(X509_sign(cert.get(), key, EVP_sha256()) > 0, __FILE__, __LINE__);
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        AliasCheck(PEM_write_bio_X509(bio.get(), cert.get()) == 1, __FILE__, __LINE__);
        char *data = nullptr;
        auto size = BIO_get_mem_data(bio.get(), &data);
        pem.assign(data, size);
    }
    int32_t Load(const std::string &, std::string &uri, std::string &chain, uint32_t &count) override
    {
        ++loads;
        uri = returnedUri;
        chain = pem;
        count = certCount;
        return loadError;
    }
    int32_t Sign(const std::string &uri, const AliasSignatureSpec &spec, const uint8_t *data, size_t size,
                 std::vector<uint8_t> &signature) override
    {
        AliasCheck(uri == "fake-owned-private-uri", __FILE__, __LINE__);
        ++signs;
        if (signError) { return signError; }
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        EVP_PKEY_CTX *pctx = nullptr;
        AliasCheck(EVP_DigestSignInit_ex(ctx.get(), &pctx, spec.digest.c_str(), nullptr,
            "provider=default", privateKey.get(), nullptr) > 0, __FILE__, __LINE__);
        if (spec.padding) {
            AliasCheck(EVP_PKEY_CTX_set_rsa_padding(pctx, spec.padding) > 0, __FILE__, __LINE__);
            if (spec.padding == RSA_PKCS1_PSS_PADDING) {
                AliasCheck(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0, __FILE__, __LINE__);
                AliasCheck(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_get_digestbyname(spec.digest.c_str())) > 0,
                    __FILE__, __LINE__);
            }
        }
        size_t length = signature.size();
        AliasCheck(EVP_DigestSign(ctx.get(), signature.data(), &length, data, size) > 0, __FILE__, __LINE__);
        signature.resize(length);
        if (resultSize >= 0) { signature.resize(static_cast<size_t>(resultSize)); }
        if (onSign) { onSign(); }
        if (corrupt) { signature[0] ^= 1; }
        return 0;
    }
    std::shared_ptr<EVP_PKEY> privateKey;
    std::shared_ptr<X509> cert;
    std::string pem;
    std::string returnedUri = "fake-owned-private-uri";
    uint32_t certCount = 1;
    std::function<void()> onSign;
    int resultSize = -1;
    int loads = 0;
    int signs = 0;
    int32_t loadError = 0;
    int32_t signError = 0;
    bool corrupt = false;
};

struct Fixture {
    explicit Fixture(bool ec) : adapter(std::make_shared<SigningAdapter>(ec)),
        state(std::make_shared<TlsConnectAttemptState>())
    {
        AliasCheck(PrepareAliasCredential("client", credential, adapter) == 0, __FILE__, __LINE__);
        AliasCheck(runtime.Initialize(credential, state), __FILE__, __LINE__);
    }
    std::shared_ptr<SigningAdapter> adapter;
    std::shared_ptr<TlsConnectAttemptState> state;
    std::shared_ptr<AliasCredential> credential;
    AliasProviderRuntime runtime;
};

} // namespace OHOS::NetStack::TlsSocket::Test
#endif
