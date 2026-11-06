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
#include <cerrno>
#include <future>
#include <limits>
#include <gtest/gtest.h>

using namespace OHOS::NetStack::TlsSocket;
using namespace OHOS::NetStack::TlsSocket::Test;

namespace {
void TestSignature(bool ec, int padding, const char *digest)
{
    Fixture f(ec);
    OSSL_PARAM *privateParams = nullptr;
    ASSERT_TRUE(EVP_PKEY_todata(f.runtime.GetKey(), EVP_PKEY_KEYPAIR, &privateParams) <= 0);
    ASSERT_TRUE(privateParams == nullptr);
    ERR_clear_error();
    ASSERT_TRUE(EVP_PKEY_eq(f.runtime.GetKey(), f.credential->publicKey.get()) == 1);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX *pctx = nullptr;
    ASSERT_TRUE(EVP_DigestSignInit_ex(md.get(), &pctx, digest, nullptr, nullptr, f.runtime.GetKey(), nullptr) > 0);
    if (!ec) {
        ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pctx, padding) > 0);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0);
        }
    }
    const unsigned char message[] = "original TLS CertificateVerify message";
    size_t length = 0;
    ASSERT_TRUE(EVP_DigestSign(md.get(), nullptr, &length, message, sizeof(message)) > 0);
    ASSERT_TRUE(f.adapter->signs == 0);
    std::vector<unsigned char> signature(length);
    ASSERT_TRUE(EVP_DigestSign(md.get(), signature.data(), &length, message, sizeof(message)) > 0);
    ASSERT_TRUE(f.adapter->signs == 1 && f.state->GetError() == 0);
    f.adapter->corrupt = true;
    length = signature.size();
    ASSERT_TRUE(EVP_DigestSign(md.get(), signature.data(), &length, message, sizeof(message)) <= 0);
    ASSERT_TRUE(f.state->GetError() == TLS_ERR_SSL_NULL);
}

bool HandshakeFails(SSL *client, SSL *server)
{
    constexpr int maxHandshakeSteps = 100;
    for (int i = 0; i < maxHandshakeSteps && !(SSL_is_init_finished(client) && SSL_is_init_finished(server)); ++i) {
        for (auto ssl : {client, server}) {
            int result = SSL_do_handshake(ssl);
            if (result > 0) {
                continue;
            }
            int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                return true;
            }
        }
    }
    return false;
}

void TestHandshake(bool ec, int version, bool requestCertificate = true,
                   bool trusted = true, bool matchingHostname = true)
{
    Fixture f(ec);
    auto serverIdentity = std::make_shared<SigningAdapter>(!ec);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client(f.runtime.CreateClientContext(), SSL_CTX_free);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    ASSERT_TRUE(client && server);
    ASSERT_TRUE(SSL_CTX_use_certificate(client.get(), f.adapter->cert.get()) == 1);
    ASSERT_TRUE(SSL_CTX_use_PrivateKey(client.get(), f.runtime.GetKey()) == 1);
    ASSERT_TRUE(SSL_CTX_check_private_key(client.get()) == 1);
    ASSERT_TRUE(SSL_CTX_use_certificate(server.get(), serverIdentity->cert.get()) == 1);
    ASSERT_TRUE(SSL_CTX_use_PrivateKey(server.get(), serverIdentity->privateKey.get()) == 1);
    ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(server.get()), f.adapter->cert.get()) == 1);
    if (trusted) {
        ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client.get()), serverIdentity->cert.get()) == 1);
    }
    SSL_CTX_set_verify(client.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify(server.get(), requestCertificate ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT :
        SSL_VERIFY_NONE, nullptr);
    ASSERT_TRUE(SSL_CTX_set_min_proto_version(client.get(), version) == 1);
    ASSERT_TRUE(SSL_CTX_set_max_proto_version(client.get(), version) == 1);
    std::unique_ptr<SSL, decltype(&SSL_free)> c(SSL_new(client.get()), SSL_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> s(SSL_new(server.get()), SSL_free);
    BIO *cbio = nullptr;
    BIO *sbio = nullptr;
    ASSERT_TRUE(SSL_set_tlsext_host_name(c.get(), "localhost") == 1);
    ASSERT_TRUE(SSL_set1_host(c.get(), matchingHostname ? "localhost" : "other.example") == 1);
    ASSERT_TRUE(BIO_new_bio_pair(&cbio, 0, &sbio, 0) == 1);
    SSL_set_bio(c.get(), cbio, cbio);
    SSL_set_bio(s.get(), sbio, sbio);
    SSL_set_connect_state(c.get());
    SSL_set_accept_state(s.get());
    bool failed = HandshakeFails(c.get(), s.get());
    if (!trusted || !matchingHostname) {
        ASSERT_TRUE(failed);
        ERR_clear_error();
        return;
    }
    ASSERT_TRUE(!failed && SSL_is_init_finished(c.get()) && SSL_is_init_finished(s.get()));
    ASSERT_TRUE(SSL_get_servername(s.get(), TLSEXT_NAMETYPE_host_name) &&
        std::string(SSL_get_servername(s.get(), TLSEXT_NAMETYPE_host_name)) == "localhost");
    if (requestCertificate) {
        std::unique_ptr<X509, decltype(&X509_free)> peer(SSL_get1_peer_certificate(s.get()), X509_free);
        ASSERT_TRUE(peer && X509_cmp(peer.get(), f.adapter->cert.get()) == 0 && f.adapter->signs == 1);
    } else {
        ASSERT_TRUE(f.adapter->signs == 0);
    }
    ASSERT_TRUE(f.state->GetError() == 0);
}
} // namespace
namespace {
class TlsCertAliasTest : public testing::Test {};

HWTEST_F(TlsCertAliasTest, ErrorContract, testing::ext::TestSize.Level1)
{
    constexpr int32_t expectedHostnameVerifyError = 2303603;
    constexpr int32_t expectedAliasNotFoundError = 2303604;
    constexpr int32_t expectedCmServiceError = 2303605;
    constexpr int32_t expectedKeyAccessError = 2303606;
    static_assert(TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED == expectedHostnameVerifyError);
    static_assert(TLS_ERR_CERT_ALIAS_NOT_FOUND == expectedAliasNotFoundError);
    static_assert(TLS_ERR_CERT_MGR_SERVICE_ERROR == expectedCmServiceError);
    static_assert(TLS_ERR_KEY_ACCESS_DENIED == expectedKeyAccessError);
    const std::pair<int32_t, const char *> errors[] = {
        {TLS_ERR_CERT_ALIAS_NOT_FOUND, "Certificate alias not found or the certificate is unavailable"},
        {TLS_ERR_CERT_MGR_SERVICE_ERROR, "Certificate manager service error"},
        {TLS_ERR_KEY_ACCESS_DENIED, "Access to the private key of the alias is denied"},
    };
    for (auto [code, message] : errors) {
        ASSERT_TRUE(IsCertAliasError(code));
        ASSERT_TRUE(CertAliasErrorMessage(code) == message);
        ASSERT_TRUE(MakeErrorMessage(code) == message);
        ASSERT_TRUE(MakeSSLErrorString(code) == message);
    }
    ASSERT_TRUE(!IsCertAliasError(TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED));
    ASSERT_TRUE(MakeErrorMessage(TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED) == "SSL server hostname verification failed");
}

HWTEST_F(TlsCertAliasTest, ConnectionErrorMessagesIgnoreErrno, testing::ext::TestSize.Level1)
{
    const std::pair<int32_t, const char *> errors[] = {
        {TLS_ERR_SYS_ECANCELED, "Operation canceled"},
        {TLS_ERR_SYS_EALREADY, "Operation already in progress"},
        {TLS_ERR_SYS_EISCONN, "Transport endpoint is already connected"},
    };
    int savedErrno = errno;
    for (auto [code, message] : errors) {
        SCOPED_TRACE(code);
        for (int previousErrno : {0, EACCES, EBADF}) {
            errno = previousErrno;
            EXPECT_EQ(MakeErrorMessage(code), message);
        }
    }
    errno = savedErrno;
}

HWTEST_F(TlsCertAliasTest, AliasSyntaxAndChain, testing::ext::TestSize.Level1)
{
    constexpr size_t maxAliasLength = 256;
    constexpr char aliasWithNul[] = "a\0b";
    constexpr uint32_t certificateCount = 2;
    ASSERT_TRUE(!IsValidCertAlias(""));
    ASSERT_TRUE(!IsValidCertAlias("   "));
    ASSERT_TRUE(!IsValidCertAlias(std::string(maxAliasLength + 1, 'a')));
    ASSERT_TRUE(IsValidCertAlias(std::string(maxAliasLength, 'a')));
    ASSERT_TRUE(IsValidCertAlias(" client A "));
    ASSERT_TRUE(!IsValidCertAlias("\tclient"));
    ASSERT_TRUE(!IsValidCertAlias(std::string(aliasWithNul, sizeof(aliasWithNul) - 1)));
    ASSERT_TRUE(!IsValidCertAlias("中文"));
    for (int i = 0; i <= std::numeric_limits<unsigned char>::max(); ++i) {
        ASSERT_TRUE(IsValidCertAlias(std::string("a") + static_cast<char>(i)) == (i >= ' ' && i <= '~'));
    }
    std::shared_ptr<AliasCredential> unsupported;
    ASSERT_TRUE(PrepareAliasCredential("valid", unsupported) == TLS_ALIAS_UNSUPPORTED && !unsupported);
    auto adapter = std::make_shared<SigningAdapter>(false);
    std::shared_ptr<AliasCredential> credential;
    ASSERT_TRUE(PrepareAliasCredential("", credential, adapter) == TLS_ALIAS_INVALID && adapter->loads == 0);
    adapter->loadError = TLS_ALIAS_PERMISSION;
    ASSERT_TRUE(PrepareAliasCredential("a", credential, adapter) == TLS_ALIAS_PERMISSION && !credential);
    adapter->loadError = 0;
    adapter->certCount = certificateCount;
    ASSERT_TRUE(PrepareAliasCredential("a", credential, adapter) == TLS_ALIAS_NOT_FOUND);
    adapter->pem += adapter->pem;
    ASSERT_TRUE(PrepareAliasCredential("a", credential, adapter) == 0 &&
        credential->certChain.size() == certificateCount);
    adapter->pem += "invalid trailing bytes";
    ASSERT_TRUE(PrepareAliasCredential("a", credential, adapter) == TLS_ALIAS_NOT_FOUND);
}

HWTEST_F(TlsCertAliasTest, FailureAndConnectionIsolation, testing::ext::TestSize.Level1)
{
    constexpr int invalidSaltLength = 8;
    Fixture f(false);
    auto sign = [&f](int salt, const char *mgf, bool cancelled) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        EVP_PKEY_CTX *pctx = nullptr;
        AliasCheck(EVP_DigestSignInit_ex(
            md.get(), &pctx, "SHA256", nullptr, nullptr, f.runtime.GetKey(), nullptr) > 0, __FILE__, __LINE__);
        AliasCheck(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0, __FILE__, __LINE__);
        AliasCheck(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt) > 0, __FILE__, __LINE__);
        AliasCheck(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_get_digestbyname(mgf)) > 0, __FILE__, __LINE__);
        if (cancelled) { f.state->Cancel(); }
        std::vector<unsigned char> result(EVP_PKEY_get_size(f.runtime.GetKey()));
        size_t size = result.size();
        constexpr unsigned char message[] = "message";
        return EVP_DigestSign(md.get(), result.data(), &size, message, sizeof(message) - 1);
    };
    ASSERT_TRUE(sign(invalidSaltLength, "SHA256", false) <= 0 && f.adapter->signs == 0);
    ASSERT_TRUE(f.state->GetError() == TLS_ERR_SSL_NULL);
    ASSERT_TRUE(sign(RSA_PSS_SALTLEN_DIGEST, "SHA384", false) <= 0 && f.adapter->signs == 0);
    // Public API may encode digest-length salt as a decimal string.
    ASSERT_TRUE(sign(SHA256_DIGEST_LENGTH, "SHA256", false) > 0);
    f.adapter->signError = TLS_ALIAS_UNAUTHORIZED;
    ASSERT_TRUE(sign(RSA_PSS_SALTLEN_DIGEST, "SHA256", false) <= 0);
    ASSERT_TRUE(f.state->GetError() == TLS_ERR_SSL_NULL); // First error survives later failures.
    f.adapter->signError = 0;
    // A different key behind the same URI cannot replace this handshake's certificate identity.
    auto replacement = std::make_shared<SigningAdapter>(false);
    f.adapter->privateKey = replacement->privateKey;
    ASSERT_TRUE(sign(RSA_PSS_SALTLEN_DIGEST, "SHA256", false) <= 0);
    int previousSigns = f.adapter->signs;
    ASSERT_TRUE(sign(RSA_PSS_SALTLEN_DIGEST, "SHA256", true) <= 0 && f.adapter->signs == previousSigns);
    ERR_clear_error();
    // A new connection has a new state, libctx and credential. Exercise both concurrently.
    auto first = std::async(std::launch::async, [] { TestSignature(false, RSA_PKCS1_PSS_PADDING, "SHA256"); });
    auto second = std::async(std::launch::async, [] { TestSignature(true, 0, "SHA256"); });
    first.get();
    second.get();
}

HWTEST_F(TlsCertAliasTest, RsaSignaturesAndPrivateExport, testing::ext::TestSize.Level1)
{
    for (const char *digest : {"SHA256", "SHA384", "SHA512"}) {
        SCOPED_TRACE(digest);
        ASSERT_NO_FATAL_FAILURE(TestSignature(false, RSA_PKCS1_PADDING, digest));
        ASSERT_NO_FATAL_FAILURE(TestSignature(false, RSA_PKCS1_PSS_PADDING, digest));
    }
}

HWTEST_F(TlsCertAliasTest, EcSignatureAndPrivateExport, testing::ext::TestSize.Level1)
{
    for (const char *digest : {"SHA256", "SHA384", "SHA512"}) {
        SCOPED_TRACE(digest);
        ASSERT_NO_FATAL_FAILURE(TestSignature(true, 0, digest));
    }
}

HWTEST_F(TlsCertAliasTest, RsaTls12And13Handshake, testing::ext::TestSize.Level1)
{
    for (int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
        SCOPED_TRACE(version);
        ASSERT_NO_FATAL_FAILURE(TestHandshake(false, version));
        ASSERT_NO_FATAL_FAILURE(TestHandshake(false, version, true, true, false));
    }
    ASSERT_NO_FATAL_FAILURE(TestHandshake(false, TLS1_3_VERSION, false));
    ASSERT_NO_FATAL_FAILURE(TestHandshake(false, TLS1_3_VERSION, true, false));
}

HWTEST_F(TlsCertAliasTest, EcTls12And13Handshake, testing::ext::TestSize.Level1)
{
    for (int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
        SCOPED_TRACE(version);
        ASSERT_NO_FATAL_FAILURE(TestHandshake(true, version));
        ASSERT_NO_FATAL_FAILURE(TestHandshake(true, version, true, true, false));
    }
    ASSERT_NO_FATAL_FAILURE(TestHandshake(true, TLS1_3_VERSION, false));
    ASSERT_NO_FATAL_FAILURE(TestHandshake(true, TLS1_3_VERSION, true, false));
}
} // namespace
