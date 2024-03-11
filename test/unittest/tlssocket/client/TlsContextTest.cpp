/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>
#include <string>

#include <openssl/ssl.h>

#define private public
#include "tls_context.h"
#include "tls.h"
#include "TlsTest.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
constexpr const char *PROTOCOL13 = "TLSv1.3";
constexpr const char *PROTOCOL12 = "TLSv1.2";
constexpr const char *PROTOCOL11 = "TLSv1.1";
constexpr const char *CIPHER_SUITE = "AES256-SHA256";
constexpr const char *SIGNATURE_ALGORITHMS = "rsa_pss_rsae_sha256:ECDSA+SHA256";
} // namespace

class TlsContextTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsContextTest, ContextTest1, TestSize.Level2)
{
    TLSConfiguration configuration;
    configuration.SetCipherSuite(CIPHER_SUITE);
    configuration.SetSignatureAlgorithms(SIGNATURE_ALGORITHMS);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);

    EXPECT_NE(tlsContext, nullptr);
    tlsContext->CloseCtx();
}

HWTEST_F(TlsContextTest, ContextTest2, TestSize.Level2)
{
    std::vector<std::string> protocol;
    protocol.push_back(PROTOCOL13);
    protocol.push_back(PROTOCOL12);
    protocol.push_back(PROTOCOL11);
    TLSConfiguration configuration;
    std::vector<std::string> caVec = {CA_CRT_FILE};
    configuration.SetCaCertificate(caVec);
    configuration.SetProtocol(protocol);
    configuration.SetCipherSuite(CIPHER_SUITE);
    configuration.SetSignatureAlgorithms(SIGNATURE_ALGORITHMS);
    configuration.SetLocalCertificate(CLIENT_FILE);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    EXPECT_NE(tlsContext, nullptr);
    TLSContext::SetMinAndMaxProtocol(tlsContext.get());
    bool isInitTlsContext = TLSContext::InitTlsContext(tlsContext.get(), configuration);
    EXPECT_TRUE(isInitTlsContext);
    bool isSetCipherList = TLSContext::SetCipherList(tlsContext.get(), configuration);
    EXPECT_TRUE(isSetCipherList);
    bool isSetSignatureAlgorithms = TLSContext::SetSignatureAlgorithms(tlsContext.get(), configuration);
    EXPECT_TRUE(isSetSignatureAlgorithms);
    TLSContext::GetCiphers(tlsContext.get());
    TLSContext::UseRemoteCipher(tlsContext.get());
    bool setCaAndVerify = TLSContext::SetCaAndVerify(tlsContext.get(), configuration);
    EXPECT_TRUE(setCaAndVerify);
    bool setLocalCert = TLSContext::SetLocalCertificate(tlsContext.get(), configuration);
    EXPECT_TRUE(setLocalCert);
    bool setKeyAndCheck = TLSContext::SetKeyAndCheck(tlsContext.get(), configuration);
    EXPECT_FALSE(setKeyAndCheck);
    TLSContext::SetVerify(tlsContext.get());
    SSL *ssl = tlsContext->CreateSsl();
    EXPECT_NE(ssl, nullptr);
    SSL_free(ssl);
    ssl = nullptr;
    tlsContext->CloseCtx();
}

HWTEST_F(TlsContextTest, ContextTest3, TestSize.Level2)
{
    TLSConfiguration configuration;
    std::vector<std::string> caVec = {};
    configuration.SetCaCertificate(caVec);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    EXPECT_NE(tlsContext, nullptr);
    bool setCaAndVerify = TLSContext::SetCaAndVerify(tlsContext.get(), configuration);
    tlsContext->CloseCtx();
    EXPECT_TRUE(setCaAndVerify);
}

HWTEST_F(TlsContextTest, InitTlsContext3, TestSize.Level2)
{
    TLSConfiguration configuration;
    std::string cipherSuite = "";
    configuration.SetCipherSuite(cipherSuite);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);

    EXPECT_NE(tlsContext, nullptr);
    tlsContext->CloseCtx();
}

HWTEST_F(TlsContextTest, InitTlsContext4, TestSize.Level2)
{
    TLSConfiguration configuration;
    std::string signatureAlgorithms = "";
    configuration.SetCipherSuite(CIPHER_SUITE);
    configuration.SetSignatureAlgorithms(signatureAlgorithms);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);

    EXPECT_NE(tlsContext, nullptr);
    tlsContext->CloseCtx();
}

HWTEST_F(TlsContextTest, ContextNullTest, TestSize.Level2)
{
    std::vector<std::string> protocol;
    protocol.push_back(PROTOCOL13);
    protocol.push_back(PROTOCOL12);
    protocol.push_back(PROTOCOL11);
    TLSConfiguration configuration;
    std::vector<std::string> caVec = {CA_CRT_FILE};
    configuration.SetCaCertificate(caVec);
    configuration.SetProtocol(protocol);
    configuration.SetCipherSuite(CIPHER_SUITE);
    configuration.SetSignatureAlgorithms(SIGNATURE_ALGORITHMS);
    configuration.SetLocalCertificate(CLIENT_FILE);
    std::unique_ptr<TLSContext> tlsContext = nullptr;
    EXPECT_EQ(tlsContext, nullptr);
    TLSContext::SetMinAndMaxProtocol(tlsContext.get());
    bool isInitTlsContext = TLSContext::InitTlsContext(tlsContext.get(), configuration);
    EXPECT_FALSE(isInitTlsContext);
    bool isSetCipherList = TLSContext::SetCipherList(tlsContext.get(), configuration);
    EXPECT_FALSE(isSetCipherList);
    bool isSetSignatureAlgorithms = TLSContext::SetSignatureAlgorithms(tlsContext.get(), configuration);
    EXPECT_FALSE(isSetSignatureAlgorithms);
    TLSContext::GetCiphers(tlsContext.get());
    TLSContext::UseRemoteCipher(tlsContext.get());
    bool setCaAndVerify = TLSContext::SetCaAndVerify(tlsContext.get(), configuration);
    EXPECT_FALSE(setCaAndVerify);
    bool setLocalCert = TLSContext::SetLocalCertificate(tlsContext.get(), configuration);
    EXPECT_FALSE(setLocalCert);
    bool setKeyAndCheck = TLSContext::SetKeyAndCheck(tlsContext.get(), configuration);
    EXPECT_FALSE(setKeyAndCheck);
    TLSContext::SetVerify(tlsContext.get());
}

HWTEST_F(TlsContextTest, ContextFailTest1, TestSize.Level2)
{
    std::vector<std::string> protocol;
    protocol.push_back("1.3");
    protocol.push_back("1.2");
    TLSConfiguration configuration;
    std::vector<std::string> caVec = {CA_CRT_FILE};
    configuration.SetCaCertificate(caVec);
    configuration.SetProtocol(protocol);
    configuration.SetCipherSuite(CIPHER_SUITE);
    configuration.SetSignatureAlgorithms(SIGNATURE_ALGORITHMS);
    configuration.SetLocalCertificate("certificate");
    SecureData key("key");
    SecureData keyPass("123456");
    configuration.SetPrivateKey(key, keyPass);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    EXPECT_NE(tlsContext, nullptr);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS