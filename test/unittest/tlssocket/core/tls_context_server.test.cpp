/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "openssl/ssl.h"

#define private public
#include "tls_context_server.h"

namespace OHOS::NetStack::TlsSocket {
class TLSContextServerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TLSContextServerTest::SetUpTestCase() {}
void TLSContextServerTest::TearDownTestCase() {}
void TLSContextServerTest::SetUp() {}
void TLSContextServerTest::TearDown() {}

HWTEST_F(TLSContextServerTest, TLSContextServerTest001, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(TLSContextServer::CreateConfiguration({}), nullptr);
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest002, testing::ext::TestSize.Level1)
{
    EXPECT_FALSE(TLSContextServer::SetCipherList(nullptr, {}));
    TLSContextServer context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    TLSContextServer::GetCiphers(&context);
    EXPECT_FALSE(TLSContextServer::SetCipherList(&context, {}));

    EXPECT_FALSE(TLSContextServer::SetSignatureAlgorithms(nullptr, {}));
    EXPECT_FALSE(TLSContextServer::SetSignatureAlgorithms(&context, {}));

    TLSConfiguration configuration;
    configuration.signatureAlgorithms_ = "AAAA";
    context.tlsConfiguration_ = configuration;
    TLSContextServer::UseRemoteCipher(nullptr);
    TLSContextServer::UseRemoteCipher(&context);
    context.tlsConfiguration_.useRemoteCipherPrefer_ = true;
    TLSContextServer::UseRemoteCipher(&context);

    TLSContextServer::UseRemoteCipher(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(100);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(UNKNOW_PROTOCOL);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(TLS_ANY_VERSION);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(999999999999999);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(-1);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = TLS_V1_2;
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = TLS_V1_3;
    TLSContextServer::SetMinAndMaxProtocol(&context);

    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(100);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(UNKNOW_PROTOCOL);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(TLS_ANY_VERSION);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(-1);
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = TLS_V1_2;
    TLSContextServer::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = TLS_V1_3;
    TLSContextServer::SetMinAndMaxProtocol(&context);

    EXPECT_FALSE(TLSContextServer::SetSignatureAlgorithms(&context, configuration));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest003, testing::ext::TestSize.Level1)
{
    EXPECT_FALSE(TLSContextServer::SetCaAndVerify(nullptr, {}));
    TLSContextServer context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    EXPECT_TRUE(TLSContextServer::SetCaAndVerify(&context, {}));

    TLSConfiguration configuration;
    configuration.signatureAlgorithms_ = "AAAA";
    configuration.caCertificateChain_.emplace_back("AAAA");
    configuration.caCertificateChain_.emplace_back("BBBB");
    context.tlsConfiguration_ = configuration;
    EXPECT_TRUE(TLSContextServer::SetCaAndVerify(&context, {}));
    EXPECT_FALSE(TLSContextServer::SetCaAndVerify(&context, configuration));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest004, testing::ext::TestSize.Level1)
{
    EXPECT_FALSE(TLSContextServer::SetLocalCertificate(nullptr, {}));
    TLSContextServer context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    EXPECT_FALSE(TLSContextServer::SetLocalCertificate(&context, {}));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest005, testing::ext::TestSize.Level1)
{
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(nullptr, {}));
    TLSContextServer context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, {}));
    TLSConfiguration configuration;
    configuration.privateKey_.keyAlgorithm_ = OPAQUE;
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    configuration.privateKey_.keyAlgorithm_ = ALGORITHM_RSA;
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    configuration.privateKey_.keyAlgorithm_ = ALGORITHM_DSA;
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    configuration.privateKey_.keyAlgorithm_ = ALGORITHM_EC;
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    configuration.privateKey_.keyAlgorithm_ = ALGORITHM_DH;
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest006, testing::ext::TestSize.Level1)
{
    TLSContextServer context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    TLSConfiguration configuration;
    configuration.tlsVerifyMode_ = ONE_WAY_MODE;
    context.tlsConfiguration_ = configuration;
    TLSContextServer::SetVerify(&context);
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    configuration.tlsVerifyMode_ = TWO_WAY_MODE;
    context.tlsConfiguration_ = configuration;
    TLSContextServer::SetVerify(&context);
    TLSContextServer::SetVerify(nullptr);
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
    SecureData data("AAAAA");
    context.tlsConfiguration_.localCertificate_.rawData_.data = data;
    context.tlsConfiguration_.privateKey_.keyData_ = data;
    TLSContextServer::SetVerify(&context);
    EXPECT_FALSE(TLSContextServer::SetKeyAndCheck(&context, configuration));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest007, testing::ext::TestSize.Level1)
{
    EXPECT_FALSE(TLSContextServer::InitTlsContext(nullptr, {}));
    TLSContextServer context;
    TLSConfiguration configuration;
    EXPECT_FALSE(TLSContextServer::InitTlsContext(&context, {}));
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    EXPECT_FALSE(TLSContextServer::InitTlsContext(&context, configuration));
    configuration.cipherSuite_ = "AAAA";
    EXPECT_FALSE(TLSContextServer::InitTlsContext(&context, configuration));
    configuration.signatureAlgorithms_ = "AAAA";
    EXPECT_FALSE(TLSContextServer::InitTlsContext(&context, configuration));
}

HWTEST_F(TLSContextServerTest, TLSContextServerTest008, testing::ext::TestSize.Level1)
{
    TLSContextServer context;
    SSL *ssl = context.CreateSsl();
    EXPECT_EQ(ssl, nullptr);
    context.CloseCtx();
}
} // namespace OHOS::NetStack::TlsSocket
