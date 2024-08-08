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

#include <fstream>

#include "gtest/gtest.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"

#define private public
#include "tls_context.h"

namespace OHOS::NetStack::TlsSocket {
class TlsContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TlsContextTest::SetUpTestCase() {}
void TlsContextTest::TearDownTestCase() {}
void TlsContextTest::SetUp() {}
void TlsContextTest::TearDown() {}

HWTEST_F(TlsContextTest, TlsContextTest001, testing::ext::TestSize.Level1)
{
    EXPECT_NE(TLSContext::CreateConfiguration({}), nullptr);
    TLSConfiguration configuration;
    configuration.signatureAlgorithms_ = "VALID";
    configuration.useRemoteCipherPrefer_ = true;
    TLSContext context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    context.tlsConfiguration_ = configuration;
    context.tlsConfiguration_.useRemoteCipherPrefer_ = true;
    TLSContext::UseRemoteCipher(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(100);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(UNKNOW_PROTOCOL);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(TLS_ANY_VERSION);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(999999999999999);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.minProtocol_ = static_cast<TLSProtocol>(-1);
    TLSContext::SetMinAndMaxProtocol(&context);

    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(100);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(UNKNOW_PROTOCOL);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(TLS_ANY_VERSION);
    TLSContext::SetMinAndMaxProtocol(&context);
    context.tlsConfiguration_.maxProtocol_ = static_cast<TLSProtocol>(-1);
    TLSContext::SetMinAndMaxProtocol(&context);
    EXPECT_EQ(TLSContext::CreateConfiguration(configuration), nullptr);
}

HWTEST_F(TlsContextTest, TlsContextTest002, testing::ext::TestSize.Level1)
{
    TLSContext context;
    TLSContext::GetCiphers(nullptr);
    TLSContext::GetCiphers(&context);
    EXPECT_FALSE(TLSContext::SetCipherList(nullptr, {}));
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    EXPECT_FALSE(TLSContext::SetCipherList(&context, {}));
    EXPECT_FALSE(context.SetSignatureAlgorithms(nullptr, {}));
    EXPECT_FALSE(context.SetSignatureAlgorithms(nullptr, {}));
    TLSConfiguration configuration;
    configuration.signatureAlgorithms_ = "VALID";
    EXPECT_FALSE(context.SetSignatureAlgorithms(nullptr, configuration));
    EXPECT_FALSE(context.SetSignatureAlgorithms(&context, {}));
    EXPECT_FALSE(context.SetSignatureAlgorithms(&context, {}));
    EXPECT_FALSE(context.SetSignatureAlgorithms(&context, configuration));
}

HWTEST_F(TlsContextTest, TlsContextTest003, testing::ext::TestSize.Level1)
{
    TLSContext context;
    TLSConfiguration configuration;
    configuration.signatureAlgorithms_ = "VALID";
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    TLSKey key;

    key.keyAlgorithm_ = ALGORITHM_RSA;
    configuration.privateKey_ = key;
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));

    key.keyAlgorithm_ = ALGORITHM_DSA;
    configuration.privateKey_ = key;
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));

    key.keyAlgorithm_ = ALGORITHM_DH;
    configuration.privateKey_ = key;
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));

    key.keyAlgorithm_ = ALGORITHM_EC;
    configuration.privateKey_ = key;
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));
}
} // namespace OHOS::NetStack::TlsSocket