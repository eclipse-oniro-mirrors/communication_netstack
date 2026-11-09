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
#undef private
#include "../alias/tls_cert_alias_test_utils.h"

namespace OHOS::NetStack::TlsSocket {
namespace AliasTest = ::OHOS::NetStack::TlsSocket::Test;
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
    EXPECT_TRUE(TLSContext::SetCipherList(&context, {}));
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
HWTEST_F(TlsContextTest, AliasConfigurationCopyAndAssignment, testing::ext::TestSize.Level1)
{
    TLSConfiguration source{};
    auto credential = std::make_shared<AliasCredential>();
    auto state = std::make_shared<TlsConnectAttemptState>();
    source.SetAliasCredential(credential);
    source.SetAttemptState(state);
    source.SetVerifyMode(TWO_WAY_MODE);
    TLSConfiguration copy(source);
    TLSConfiguration assigned;
    assigned = source;
    for (const auto *configuration : {&copy, &assigned}) {
        EXPECT_EQ(configuration->GetAliasCredential(), credential);
        EXPECT_EQ(configuration->GetAttemptState(), state);
        EXPECT_EQ(configuration->GetVerifyMode(), TWO_WAY_MODE);
    }
    assigned = TLSConfiguration{};
    EXPECT_EQ(assigned.GetAliasCredential(), nullptr);
    EXPECT_EQ(assigned.GetAttemptState(), nullptr);
}

HWTEST_F(TlsContextTest, AliasForcesPeerVerificationWithoutPemPrivateKey, testing::ext::TestSize.Level1)
{
    TLSContext context;
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(context.ctx_, nullptr);
    context.tlsConfiguration_.SetAliasCredential(std::make_shared<AliasCredential>());
    TLSContext::SetVerify(&context);
    EXPECT_EQ(context.verifyMode_, TWO_WAY_MODE);
    EXPECT_EQ(SSL_CTX_get_verify_mode(context.ctx_), SSL_VERIFY_PEER);
    context.tlsConfiguration_.SetAliasCredential(nullptr);
    TLSContext::SetVerify(&context);
    EXPECT_EQ(context.verifyMode_, ONE_WAY_MODE);
}

HWTEST_F(TlsContextTest, AliasRuntimeInitializationFailureStopsContextCreation, testing::ext::TestSize.Level1)
{
    TLSConfiguration configuration{};
    configuration.SetAliasCredential(std::make_shared<AliasCredential>());
    configuration.SetAttemptState(std::make_shared<TlsConnectAttemptState>());
    TLSContext context;
    EXPECT_FALSE(TLSContext::InitTlsContext(&context, configuration));
    EXPECT_EQ(context.ctx_, nullptr);
    EXPECT_EQ(TLSContext::CreateConfiguration(configuration), nullptr);
}

HWTEST_F(TlsContextTest, AliasKeyMatchAndCleanup, testing::ext::TestSize.Level1)
{
    AliasTest::Fixture fixture(false);
    TLSConfiguration configuration{};
    configuration.SetAliasCredential(fixture.credential);
    configuration.SetAttemptState(fixture.state);
    TLSContext context;
    context.aliasRuntime_ = std::make_unique<AliasProviderRuntime>();
    ASSERT_TRUE(context.aliasRuntime_->Initialize(fixture.credential, fixture.state));
    context.ctx_ = context.aliasRuntime_->CreateClientContext();
    ASSERT_NE(context.ctx_, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(context.ctx_, fixture.adapter->cert.get()), 1);
    EXPECT_TRUE(TLSContext::SetKeyAndCheck(&context, configuration));
    EXPECT_EQ(fixture.state->GetError(), 0);
    context.CloseCtx();
    EXPECT_EQ(context.aliasRuntime_, nullptr);
    EXPECT_EQ(context.ctx_, nullptr);
}

HWTEST_F(TlsContextTest, AliasKeyMismatchPreservesFirstError, testing::ext::TestSize.Level1)
{
    AliasTest::Fixture fixture(false);
    AliasTest::SigningAdapter different(false);
    TLSConfiguration configuration{};
    configuration.SetAttemptState(fixture.state);
    TLSContext context;
    context.aliasRuntime_ = std::make_unique<AliasProviderRuntime>();
    ASSERT_TRUE(context.aliasRuntime_->Initialize(fixture.credential, fixture.state));
    context.ctx_ = context.aliasRuntime_->CreateClientContext();
    ASSERT_NE(context.ctx_, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(context.ctx_, different.cert.get()), 1);
    fixture.state->SetFirstError(TLS_ALIAS_UNAUTHORIZED);
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));
    EXPECT_EQ(fixture.state->GetError(), TLS_ALIAS_UNAUTHORIZED);
    ERR_clear_error();
}

HWTEST_F(TlsContextTest, UninitializedAliasRuntimeHasNoSigningKey, testing::ext::TestSize.Level1)
{
    TLSConfiguration configuration{};
    auto state = std::make_shared<TlsConnectAttemptState>();
    configuration.SetAttemptState(state);
    TLSContext context;
    context.aliasRuntime_ = std::make_unique<AliasProviderRuntime>();
    context.ctx_ = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(context.ctx_, nullptr);
    EXPECT_FALSE(TLSContext::SetKeyAndCheck(&context, configuration));
    EXPECT_EQ(state->GetError(), TLS_ERR_SSL_NULL);
}
} // namespace OHOS::NetStack::TlsSocket
