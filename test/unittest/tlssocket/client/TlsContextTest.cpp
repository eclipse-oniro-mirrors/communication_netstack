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

#include "tls_context.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace {
using namespace testing::ext;
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
    std::string cipherSuite = "AES256-SHA256";
    configuration.SetCipherSuite(cipherSuite);
    std::string signatureAlgorithms = "rsa_pss_rsae_sha256:ECDSA+SHA256";
    configuration.SetSignatureAlgorithms(signatureAlgorithms);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    EXPECT_NE(tlsContext, nullptr);
    tlsContext->CloseCtx();
}

HWTEST_F(TlsContextTest, ContextTest2, TestSize.Level2)
{
    std::vector<std::string> protocol;
    std::string protocolVer = "TLSv1.3";
    protocol.push_back(protocolVer);
    TLSConfiguration configuration;
    configuration.SetProtocol(protocol);
    std::unique_ptr<TLSContext> tlsContext = TLSContext::CreateConfiguration(configuration);
    EXPECT_NE(tlsContext, nullptr);
    SSL *ssl = tlsContext->CreateSsl();
    EXPECT_NE(ssl, nullptr);
    SSL_free(ssl);
    ssl = nullptr;
    tlsContext->CloseCtx();
}
} // namespace NetStack
} // namespace OHOS