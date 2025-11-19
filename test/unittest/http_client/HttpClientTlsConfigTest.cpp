/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <memory>

#include "curl/curl.h"
#include "gtest/gtest.h"

#define private public
#include "http_client_tls_config.h"

namespace OHOS::NetStack::HttpClient {
class HttpClientTlsConfigTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void HttpClientTlsConfigTest::SetUpTestCase() {}
void HttpClientTlsConfigTest::TearDownTestCase() {}
void HttpClientTlsConfigTest::SetUp() {}
void HttpClientTlsConfigTest::TearDown() {}

HWTEST_F(HttpClientTlsConfigTest, HttpClientTlsConfigTest0001, testing::ext::TestSize.Level1)
{
    TlsCipherString cipherString;

    cipherString = ConvertCipherSuiteToCipherString({CipherSuite::TLS_AES_128_GCM_SHA256});
    EXPECT_EQ(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString({CipherSuite::TLS_AES_256_GCM_SHA384});
    EXPECT_EQ(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString({CipherSuite::TLS_CHACHA20_POLY1305_SHA256});
    EXPECT_EQ(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString({CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256});
    EXPECT_NE(cipherString.ciperSuiteString, "");
    EXPECT_EQ(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString({
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        static_cast<CipherSuite>(-1),
    });
    EXPECT_NE(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString(
        {CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA});
    EXPECT_NE(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");

    cipherString = ConvertCipherSuiteToCipherString(
        {CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_256_GCM_SHA384,
         CipherSuite::TLS_CHACHA20_POLY1305_SHA256, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256});
    EXPECT_NE(cipherString.ciperSuiteString, "");
    EXPECT_NE(cipherString.tlsV13CiperSuiteString, "");
}

HWTEST_F(HttpClientTlsConfigTest, HttpClientTlsConfigTest0002, testing::ext::TestSize.Level1)
{
    auto ret = GetTlsCipherSuiteFromStandardName("AAAAAAA");
    EXPECT_EQ(ret, CipherSuite::INVALID);
    ret = GetTlsCipherSuiteFromStandardName("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
    EXPECT_EQ(ret, CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA);
}

HWTEST_F(HttpClientTlsConfigTest, HttpClientTlsConfigTest0003, testing::ext::TestSize.Level1)
{
    auto ret = GetInnerNameFromCipherSuite(CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA);
    EXPECT_EQ(ret, "DES-CBC3-SHA");
    ret = GetInnerNameFromCipherSuite(CipherSuite::INVALID);
    EXPECT_EQ(ret, "");
}
} // namespace OHOS::NetStack::HttpClient