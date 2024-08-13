/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "tls_config_enhanced.h"

namespace OHOS::NetStack::TlsSocket {
class TlsConfigEnhancedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TlsConfigEnhancedTest::SetUpTestCase() {}
void TlsConfigEnhancedTest::TearDownTestCase() {}
void TlsConfigEnhancedTest::SetUp() {}
void TlsConfigEnhancedTest::TearDown() {}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0002, testing::ext::TestSize.Level1)
{
    ClientCertificate certificate;
    certificate.type = CertType::PEM;
    EXPECT_EQ(certificate.GetCertTypeString(), "PEM");
    certificate.type = CertType::DER;
    EXPECT_EQ(certificate.GetCertTypeString(), "DER");
    certificate.type = CertType::P12;
    EXPECT_EQ(certificate.GetCertTypeString(), "P12");
    certificate.type = static_cast<CertType>(-1);
    EXPECT_EQ(certificate.GetCertTypeString(), "");
    certificate.type = static_cast<CertType>(-2);
    EXPECT_EQ(certificate.GetCertTypeString(), "");
    certificate.type = static_cast<CertType>(-3);
    EXPECT_EQ(certificate.GetCertTypeString(), "");
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0008, testing::ext::TestSize.Level1)
{
    DnsServers dnsServers;
    EXPECT_EQ(dnsServers.ToString(), "");
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0009, testing::ext::TestSize.Level1)
{
    DnsServers dnsServers;
    EXPECT_EQ(dnsServers.ToString(), "");

    IpAndPort a;

    a.ip = "127.0.0.1";
    a.port = 90;
    dnsServers.emplace_back(a);
    a.ip = "127.0.0.2";
    a.port = 500;
    dnsServers.emplace_back(a);
    a.ip = "127.0.0.3";
    a.port = 0;
    dnsServers.emplace_back(a);
    EXPECT_EQ(dnsServers.ToString(), "127.0.0.1:90,127.0.0.2:500,127.0.0.3");
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0012, testing::ext::TestSize.Level1)
{
    TransferRange range;
    range.push_back({});
    range.push_back({
        .from = 100,
        .to = 200,
    });
    range.push_back({
        .from = 300,
        .to = 400,
    });
    EXPECT_EQ(range.ToHeaderString(), "100-200, 300-400");

    range = {};
    EXPECT_EQ(range.ToHeaderString(), "");
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0013, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(GetCipherSuiteFromStandardName("TLS_AES_128_GCM_SHA256"), CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_EQ(GetCipherSuiteFromStandardName("INVALID"), CipherSuite::INVALID);
    EXPECT_EQ(GetInnerNameFromCipherSuite(CipherSuite::TLS_AES_128_GCM_SHA256), "TLS_AES_128_GCM_SHA256");
    EXPECT_EQ(GetInnerNameFromCipherSuite(CipherSuite::INVALID), "");
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0014, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ConvertTlsVersion("default"), TlsVersion::DEFAULT);
    EXPECT_EQ(ConvertTlsVersion("TlsV1.0"), TlsVersion::TLSv1_0);
    EXPECT_EQ(ConvertTlsVersion("TlsV1.1"), TlsVersion::TLSv1_1);
    EXPECT_EQ(ConvertTlsVersion("TlsV1.2"), TlsVersion::TLSv1_2);
    EXPECT_EQ(ConvertTlsVersion("TlsV1.3"), TlsVersion::TLSv1_3);
    EXPECT_EQ(ConvertTlsVersion("INVALID"), TlsVersion::DEFAULT);
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0015, testing::ext::TestSize.Level1)
{
    TlsVersionRange range;
    range = ConvertTlsVersion(TlsVersion::DEFAULT);
    EXPECT_EQ(range.min, std::nullopt);
    EXPECT_EQ(range.max, std::nullopt);
    range = ConvertTlsVersion(static_cast<TlsVersion>(-1));
    EXPECT_EQ(range.min, std::nullopt);
    EXPECT_EQ(range.max, std::nullopt);
    range = ConvertTlsVersion(TlsVersion::TLSv1_0);
    EXPECT_EQ(range.min.value(), TlsVersion::TLSv1_0);
    EXPECT_EQ(range.max.value(), TlsVersion::TLSv1_0);
    range = ConvertTlsVersion(TlsVersion::TLSv1_1);
    EXPECT_EQ(range.min.value(), TlsVersion::TLSv1_1);
    EXPECT_EQ(range.max.value(), TlsVersion::TLSv1_1);
    range = ConvertTlsVersion(TlsVersion::TLSv1_2);
    EXPECT_EQ(range.min.value(), TlsVersion::TLSv1_2);
    EXPECT_EQ(range.max.value(), TlsVersion::TLSv1_2);
    range = ConvertTlsVersion(TlsVersion::TLSv1_3);
    EXPECT_EQ(range.min.value(), TlsVersion::TLSv1_3);
    EXPECT_EQ(range.max.value(), TlsVersion::TLSv1_3);
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0016, testing::ext::TestSize.Level1)
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
}

HWTEST_F(TlsConfigEnhancedTest, TlsConfigEnhancedTest0017, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(GetHashAlgorithm("SHA-256"), HashAlgorithm::SHA256);
    EXPECT_EQ(GetHashAlgorithm("INVALID"), HashAlgorithm::INVALID);
}
} // namespace OHOS::NetStack::TlsSocket