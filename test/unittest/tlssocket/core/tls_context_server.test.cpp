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

constexpr const char CERTIFICATCHAIN1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDWzCCAkMCFAd4hTk+2V0twNIleg+RMdJiDf3rMA0GCSqGSIb3DQEBCwUAMFYx\r\n"
    "CzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5n\r\n"
    "MQ4wDAYDVQQKDAVNeSBDQTETMBEGA1UEAwwKTXkgUm9vdCBDQTAeFw0yNTEyMDQw\r\n"
    "ODI3NDdaFw0yNjEyMDQwODI3NDdaMH4xCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdi\r\n"
    "ZWlqaW5nMRAwDgYDVQQHDAdiZWlqaW5nMQ8wDQYDVQQKDAZIVUFXRUkxFjAUBgNV\r\n"
    "BAsMDWNvbW11bmljYXRpb24xEDAOBgNVBAMMBzAuMC4wLjAxEDAOBgkqhkiG9w0B\r\n"
    "CQEWATEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgm2c4+EvB7fUj\r\n"
    "OTMFpZ8nD4bAIjWNKaEklFMQxoQOgcz+674hAbCIM7gfkdcUrV8TFSbGdC7l6m5e\r\n"
    "L/8cqbnGozXdfYLi3EoZ4uGtzQnYcu5e8C3NMX6FP1VsBpwHvqsgSOs9CqejFMIA\r\n"
    "rzXhfoGBs5d1uF5GXbrfDnI4aD1InxX6rkwdFQbcd6pxe+9jqjUDsaaycI+tIxV+\r\n"
    "jwOGIauGbmePpY+peEy1z+rY9MAubrXpgtzH6afd0N7SZX6YKo1focRN9dBPfFAc\r\n"
    "Zc2uE0bFLOR/LrV0yCrGJ+ZHRRGr2UK8kMtJw9vUpBajSJTFMEOO6XwreMNwdyOU\r\n"
    "ofgjiOnHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAC+irqFOM+/HQY9K9J2RmxSe\r\n"
    "siiIc2Rqh71BFT2OHOmTko8I0D3siSs1kH7x77b2IPWyLUbnDs2IRrt06hHdZt4r\r\n"
    "BYNh95U8H25/CMNXgCm5wWC7a23wN6fsmwXk8UK2fm1ZtoLYqLPaXLMUyU/JfdNU\r\n"
    "Ziv2RiK4iT+g8p59o6/q/wB7yTY6wdpbUMg0nfus2aqCtVVUsVhvHnQJ1O0lS8cu\r\n"
    "fKneyr2zRZf8Irx7yiWeY2+CzHFWIfJ1RHrlvPkGA3UdD0UAssZkyhNuP1HSUCKW\r\n"
    "OsdZPnJNON1wyId1KzmGbSsFh6yqMwerYCZkN5McglU6KSxpctGATKC0y1q4/wE=\r\n"
    "-----END CERTIFICATE-----\r\n";

constexpr const char CERTIFICATCHAIN2[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDjTCCAnWgAwIBAgIUOs5K47mhbnfCywd9U9lzPTvOzGMwDQYJKoZIhvcNAQEL\r\n"
    "BQAwVjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\r\n"
    "aWppbmcxDjAMBgNVBAoMBU15IENBMRMwEQYDVQQDDApNeSBSb290IENBMB4XDTI1\r\n"
    "MTIwNDA3MzI0MVoXDTM1MTIwMjA3MzI0MVowVjELMAkGA1UEBhMCQ04xEDAOBgNV\r\n"
    "BAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWppbmcxDjAMBgNVBAoMBU15IENBMRMw\r\n"
    "EQYDVQQDDApNeSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\r\n"
    "AQEAqDLENI4F1aqUV1Jqh16yWkgO5fpco5m3m4oT4RSxcAKVc4AfOZIR4EGDk7Lx\r\n"
    "mjMsRyYnOrvnEm0olacykajI4sh0K6N6yEIYlAljrZ6wzUsifgWcMnu34iZhlWkq\r\n"
    "NQt8jew1T8ThwBc5Q7OT/X3zKcETFmIFqL2iXeKiB4YkFIv2p701ghqJG2q4hToq\r\n"
    "uTcSfNW1RmRU6VKXR7iPvAquXRuJG/LQLJIZyYt4lJ/B1ab3iDl+QqeTunmFwc3s\r\n"
    "ZzOgUtP3ZEWxm+6kvSlBkQC24kqgd/ALllUWBNxj0ZBncY0UvreQxrmO1CrSs1f3\r\n"
    "bvYG75DxCux721pY7/xV5aAJywIDAQABo1MwUTAdBgNVHQ4EFgQUJGV56hcSKnl/\r\n"
    "KUKEqN0PD6tMItUwHwYDVR0jBBgwFoAUJGV56hcSKnl/KUKEqN0PD6tMItUwDwYD\r\n"
    "VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbZ7gzy2xnJX8KXnQabZV\r\n"
    "qLh5846x7TrluB1djbxPVzsafez2lmNpSq+JHKAYc2cq9Y5a3waCYrCYs+0VFiyU\r\n"
    "+jrCy2LqXrDjMxeGk8Gk3YHj+5lcGi3X8i6ec69KTsqIsY032+y2ihVrDUWvq+iQ\r\n"
    "NXi7onaUiyQKo/eN9A83vZbTKLxrtM+Ko3crsG+R9l3nf2J+KnG7l18ZAxWiwS+7\r\n"
    "Y/+dzrKNAC+TCwYr8ys+wMgEEKt/BjjgpxgrzLLfi4e7rHS7/3zSDFf5gtYSbcR/\r\n"
    "d6J4Xvh/+tfPFqTaVPtGAabvsSIrTWMH7gVOP0GTDwwi3hVhDw5iUGuEiGAboYeq\r\n"
    "qA==\r\n"
    "-----END CERTIFICATE-----\r\n";

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

HWTEST_F(TLSContextServerTest, SetLocalCertificateTest, testing::ext::TestSize.Level1)
{
    TLSConfiguration configuration1;
    //正常cert，用两个证书
    std::vector<std::string> certVec;
    certVec.push_back(CERTIFICATCHAIN1);
    certVec.push_back(CERTIFICATCHAIN2);
    configuration1.SetLocalCertificate(certVec);
    std::unique_ptr<TLSContextServer> tlsContext = TLSContextServer::CreateConfiguration(configuration1);
    bool setLocalCertChain = TLSContextServer::SetLocalCertificate(tlsContext.get(), configuration1);
    EXPECT_TRUE(setLocalCertChain);
    //空cert
    TLSConfiguration configuration2;
    std::vector<std::string> certificate;
    configuration2.SetLocalCertificate(certificate);
    bool setLocalCertNull = TLSContextServer::SetLocalCertificate(tlsContext.get(), configuration2);
    EXPECT_FALSE(setLocalCertNull);
    //第一个cert格式不对
    TLSConfiguration configuration3;
    std::vector<std::string> certVecFirstInvalid = {"abc"};
    configuration3.SetLocalCertificate(certVecFirstInvalid);
    bool setLocalCertFirstInvalid = TLSContextServer::SetLocalCertificate(tlsContext.get(), configuration3);
    EXPECT_FALSE(setLocalCertFirstInvalid);
    //第二个cert格式不对
    TLSConfiguration configuration4;
    std::vector<std::string> certVecSecondInvalid = {CERTIFICATCHAIN1};
    certVecSecondInvalid.push_back("abc");
    configuration4.SetLocalCertificate(certVecSecondInvalid);
    bool setLocalCertSecondInvalid = TLSContextServer::SetLocalCertificate(tlsContext.get(), configuration4);
    EXPECT_FALSE(setLocalCertSecondInvalid);
}
} // namespace OHOS::NetStack::TlsSocket
