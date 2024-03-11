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

#include "tls_configuration.h"
#include "tls.h"
#include "TlsTest.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
} // namespace

class TlsConfigurationTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsConfigurationTest, AssignmentConstruction, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    TLSConfiguration configuration = tlsConfiguration;
    configuration.SetLocalCertificate(CLIENT_FILE);
    TLSCertificate tlsCertificate = configuration.GetLocalCertificate();
    EXPECT_NE(tlsCertificate.handle(), nullptr);
    X509CertRawData x509CertRawData = configuration.GetCertificate();
    EXPECT_NE(x509CertRawData.data.Length(), 0);
}

HWTEST_F(TlsConfigurationTest, CopyConstruction, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    tlsConfiguration.SetLocalCertificate(CLIENT_FILE);
    TLSConfiguration configuration = TLSConfiguration(tlsConfiguration);
    TLSCertificate tlsCertificate = configuration.GetLocalCertificate();
    EXPECT_NE(tlsCertificate.handle(), nullptr);
}

HWTEST_F(TlsConfigurationTest, SetAndGetCa, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    tlsConfiguration.SetLocalCertificate(CLIENT_FILE);
    std::vector<std::string> certificate;
    certificate.push_back(CA_CRT_FILE);
    tlsConfiguration.SetCaCertificate(certificate);
    std::vector<std::string> getCaCertificate;
    getCaCertificate = tlsConfiguration.GetCaCertificate();
    EXPECT_NE(getCaCertificate.size(), 0);
}

HWTEST_F(TlsConfigurationTest, SetPrivateKey, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    tlsConfiguration.SetLocalCertificate(CLIENT_FILE);
    SecureData structureData(PRI_KEY_FILE);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    tlsConfiguration.SetPrivateKey(structureData, keyPass);
    TLSKey tlsKey = tlsConfiguration.GetPrivateKey();
    SecureData tlsKeyData = tlsKey.GetKeyData();
    EXPECT_EQ(tlsKeyData.Length(), strlen(PRI_KEY_FILE));
}

HWTEST_F(TlsConfigurationTest, SetProtocol, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    std::vector<std::string> protocol;
    std::string protocolVer = "TLSv1.3";
    protocol.push_back(protocolVer);
    tlsConfiguration.SetProtocol(protocol);
    TLSProtocol tlsProtocol = tlsConfiguration.GetProtocol();
    EXPECT_EQ(tlsProtocol, TLS_V1_3);
    TLSProtocol minProtocol = tlsConfiguration.GetMinProtocol();
    EXPECT_EQ(minProtocol, TLS_V1_3);
    TLSProtocol maxProtocol = tlsConfiguration.GetMaxProtocol();
    EXPECT_EQ(maxProtocol, TLS_V1_3);

    protocol.clear();
    protocolVer = "TLSv1.2";
    protocol.push_back(protocolVer);
    tlsConfiguration.SetProtocol(protocol);
    tlsProtocol = tlsConfiguration.GetProtocol();
    EXPECT_EQ(tlsProtocol, TLS_V1_2);
    minProtocol = tlsConfiguration.GetMinProtocol();
    EXPECT_EQ(minProtocol, TLS_V1_2);
    maxProtocol = tlsConfiguration.GetMaxProtocol();
    EXPECT_EQ(maxProtocol, TLS_V1_2);
}

HWTEST_F(TlsConfigurationTest, UseRemoteCipherPrefer, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    tlsConfiguration.SetUseRemoteCipherPrefer(true);
    bool isUsePemoteCipherPrefer = tlsConfiguration.GetUseRemoteCipherPrefer();
    EXPECT_TRUE(isUsePemoteCipherPrefer);
}

HWTEST_F(TlsConfigurationTest, CipherSuite, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    std::string cipherSuite = "AES256-SHA256";
    tlsConfiguration.SetCipherSuite(cipherSuite);
    std::string getCipherSuite;
    getCipherSuite = tlsConfiguration.GetCipherSuite();
    std::cout << "getCipherSuite:" << getCipherSuite << std::endl;
    int idx = getCipherSuite.find(cipherSuite);
    EXPECT_NE(idx, std::string::npos);
}

HWTEST_F(TlsConfigurationTest, SignatureAlgorithms, TestSize.Level2)
{
    TLSConfiguration tlsConfiguration;
    std::string signatureAlgorithms = "rsa_pss_rsae_sha256:ECDSA+SHA256";
    tlsConfiguration.SetSignatureAlgorithms(signatureAlgorithms);
    std::string getSignatureAlgorithms;
    getSignatureAlgorithms = tlsConfiguration.GetSignatureAlgorithms();
    std::cout << "getSignatureAlgorithms:" << getSignatureAlgorithms << std::endl;
    std::string subStr = "ECDSA+SHA256";
    int idx = getSignatureAlgorithms.find(subStr);
    EXPECT_NE(idx, std::string::npos);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
