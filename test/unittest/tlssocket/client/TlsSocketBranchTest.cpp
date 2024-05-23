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

#include <openssl/ssl.h>

#define private public
#include "accesstoken_kit.h"
#include "tls_socket.h"
#include "socket_remote_info.h"
#include "token_setproc.h"
#include "tls.h"
#include "TlsTest.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;
static constexpr const char *KEY_PASS = "";
static constexpr const char *PROTOCOL12 = "TLSv1.2";
static constexpr const char *PROTOCOL13 = "TLSv1.3";
static constexpr const char *IP_ADDRESS = "127.0.0.1";
static constexpr const char *ALPN_PROTOCOL = "http/1.1";
static constexpr const char *SIGNATURE_ALGORITHM = "rsa_pss_rsae_sha256:ECDSA+SHA256";
static constexpr const char *CIPHER_SUITE = "AES256-SHA256";
const int PORT = 7838;

TLSConnectOptions BaseOption()
{
    TLSSecureOptions secureOption;
    SecureData structureData(PRI_KEY_FILE);
    secureOption.SetKey(structureData);
    std::vector<std::string> caChain;
    caChain.push_back(CA_CRT_FILE);
    secureOption.SetCaChain(caChain);
    secureOption.SetCert(CLIENT_FILE);
    secureOption.SetCipherSuite(CIPHER_SUITE);
    secureOption.SetSignatureAlgorithms(SIGNATURE_ALGORITHM);
    std::vector<std::string> protocol;
    protocol.push_back(PROTOCOL13);
    secureOption.SetProtocolChain(protocol);

    TLSConnectOptions connectOptions;
    connectOptions.SetTlsSecureOptions(secureOption);
    Socket::NetAddress netAddress;
    netAddress.SetAddress(IP_ADDRESS);
    netAddress.SetPort(0);
    netAddress.SetFamilyBySaFamily(AF_INET);
    connectOptions.SetNetAddress(netAddress);
    std::vector<std::string> alpnProtocols;
    alpnProtocols.push_back(ALPN_PROTOCOL);
    connectOptions.SetAlpnProtocols(alpnProtocols);
    return connectOptions;
}

HapInfoParams testInfoParms = {.bundleName = "TlsSocketBranchTest",
                               .userID = 1,
                               .instIndex = 0,
                               .appIDDesc = "test",
                               .isSystemApp = true};

PermissionDef testPermDef = {
    .permissionName = "ohos.permission.INTERNET",
    .bundleName = "TlsSocketBranchTest",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "Test Tls Socket Branch",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testState = {
    .grantFlags = {2},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .permissionName = "ohos.permission.INTERNET",
    .resDeviceID = {"local"},
};

HapPolicyParams testPolicyPrams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = {testPermDef},
    .permStateList = {testState},
};
} // namespace

class AccessToken {
public:
    AccessToken() : currentID_(GetSelfTokenID())
    {
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParms, testPolicyPrams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }

private:
    AccessTokenID currentID_;
    AccessTokenID accessID_ = 0;
};

class TlsSocketBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsSocketBranchTest, BranchTest1, TestSize.Level2)
{
    TLSSecureOptions secureOption;
    SecureData structureData(PRI_KEY_FILE);
    secureOption.SetKey(structureData);

    SecureData keyPass(KEY_PASS);
    secureOption.SetKeyPass(keyPass);
    SecureData secureData = secureOption.GetKey();
    EXPECT_EQ(structureData.Length(), strlen(PRI_KEY_FILE));
    std::vector<std::string> caChain;
    caChain.push_back(CA_CRT_FILE);
    secureOption.SetCaChain(caChain);
    std::vector<std::string> getCaChain = secureOption.GetCaChain();
    EXPECT_NE(getCaChain.data(), nullptr);

    secureOption.SetCert(CLIENT_FILE);
    std::string getCert = secureOption.GetCert();
    EXPECT_NE(getCert.data(), nullptr);

    std::vector<std::string> protocolVec = {PROTOCOL12, PROTOCOL13};
    secureOption.SetProtocolChain(protocolVec);
    std::vector<std::string> getProtocol;
    getProtocol = secureOption.GetProtocolChain();

    TLSSecureOptions copyOption = TLSSecureOptions(secureOption);
    TLSSecureOptions equalOption = secureOption;
}

HWTEST_F(TlsSocketBranchTest, BranchTest2, TestSize.Level2)
{
    TLSSecureOptions secureOption;
    secureOption.SetUseRemoteCipherPrefer(false);
    bool isUseRemoteCipher = secureOption.UseRemoteCipherPrefer();
    EXPECT_FALSE(isUseRemoteCipher);

    secureOption.SetSignatureAlgorithms(SIGNATURE_ALGORITHM);
    std::string getSignatureAlgorithm = secureOption.GetSignatureAlgorithms();
    EXPECT_STREQ(getSignatureAlgorithm.data(), SIGNATURE_ALGORITHM);

    secureOption.SetCipherSuite(CIPHER_SUITE);
    std::string getCipherSuite = secureOption.GetCipherSuite();
    EXPECT_STREQ(getCipherSuite.data(), CIPHER_SUITE);

    TLSSecureOptions copyOption = TLSSecureOptions(secureOption);
    TLSSecureOptions equalOption = secureOption;

    TLSConnectOptions connectOptions;
    connectOptions.SetTlsSecureOptions(secureOption);
}

HWTEST_F(TlsSocketBranchTest, BranchTest3, TestSize.Level2)
{
    TLSSecureOptions secureOption;
    TLSConnectOptions connectOptions;
    connectOptions.SetTlsSecureOptions(secureOption);

    Socket::NetAddress netAddress;
    netAddress.SetAddress(IP_ADDRESS);
    netAddress.SetPort(PORT);
    connectOptions.SetNetAddress(netAddress);
    Socket::NetAddress getNetAddress = connectOptions.GetNetAddress();
    std::string address = getNetAddress.GetAddress();
    EXPECT_STREQ(IP_ADDRESS, address.data());
    int port = getNetAddress.GetPort();
    EXPECT_EQ(port, PORT);
    netAddress.SetFamilyBySaFamily(AF_INET6);
    sa_family_t getFamily = netAddress.GetSaFamily();
    EXPECT_EQ(getFamily, AF_INET6);

    std::vector<std::string> alpnProtocols;
    alpnProtocols.push_back(ALPN_PROTOCOL);
    connectOptions.SetAlpnProtocols(alpnProtocols);
    std::vector<std::string> getAlpnProtocols;
    getAlpnProtocols = connectOptions.GetAlpnProtocols();
    EXPECT_STREQ(getAlpnProtocols[0].data(), alpnProtocols[0].data());
}

HWTEST_F(TlsSocketBranchTest, BranchTest4, TestSize.Level2)
{
    TLSSecureOptions secureOption;
    SecureData structureData(PRI_KEY_FILE);
    secureOption.SetKey(structureData);
    std::vector<std::string> caChain;
    caChain.push_back(CA_CRT_FILE);
    secureOption.SetCaChain(caChain);
    secureOption.SetCert(CLIENT_FILE);

    TLSConnectOptions connectOptions;
    connectOptions.SetTlsSecureOptions(secureOption);

    Socket::NetAddress netAddress;
    netAddress.SetAddress(IP_ADDRESS);
    netAddress.SetPort(0);
    netAddress.SetFamilyBySaFamily(AF_INET);
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);
}

HWTEST_F(TlsSocketBranchTest, BranchTest5, TestSize.Level2)
{
    TLSConnectOptions tlsConnectOptions = BaseOption();

    AccessToken token;
    TLSSocket tlsSocket;
    tlsSocket.OnError(
        [](int32_t errorNumber, const std::string &errorString) { EXPECT_NE(TLSSOCKET_SUCCESS, errorNumber); });
    tlsSocket.Connect(tlsConnectOptions, [](int32_t errCode) { EXPECT_NE(TLSSOCKET_SUCCESS, errCode); });
    std::string getData;
    tlsSocket.OnMessage([&getData](const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        EXPECT_STREQ(getData.data(), nullptr);
    });
    const std::string data = "how do you do?";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    tlsSocket.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_EQ(errCode, TLS_ERR_SSL_NULL); });
    tlsSocket.GetSignatureAlgorithms(
        [](int32_t errCode, const std::vector<std::string> &algorithms) { EXPECT_EQ(errCode, TLS_ERR_SSL_NULL); });
    tlsSocket.GetCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_NE(errCode, TLSSOCKET_SUCCESS); });
    tlsSocket.GetCipherSuite(
        [](int32_t errCode, const std::vector<std::string> &suite) { EXPECT_EQ(errCode, TLS_ERR_SSL_NULL); });
    tlsSocket.GetProtocol([](int32_t errCode, const std::string &protocol) { EXPECT_EQ(errCode, TLSSOCKET_SUCCESS); });
    tlsSocket.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_EQ(errCode, TLS_ERR_SSL_NULL); });
    (void)tlsSocket.Close([](int32_t errCode) { EXPECT_FALSE(errCode == TLSSOCKET_SUCCESS); });
}


HWTEST_F(TlsSocketBranchTest, BranchTest7, TestSize.Level2)
{
    TLSSocket tlsSocket;
    TLSSocket::TLSSocketInternal *tlsSocketInternal = new TLSSocket::TLSSocketInternal();

    std::vector<std::string> alpnProtocols;
    alpnProtocols.push_back(ALPN_PROTOCOL);
    bool alpnProSslNull = tlsSocketInternal->SetAlpnProtocols(alpnProtocols);
    EXPECT_FALSE(alpnProSslNull);
    std::vector<std::string> getCipherSuite = tlsSocketInternal->GetCipherSuite();
    EXPECT_EQ(getCipherSuite.size(), 0);
    bool setSharedSigals = tlsSocketInternal->SetSharedSigals();
    EXPECT_FALSE(setSharedSigals);
    tlsSocketInternal->ssl_ = SSL_new(SSL_CTX_new(TLS_client_method()));
    getCipherSuite = tlsSocketInternal->GetCipherSuite();
    EXPECT_NE(getCipherSuite.size(), 0);
    setSharedSigals = tlsSocketInternal->SetSharedSigals();
    EXPECT_FALSE(setSharedSigals);
    TLSConnectOptions connectOptions = BaseOption();
    bool alpnPro = tlsSocketInternal->SetAlpnProtocols(alpnProtocols);
    EXPECT_TRUE(alpnPro);

    Socket::SocketRemoteInfo remoteInfo;
    tlsSocketInternal->hostName_ = IP_ADDRESS;
    tlsSocketInternal->port_ = PORT;
    tlsSocketInternal->family_ = AF_INET;
    tlsSocketInternal->MakeRemoteInfo(remoteInfo);
    getCipherSuite = tlsSocketInternal->GetCipherSuite();
    EXPECT_NE(getCipherSuite.size(), 0);

    std::string getRemoteCert = tlsSocketInternal->GetRemoteCertificate();
    EXPECT_EQ(getRemoteCert, "");

    std::vector<std::string> getSignatureAlgorithms = tlsSocketInternal->GetSignatureAlgorithms();
    EXPECT_EQ(getSignatureAlgorithms.size(), 0);

    std::string getProtocol = tlsSocketInternal->GetProtocol();
    EXPECT_NE(getProtocol, "");

    setSharedSigals = tlsSocketInternal->SetSharedSigals();
    EXPECT_FALSE(setSharedSigals);

    ssl_st *ssl = tlsSocketInternal->GetSSL();
    EXPECT_NE(ssl, nullptr);
    delete tlsSocketInternal;
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
