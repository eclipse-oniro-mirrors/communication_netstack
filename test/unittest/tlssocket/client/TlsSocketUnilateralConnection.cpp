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

#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "net_address.h"
#include "secure_data.h"
#include "socket_error.h"
#include "socket_state_base.h"
#include "tls.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_key.h"
#include "tls_socket.h"
#include "token_setproc.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
using namespace Security::AccessToken;
const std::string_view PRIVATE_KEY_PEM_CHAIN = "/data/ClientCertChain/privekey.pem.unsecure";
const std::string_view CA_PATH_CHAIN = "/data/ClientCertChain/RootCa.pem";
const std::string_view MID_CA_PATH_CHAIN = "/data/ClientCertChain/MidCa.pem";
const std::string_view CLIENT_CRT_CHAIN = "/data/ClientCertChain/secondServer.crt";
const std::string_view IP_ADDRESS = "/data/Ip/address.txt";
const std::string_view PORT = "/data/Ip/port.txt";

inline bool CheckCaFileExistence(const char *function)
{
    if (access(CA_PATH_CHAIN.data(), 0)) {
        std::cout << "CA file does not exist! (" << function << ")";
        return false;
    }
    return true;
}

std::string ReadFileContent(const std::string_view fileName)
{
    std::ifstream file;
    file.open(fileName);
    std::stringstream ss;
    ss << file.rdbuf();
    std::string infos = ss.str();
    file.close();
    return infos;
}

std::string GetIp(std::string ip)
{
    return ip.substr(0, ip.length() - 1);
}
} // namespace

class TlsSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

void SetUnilateralHwTestShortParam(TLSSocket &server)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ReadFileContent(IP_ADDRESS)));
    address.SetPort(std::atoi(ReadFileContent(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ReadFileContent(PRIVATE_KEY_PEM_CHAIN)));
    std::vector<std::string> caVec = {ReadFileContent(CA_PATH_CHAIN), ReadFileContent(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ReadFileContent(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
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

HWTEST_F(TlsSocketTest, bindInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("bindInterface")) {
        return;
    }

    TLSSocket serverTLS;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ReadFileContent(IP_ADDRESS)));
    address.SetPort(std::atoi(ReadFileContent(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    AccessToken token;
    serverTLS.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("connectInterface")) {
        return;
    }
    TLSSocket server;
    SetUnilateralHwTestShortParam(server);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("closeInterface")) {
        return;
    }
    TLSSocket server;
    SetUnilateralHwTestShortParam(server);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    ;
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("sendInterface")) {
        return;
    }
    TLSSocket server;
    SetUnilateralHwTestShortParam(server);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }
    TLSSocket server;
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ReadFileContent(IP_ADDRESS)));
    address.SetPort(std::atoi(ReadFileContent(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ReadFileContent(PRIVATE_KEY_PEM_CHAIN)));
    std::vector<std::string> caVec = {ReadFileContent(CA_PATH_CHAIN), ReadFileContent(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ReadFileContent(CLIENT_CRT_CHAIN));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    AccessToken token;
    Socket::NetAddress netAddress;
    server.GetRemoteAddress([&netAddress](int32_t errCode, const Socket::NetAddress &address) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
        netAddress.SetAddress(address.GetAddress());
        netAddress.SetPort(address.GetPort());
    });
    EXPECT_STREQ(netAddress.GetAddress().c_str(), GetIp(ReadFileContent(IP_ADDRESS)).c_str());
    EXPECT_EQ(address.GetPort(), std::atoi(ReadFileContent(PORT).c_str()));
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getStateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocket server;
    SetUnilateralHwTestShortParam(server);

    AccessToken token;
    Socket::SocketStateBase TlsSocketstate;
    server.GetState([&TlsSocketstate](int32_t errCode, const Socket::SocketStateBase &state) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket server;
    SetUnilateralHwTestShortParam(server);
    Socket::TCPSendOptions tcpSendOptions;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";

    AccessToken token;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    server.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("protocolInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ReadFileContent(IP_ADDRESS)));
    address.SetPort(std::atoi(ReadFileContent(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ReadFileContent(PRIVATE_KEY_PEM_CHAIN)));
    std::vector<std::string> caVec = {ReadFileContent(CA_PATH_CHAIN), ReadFileContent(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ReadFileContent(CLIENT_CRT_CHAIN));
    std::string protocolV13 = "TLSv1.2";
    std::vector<std::string> protocolVec = {protocolV13};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    AccessToken token;
    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    std::string getProtocolVal;
    server.GetProtocol([&getProtocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        getProtocolVal = protocol;
    });
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.2");

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCipherSuiteInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ReadFileContent(IP_ADDRESS)));
    address.SetPort(std::atoi(ReadFileContent(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ReadFileContent(PRIVATE_KEY_PEM_CHAIN)));
    std::vector<std::string> caVec = {ReadFileContent(CA_PATH_CHAIN), ReadFileContent(MID_CA_PATH_CHAIN)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ReadFileContent(CLIENT_CRT_CHAIN));
    secureOption.SetCipherSuite("ECDHE-RSA-AES128-GCM-SHA256");

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    bool flag = false;
    AccessToken token;
    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](int32_t errCode, const std::vector<std::string> &suite) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        cipherSuite = suite;
    });

    for (auto const &iter : cipherSuite) {
        if (iter == "ECDHE-RSA-AES128-GCM-SHA256") {
            flag = true;
        }
    }

    EXPECT_TRUE(flag);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS

