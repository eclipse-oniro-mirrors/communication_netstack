/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "tls_utils_test.h"
#include "token_setproc.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
using namespace Security::AccessToken;
} // namespace

void MockConnectionNetAddress(Socket::NetAddress &address)
{
    address.SetAddress(TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);
}

void MockConnectionParamOptions(Socket::NetAddress &address, TLSSecureOptions &secureOption, TLSConnectOptions &options)
{
    secureOption.SetKey(SecureData(TlsUtilsTest::ChangeToFile(PRIVATE_KEY_PEM_CHAIN)));
    secureOption.SetCert(TlsUtilsTest::ChangeToFile(CLIENT_CRT_CHAIN));

    MockConnectionNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    options.SetNetAddress(address);
}

void SetUnilateralHwTestShortParam(TLSSocket &server)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(ROOT_CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_CHAIN) };
    secureOption.SetCaChain(caVec);
    MockConnectionParamOptions(address, secureOption, options);

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
    if (!TlsUtilsTest::CheckCaPathChainExistence("bindInterface")) {
        return;
    }

    TLSSocket tlsService;
    Socket::NetAddress address;
    MockConnectionNetAddress(address);

    AccessToken token;
    tlsService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("connectInterface")) {
        return;
    }
    TLSSocket tlsService;
    SetUnilateralHwTestShortParam(tlsService);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("closeInterface")) {
        return;
    }
    TLSSocket tlsService;
    SetUnilateralHwTestShortParam(tlsService);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    ;
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("sendInterface")) {
        return;
    }
    TLSSocket tlsService;
    SetUnilateralHwTestShortParam(tlsService);

    AccessToken token;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteAddressInterface")) {
        return;
    }
    TLSSocket tlsService;
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(ROOT_CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_CHAIN) };
    secureOption.SetCaChain(caVec);
    MockConnectionParamOptions(address, secureOption, options);

    tlsService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    tlsService.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    AccessToken token;
    Socket::NetAddress netAddress;
    tlsService.GetRemoteAddress([&netAddress](int32_t errCode, const Socket::NetAddress &address) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
        netAddress.SetAddress(address.GetAddress());
        netAddress.SetPort(address.GetPort());
    });
    EXPECT_STREQ(netAddress.GetAddress().c_str(), TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)).c_str());
    EXPECT_EQ(address.GetPort(), std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getStateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocket tlsService;
    SetUnilateralHwTestShortParam(tlsService);

    AccessToken token;
    Socket::SocketStateBase TlsSocketstate;
    tlsService.GetState([&TlsSocketstate](int32_t errCode, const Socket::SocketStateBase &state) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketUnilateralConnection TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string connectionData = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(connectionData);
    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket tlsService;
    SetUnilateralHwTestShortParam(tlsService);
    Socket::TCPSendOptions tcpSendOptions;
    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";

    AccessToken token;
    tcpSendOptions.SetData(data);

    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    tlsService.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("protocolInterface")) {
        return;
    }

    TLSSocket tlsService;
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(ROOT_CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_CHAIN) };
    secureOption.SetCaChain(caVec);
    std::string protocolV13 = "TLSv1.2";
    std::vector<std::string> protocolVec = { protocolV13 };
    secureOption.SetProtocolChain(protocolVec);
    Socket::NetAddress address;
    MockConnectionParamOptions(address, secureOption, options);

    AccessToken token;
    tlsService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    tlsService.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    std::string getProtocolVal;
    tlsService.GetProtocol([&getProtocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        getProtocolVal = protocol;
    });
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.2");

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getCipherSuiteInterface")) {
        return;
    }

    TLSConnectOptions options;
    TLSSocket tlsService;
    TLSSecureOptions secureOption;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(ROOT_CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_CHAIN) };
    secureOption.SetCaChain(caVec);
    secureOption.SetCipherSuite("ECDHE-RSA-AES128-GCM-SHA256");
    Socket::NetAddress address;
    MockConnectionParamOptions(address, secureOption, options);

    bool flag = false;
    AccessToken token;
    tlsService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    tlsService.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    const std::string data = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: keep-alive\r\n\r\n";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    tlsService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> cipherSuite;
    tlsService.GetCipherSuite([&cipherSuite](int32_t errCode, const std::vector<std::string> &suite) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        cipherSuite = suite;
    });

    for (auto const &iter : cipherSuite) {
        if (iter == "ECDHE-RSA-AES128-GCM-SHA256") {
            flag = true;
        }
    }

    EXPECT_TRUE(flag);

    (void)tlsService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS

