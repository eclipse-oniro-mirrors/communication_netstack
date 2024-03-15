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

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
void MockOneWayNetAddress(Socket::NetAddress &address)
{
    address.SetAddress(TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);
}

void MockOneWayParamOptions(Socket::NetAddress &address, TLSSecureOptions &secureOption, TLSConnectOptions &options)
{
    secureOption.SetKey(SecureData(TlsUtilsTest::ChangeToFile(PRIVATE_KEY_PEM)));
    secureOption.SetCert(TlsUtilsTest::ChangeToFile(CLIENT_CRT));

    MockOneWayNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
    options.SetNetAddress(address);
}

void SetOneWayHwTestShortParam(TLSSocket &server)
{
    TLSSecureOptions secureOption;
    Socket::NetAddress address;
    TLSConnectOptions options;
    std::vector<std::string> caVec = {TlsUtilsTest::ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    MockOneWayParamOptions(address, secureOption, options);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

void SetOneWayHwTestLongParam(TLSSocket &server)
{
    Socket::NetAddress address;
    TLSSecureOptions secureOption;

    std::vector<std::string> caVec = {TlsUtilsTest::ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCipherSuite("AES256-SHA256");
    std::string protocolV13 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV13};
    secureOption.SetProtocolChain(protocolVec);
    TLSConnectOptions options;
    MockOneWayParamOptions(address, secureOption, options);
    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, bindInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("bindInterface")) {
        return;
    }

    TLSSocket oneWayService;
    Socket::NetAddress address;
    MockOneWayNetAddress(address);

    oneWayService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("connectInterface")) {
        return;
    }

    TLSSocket oneWayService;
    SetOneWayHwTestShortParam(oneWayService);

    const std::string data = "how do you do? this is connectInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("closeInterface")) {
        return;
    }

    TLSSocket oneWayService;
    SetOneWayHwTestShortParam(oneWayService);

    const std::string data = "how do you do? this is closeInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("sendInterface")) {
        return;
    }

    TLSSocket oneWayService;
    SetOneWayHwTestShortParam(oneWayService);

    const std::string data = "how do you do? this is sendInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocket oneWayService;
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    std::vector<std::string> caVec = {TlsUtilsTest::ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    MockOneWayParamOptions(address, secureOption, options);

    oneWayService.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    oneWayService.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    Socket::NetAddress netAddress;
    oneWayService.GetRemoteAddress([&netAddress](int32_t errCode, const Socket::NetAddress &address) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        netAddress.SetAddress(address.GetAddress());
        netAddress.SetPort(address.GetPort());
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
    });
    EXPECT_STREQ(netAddress.GetAddress().c_str(), TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)).c_str());
    EXPECT_EQ(address.GetPort(), std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "how do you do? this is getRemoteAddressInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getStateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocket oneWayService;
    SetOneWayHwTestShortParam(oneWayService);

    Socket::SocketStateBase TlsSocketstate;
    oneWayService.GetState([&TlsSocketstate](int32_t errCode, const Socket::SocketStateBase &state) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketTest TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string tlsSocketTestData = "how do you do? this is getStateInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(tlsSocketTestData);
    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket oneWayService;
    SetOneWayHwTestShortParam(oneWayService);

    const std::string data = "how do you do? This is UT test getRemoteCertificateInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    oneWayService.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("protocolInterface")) {
        return;
    }
    TLSSocket oneWayService;
    SetOneWayHwTestLongParam(oneWayService);

    const std::string data = "how do you do? this is protocolInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    std::string protocolVal;
    oneWayService.GetProtocol([&protocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        protocolVal = protocol;
    });
    EXPECT_STREQ(protocolVal.c_str(), "TLSv1.3");

    Socket::SocketStateBase stateBase;
    oneWayService.GetState([&stateBase](int32_t errCode, Socket::SocketStateBase state) {
        if (errCode == TLSSOCKET_SUCCESS) {
            EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
            stateBase.SetIsBound(state.IsBound());
            stateBase.SetIsClose(state.IsClose());
            stateBase.SetIsConnected(state.IsConnected());
        }
    });
    EXPECT_TRUE(stateBase.IsConnected());
    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("getCipherSuiteInterface")) {
        return;
    }
    TLSSocket oneWayService;
    SetOneWayHwTestLongParam(oneWayService);

    bool flag = false;
    const std::string data = "how do you do? This is getCipherSuiteInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> testSuite;
    oneWayService.GetCipherSuite([&testSuite](int32_t errCode, const std::vector<std::string> &suite) {
        if (errCode == TLSSOCKET_SUCCESS) {
            testSuite = suite;
        }
    });

    for (auto const &iter : testSuite) {
        if (iter == "AES256-SHA256") {
            flag = true;
        }
    }

    EXPECT_TRUE(flag);
    sleep(2);

    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, onMessageDataInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaFileExistence("tlsSocketOnMessageData")) {
        return;
    }
    std::string getData = "server->client";
    TLSSocket oneWayService;
    SetOneWayHwTestLongParam(oneWayService);

    oneWayService.OnMessage([&getData](const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        EXPECT_TRUE(data == getData);
    });

    const std::string data = "how do you do? this is tlsSocketOnMessageData";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    oneWayService.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)oneWayService.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
