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
void MockCertChainNetAddress(Socket::NetAddress &address)
{
    address.SetAddress(TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);
}

void MockCertChainParamOptions(Socket::NetAddress &address, TLSSecureOptions &secureOption, TLSConnectOptions &options)
{
    secureOption.SetKey(SecureData(TlsUtilsTest::ChangeToFile(PRIVATE_KEY_PEM_CHAIN)));
    secureOption.SetCert(TlsUtilsTest::ChangeToFile(CLIENT_CRT_CHAIN));

    MockCertChainNetAddress(address);
    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);
}

void SetCertChainHwTestShortParam(TLSSocket &server)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_PATH_CHAIN) };
    secureOption.SetCaChain(caVec);
    Socket::NetAddress address;
    MockCertChainParamOptions(address, secureOption, options);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

void SetCertChainHwTestLongParam(TLSSocket &server)
{
    Socket::NetAddress address;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_PATH_CHAIN) };
    TLSSecureOptions secureOption;
    secureOption.SetCaChain(caVec);
    std::string protocolV13 = "TLSv1.3";
    std::vector<std::string> protocolVec = { protocolV13 };
    secureOption.SetProtocolChain(protocolVec);
    secureOption.SetCipherSuite("AES256-SHA256");

    TLSConnectOptions options;
    MockCertChainParamOptions(address, secureOption, options);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, bindInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("bindInterface")) {
        return;
    }

    TLSSocket testServer;
    Socket::NetAddress address;
    MockCertChainNetAddress(address);
    testServer.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("connectInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);

    const std::string data = "how do you do? this is connectInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("closeInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);

    const std::string data = "how do you do? this is closeInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("sendInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);

    const std::string data = "how do you do? this is sendInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteAddressInterface")) {
        return;
    }
    TLSSocket certChainServer;
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_PATH_CHAIN) };
    secureOption.SetCaChain(caVec);
    MockCertChainParamOptions(address, secureOption, options);

    certChainServer.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    certChainServer.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    Socket::NetAddress netAddress;
    certChainServer.GetRemoteAddress([&netAddress](int32_t errCode, const Socket::NetAddress &address) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        netAddress.SetPort(address.GetPort());
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
        netAddress.SetAddress(address.GetAddress());
    });
    EXPECT_STREQ(netAddress.GetAddress().c_str(), TlsUtilsTest::GetIp(TlsUtilsTest::ChangeToFile(IP_ADDRESS)).c_str());
    EXPECT_EQ(address.GetPort(), std::atoi(TlsUtilsTest::ChangeToFile(PORT).c_str()));
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "how do you do? this is getRemoteAddressInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getStateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteAddressInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);

    Socket::SocketStateBase TlsSocketstate;
    certChainServer.GetState([&TlsSocketstate](int32_t errCode, const Socket::SocketStateBase &state) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketCertChainTest TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string tlsSocketCertChainTestData = "how do you do? this is getStateInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(tlsSocketCertChainTestData);
    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getCertificateInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);
    Socket::TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test getCertificateInterface";

    tcpSendOptions.SetData(data);
    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    certChainServer.GetCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestShortParam(certChainServer);
    Socket::TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test getRemoteCertificateInterface";
    tcpSendOptions.SetData(data);

    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    certChainServer.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("protocolInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestLongParam(certChainServer);

    const std::string data = "how do you do? this is protocolInterface.";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    std::string getProtocolVal = "";
    certChainServer.GetProtocol([&getProtocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        getProtocolVal = protocol;
    });
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.3");
    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getCipherSuiteInterface")) {
        return;
    }
    TLSSocket certChainServer;
    SetCertChainHwTestLongParam(certChainServer);

    bool successFlag = false;
    const std::string data = "how do you do? This is getCipherSuiteInterface";
    Socket::TCPSendOptions testTcpSendOptions;
    testTcpSendOptions.SetData(data);
    certChainServer.Send(testTcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> testCipherSuite;
    certChainServer.GetCipherSuite([&testCipherSuite](int32_t errCode, const std::vector<std::string> &suite) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        testCipherSuite = suite;
    });

    for (auto const &iter : testCipherSuite) {
        if (iter == "AES256-SHA256") {
            successFlag = true;
        }
    }

    EXPECT_TRUE(successFlag);
    sleep(2);

    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getSignatureAlgorithmsInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("getSignatureAlgorithmsInterface")) {
        return;
    }
    
    TLSSocket certChainServer;
    TLSSecureOptions secureOption;
    std::string signatureAlgorithmVec = {"rsa_pss_rsae_sha256:ECDSA+SHA256"};
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);
    std::vector<std::string> caVec = { TlsUtilsTest::ChangeToFile(CA_PATH_CHAIN),
        TlsUtilsTest::ChangeToFile(MID_CA_PATH_CHAIN) };
    secureOption.SetCaChain(caVec);
    std::string protocolV13 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV13};
    secureOption.SetProtocolChain(protocolVec);
    Socket::NetAddress address;
    TLSConnectOptions options;
    MockCertChainParamOptions(address, secureOption, options);

    bool successFlag = false;
    certChainServer.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    certChainServer.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    const std::string data = "how do you do? this is getSignatureAlgorithmsInterface";
    Socket::TCPSendOptions testOptions;
    testOptions.SetData(data);
    certChainServer.Send(testOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> testSignatureAlgorithms;
    certChainServer.GetSignatureAlgorithms(
        [&testSignatureAlgorithms](int32_t errCode, const std::vector<std::string> &algorithms) {
            if (errCode == TLSSOCKET_SUCCESS) {
                testSignatureAlgorithms = algorithms;
            }
        });

    for (auto const &iter : testSignatureAlgorithms) {
        if (iter == "ECDSA+SHA256") {
            successFlag = true;
        }
    }
    EXPECT_TRUE(successFlag);
    sleep(2);
    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, onMessageDataInterface, testing::ext::TestSize.Level2)
{
    if (!TlsUtilsTest::CheckCaPathChainExistence("tlsSocketOnMessageData")) {
        return;
    }
    std::string getData = "server->client";
    TLSSocket certChainServer;
    SetCertChainHwTestLongParam(certChainServer);
    certChainServer.OnMessage([&getData](const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        if (data == getData) {
            EXPECT_TRUE(true);
        } else {
            EXPECT_TRUE(false);
        }
    });

    const std::string data = "how do you do? this is tlsSocketOnMessageData";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    certChainServer.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)certChainServer.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
