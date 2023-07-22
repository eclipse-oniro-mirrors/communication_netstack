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

#include "net_address.h"
#include "secure_data.h"
#include "socket_error.h"
#include "socket_state_base.h"
#include "tls.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_key.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
const std::string_view PRIVATE_KEY_PEM = "/data/ClientCert/client_rsa_private.pem.unsecure";
const std::string_view CA_DER = "/data/ClientCert/ca.crt";
const std::string_view CLIENT_CRT = "/data/ClientCert/client.crt";
const std::string_view IP_ADDRESS = "/data/Ip/address.txt";
const std::string_view PORT = "/data/Ip/port.txt";

inline bool CheckCaFileExistence(const char *function)
{
    if (access(CA_DER.data(), 0)) {
        std::cout << "CA file does not exist! (" << function << ")";
        return false;
    }
    return true;
}

std::string ChangeToFile(std::string_view fileName)
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

void socketTestSplitCode_X(TLSSocket &server)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ChangeToFile(PRIVATE_KEY_PEM)));
    std::vector<std::string> caVec = {ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFile(CLIENT_CRT));

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

void socketTestSplitCode_Y(TLSSocket &server)
{
    TLSConnectOptions options;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    secureOption.SetKey(SecureData(ChangeToFile(PRIVATE_KEY_PEM)));
    std::vector<std::string> caVec = {ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFile(CLIENT_CRT));
    secureOption.SetCipherSuite("AES256-SHA256");
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, bindInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("bindInterface")) {
        return;
    }

    TLSSocket server;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, connectInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("connectInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_X(server);

    const std::string data = "how do you do? this is connectInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);
}

HWTEST_F(TlsSocketTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("closeInterface")) {
        return;
    }

    TLSSocket server;
    socketTestSplitCode_X(server);

    const std::string data = "how do you do? this is closeInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("sendInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_X(server);

    const std::string data = "how do you do? this is sendInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocket server;
    socketTestSplitCode_X(server);

    Socket::NetAddress netAddress;
    server.GetRemoteAddress([&netAddress](int32_t errCode, const Socket::NetAddress &address) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        netAddress.SetAddress(address.GetAddress());
        netAddress.SetPort(address.GetPort());
        netAddress.SetFamilyBySaFamily(address.GetSaFamily());
    });
    EXPECT_STREQ(netAddress.GetAddress().c_str(), GetIp(ChangeToFile(IP_ADDRESS)).c_str());
    EXPECT_EQ(address.GetPort(), std::atoi(ChangeToFile(PORT).c_str()));
    EXPECT_EQ(netAddress.GetSaFamily(), AF_INET);

    const std::string data = "how do you do? this is getRemoteAddressInterface";
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
    socketTestSplitCode_X(server);

    Socket::SocketStateBase TlsSocketstate;
    server.GetState([&TlsSocketstate](int32_t errCode, const Socket::SocketStateBase &state) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        TlsSocketstate = state;
    });
    std::cout << "TlsSocketstate.IsClose(): " << TlsSocketstate.IsClose() << std::endl;
    EXPECT_TRUE(TlsSocketstate.IsBound());
    EXPECT_TRUE(!TlsSocketstate.IsClose());
    EXPECT_TRUE(TlsSocketstate.IsConnected());

    const std::string data = "how do you do? this is getStateInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCertificateInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_X(server);

    const std::string data = "how do you do? This is UT test getCertificateInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    server.GetCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteCertificateInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_X(server);

    Socket::TCPSendOptions tcpSendOptions;
    const std::string data = "how do you do? This is UT test getRemoteCertificateInterface";
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    server.GetRemoteCertificate(
        [](int32_t errCode, const X509CertRawData &cert) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("protocolInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_Y(server);

    const std::string data = "how do you do? this is protocolInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);

    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    std::string getProtocolVal;
    server.GetProtocol([&getProtocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
        getProtocolVal = protocol;
    });
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.3");

    Socket::SocketStateBase stateBase;
    server.GetState([&stateBase](int32_t errCode, Socket::SocketStateBase state) {
        if (errCode == TLSSOCKET_SUCCESS) {
            EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS);
            stateBase.SetIsBound(state.IsBound());
            stateBase.SetIsClose(state.IsClose());
            stateBase.SetIsConnected(state.IsConnected());
        }
    });
    EXPECT_TRUE(stateBase.IsConnected());
    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getCipherSuiteInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCipherSuiteInterface")) {
        return;
    }
    TLSSocket server;
    socketTestSplitCode_Y(server);

    bool flag = false;
    const std::string data = "how do you do? This is getCipherSuiteInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> cipherSuite;
    server.GetCipherSuite([&cipherSuite](int32_t errCode, const std::vector<std::string> &suite) {
        if (errCode == TLSSOCKET_SUCCESS) {
            cipherSuite = suite;
        }
    });

    for (auto const &iter : cipherSuite) {
        if (iter == "AES256-SHA256") {
            flag = true;
        }
    }

    EXPECT_TRUE(flag);
    sleep(2);

    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, getSignatureAlgorithmsInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getSignatureAlgorithmsInterface")) {
        return;
    }
    TLSConnectOptions options;
    TLSSocket server;
    TLSSecureOptions secureOption;
    Socket::NetAddress address;

    address.SetAddress(GetIp(ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    std::string signatureAlgorithmVec = {"rsa_pss_rsae_sha256:ECDSA+SHA256"};
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);
    secureOption.SetKey(SecureData(ChangeToFile(PRIVATE_KEY_PEM)));
    std::vector<std::string> caVec = {ChangeToFile(CA_DER)};
    secureOption.SetCaChain(caVec);
    secureOption.SetCert(ChangeToFile(CLIENT_CRT));
    std::string protocolV1_3 = "TLSv1.3";
    std::vector<std::string> protocolVec = {protocolV1_3};
    secureOption.SetProtocolChain(protocolVec);

    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    server.Bind(address, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
    server.Connect(options, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    bool flag = false;
    const std::string data = "how do you do? this is getSignatureAlgorithmsInterface";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    std::vector<std::string> signatureAlgorithms;
    server.GetSignatureAlgorithms([&signatureAlgorithms](int32_t errCode, const std::vector<std::string> &algorithms) {
        if (errCode == TLSSOCKET_SUCCESS) {
            signatureAlgorithms = algorithms;
        }
    });
    for (auto const &iter : signatureAlgorithms) {
        if (iter == "ECDSA+SHA256") {
            flag = true;
        }
    }
    EXPECT_TRUE(flag);
    sleep(2);
    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketTest, onMessageDataInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("tlsSocketOnMessageData")) {
        return;
    }
    std::string getData = "server->client";
    TLSSocket server;
    socketTestSplitCode_Y(server);

    server.OnMessage([&getData](const std::string &data, const Socket::SocketRemoteInfo &remoteInfo) {
        if (data == getData) {
            EXPECT_TRUE(true);
        } else {
            EXPECT_TRUE(false);
        }
    });

    const std::string data = "how do you do? this is tlsSocketOnMessageData";
    Socket::TCPSendOptions tcpSendOptions;
    tcpSendOptions.SetData(data);
    server.Send(tcpSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)server.Close([](int32_t errCode) { EXPECT_TRUE(errCode == TLSSOCKET_SUCCESS); });
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
