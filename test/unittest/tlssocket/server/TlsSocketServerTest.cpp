/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "tls_socket_server.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
const std::string_view CA_DER = "/data/ClientCert/ca.crt";
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
class TlsSocketServerTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsSocketServerTest, ListenInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("ListenInterface")) {
        return;
    }
    TLSSocketServer server;
    TlsSocket::TLSConnectOptions tlsListenOptions;
	
    server.Listen(tlsListenOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, sendInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("sendInterface")) {
        return;
    }

    TLSSocketServer server;

    TLSServerSendOptions tlsServerSendOptions;

    const std::string data = "how do you do? this is sendInterface";
    tlsServerSendOptions.SetSendData(data);
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, closeInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("closeInterface")) {
        return;
    }

    TLSSocketServer server;

    const std::string data = "how do you do? this is closeInterface";
    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSendData(data);
    int socketFd =  tlsServerSendOptions.GetSocket();

    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, stopInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("stopInterface")) {
        return;
    }

    TLSSocketServer server;

    TLSServerSendOptions tlsServerSendOptions;
    int socketFd =  tlsServerSendOptions.GetSocket();


    const std::string data = "how do you do? this is stopInterface";
    tlsServerSendOptions.SetSendData(data);
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);


    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);


    server.Stop([](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, getRemoteAddressInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteAddressInterface")) {
        return;
    }

    TLSSocketServer server;

    TLSServerSendOptions tlsServerSendOptions;
    int socketFd = tlsServerSendOptions.GetSocket();
    Socket::NetAddress address;

    address.SetAddress(GetIp(ChangeToFile(IP_ADDRESS)));
    address.SetPort(std::atoi(ChangeToFile(PORT).c_str()));
    address.SetFamilyBySaFamily(AF_INET);

    Socket::NetAddress netAddress;
    server.GetRemoteAddress(socketFd, [&netAddress](int32_t errCode,
        const Socket::NetAddress &address) {
    EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS);
    netAddress.SetAddress(address.GetAddress());
    netAddress.SetPort(address.GetPort());
    netAddress.SetFamilyBySaFamily(address.GetSaFamily());
    });

    const std::string data = "how do you do? this is getRemoteAddressInterface";
    tlsServerSendOptions.SetSendData(data);
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    server.Stop([](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, getRemoteCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getRemoteCertificateInterface")) {
        return;
    }

    TLSSocketServer server;

    TLSServerSendOptions tlsServerSendOptions;
    int socketFd = tlsServerSendOptions.GetSocket();


    const std::string data = "how do you do? This is UT test getRemoteCertificateInterface";
    tlsServerSendOptions.SetSendData(data);
    server.Send(tlsServerSendOptions, [](int32_t errCode) {
        EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    server.GetRemoteCertificate(socketFd, [](int32_t errCode, const TlsSocket::X509CertRawData &cert) {
        EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });

    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    server.Stop([](int32_t errCode) { EXPECT_TRUE(errCode == TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, getCertificateInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getCertificateInterface")) {
        return;
    }
    TLSSocketServer server;

    const std::string data = "how do you do? This is UT test getCertificateInterface";
    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSendData(data);
    int socketFd = tlsServerSendOptions.GetSocket();
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });

    server.GetCertificate(
        [](int32_t errCode, const TlsSocket::X509CertRawData &cert) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });

    sleep(2);
    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, protocolInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("protocolInterface")) {
        return;
    }
    TLSSocketServer server;

    const std::string data = "how do you do? this is protocolInterface";
    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSendData(data);

    int socketFd = tlsServerSendOptions.GetSocket();
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });
    std::string getProtocolVal;
    server.GetProtocol([&getProtocolVal](int32_t errCode, const std::string &protocol) {
        EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS);
        getProtocolVal = protocol;
    });
    EXPECT_STREQ(getProtocolVal.c_str(), "TLSv1.3");

    Socket::SocketStateBase stateBase;
    server.GetState([&stateBase](int32_t errCode, Socket::SocketStateBase state) {
        if (TlsSocket::TLSSOCKET_SUCCESS) {
            EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS);
            stateBase.SetIsBound(state.IsBound());
            stateBase.SetIsClose(state.IsClose());
            stateBase.SetIsConnected(state.IsConnected());
        }
    });
    EXPECT_TRUE(stateBase.IsConnected());
    sleep(2);

    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });
}

HWTEST_F(TlsSocketServerTest, getSignatureAlgorithmsInterface, testing::ext::TestSize.Level2)
{
    if (!CheckCaFileExistence("getSignatureAlgorithmsInterface")) {
        return;
    }

    TLSSocketServer server;
    TlsSocket::TLSSecureOptions secureOption;

    const std::string data = "how do you do? this is getSigntureAlgorithmsInterface";
    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSendData(data);

    int socketFd = tlsServerSendOptions.GetSocket();
    server.Send(tlsServerSendOptions, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });
    sleep(2);

    bool testFlag = false;
    std::string signatureAlgorithmVec = {"rsa_pss_rsae_sha256:ECDSA+SHA256"};
    secureOption.SetSignatureAlgorithms(signatureAlgorithmVec);
    std::vector<std::string> testSignatureAlgorithms;
    server.GetSignatureAlgorithms(socketFd, [&testSignatureAlgorithms](int32_t errCode,
        const std::vector<std::string> &algorithms) {
        if (errCode == TlsSocket::TLSSOCKET_SUCCESS) {
            testSignatureAlgorithms = algorithms;
        }
    });
    for (auto const &iter : testSignatureAlgorithms) {
        if (iter == "ECDSA+SHA256") {
            testFlag = true;
        }
    }
    EXPECT_TRUE(testFlag);
    sleep(2);


    (void)server.Close(socketFd, [](int32_t errCode) { EXPECT_TRUE(TlsSocket::TLSSOCKET_SUCCESS); });
}


} //TlsSocketServer
} //NetStack
} //OHOS
