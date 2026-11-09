/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <openssl/ssl.h>

#ifdef GTEST_API_
#define private public
#endif

#include "net_address.h"
#include "secure_data.h"
#include "socket_error.h"
#include "socket_state_base.h"
#include "tls.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_key.h"
#include "tls_socket_server_innerapi.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {

using testing::ext::TestSize;

class TlsSocketServerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(TlsSocketServerTest, BranchTest001, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    TLSServerSendOptions data;
    TlsSocket::SendCallback sendCallback;
    bool ret = tlsSocketServer->Send(data, sendCallback);
    EXPECT_FALSE(ret);

    Socket::TCPExtraOptions tcpExtraOptions;
    TlsSocket::SetExtraOptionsCallback callback;
    ret = tlsSocketServer->SetExtraOptions(tcpExtraOptions, callback);
    EXPECT_FALSE(ret);

    tcpExtraOptions.SetKeepAlive(true);
    ret = tlsSocketServer->SetExtraOptions(tcpExtraOptions, callback);
    EXPECT_FALSE(ret);

    tcpExtraOptions.SetOOBInline(true);
    ret = tlsSocketServer->SetExtraOptions(tcpExtraOptions, callback);
    EXPECT_FALSE(ret);

    tcpExtraOptions.SetTCPNoDelay(true);
    ret = tlsSocketServer->SetExtraOptions(tcpExtraOptions, callback);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsSocketServerTest, BranchTest002, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    TlsSocket::TLSConnectOptions config;
    tlsSocketServer->SetLocalTlsConfiguration(config);

    int socketFd = 0;
    tlsSocketServer->ProcessTcpAccept(config, socketFd);
    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
    tlsSocketServer->AddConnect(socketFd, connection);

    std::string data = "test";
    auto ret = connection->Send(data);
    EXPECT_FALSE(ret);

    char *buffer = nullptr;
    int maxBufferSize = 0;
    auto value = connection->Recv(buffer, maxBufferSize);
    EXPECT_EQ(value, -1);

    ret = connection->Close();
    EXPECT_FALSE(ret);

    std::vector<std::string> alpnProtocols;
    ret = connection->SetAlpnProtocols(alpnProtocols);
    EXPECT_FALSE(ret);

    auto stringVector = connection->GetCipherSuite();
    EXPECT_TRUE(stringVector.empty());

    auto protocol = connection->GetProtocol();
    EXPECT_EQ(protocol, "UNKNOW_PROTOCOL");

    ret = connection->SetSharedSigals();
    EXPECT_FALSE(ret);

    ret = connection->StartShakingHands(config);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsSocketServerTest, BranchTest003, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
    OnMessageCallback onMessageCallback;
    connection->OnMessage(onMessageCallback);
    OnCloseCallback onCloseCallback;
    connection->OnClose(onCloseCallback);
    connection->OffMessage();

    TlsSocket::OnErrorCallback onErrorCallback;
    connection->OnError(onErrorCallback);
    connection->OffClose();
    connection->OffError();

    int32_t err = 0;
    std::string testString = "test";
    connection->CallOnErrorCallback(err, testString);

    OnConnectCallback onConnectCallback;
    tlsSocketServer->OnConnect(onConnectCallback);
    tlsSocketServer->OnError(onErrorCallback);
    tlsSocketServer->OffConnect();
    tlsSocketServer->OffError();

    sa_family_t family = 0;
    tlsSocketServer->MakeIpSocket(family);
    family = 2;
    tlsSocketServer->MakeIpSocket(family);
    tlsSocketServer->CallOnErrorCallback(err, testString);
    EXPECT_TRUE(tlsSocketServer->onErrorCallback_ == nullptr);
}

HWTEST_F(TlsSocketServerTest, BranchTest004, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    int socketFd = 0;
    auto userCounter = tlsSocketServer->GetConnectionClientCount();
    EXPECT_EQ(userCounter, 0);

    Socket::SocketStateBase state;
    TlsSocket::GetStateCallback stateCallback;
    tlsSocketServer->CallGetStateCallback(socketFd, state, stateCallback);
    Socket::NetAddress address;
    sockaddr_in addr4 = { 0 };
    sockaddr_in6 addr6 = { 0 };
    sockaddr *addr = nullptr;
    socklen_t len;
    tlsSocketServer->GetAddr(address, &addr4, &addr6, &addr, &len);

    auto result = tlsSocketServer->GetConnectionByClientID(socketFd);
    EXPECT_TRUE(result == nullptr);

    int32_t err = 0;
    ListenCallback callback;
    tlsSocketServer->CallListenCallback(err, callback);

    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
    address.SetPort(0);
    connection->SetAddress(address);
    address = connection->GetAddress();
    EXPECT_EQ(address.GetPort(), 0);

    TlsSocket::TLSConnectOptions options;
    connection->SetTlsConfiguration(options);

    auto ret = connection->TlsAcceptToHost(socketFd, options);
    EXPECT_FALSE(ret);

    std::string data = "";
    ret = connection->Send(data);
    EXPECT_FALSE(ret);

    char *buffer = nullptr;
    int maxBufferSize = 0;
    auto value = connection->Recv(buffer, maxBufferSize);
    EXPECT_EQ(value, -1);
}

HWTEST_F(TlsSocketServerTest, BranchTest005, TestSize.Level2)
{
    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
    auto ret = connection->Close();
    EXPECT_FALSE(ret);

    std::vector<std::string> alpnProtocols;
    ret = connection->SetAlpnProtocols(alpnProtocols);
    EXPECT_FALSE(ret);

    Socket::SocketRemoteInfo remoteInfo;
    connection->MakeRemoteInfo(remoteInfo);

    TlsSocket::TLSConfiguration tLSConfiguration;
    tLSConfiguration = connection->GetTlsConfiguration();
    std::vector<std::string> certificate;
    tLSConfiguration.SetCaCertificate(certificate);
    EXPECT_TRUE(tLSConfiguration.GetCaCertificate().empty());

    auto cipherSuiteVec = connection->GetCipherSuite();
    EXPECT_TRUE(cipherSuiteVec.empty());

    auto remoteCert = connection->GetRemoteCertificate();
    EXPECT_TRUE(remoteCert.empty());

    auto signatureAlgorithms = connection->GetSignatureAlgorithms();
    EXPECT_TRUE(signatureAlgorithms.empty());

    ret = connection->SetSharedSigals();
    EXPECT_FALSE(ret);

    auto point = connection->GetSSL();
    EXPECT_TRUE(point == nullptr);
}

HWTEST_F(TlsSocketServerTest, BranchTest006, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);

    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSocket(0);
    auto socketFd = connection->GetSocketFd();
    EXPECT_LE(socketFd, 0);
    socketFd = tlsServerSendOptions.GetSocket();
    EXPECT_EQ(socketFd, 0);

    std::string testString = "test";
    tlsServerSendOptions.SetSendData(testString);
    auto data = tlsServerSendOptions.GetSendData();
    EXPECT_EQ(data, testString);

    int32_t clientID = 0;
    connection->SetClientID(clientID);
    clientID = connection->GetClientID();
    EXPECT_EQ(clientID, 0);

    TlsSocket::TLSConnectOptions options;
    bool ret = connection->StartTlsAccept(options);
    EXPECT_FALSE(ret);

    ret = connection->CreatTlsContext();
    EXPECT_FALSE(ret);

    ret = connection->StartShakingHands(options);
    EXPECT_FALSE(ret);

    X509 *peerX509 = SSL_get_peer_certificate(connection->ssl_);
    ret = connection->SetRemoteCertRawData(peerX509);
    EXPECT_FALSE(ret);
    X509_free(peerX509);

    int index = 0;
    tlsSocketServer->InitPollList(index);
    tlsSocketServer->DropFdFromPollList(index);

    connection->CallOnCloseCallback(socketFd);
    tlsSocketServer->CallOnConnectCallback(socketFd);
    tlsSocketServer->RemoveConnect(socketFd);
    tlsSocketServer->RecvRemoteInfo(socketFd, index);

    Socket::SocketRemoteInfo remoteInfo;
    connection->CallOnMessageCallback(socketFd, testString, remoteInfo);

    auto result = tlsSocketServer->GetConnectionByClientID(0);
    EXPECT_TRUE(result == nullptr);
}

HWTEST_F(TlsSocketServerTest, BranchTest016, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    bool callbackCalled = false;
    tlsSocketServer->GetCertificate(
        [&callbackCalled](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        EXPECT_EQ(errorNumber, -1);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest017, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    int sockFd = 0;
    bool callbackCalled = false;
    tlsSocketServer->GetRemoteCertificate(
        sockFd, [&callbackCalled](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        EXPECT_EQ(errorNumber, TlsSocket::TLS_ERR_SYS_EINVAL);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest018, TestSize.Level2)
{
    constexpr int sockFd = 1;
    constexpr int testLen = 5;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->remoteRawData_.data.length_ = testLen;
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);
    bool callbackCalled = false;
    tlsSocketServer->GetRemoteCertificate(
        sockFd, [&callbackCalled, testLen](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(cert.data.Length(), testLen);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest019, TestSize.Level2)
{
    constexpr int sockFd = 1;
    constexpr int testLen = 0;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->remoteRawData_.data.length_ = testLen;
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);
    bool callbackCalled = false;
    tlsSocketServer->GetRemoteCertificate(
        sockFd, [&callbackCalled, testLen](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        EXPECT_NE(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(cert.data.Length(), testLen);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest020, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    tlsSocketServer->TLSServerConfiguration_.protocol_ = TlsSocket::TLS_V1_3;
    bool callbackCalled = false;
    tlsSocketServer->GetProtocol(
        [&callbackCalled](int32_t errorNumber, const std::string &protocol) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(protocol, TlsSocket::PROTOCOL_TLS_V13);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest021, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    tlsSocketServer->TLSServerConfiguration_.protocol_ = TlsSocket::TLS_V1_2;
    bool callbackCalled = false;
    tlsSocketServer->GetProtocol(
        [&callbackCalled](int32_t errorNumber, const std::string &protocol) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(protocol, TlsSocket::PROTOCOL_TLS_V12);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest022, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    constexpr int sockFd = 1;
    bool callbackCalled = false;
    tlsSocketServer->GetCipherSuite(
        sockFd, [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_EQ(errorNumber, TlsSocket::TLS_ERR_SYS_EINVAL);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest023, TestSize.Level2)
{
    constexpr int sockFd = 1;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);

    bool callbackCalled = false;
    tlsSocketServer->GetCipherSuite(
        sockFd, [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_NE(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest024, TestSize.Level2)
{
    constexpr int sockFd = 1;
    auto tlsSocketServer = new TLSSocketServer();

    bool callbackCalled = false;
    tlsSocketServer->GetSignatureAlgorithms(
        sockFd, [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &algorithms) {
        EXPECT_EQ(errorNumber, TlsSocket::TLS_ERR_SYS_EINVAL);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest025, TestSize.Level2)
{
    constexpr int sockFd = 1;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);

    bool callbackCalled = false;
    tlsSocketServer->GetSignatureAlgorithms(
        sockFd, [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_NE(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest026, TestSize.Level2)
{
    constexpr int sockFd = 1;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->signatureAlgorithms_ = {"TEST"};
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);

    bool callbackCalled = false;
    tlsSocketServer->GetSignatureAlgorithms(
        sockFd, [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerTest, BranchTest033, TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    std::shared_ptr<TLSSocketServer::Connection> connection =
        std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);

    int index = 1;
    tlsSocketServer->DropFdFromPollList(index);
    index = 2;
    bool res = tlsSocketServer->DropFdFromPollList(index);
    tlsSocketServer->NotifyRcvThdExit();
    tlsSocketServer->WaitForRcvThdExit();
    EXPECT_TRUE(res);
}

} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
