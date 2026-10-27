/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <unistd.h>

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
#include "tls_socket.h"
#include "tls_socket_server.h"
#include <openssl/ssl.h>

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {

class TlsSocketServerBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest001, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    Socket::TCPExtraOptions tcpExtraOptions;
    TlsSocket::SetExtraOptionsCallback callback;
    bool ret = tlsSocketServer->SetExtraOptions(tcpExtraOptions, callback);
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest002, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    TlsSocket::TLSConnectOptions config;
    tlsSocketServer->SetLocalTlsConfiguration(config);

    int socketFd = 0;
    tlsSocketServer->ProcessTcpAccept(config, socketFd);
    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
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

    ret = connection->SetSharedSigals();
    EXPECT_FALSE(ret);

    ret = connection->StartShakingHands(config);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest003, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest004, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);

    int socketFd = 0;
    TlsSocket::CloseCallback closeCallback;
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

    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest005, testing::ext::TestSize.Level2)
{
    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
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
    EXPECT_FALSE(point != nullptr);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest006, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);

    auto socketFd = connection->GetSocketFd();
    EXPECT_LE(socketFd, 0);

    std::shared_ptr<EventManager> eventManager = nullptr;
    auto tlsServerSharedPtr = std::make_shared<TLSSocketServer>();
    connection->SetOwner(tlsServerSharedPtr);
    EXPECT_FALSE(connection->GetOwner().expired());

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
    tlsSocketServer->CallOnConnectCallback(socketFd, eventManager);
    tlsSocketServer->RemoveConnect(socketFd);
    tlsSocketServer->RecvRemoteInfo(socketFd, index);

    Socket::SocketRemoteInfo remoteInfo;
    std::string testString = "test";
    connection->CallOnMessageCallback(socketFd, testString, remoteInfo);

    auto manager = std::make_shared<EventManager>();
    tlsSocketServer->RemoveConnect(connection->GetSocketFd());
    auto connections = tlsSocketServer->GetConnectionByClientID(0);
    EXPECT_TRUE(connections == nullptr);
    tlsServerSharedPtr.reset();
    EXPECT_TRUE(connection->GetOwner().expired());
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest016, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    bool callbackCalled = false;
    tlsSocketServer->GetCertificate([&callbackCalled](int32_t errorNumber, const TlsSocket::X509CertRawData &cert) {
        EXPECT_EQ(errorNumber, -1);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest017, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    auto remoteCert = connection->GetRemoteCertRawData();
    EXPECT_EQ(remoteCert.data.Length(), 0);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest018, testing::ext::TestSize.Level2)
{
    constexpr int testLen = 5;
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->remoteRawData_.data.length_ = testLen;
    auto remoteCert = connection->GetRemoteCertRawData();
    EXPECT_EQ(remoteCert.data.Length(), testLen);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest019, testing::ext::TestSize.Level2)
{
    constexpr int testLen = 0;
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->remoteRawData_.data.length_ = testLen;
    auto remoteCert = connection->GetRemoteCertRawData();
    EXPECT_EQ(remoteCert.data.Length(), testLen);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest020, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    tlsSocketServer->TLSServerConfiguration_.protocol_ = TlsSocket::TLS_V1_3;
    bool callbackCalled = false;
    tlsSocketServer->GetProtocol([&callbackCalled](int32_t errorNumber, const std::string &protocol) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(protocol, TlsSocket::PROTOCOL_TLS_V13);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest021, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    tlsSocketServer->TLSServerConfiguration_.protocol_ = TlsSocket::TLS_V1_2;
    bool callbackCalled = false;
    tlsSocketServer->GetProtocol([&callbackCalled](int32_t errorNumber, const std::string &protocol) {
        EXPECT_EQ(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        EXPECT_EQ(protocol, TlsSocket::PROTOCOL_TLS_V12);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest022, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    auto cipherSuite = connection->GetCipherSuite();
    EXPECT_TRUE(cipherSuite.empty());
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest023, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    auto signatureAlgorithms = connection->GetSignatureAlgorithms();
    EXPECT_TRUE(signatureAlgorithms.empty());
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest024, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    connection->signatureAlgorithms_ = {"TEST"};
    auto signatureAlgorithms = connection->GetSignatureAlgorithms();
    EXPECT_EQ(signatureAlgorithms.size(), 1UL);
    EXPECT_EQ(signatureAlgorithms[0], "TEST");
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest033, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
 
    int index = 1;
    tlsSocketServer->DropFdFromPollList(index);
    index = 2;
    bool res = tlsSocketServer->DropFdFromPollList(index);
    tlsSocketServer->NotifyRcvThdExit();
    tlsSocketServer->WaitForRcvThdExit();
    EXPECT_FALSE(res == false);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest034, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);
    int fds[2];
    EXPECT_EQ(pipe(fds), 0);
    connection->socketFd_ = fds[0];
    connection->ssl_ = nullptr;
    bool ret = connection->Close();
    EXPECT_FALSE(ret);
    EXPECT_EQ(connection->socketFd_, -1);
    close(fds[1]);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest035, testing::ext::TestSize.Level2)
{
    TLSSocketServer *server = new TLSSocketServer();
    EXPECT_TRUE(server != nullptr);
    server->NotifyRcvThdExit();
    delete server;
    EXPECT_TRUE(server->sockRcvExit_);
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
