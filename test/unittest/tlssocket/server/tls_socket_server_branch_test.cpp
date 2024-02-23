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
    if (tlsSocketServer == nullptr) {
        return;
    }

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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest002, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    if (tlsSocketServer == nullptr) {
        return;
    }

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

    auto protocol = connection->GetProtocol();
    EXPECT_EQ(protocol, "UNKNOW_PROTOCOL");

    ret = connection->SetSharedSigals();
    EXPECT_FALSE(ret);

    ret = connection->StartShakingHands(config);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest003, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    EXPECT_TRUE(tlsSocketServer != nullptr);
    if (tlsSocketServer == nullptr) {
        return;
    }

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
    if (tlsSocketServer == nullptr) {
        return;
    }

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
    if (tlsSocketServer == nullptr) {
        return;
    }
    std::shared_ptr<TLSSocketServer::Connection> connection = std::make_shared<TLSSocketServer::Connection>();
    EXPECT_TRUE(connection != nullptr);

    TLSServerSendOptions tlsServerSendOptions;
    tlsServerSendOptions.SetSocket(0);
    auto socketFd = connection->GetSocketFd();
    EXPECT_EQ(socketFd, 0);
    socketFd = tlsServerSendOptions.GetSocket();
    EXPECT_EQ(socketFd, 0);

    std::string testString = "test";
    tlsServerSendOptions.SetSendData(testString);
    auto data = tlsServerSendOptions.GetSendData();
    EXPECT_EQ(data, testString);

    std::shared_ptr<EventManager> eventManager = nullptr;
    connection->SetEventManager(eventManager);
    EXPECT_TRUE(connection->GetEventManager() == nullptr);

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

    ret = connection->SetRemoteCertRawData();
    EXPECT_FALSE(ret);

    int index = 0;
    tlsSocketServer->InitPollList(index);
    tlsSocketServer->DropFdFromPollList(index);

    connection->CallOnCloseCallback(socketFd);
    tlsSocketServer->CallOnConnectCallback(socketFd, eventManager);
    tlsSocketServer->RemoveConnect(socketFd);
    tlsSocketServer->RecvRemoteInfo(socketFd, index);

    Socket::SocketRemoteInfo remoteInfo;
    connection->CallOnMessageCallback(socketFd, testString, remoteInfo);

    EventManager manager;
    tlsSocketServer->CloseConnectionByEventManager(&manager);
    tlsSocketServer->DeleteConnectionByEventManager(&manager);
    auto connections = tlsSocketServer->GetConnectionByClientEventManager(&manager);
    EXPECT_TRUE(connections == nullptr);
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
