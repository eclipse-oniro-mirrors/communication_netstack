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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest007, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    std::string hostName = "testHost";
    X509 *x509Certificates = X509_new();

    std::string result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    EXPECT_GE(result.length(), 0);
    X509_EXTENSION *ext = X509_EXTENSION_new();
    X509_add_ext(x509Certificates, ext, -1);
    result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    EXPECT_GE(result.length(), 0);

    X509_EXTENSION_free(ext);
    X509_free(x509Certificates);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest008, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    std::string hostName = "172.0.0.1";
    X509 *x509Certificates = X509_new();

    std::string result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    EXPECT_GE(result.length(), 0);
    X509_EXTENSION *ext = X509_EXTENSION_new();
    X509_add_ext(x509Certificates, ext, -1);
    result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    EXPECT_GE(result.length(), 0);

    X509_EXTENSION_free(ext);
    X509_free(x509Certificates);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest009, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    std::string hostName = "testHost";
    X509 *x509Certificates = X509_new();
    X509_NAME *subjectName = X509_get_subject_name(x509Certificates);
    X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, (unsigned char *)"testHost", -1, -1, 0);
    int index = X509_get_ext_by_NID(x509Certificates, NID_subject_alt_name, -1);
    X509_EXTENSION *ext = X509_EXTENSION_new();
    X509_add_ext(x509Certificates, ext, index);
    std::string result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    EXPECT_GE(result.length(), 0);
    X509_EXTENSION_free(ext);
    X509_free(x509Certificates);
}

extern bool IsIP(const std::string &ip);
HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest010, testing::ext::TestSize.Level2)
{
    std::string ip = "192.168.1.1";

    EXPECT_EQ(IsIP(ip), true);
    std::string ip2 = "192.168.1";
    EXPECT_EQ(IsIP(ip2), false);
    std::string ip3;
    EXPECT_EQ(IsIP(ip3), false);
}

extern std::vector<std::string> SplitHostName(std::string &hostName);
HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest011, testing::ext::TestSize.Level2)
{
    std::string hostName = "www.example.com";
    std::vector<std::string> result = TlsSocketServer::SplitHostName(hostName);
    std::vector<std::string> expect = {"www", "example", "com"};
    EXPECT_EQ(result, expect);
}

extern bool SeekIntersection(std::vector<std::string> &vecA, std::vector<std::string> &vecB);
HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest012, testing::ext::TestSize.Level2)
{
    std::vector<std::string> vecA = {"apple", "banana", "cherry"};
    std::vector<std::string> vecB = {"banana", "cherry", "date"};
    EXPECT_TRUE(SeekIntersection(vecA, vecB));
}

extern std::vector<std::string> SplitEscapedAltNames(std::string &altNames);
HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest014, testing::ext::TestSize.Level2)
{
    std::string altNames = R"("test1", "test2", "test3", "test4")";
    std::vector<std::string> expected = {""};
    std::vector<std::string> result = SplitEscapedAltNames(altNames);
    EXPECT_EQ(result, expected);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest015, testing::ext::TestSize.Level2)
{
    std::string altNames = "test1";
    std::vector<std::string> expected = {"test1"};
    std::vector<std::string> result = SplitEscapedAltNames(altNames);
    EXPECT_EQ(result, expected);
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest018, testing::ext::TestSize.Level2)
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest019, testing::ext::TestSize.Level2)
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
    auto tlsSocketServer = new TLSSocketServer();
    constexpr int sockFd = 1;
    bool callbackCalled = false;
    tlsSocketServer->GetCipherSuite(sockFd,
                                    [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_EQ(errorNumber, TlsSocket::TLS_ERR_SYS_EINVAL);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest023, testing::ext::TestSize.Level2)
{
    constexpr int sockFd = 1;
    auto tlsSocketServer = new TLSSocketServer();
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    tlsSocketServer->clientIdConnections_.emplace(sockFd, connection);

    bool callbackCalled = false;
    tlsSocketServer->GetCipherSuite(sockFd,
                                    [&callbackCalled](int32_t errorNumber, const std::vector<std::string> &suite) {
        EXPECT_NE(errorNumber, TlsSocket::TLSSOCKET_SUCCESS);
        callbackCalled = true;
    });
    EXPECT_TRUE(callbackCalled);
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest024, testing::ext::TestSize.Level2)
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest025, testing::ext::TestSize.Level2)
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

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest026, testing::ext::TestSize.Level2)
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

extern void CheckIpAndDnsName(const std::string &hostName, std::vector<std::string> &dnsNames,
                              std::vector<std::string> &ips, const X509 *x509Certificates,
                              std::tuple<bool, std::string> &result);
HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest027, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    std::string hostName = "192.168.1.1";
    std::vector<std::string> dnsNames = {"www.test.com", "www.example.com"};
    std::vector<std::string>  ips = {"192.168.1.1", "192.168.1.2"};
    const X509 *x509Certificates = X509_new();
    std::tuple<bool, std::string> result;
    CheckIpAndDnsName(hostName, dnsNames, ips, x509Certificates, result);
    EXPECT_FALSE(std::get<0>(result));
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest028, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    std::string hostName = "192.168.1.3";
    std::vector<std::string> dnsNames = {"www.test.com", "www.example.com"};
    std::vector<std::string>  ips = {"192.168.1.1", "192.168.1.2"};
    const X509 *x509Certificates = X509_new();
    std::tuple<bool, std::string> result;
    CheckIpAndDnsName(hostName, dnsNames, ips, x509Certificates, result);
    EXPECT_FALSE(std::get<0>(result));
    EXPECT_EQ(std::get<1>(result), "IP: 192.168.1.3 is not in the cert's list");
    delete tlsSocketServer;
}


HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest029, testing::ext::TestSize.Level2)
{
    auto tlsSocketServer = new TLSSocketServer();
    std::string hostName = "www.test.com";
    std::vector<std::string> dnsNames = {"www", "test", "com"};
    std::vector<std::string>  ips = {"192.168.1.1", "192.168.1.2"};
    const X509 *x509Certificates = X509_new();
    std::tuple<bool, std::string> result;
    CheckIpAndDnsName(hostName, dnsNames, ips, x509Certificates, result);
    EXPECT_TRUE(std::get<0>(result));
    delete tlsSocketServer;
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest031, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    std::string hostName = "testHost";
    X509 *x509Certificates = X509_new();
    std::string result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    ASSERT_EQ(result, "X509 get ext nid error");
    X509_free(x509Certificates);
}

HWTEST_F(TlsSocketServerBranchTest, TlsSocketServerBranchTest032, testing::ext::TestSize.Level2)
{
    auto connection = std::make_shared<TLSSocketServer::Connection>();
    std::string hostName = "testHost";
    X509 *x509Certificates = X509_new();
    X509_EXTENSION *ext = X509_EXTENSION_new();
    X509_add_ext(x509Certificates, ext, -1);
    std::string result = connection->CheckServerIdentityLegal(hostName, x509Certificates);
    ASSERT_EQ(result, "X509 get ext nid error");
    X509_EXTENSION_free(ext);
    X509_free(x509Certificates);
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
