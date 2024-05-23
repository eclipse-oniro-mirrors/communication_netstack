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
#include "netstack_log.h"
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
namespace TlsSocket {

class TLSSecureOptionsBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TLSSecureOptionsBranchTest, TLSSecureOptionsBranchTest001, testing::ext::TestSize.Level2)
{
    TLSSecureOptions secureOption;
    std::vector<std::string> crlChain = {};
    secureOption.SetCrlChain(crlChain);
    auto caChain = secureOption.GetCrlChain();
    EXPECT_TRUE(crlChain == caChain);

    VerifyMode verifyMode = VerifyMode::ONE_WAY_MODE;
    secureOption.SetVerifyMode(verifyMode);
    auto mode = secureOption.GetVerifyMode();
    EXPECT_EQ(mode, verifyMode);

    TLSConnectOptions connectOptions;
    CheckServerIdentity checkServerIdentity;
    connectOptions.SetCheckServerIdentity(checkServerIdentity);
    auto identity = connectOptions.GetCheckServerIdentity();
    EXPECT_TRUE(identity == nullptr);

    sockaddr *addr = nullptr;
    TLSSocket server;
    auto testString = server.MakeAddressString(addr);
    EXPECT_TRUE(testString.empty());

    sockaddr addrInfo;
    addrInfo.sa_family = 0;
    testString = server.MakeAddressString(&addrInfo);
    EXPECT_TRUE(testString.empty());

    addrInfo.sa_family = AF_INET;
    testString = server.MakeAddressString(&addrInfo);
    EXPECT_FALSE(testString.empty());

    addrInfo.sa_family = AF_INET6;
    testString = server.MakeAddressString(&addrInfo);
    EXPECT_FALSE(testString.empty());

    Socket::NetAddress address;
    sockaddr_in6 addr6 = { 0 };
    sockaddr_in addr4 = { 0 };
    socklen_t len;
    server.GetAddr(address, &addr4, &addr6, &addr, &len);
}

HWTEST_F(TLSSecureOptionsBranchTest, TLSSecureOptionsBranchTest002, testing::ext::TestSize.Level2)
{
    TLSSocket server;
    sa_family_t family = 0;
    server.MakeIpSocket(family);

    family = AF_INET;
    server.MakeIpSocket(family);

    family = AF_INET6;
    server.MakeIpSocket(family);

    std::string data = "";
    Socket::SocketRemoteInfo remoteInfo;
    server.CallOnMessageCallback(data, remoteInfo);
    server.CallOnConnectCallback();
    server.CallOnCloseCallback();

    int32_t err = 0;
    BindCallback bindCallback;
    server.CallBindCallback(err, bindCallback);

    ConnectCallback connectCallback;
    server.CallConnectCallback(err, connectCallback);

    CloseCallback closeCallback;
    server.CallCloseCallback(err, closeCallback);

    Socket::NetAddress address;
    GetRemoteAddressCallback addressCallback;
    server.CallGetRemoteAddressCallback(err, address, addressCallback);

    Socket::SocketStateBase state;
    GetStateCallback stateCallback;
    server.CallGetStateCallback(err, state, stateCallback);

    SetExtraOptionsCallback optionsCallback;
    server.CallSetExtraOptionsCallback(err, optionsCallback);

    X509CertRawData cert;
    GetCertificateCallback certificateCallback;
    server.CallGetCertificateCallback(err, cert, certificateCallback);

    GetRemoteCertificateCallback remoteCertificateCallback;
    server.CallGetRemoteCertificateCallback(err, cert, remoteCertificateCallback);

    std::string protocol = "";
    GetProtocolCallback protocolCallback;
    server.CallGetProtocolCallback(err, protocol, protocolCallback);

    OnMessageCallback onMessageCallback;
    server.OnMessage(onMessageCallback);
    server.OffMessage();
    EXPECT_TRUE(server.onMessageCallback_ == nullptr);
}

HWTEST_F(TLSSecureOptionsBranchTest, TLSSecureOptionsBranchTest003, testing::ext::TestSize.Level2)
{
    TLSSocket server;
    int32_t err = 0;
    std::vector<std::string> suite = {};
    GetCipherSuiteCallback cipherSuiteCallback;
    server.CallGetCipherSuiteCallback(err, suite, cipherSuiteCallback);

    GetSignatureAlgorithmsCallback algorithmsCallback;
    server.CallGetSignatureAlgorithmsCallback(err, suite, algorithmsCallback);

    Socket::NetAddress address;
    BindCallback bindCallback;
    server.Bind(address, bindCallback);

    GetRemoteAddressCallback addressCallback;
    server.GetRemoteAddress(addressCallback);
    server.GetIp4RemoteAddress(addressCallback);
    server.GetIp6RemoteAddress(addressCallback);

    GetStateCallback stateCallback;
    server.GetState(stateCallback);

    Socket::ExtraOptionsBase option;
    bool ret = server.SetBaseOptions(option);
    EXPECT_TRUE(ret);

    TlsSocket::SetExtraOptionsCallback optionsCallback;
    Socket::TCPExtraOptions tcpExtraOptions;
    ret = server.SetExtraOptions(tcpExtraOptions);
    EXPECT_TRUE(ret);

    tcpExtraOptions.SetKeepAlive(true);
    ret = server.SetExtraOptions(tcpExtraOptions);
    EXPECT_TRUE(ret);

    tcpExtraOptions.SetOOBInline(true);
    ret = server.SetExtraOptions(tcpExtraOptions);
    EXPECT_TRUE(ret);

    tcpExtraOptions.SetTCPNoDelay(true);
    ret = server.SetExtraOptions(tcpExtraOptions);
    EXPECT_TRUE(ret);

    OnConnectCallback onConnectCallback;
    server.OffConnect();
    server.OnConnect(onConnectCallback);
    EXPECT_TRUE(server.onConnectCallback_ == nullptr);
}

} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
