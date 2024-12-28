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

#include "netstack_log.h"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

#include "local_socket_context.h"
#include "local_socket_exec.h"
#include "local_socket_server_context.h"
#include "multicast_get_loopback_context.h"
#include "multicast_get_ttl_context.h"
#include "multicast_membership_context.h"
#include "multicast_set_loopback_context.h"
#include "multicast_set_ttl_context.h"
#include "socket_exec.h"
#include "socket_exec_common.h"

#include "socks5.h"
#include "socks5_instance.h"
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_package.h"
#include "socks5_utils.h"

class SocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NetStack::Socket;
using namespace OHOS::NetStack::Socks5;

HWTEST_F(SocketTest, MulticastTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastMembershipContext context(env, &eventManager);
    bool ret = SocketExec::ExecUdpAddMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastMembershipContext context(env, &eventManager);
    bool ret = SocketExec::ExecUdpDropMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastSetTTLContext context(env, &eventManager);
    bool ret = SocketExec::ExecSetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastGetTTLContext context(env, &eventManager);
    bool ret = SocketExec::ExecGetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastSetLoopbackContext context(env, &eventManager);
    bool ret = SocketExec::ExecSetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    MulticastGetLoopbackContext context(env, &eventManager);
    bool ret = SocketExec::ExecGetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketBindContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketBind(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketConnectContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketSendContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketCloseContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketGetStateContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketGetSocketFdContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetSocketFd(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketSetExtraOptionsContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSetExtraOptions(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest008, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketGetExtraOptionsContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerListenContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerListen(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerGetStateContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketServerTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerSetExtraOptionsContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerSetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerGetExtraOptionsContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerSendContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    LocalSocketServerCloseContext context(env, &eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, Socks5SocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    ConnectContext context(env, &eventManager);
    bool ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);

    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type = ProxyType::SOCKS5;
    ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, Socks5SocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    OHOS::NetStack::EventManager eventManager;
    UdpSendContext context(env, &eventManager);
    context.parseOK_ = false;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.parseOK_ = true;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    int data = 1;
    eventManager.data_ = &data;
    shared_ptr<Socks5Instance> socks5Udp = make_shared<Socks5UdpInstance>();
    socks5Udp->options_ = make_shared<Socks5Option>();
    eventManager.proxyData_ = socks5Udp;
    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type = ProxyType::NONE;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.proxyOptions->type = ProxyType::SOCKS5;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));
}

// socks5 proxy text

HWTEST_F(SocketTest, SetSocks5OptionTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    shared_ptr<Socks5Option> opt = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Option(opt);
    EXPECT_FALSE(socks5Inst->options_ == nullptr);
}

HWTEST_F(SocketTest, DoConnectTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = make_shared<Socks5Option>();
    auto ret = socks5Inst->DoConnect(Socks5Command::TCP_CONNECTION);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(socks5Inst->IsConnected());
}

HWTEST_F(SocketTest, RequestMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    vector<Socks5MethodType> methods = {Socks5MethodType::NO_AUTH, Socks5MethodType::PASSWORD};
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = make_shared<Socks5Option>();
    auto ret = socks5Inst->RequestMethod(methods);
    EXPECT_FALSE(ret);
}

HWTEST_F(SocketTest, CreateSocks5MethodByTypeTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    auto ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    EXPECT_FALSE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    EXPECT_FALSE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::GSSAPI);
    EXPECT_TRUE(ret == nullptr);

    ret = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_METHODS);
    EXPECT_TRUE(ret == nullptr);
}

HWTEST_F(SocketTest, ConnectTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5TcpInst = make_shared<Socks5TcpInstance>(socketId);
    socks5TcpInst->options_ = make_shared<Socks5Option>();
    socks5TcpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5TcpInst->Connect());
    socks5TcpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5TcpInst->Connect());
}

HWTEST_F(SocketTest, ConnectTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    socks5UdpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5UdpInst->Connect());
    socks5UdpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5UdpInst->Connect());
}

HWTEST_F(SocketTest, ConnectProxyTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    EXPECT_FALSE(socks5UdpInst->ConnectProxy());
}

HWTEST_F(SocketTest, RemoveHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    void *data = nullptr;
    size_t len = 2;
    int af = AF_INET;
    EXPECT_FALSE(socks5UdpInst->RemoveHeader(data, len, af));
}

HWTEST_F(SocketTest, AddHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv4));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv4);
}

HWTEST_F(SocketTest, AddHeaderTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv6));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv6);
}

HWTEST_F(SocketTest, AddHeaderTest003, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::DOMAIN));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::DOMAIN);
}

HWTEST_F(SocketTest, NoAuthMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    auto noAuthMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    Socks5ProxyAddress proxyAddr;
    EXPECT_TRUE(noAuthMethod->RequestAuth(socketId, "", "", proxyAddr));

    NetAddress dest;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv4;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv6;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::DOMAIN;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);    
}

HWTEST_F(SocketTest, passWdMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    auto passWdMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    Socks5ProxyAddress proxyAddr;
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "", "pass", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "pass", proxyAddr));
}

HWTEST_F(SocketTest, Socks5PkgTest001, TestSize.Level1)
{
    Socks5MethodRequest request;
    Socks5MethodResponse response;

    request.version = 1;
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest002, TestSize.Level1)
{
    Socks5AuthRequest request;
    Socks5AuthResponse response;
    EXPECT_EQ(request.Serialize(), "");
    
    request.version = 1;
    request.username = "user";
    request.password = "pass";
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");

    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest003, TestSize.Level1)
{
    Socks5ProxyRequest request;
    Socks5ProxyResponse response;
    EXPECT_EQ(request.Serialize(), "");

    request.version = 1;
    request.cmd = Socks5Command::TCP_CONNECTION;
    request.reserved = 1;
    request.destPort = 1;
    request.destAddr = "180.76.76.76";
    request.addrType = Socks5AddrType::IPV4;
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    request.destAddr = "www.baidu.com";
    request.addrType = Socks5AddrType::DOMAIN;
    string serialized2 = request.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    request.destAddr = "2400:da00::6666";
    request.addrType = Socks5AddrType::IPV6;
    string serialized3 = request.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest004, TestSize.Level1)
{
    Socks5UdpHeader header;
    EXPECT_EQ(header.Serialize(), "");

    header.reserved = 0;
    header.frag = 0;
    header.dstPort = 1;

    header.destAddr = "180.76.76.76";
    header.addrType = Socks5AddrType::IPV4;
    string serialized = header.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(header.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    header.destAddr = "www.baidu.com";
    header.addrType = Socks5AddrType::DOMAIN;
    string serialized2 = header.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    header.destAddr = "2400:da00::6666";
    header.addrType = Socks5AddrType::IPV6;
    string serialized3 = header.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

} // namespace