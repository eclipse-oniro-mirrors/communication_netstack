/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Socket;
using namespace OHOS::NetStack::Socks5;

HWTEST_F(SocketTest, MulticastTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastMembershipContext context(env, eventManager);
    bool ret = SocketExec::ExecUdpAddMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastMembershipContext context(env, eventManager);
    bool ret = SocketExec::ExecUdpDropMembership(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetTTLContext context(env, eventManager);
    bool ret = SocketExec::ExecSetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastGetTTLContext context(env, eventManager);
    bool ret = SocketExec::ExecGetMulticastTTL(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastSetLoopbackContext context(env, eventManager);
    bool ret = SocketExec::ExecSetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, MulticastTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    MulticastGetLoopbackContext context(env, eventManager);
    bool ret = SocketExec::ExecGetLoopbackMode(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketBindContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketBind(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketConnectContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketSendContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketCloseContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetStateContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetSocketFdContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetSocketFd(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketSetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketSetExtraOptions(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketTest008, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketGetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerListenContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerListen(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerGetStateContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetState(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SocketTest, LocalSocketServerTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerSetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerSetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerGetExtraOptionsContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerGetExtraOptions(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerSendContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerCloseContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketConnectionClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, LocalSocketServerTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    LocalSocketServerEndContext context(env, eventManager);
    bool ret = LocalSocketExec::ExecLocalSocketServerEnd(&context);
    EXPECT_EQ(ret, false);
}

// socks5 proxy test start
HWTEST_F(SocketTest, Socks5SocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    bool ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);

    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type_ = ProxyType::SOCKS5;
    ret = SocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SocketTest, Socks5SocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    UdpSendContext context(env, eventManager);
    context.parseOK_ = false;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.parseOK_ = true;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    int data = 1;
    eventManager->data_ = &data;
    shared_ptr<Socks5Instance> socks5Udp = make_shared<Socks5UdpInstance>();
    socks5Udp->options_ = make_shared<Socks5Option>();
    socks5Udp->SetSocks5Instance(socks5Udp);
    eventManager->proxyData_ = socks5Udp;
    context.proxyOptions = make_shared<ProxyOptions>();
    context.proxyOptions->type_ = ProxyType::NONE;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));

    context.proxyOptions->type_ = ProxyType::SOCKS5;
    EXPECT_FALSE(SocketExec::ExecUdpSend(&context));
    sleep(2);
}

HWTEST_F(SocketTest, SetSocks5OptionTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    shared_ptr<Socks5Option> opt = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Option(opt);
    EXPECT_FALSE(socks5Inst->options_ == nullptr);
}

HWTEST_F(SocketTest, DoConnectTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->options_ = make_shared<Socks5Option>();
    socks5Inst->SetSocks5Instance(socks5Inst);
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
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto ret = socks5Inst->RequestMethod(methods);
    EXPECT_FALSE(ret);
}

HWTEST_F(SocketTest, CreateSocks5MethodByTypeTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
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
    socks5TcpInst->SetSocks5Instance(socks5TcpInst);
    socks5TcpInst->options_ = make_shared<Socks5Option>();
    socks5TcpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5TcpInst->Connect());
    socks5TcpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5TcpInst->Connect());
}

HWTEST_F(SocketTest, ConnectTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    socks5UdpInst->state_ = Socks5AuthState::SUCCESS;
    EXPECT_TRUE(socks5UdpInst->Connect());
    socks5UdpInst->state_ = Socks5AuthState::INIT;
    EXPECT_FALSE(socks5UdpInst->Connect());
}

HWTEST_F(SocketTest, ConnectProxyTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    socks5UdpInst->options_ = make_shared<Socks5Option>();
    EXPECT_FALSE(socks5UdpInst->ConnectProxy());
}

HWTEST_F(SocketTest, RemoveHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    void *data = nullptr;
    size_t len = 2;
    int af = AF_INET;
    EXPECT_FALSE(socks5UdpInst->RemoveHeader(data, len, af));
}

HWTEST_F(SocketTest, AddHeaderTest001, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv4));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv4);
}

HWTEST_F(SocketTest, AddHeaderTest002, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::IPv6));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::IPv6);
}

HWTEST_F(SocketTest, AddHeaderTest003, TestSize.Level1)
{
    auto socks5UdpInst = make_shared<Socks5UdpInstance>();
    socks5UdpInst->SetSocks5Instance(socks5UdpInst);
    NetAddress dest;
    dest.SetFamilyByJsValue(static_cast<uint32_t>(NetAddress::Family::DOMAIN_NAME));
    socks5UdpInst->dest_ = dest;
    socks5UdpInst->AddHeader();
    EXPECT_EQ(socks5UdpInst->dest_.GetFamily(), NetAddress::Family::DOMAIN_NAME);
}

HWTEST_F(SocketTest, NoAuthMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto noAuthMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::NO_AUTH);
    noAuthMethod->socks5Inst_ = socks5Inst;
    Socks5ProxyAddress proxyAddr;
    EXPECT_TRUE(noAuthMethod->RequestAuth(socketId, "", "", proxyAddr));

    NetAddress dest;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv4;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::IPv6;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);

    dest.family_ = NetAddress::Family::DOMAIN_NAME;
    EXPECT_FALSE(noAuthMethod->RequestProxy(socketId, Socks5Command::TCP_CONNECTION, dest, proxyAddr).first);
}

HWTEST_F(SocketTest, passWdMethodTest001, TestSize.Level1)
{
    int32_t socketId = 1;
    auto socks5Inst = make_shared<Socks5TcpInstance>(socketId);
    socks5Inst->SetSocks5Instance(socks5Inst);
    auto passWdMethod = socks5Inst->CreateSocks5MethodByType(Socks5MethodType::PASSWORD);
    passWdMethod->socks5Inst_ = socks5Inst;
    Socks5ProxyAddress proxyAddr;
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "", "pass", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "", proxyAddr));
    EXPECT_FALSE(passWdMethod->RequestAuth(socketId, "user", "pass", proxyAddr));
}

HWTEST_F(SocketTest, Socks5PkgTest001, TestSize.Level1)
{
    Socks5MethodRequest request;
    Socks5MethodResponse response;

    request.version_ = 1;
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
    
    request.version_ = 1;
    request.username_ = "user";
    request.password_ = "pass";
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

    request.version_ = 1;
    request.cmd_ = Socks5Command::TCP_CONNECTION;
    request.reserved_ = 1;
    request.destPort_ = 1;
    request.destAddr_ = "192.168.1.10";
    request.addrType_ = Socks5AddrType::IPV4;
    string serialized = request.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(response.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    request.destAddr_ = "www.xxx.com";
    request.addrType_ = Socks5AddrType::DOMAIN_NAME;
    string serialized2 = request.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    request.destAddr_ = "fe80::100";
    request.addrType_ = Socks5AddrType::IPV6;
    string serialized3 = request.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(response.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

HWTEST_F(SocketTest, Socks5PkgTest004, TestSize.Level1)
{
    Socks5UdpHeader header;
    EXPECT_EQ(header.Serialize(), "");

    header.reserved_ = 0;
    header.frag_ = 0;
    header.dstPort_ = 1;

    header.destAddr_ = "192.168.1.10";
    header.addrType_ = Socks5AddrType::IPV4;
    string serialized = header.Serialize();
    EXPECT_NE(serialized, "");
    EXPECT_FALSE(header.Deserialize((uint8_t*) serialized.c_str(), 1));
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized.c_str(), serialized.size()));

    header.destAddr_ = "www.xxx.com";
    header.addrType_ = Socks5AddrType::DOMAIN_NAME;
    string serialized2 = header.Serialize();
    EXPECT_NE(serialized2, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized2.c_str(), serialized2.size()));

    header.destAddr_ = "fe80::100";
    header.addrType_ = Socks5AddrType::IPV6;
    string serialized3 = header.Serialize();
    EXPECT_NE(serialized3, "");
    EXPECT_TRUE(header.Deserialize((uint8_t*) serialized3.c_str(), serialized3.size()));
}

} // namespace