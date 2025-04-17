/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

class SocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::Socket;

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
} // namespace