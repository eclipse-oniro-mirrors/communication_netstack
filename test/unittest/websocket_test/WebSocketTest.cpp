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

#include "close_context.h"
#include "connect_context.h"
#include "send_context.h"
#include "websocket_async_work.h"
#include "websocket_exec.h"
#include "websocket_module.h"
#ifdef NETSTACK_WEBSOCKETSERVER
#include "server_start_context.h"
#include "server_close_context.h"
#include "server_send_context.h"
#include "server_stop_context.h"
#include "list_all_connections_context.h"
#include "websocket_server_exec.h"
#endif // NETSTACK_WEBSOCKETSERVER

class WebSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::Websocket;

HWTEST_F(WebSocketTest, WebSocketTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    SendContext context(env, eventManager);
    bool ret = WebSocketExec::ExecSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    CloseContext context(env, eventManager);
    bool ret = WebSocketExec::ExecClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest004, TestSize.Level1)
{
    bool ret = WebSocketExec::ExecConnect(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    context.caPath_ = "/etc/ssl/certs/test_ca.crt";
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest006, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    context.caPath_ = "";
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest007, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);

    context.url = "ws://123.123.123.123:9000";
    std::string myProtocol = "my-protocol";
    context.SetProtocol(myProtocol);
    std::string getMyProtocol = context.GetProtocol();
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(getMyProtocol, "my-protocol");
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest008, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);

    context.url = "ws://123.123.123.123:9000";
    context.SetWebsocketProxyType(WebsocketProxyType::USE_SPECIFIED);
    std::string host = "192.168.147.60";
    int32_t port = 8888;
    std::string exclusions = "www.httpbin.org";
    context.SetSpecifiedWebsocketProxy(host, port, exclusions);
    std::string getHost;
    uint32_t getPort;
    std::string getExclusions;
    context.GetSpecifiedWebsocketProxy(getHost, getPort, getExclusions);
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(getHost, "192.168.147.60");
    EXPECT_EQ(getPort, 8888);
    EXPECT_EQ(getExclusions, "www.httpbin.org");
    EXPECT_EQ(ret, false);
}

#ifdef NETSTACK_WEBSOCKETSERVER
HWTEST_F(WebSocketTest, WebSocketTest009, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest010, TestSize.Level1)
{
    bool ret = WebSocketServerExec::ExecServerStart(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest011, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest012, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerSendContext context(env, eventManager);
    bool ret = WebSocketServerExec::ExecServerSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest013, TestSize.Level1)
{
    bool ret = WebSocketServerExec::ExecServerSend(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest014, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerSendContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketServerExec::ExecServerSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest015, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest016, TestSize.Level1)
{
    bool ret = WebSocketServerExec::ExecServerClose(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest017, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest018, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    bool ret = WebSocketServerExec::ExecServerStop(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest019, TestSize.Level1)
{
    bool ret = WebSocketServerExec::ExecServerStop(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest020, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketServerExec::ExecServerStop(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest021, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    bool ret = WebSocketServerExec::ExecListAllConnections(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest022, TestSize.Level1)
{
    bool ret = WebSocketServerExec::ExecListAllConnections(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest023, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketServerExec::ExecListAllConnections(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest024, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest025, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    SendContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketExec::ExecSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest026, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    CloseContext context(env, eventManager);
    context.SetPermissionDenied(true);
    bool ret = WebSocketExec::ExecClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest027, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest028, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerSendContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketServerExec::ExecServerSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest029, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest030, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketServerExec::ExecServerStop(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest031, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketServerExec::ExecListAllConnections(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest032, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest033, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    SendContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketExec::ExecSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest034, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    CloseContext context(env, eventManager);
    context.SetPermissionDenied(false);
    bool ret = WebSocketExec::ExecClose(&context);
    EXPECT_EQ(ret, false);
}
#endif
}   // namespace