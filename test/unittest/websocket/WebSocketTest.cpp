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

#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

#include "close_context.h"
#include "connect_context.h"
#include "napi_utils.h"
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
using namespace OHOS::NetStack;
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
    WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(getMyProtocol, "my-protocol");
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
    WebSocketExec::ExecConnect(&context);
    EXPECT_EQ(getHost, "192.168.147.60");
    EXPECT_EQ(getPort, 8888);
    EXPECT_EQ(getExclusions, "www.httpbin.org");
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

HWTEST_F(WebSocketTest, WebSocketTest035, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest036, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    context.SetServerIP(ip);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest037, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "266.0.0.0";
    context.SetServerIP(ip);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest038, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234";
    context.SetServerIP(ip);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest039, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 444;
    context.SetServerPort(port);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest040, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 65555;
    context.SetServerPort(port);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest041, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 444;
    context.SetServerPort(port);
    uint32_t number = 15;
    context.SetMaxConcurrentClientsNumber(number);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest042, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 444;
    context.SetServerPort(port);
    uint32_t number = 9;
    context.SetMaxConcurrentClientsNumber(number);
    uint32_t cnt = 15;
    context.SetMaxConnectionsForOneClient(cnt);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest043, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 444;
    context.SetServerPort(port);
    uint32_t number = 9;
    context.SetMaxConcurrentClientsNumber(number);
    uint32_t cnt = 9;
    context.SetMaxConnectionsForOneClient(cnt);
    uint32_t cnt2 = 9;
    context.SetMaxConnectionsForOneClient(cnt2);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest044, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    std::string ip = "0.0.0.0";
    context.SetServerIP(ip);
    uint32_t port = 444;
    context.SetServerPort(port);
    uint32_t number = 9;
    context.SetMaxConcurrentClientsNumber(number);
    uint32_t cnt = 9;
    context.SetMaxConnectionsForOneClient(cnt);
    uint32_t cnt2 = 9;
    context.SetMaxConnectionsForOneClient(cnt2);
    bool ret = WebSocketServerExec::ExecServerStart(&context);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest045, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerSendContext context(env, eventManager);
    context.SetPermissionDenied(true);
    uint32_t port = 444;
    std::string ip = "";
    context.SetClientWebSocketConn(port, ip);
    bool ret = WebSocketServerExec::ExecServerSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest046, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerSendContext context(env, eventManager);
    context.SetPermissionDenied(true);
    uint32_t port = 444;
    std::string ip = "0.0.0.0";
    context.SetClientWebSocketConn(port, ip);
    bool ret = WebSocketServerExec::ExecServerSend(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest047, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::shared_ptr<EventManager> sharedManager = nullptr;
    context.SetSharedManager(sharedManager);
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest048, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    context.SetPermissionDenied(true);
    context.connection.clientIP = "";
    context.connection.clientPort = 444;
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest049, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerCloseContext context(env, eventManager);
    context.SetPermissionDenied(true);
    context.connection.clientIP = "0.0.0.0";
    context.connection.clientPort = 444;
    bool ret = WebSocketServerExec::ExecServerClose(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest050, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::shared_ptr<UserData> userData = nullptr;
    eventManager->SetWebSocketUserData(userData);
    context.SetSharedManager(eventManager);
    bool ret = WebSocketServerExec::ExecServerStop(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest051, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    context.SetPermissionDenied(true);
    context.SetSharedManager(nullptr);
    bool ret = WebSocketServerExec::ExecListAllConnections(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest052, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    context.SetPermissionDenied(true);
    std::shared_ptr<UserData> userData = nullptr;
    eventManager->SetWebSocketUserData(userData);
    context.SetSharedManager(eventManager);
    bool ret = WebSocketServerExec::ExecListAllConnections(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest053, TestSize.Level1)
{
    napi_value ret = WebSocketServerExec::ListAllConnectionsCallback(nullptr);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest054, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ListAllConnectionsContext context(env, eventManager);
    std::vector<OHOS::NetStack::Websocket::WebSocketConnection> connections;
    context.SetAllConnections(connections);
    napi_value connectionsArray = NapiUtils::CreateArray(context.GetEnv(), 0);
    napi_value ret = WebSocketServerExec::ListAllConnectionsCallback(&context);
    EXPECT_EQ(ret, connectionsArray);
}

HWTEST_F(WebSocketTest, WebSocketTest055, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    context.SetSharedManager(nullptr);
    napi_value ret = WebSocketServerExec::ServerStopCallback(&context);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest056, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStopContext context(env, eventManager);
    napi_value ret = WebSocketServerExec::ServerStopCallback(&context);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest057, TestSize.Level1)
{
    lws *wsi = nullptr;
    WebSocketServerExec::OnConnect(wsi, nullptr);
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest058, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    WebSocketServerExec::OnConnect(wsi, eventManager.get());
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest059, TestSize.Level1)
{
    lws *wsi = nullptr;
    lws_close_status closeStatus = LWS_CLOSE_STATUS_NOSTATUS;
    std::string closeReason = "The link is down, onError";
    WebSocketServerExec::OnServerClose(wsi, nullptr, closeStatus, closeReason);
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest060, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    lws_close_status closeStatus = LWS_CLOSE_STATUS_NOSTATUS;
    std::string closeReason = "The link is down, onError";
    WebSocketServerExec::OnServerClose(wsi, eventManager.get(), closeStatus, closeReason);
    EXPECT_EQ(closeStatus, LWS_CLOSE_STATUS_NOSTATUS);
}

HWTEST_F(WebSocketTest, WebSocketTest061, TestSize.Level1)
{
    lws *wsi = nullptr;
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = false;
    bool isFinal = false;
    WebSocketServerExec::OnServerMessage(wsi, nullptr, data, length, isBinary, isFinal);
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest062, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = false;
    bool isFinal = false;
    WebSocketServerExec::OnServerMessage(wsi, eventManager.get(), data, length, isBinary, isFinal);
    EXPECT_EQ(isBinary, false);
}

HWTEST_F(WebSocketTest, WebSocketTest063, TestSize.Level1)
{
    int32_t code = 0;
    WebSocketServerExec::OnServerError(nullptr, code);
    EXPECT_EQ(code, 0);
}

HWTEST_F(WebSocketTest, WebSocketTest064, TestSize.Level1)
{
    auto eventManager = std::make_shared<EventManager>();
    int32_t code = 0;
    WebSocketServerExec::OnServerError(eventManager.get(), code);
    EXPECT_EQ(code, 0);
}

HWTEST_F(WebSocketTest, WebSocketTest065, TestSize.Level1)
{
    lws *wsi = nullptr;
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = true;
    bool isFinal = true;
    WebSocketServerExec::HandleServerRcvMessage(wsi, nullptr, data, length, isBinary, isFinal);
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest066, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = true;
    bool isFinal = false;
    WebSocketServerExec::HandleServerRcvMessage(wsi, eventManager.get(), data, length, isBinary, isFinal);
    EXPECT_EQ(isFinal, false);
}

HWTEST_F(WebSocketTest, WebSocketTest067, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = false;
    bool isFinal = true;
    WebSocketServerExec::HandleServerRcvMessage(wsi, eventManager.get(), data, length, isBinary, isFinal);
    EXPECT_EQ(isFinal, true);
}

HWTEST_F(WebSocketTest, WebSocketTest068, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    void *data = nullptr;
    size_t length = 0;
    bool isBinary = false;
    bool isFinal = false;
    WebSocketServerExec::HandleServerRcvMessage(wsi, eventManager.get(), data, length, isBinary, isFinal);
    EXPECT_EQ(isFinal, false);
}

HWTEST_F(WebSocketTest, WebSocketTest069, TestSize.Level1)
{
    lws *wsi = nullptr;
    std::string msgFromManager = "";
    void *dataMsg = nullptr;
    WebSocketServerExec::SetWebsocketMessage(wsi, nullptr, msgFromManager, dataMsg);
    EXPECT_EQ(wsi, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest070, TestSize.Level1)
{
    lws *wsi = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    std::string msgFromManager = "";
    void *dataMsg = nullptr;
    WebSocketServerExec::SetWebsocketMessage(wsi, eventManager.get(), msgFromManager, dataMsg);
    EXPECT_NE(eventManager, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest071, TestSize.Level1)
{
    std::string clientId = "0.0.0.0:444";
    auto ret = WebSocketServerExec::GetClientWsi(clientId);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest072, TestSize.Level1)
{
    std::shared_ptr<UserData> userData = nullptr;
    WebSocketServerExec::CloseAllConnection(userData);
    EXPECT_EQ(userData, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest073, TestSize.Level1)
{
    lws_context *context = nullptr;
    std::shared_ptr<UserData> userData = std::make_shared<UserData>(context);
    WebSocketServerExec::CloseAllConnection(userData);
    EXPECT_NE(userData, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest074, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    lws_context_creation_info info;
    auto ret = WebSocketServerExec::FillServerCertPath(&context, info);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WebSocketTest, WebSocketTest075, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ServerStartContext context(env, eventManager);
    context.certPath_ = "/path/to/your/certificate.pem";
    lws_context_creation_info info;
    auto ret = WebSocketServerExec::FillServerCertPath(&context, info);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WebSocketTest, WebSocketTest076, TestSize.Level1)
{
    std::string id = "0.0.0.0:444";
    lws_context *context = nullptr;
    std::shared_ptr<UserData> userData = std::make_shared<UserData>(context);
    WebSocketConnection conn;
    WebSocketServerExec::AddConnections(id, nullptr, userData, conn);
    EXPECT_NE(userData, nullptr);
}

HWTEST_F(WebSocketTest, WebSocketTest077, TestSize.Level1)
{
    std::string id = "0.0.0.0:444";
    lws_context *context = nullptr;
    std::shared_ptr<UserData> userData = std::make_shared<UserData>(context);
    WebSocketConnection conn;
    userData->SetThreadStop(true);
    WebSocketServerExec::AddConnections(id, nullptr, userData, conn);
    EXPECT_EQ(userData->IsThreadStop(), true);
}

HWTEST_F(WebSocketTest, WebSocketTest078, TestSize.Level1)
{
    std::string id = "0.0.0.0:444";
    lws_context *context = nullptr;
    std::shared_ptr<UserData> userData = std::make_shared<UserData>(context);
    WebSocketConnection conn;
    lws_close_status status = LWS_CLOSE_STATUS_NOSTATUS;
    std::string reason = "The link is down, onError";
    userData->Close(status, reason);
    WebSocketServerExec::AddConnections(id, nullptr, userData, conn);
    EXPECT_EQ(userData->IsClosed(), true);
}

HWTEST_F(WebSocketTest, WebSocketTest079, TestSize.Level1)
{
    std::string id = "0.0.0.0:444";
    lws_context *context = nullptr;
    std::shared_ptr<UserData> userData = std::make_shared<UserData>(context);
    WebSocketServerExec::RemoveConnections(id, *userData);
    EXPECT_NE(userData, nullptr);
}
#endif

HWTEST_F(WebSocketTest, WebSocketTest080, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    context.url = "wss://whale.tooly.top/ws";
    context.skipServerCertVerification_ = true;
    WebSocketExec::ExecConnect(&context);
    context.skipServerCertVerification_ = false;
    EXPECT_FALSE(WebSocketExec::ExecConnect(&context));
}
 
HWTEST_F(WebSocketTest, WebSocketTest081, TestSize.Level1)
{
    napi_env env = nullptr;
    auto eventManager = std::make_shared<EventManager>();
    ConnectContext context(env, eventManager);
    std::string property = "skipServerCertVerification";
    napi_value obj = NapiUtils::CreateObject(context.GetEnv());
    context.ParseSkipServerCertVerify(obj);
    NapiUtils::SetInt32Property(context.GetEnv(), obj, property, 0);
    context.ParseSkipServerCertVerify(obj);
    napi_value obj2 = NapiUtils::CreateObject(context.GetEnv());
    NapiUtils::SetBooleanProperty(context.GetEnv(), obj2, property, true);
    context.ParseSkipServerCertVerify(obj2);
    EXPECT_FALSE(WebSocketExec::ExecConnect(&context));
}
} // namespace