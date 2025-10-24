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

#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>

#include "netstack_log.h"
#include "gtest/gtest.h"
#ifdef GTEST_API_
#define private public
#endif
#include "websocket_client_innerapi.h"
#include "websocket_server_innerapi.h"
#include "libwebsockets.h"

class WebSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
    using namespace testing::ext;
    using namespace OHOS::NetStack::WebSocketClient;
    static constexpr const size_t TEST_MAX_DATA_LENGTH = 5 * 1024 * 1024;
    static constexpr const size_t TEST_LENGTH = 1;

    OpenOptions openOptions;

    CloseOption closeOptions;

    static void OnMessage(WebSocketClient *client, const std::string &data, size_t length) {}

    static void OnOpen(WebSocketClient *client, OpenResult openResult) {}

    static void OnError(WebSocketClient *client, ErrorResult error) {}

    static void OnClose(WebSocketClient *client, CloseResult closeResult) {}

    WebSocketClient *client = new WebSocketClient();

    enum WebsocketErrorCode {
        WEBSOCKET_CONNECT_FAILED = -1,
        WEBSOCKET_ERROR_CODE_BASE = 2302000,
        WEBSOCKET_ERROR_CODE_URL_ERROR = WEBSOCKET_ERROR_CODE_BASE + 1,
        WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 2,
        WEBSOCKET_ERROR_CODE_CONNECT_ALREADY_EXIST = WEBSOCKET_ERROR_CODE_BASE + 3,
        WEBSOCKET_ERROR_CODE_INVALID_NIC = WEBSOCKET_ERROR_CODE_BASE + 4,
        WEBSOCKET_ERROR_CODE_INVALID_PORT = WEBSOCKET_ERROR_CODE_BASE + 5,
        WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST = WEBSOCKET_ERROR_CODE_BASE + 6,
        WEBSOCKET_NOT_ALLOWED_HOST = 2302998,
        WEBSOCKET_UNKNOWN_OTHER_ERROR = 2302999
    };

    HWTEST_F(WebSocketTest, WebSocketRegistcallback001, TestSize.Level1)
    {
        const int32_t websocketConnectionParseurlError = 1004;
        openOptions.headers["Content-Type"] = "application/json";
        openOptions.headers["Authorization"] = "Bearer your_token_here";
        closeOptions.code = LWS_CLOSE_STATUS_NORMAL;
        closeOptions.reason = "";
        client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
        int32_t ret = client->Connect("www.baidu.com", openOptions);
        EXPECT_EQ(ret, websocketConnectionParseurlError);
    }

    HWTEST_F(WebSocketTest, WebSocketConnect002, TestSize.Level1)
    {
        int32_t ret = 0;
        const int32_t websocketConnectionParseurlError = 1004;
        openOptions.headers["Content-Type"] = "application/json";
        openOptions.headers["Authorization"] = "Bearer your_token_here";
        client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
        ret = client->Connect("www.baidu.com", openOptions);
        EXPECT_EQ(ret, websocketConnectionParseurlError);
    }

    HWTEST_F(WebSocketTest, WebSocketSend003, TestSize.Level1)
    {
        int32_t ret;
        const char *data = "Hello, world!";
        int32_t length = std::strlen(data);
        client->Connect("www.baidu.com", openOptions);
        ret = client->Send(const_cast<char *>(data), length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClose004, TestSize.Level1)
    {
        const int32_t websocketNoConnection = 1017;
        CloseOption CloseOptions;
        CloseOptions.code = LWS_CLOSE_STATUS_NORMAL;
        CloseOptions.reason = "";
        int32_t ret = client->Close(CloseOptions);
        EXPECT_EQ(ret, websocketNoConnection);
    }

    HWTEST_F(WebSocketTest, WebSocketDestroy005, TestSize.Level1)
    {
        int32_t ret;
        WebSocketClient *client = new WebSocketClient();
        ret = client->Destroy();
        delete client;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT_CONTEXT);
    }

    HWTEST_F(WebSocketTest, WebSocketBranchTest001, TestSize.Level1)
    {
        const char *data = "test data";
        char *testData = nullptr;
        size_t length = 0;
        int32_t ret = client->Send(testData, length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_SEND_DATA_NULL);

        ret = client->Send(const_cast<char *>(data), TEST_MAX_DATA_LENGTH);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_DATA_LENGTH_EXCEEDS);

        CloseOption options;
        options.reason = "";
        options.code = 0;
        EXPECT_TRUE(client->GetClientContext() != nullptr);
        client->GetClientContext()->openStatus = TEST_LENGTH;
        ret = client->Close(options);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
        client->GetClientContext()->openStatus = 0;
        ret = client->Close(options);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT);
    }

    HWTEST_F(WebSocketTest, WebSocketBranchTest002, TestSize.Level1)
    {
        client->clientContext = nullptr;
        const char *data = "test data";
        size_t length = 0;
        int32_t ret = client->Send(const_cast<char *>(data), length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);

        CloseOption options;
        ret = client->Close(options);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);
    }

    HWTEST_F(WebSocketTest, WebSocketServerRegistcallback001, TestSize.Level1)
    {
        OHOS::NetStack::WebSocketServer::WebSocketServer *server =
            new OHOS::NetStack::WebSocketServer::WebSocketServer();
        auto ret = server->Registcallback(nullptr, nullptr, nullptr, nullptr);
        EXPECT_EQ(ret, 0);
    }

    HWTEST_F(WebSocketTest, WebSocketCloseEx001, TestSize.Level1)
    {
        const int32_t websocketErrorNoClientcontex = 1014;
        CloseOption CloseOptions;
        CloseOptions.code = LWS_CLOSE_STATUS_NORMAL;
        CloseOptions.reason = "";
        int32_t ret = client->CloseEx(CloseOptions);
        EXPECT_EQ(ret, websocketErrorNoClientcontex);
    }

    HWTEST_F(WebSocketTest, WebSocketBranchTest004, TestSize.Level1)
    {
        client->clientContext = nullptr;
        const char *data = "test data";
        size_t length = 0;
        int32_t ret = client->SendEx(const_cast<char *>(data), length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);

        CloseOption options;
        ret = client->CloseEx(options);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);
    }

    HWTEST_F(WebSocketTest, WebSocketConnectEx001, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketClient::WebSocketClient> clients =
            std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        OHOS::NetStack::WebSocketClient::OpenOptions option;
        option.headers["Content-Type"] = "application/json";
        option.headers["Authorization"] = "Bearer your_token_here";
        int32_t ret = clients->ConnectEx("www.baidu.com", option);
        EXPECT_EQ(ret, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_URL_ERROR);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStart001, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerCert serverCert{
            .certPath = "111111111",
            .keyPath = "222222222"};
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "invalidIp",
            .serverPort = 8888,
            .serverCert = serverCert,
            .maxConcurrentClientsNumber = 2,
            .protocol = "aaa",
            .maxConnectionsForOneClient = 1};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, WEBSOCKET_ERROR_CODE_INVALID_NIC);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStart002, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerCert serverCert{
            .certPath = "111111111",
            .keyPath = "222222222"};
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "192.168.1.88",
            .serverPort = -1,
            .serverCert = serverCert,
            .maxConcurrentClientsNumber = 2,
            .protocol = "aaa",
            .maxConnectionsForOneClient = 1};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, WEBSOCKET_ERROR_CODE_INVALID_PORT);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStart003, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerCert serverCert{
            .certPath = "111111111",
            .keyPath = "222222222"};
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "192.168.1.88",
            .serverPort = 8888,
            .serverCert = serverCert,
            .maxConcurrentClientsNumber = 20,
            .protocol = "aaa",
            .maxConnectionsForOneClient = 1};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, WEBSOCKET_UNKNOWN_OTHER_ERROR);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStart004, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerCert serverCert{
            .certPath = "111111111",
            .keyPath = "222222222"};
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "192.168.1.88",
            .serverPort = 8888,
            .serverCert = serverCert,
            .maxConcurrentClientsNumber = 10,
            .protocol = "aaa",
            .maxConnectionsForOneClient = 20};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, WEBSOCKET_UNKNOWN_OTHER_ERROR);
    }

    HWTEST_F(WebSocketTest, WebSocketServerListAllConnections001, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connectionList;
        auto ret = server->ListAllConnections(connectionList);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketServerGetServerContext001, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerContext *serverContext_ = server->GetServerContext();
        EXPECT_NE(serverContext_, nullptr);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStop002, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketServer::WebSocketServer> server =
            std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        auto ret = server->Stop();
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose001, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketServer::WebSocketServer> server =
            std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        std::string strIP = "";
        int32_t iPort = 8888;
        OHOS::NetStack::WebSocketServer::CloseOption option;
        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = strIP,
            .clientPort = static_cast<uint32_t>(iPort),
        };
        auto ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend001, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketServer::WebSocketServer> server =
            std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        server->serverContext_->context_ = nullptr;
        const char *data = "Hello, world!";
        std::string strIP = "";
        int32_t iPort = 8888;
        OHOS::NetStack::WebSocketServer::SocketConnection socketConn{
            .clientIP = strIP,
            .clientPort = static_cast<uint32_t>(iPort),
        };
        auto ret = server->Send(data, std::strlen(data), socketConn);
        EXPECT_EQ(ret, -1);
    }
} // namespace