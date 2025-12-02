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

namespace OHOS::NetStack::WebSocketServer {
    class ServerContext;
    void CloseAllConnection(ServerContext *serverContext);
    void OnServerError(WebSocketServer *server, int32_t code);
    bool GetPeerConnMsg(lws *wsi, std::string &clientId, SocketConnection &conn);
    bool FillServerCertPath(ServerContext *context, lws_context_creation_info &info);
    bool IsOverMaxCntForOneClient(WebSocketServer *server, const std::vector<SocketConnection> &connections,
        const std::string &ip);
    bool IsOverMaxConcurrentClientsCnt(WebSocketServer *server, const std::vector<SocketConnection> &connections,
        const std::string &ip);
    bool IsOverMaxClientConns(WebSocketServer *server, const std::string &ip);
}

namespace OHOS::NetStack::WebSocketClient {
    int LwsCallbackClientAppendHandshakeHeader(
        lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
    int LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
    int LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
    int CreatConnectInfoEx(const std::string url, lws_context *lwsContext, WebSocketClient *client);
    std::vector<std::string> Split(const std::string &str, const std::string &sep, size_t size);
    bool ParseUrlEx(const std::string url, char *prefix, char *address, char *path, int *port);
    int LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
}

namespace {
    using namespace testing::ext;
    using namespace OHOS::NetStack::WebSocketClient;
    static constexpr const size_t TEST_MAX_DATA_LENGTH = 5 * 1024 * 1024;
    static constexpr const size_t TEST_LENGTH = 1;
    static constexpr const int MAX_URI_LENGTH = 1024;

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

    namespace {
        static bool g_onErrorCalled = false;
        static OHOS::NetStack::WebSocketServer::ErrorResult g_lastErrorResult = {};
        static bool g_onOpenCalled = false;
        static OHOS::NetStack::WebSocketClient::OpenResult g_lastOpenResult = {};

        static void TestOnOpenCallback(OHOS::NetStack::WebSocketClient::WebSocketClient *client,
            OHOS::NetStack::WebSocketClient::OpenResult openResult) {
            g_onOpenCalled = true;
            g_lastOpenResult.status = openResult.status;
            g_lastOpenResult.message = openResult.message;
        }

        void TestOnServerErrorCallback(OHOS::NetStack::WebSocketServer::WebSocketServer *server,
            OHOS::NetStack::WebSocketServer::ErrorResult result)
        {
            (void)server;
            g_onErrorCalled = true;
            g_lastErrorResult = result;
        }

        static bool g_onConnectCalled = false;
        static void TestOnConnectCallback(OHOS::NetStack::WebSocketServer::WebSocketServer *server,
            OHOS::NetStack::WebSocketServer::SocketConnection connection) {
            (void)server;
            (void)connection;
            g_onConnectCalled = true;
        }
    } // namespace

    HWTEST_F(WebSocketTest, WebSocketRegistcallback001, TestSize.Level1)
    {
        openOptions.headers["Content-Type"] = "application/json";
        openOptions.headers["Authorization"] = "Bearer your_token_here";
        closeOptions.code = LWS_CLOSE_STATUS_NORMAL;
        closeOptions.reason = "";
        client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
        int32_t ret = client->Connect("www.baidu.com", openOptions);
        EXPECT_TRUE(ret == WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL ||
                    ret == WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketConnect002, TestSize.Level1)
    {
        int32_t ret = 0;
        openOptions.headers["Content-Type"] = "application/json";
        openOptions.headers["Authorization"] = "Bearer your_token_here";
        client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
        ret = client->Connect("www.baidu.com", openOptions);
        EXPECT_TRUE(ret == WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL ||
                    ret == WebSocketErrorCode::WEBSOCKET_NONE_ERR);
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
        OHOS::NetStack::WebSocketServer::ServerContext *serverContext = server->GetServerContext();
        EXPECT_NE(serverContext, nullptr);
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

    HWTEST_F(WebSocketTest, WebSocketClientDataManipulation006, TestSize.Level1)
    {
        auto localClient = std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        localClient->AppendData(reinterpret_cast<void *>(const_cast<char *>("abc")), 3);
        EXPECT_STREQ(localClient->GetData().c_str(), "abc");
        localClient->ClearData();
        EXPECT_TRUE(localClient->GetData().empty());
    }

    HWTEST_F(WebSocketTest, WebSocketClientRunLwsThread007, TestSize.Level1)
    {
        auto clients = std::make_shared<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        clients->RunLwsThread();
        EXPECT_NE(clients->GetClientContext(), nullptr);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStartFileNotExist008, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerCert serverCert{
            .certPath = "nonexistent_cert.pem",
            .keyPath = "nonexistent_key.pem"};
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "127.0.0.1",
            .serverPort = 8888,
            .serverCert = serverCert,
            .maxConcurrentClientsNumber = 2,
            .protocol = "aaa",
            .maxConnectionsForOneClient = 1};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
    }

    HWTEST_F(WebSocketTest, WebSocketServerDestroy008, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        int ret = server->Destroy();
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientRegistcallback010, TestSize.Level1)
    {
        auto localClient = std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        int ret = localClient->Registcallback(nullptr, nullptr, nullptr, nullptr);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendZeroLength001, TestSize.Level1)
    {
        const char *data = "";
        size_t length = 0;
        int32_t ret = client->Send(const_cast<char *>(data), length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseNoContext002, TestSize.Level1)
    {
        client->clientContext = nullptr;
        CloseOption options;
        int32_t ret = client->Close(options);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExZeroLength001, TestSize.Level1)
    {
        const char *data = "";
        size_t length = 0;
        int32_t ret = client->SendEx(const_cast<char *>(data), length);
        EXPECT_TRUE(ret == WebSocketErrorCode::WEBSOCKET_NONE_ERR ||
                    ret != 0);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSendNullData002, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketServer::WebSocketServer> server =
            std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        server->serverContext_->context_ = nullptr;
        const char *data = nullptr;
        std::string strIP = "0.0.0.0";
        int32_t iPort = 0;
        OHOS::NetStack::WebSocketServer::SocketConnection socketConn{
            .clientIP = strIP,
            .clientPort = static_cast<uint32_t>(iPort),
        };
        int32_t ret = server->Send(data, 0, socketConn);
        EXPECT_TRUE(ret != 0);
    }

    HWTEST_F(WebSocketTest, WebSocketServerCloseInvalidIP002, TestSize.Level1)
    {
        std::unique_ptr<OHOS::NetStack::WebSocketServer::WebSocketServer> server =
            std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        std::string strIP = "255.255.255.255";
        int32_t iPort = 65536;
        OHOS::NetStack::WebSocketServer::CloseOption option;
        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = strIP,
            .clientPort = static_cast<uint32_t>(iPort),
        };
        int32_t ret = server->Close(connection, option);
        EXPECT_TRUE(ret != 0);
    }

    HWTEST_F(WebSocketTest, WebSocketClientConnectExFileNotExist011, TestSize.Level1)
    {
        auto clients = std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        clients->GetClientContext()->caPath = "nonexistent_cert.pem";
        OHOS::NetStack::WebSocketClient::OpenOptions option;
        int32_t ret = clients->ConnectEx("wss://example.com", option);
        EXPECT_EQ(ret, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendBinary012, TestSize.Level1)
    {
        auto clients = std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        clients->GetClientContext()->SetContext(reinterpret_cast<lws_context *>(0x1));

        const char binaryData[] = {'a', '\0', 'b', '\0'};
        size_t length = 3;
        int32_t ret = clients->Send(const_cast<char *>(binaryData), length);
        EXPECT_EQ(ret, WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExNoContext013, TestSize.Level1)
    {
        WebSocketClient *tmp = new WebSocketClient();
        const char *data = "abc";
        size_t length = std::strlen(data);
        int32_t ret = tmp->SendEx(const_cast<char *>(data), length);
        delete tmp;
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientConnectExAlreadyExist014, TestSize.Level1)
    {
        auto clients = std::make_unique<OHOS::NetStack::WebSocketClient::WebSocketClient>();
        clients->GetClientContext()->SetContext(reinterpret_cast<lws_context *>(0x1));
        OHOS::NetStack::WebSocketClient::OpenOptions option;
        int32_t ret = clients->ConnectEx("wss://example.com", option);
        EXPECT_EQ(ret, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_CONNECT_ALREADY_EXIST);
    }

    HWTEST_F(WebSocketTest, WebSocketServerCloseNotExist003, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "127.0.0.1",
            .clientPort = static_cast<uint32_t>(12345),
        };
        OHOS::NetStack::WebSocketServer::CloseOption option;
        int32_t ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStop_ThreadStop_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *raw = std::malloc(1024);
        ASSERT_NE(raw, nullptr);
        std::fill_n(static_cast<char*>(raw), 1024, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(raw);
        server->GetServerContext()->SetContext(tmpCtx);
        server->GetServerContext()->SetThreadStop(true);

        int ret = server->Stop();
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->SetContext(nullptr);
        std::free(raw);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStop_PermissionDenied_AttemptReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *raw = std::malloc(1024);
        ASSERT_NE(raw, nullptr);
        std::fill_n(static_cast<char*>(raw), 1024, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(raw);
        server->GetServerContext()->SetContext(tmpCtx);
        server->GetServerContext()->SetPermissionDenied(true);

        int ret = server->Stop();
        EXPECT_TRUE(ret == WebSocketErrorCode::WEBSOCKET_NONE_ERR);

        server->GetServerContext()->SetContext(nullptr);
        std::free(raw);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStop_NormalContext_ReturnsZeroOrMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *raw = std::malloc(1024);
        ASSERT_NE(raw, nullptr);
        std::fill_n(static_cast<char*>(raw), 1024, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(raw);
        server->GetServerContext()->SetContext(tmpCtx);
        server->GetServerContext()->SetThreadStop(false);

        int ret = server->Stop();
        EXPECT_TRUE(ret == WebSocketErrorCode::WEBSOCKET_NONE_ERR);
        server->GetServerContext()->SetContext(nullptr);
        std::free(raw);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose_EmptyClientIP_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(256);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 256, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "",
            .clientPort = static_cast<uint32_t>(12345),
        };
        OHOS::NetStack::WebSocketServer::CloseOption option;
        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose_ClientNotFound_ReturnsConnectionNotExist, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();

        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "1.2.3.4",
            .clientPort = static_cast<uint32_t>(12345),
        };
        OHOS::NetStack::WebSocketServer::CloseOption option;

        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose_ClientUserDataNull_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);
        const size_t wsiPad = 64 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "10.0.0.1",
            .clientPort = static_cast<uint32_t>(6000),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        OHOS::NetStack::WebSocketServer::CloseOption option;
        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose_ClientThreadStoppedOrClosed_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 64 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
        clientUserData->SetThreadStop(true);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "192.168.0.2",
            .clientPort = static_cast<uint32_t>(9000),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);

        server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        OHOS::NetStack::WebSocketServer::CloseOption option;
        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->RemoveClientUserData(tmpWsi);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerCloseTest01, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();

        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 64 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
        clientUserData->SetThreadStop(false);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "127.0.0.1",
            .clientPort = static_cast<uint32_t>(8088),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);

        server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        OHOS::NetStack::WebSocketServer::CloseOption option;
        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->RemoveClientUserData(tmpWsi);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend_ClientNotFound_ReturnsConnectionNotExist, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "9.9.9.9",
            .clientPort = static_cast<uint32_t>(1234),
        };
        const char *data = "hello";
        int ret = server->Send(data, std::strlen(data), connection);
        EXPECT_EQ(ret, WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend_ClientUserDataNull_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 8 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "10.10.10.10",
            .clientPort = static_cast<uint32_t>(5678),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);

        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        const char *data = "payload";
        int ret = server->Send(data, std::strlen(data), connection);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend_ClientClosedOrThreadStop_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 8 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
        clientUserData->SetThreadStop(true);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "172.16.0.1",
            .clientPort = static_cast<uint32_t>(9001),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);

        lws_set_wsi_user(tmpWsi, clientUserData.get());
        server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        const char *data = "x";
        int ret = server->Send(data, std::strlen(data), connection);
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->RemoveClientUserData(tmpWsi);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend_SuccessReturnsZero, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 8 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
        clientUserData->SetThreadStop(false);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "127.0.0.2",
            .clientPort = static_cast<uint32_t>(9002),
        };
        std::string clientId = connection.clientIP + ":" + std::to_string(connection.clientPort);

        lws_set_wsi_user(tmpWsi, clientUserData.get());
        server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, connection);

        const char *payload = "hello-server";
        int ret = server->Send(payload, std::strlen(payload), connection);
        EXPECT_EQ(ret, 0);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->RemoveClientUserData(tmpWsi);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerClose_ClientIPBranch_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(256);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 256, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "",
            .clientPort = static_cast<uint32_t>(1234),
        };
        OHOS::NetStack::WebSocketServer::CloseOption option;
        int ret = server->Close(connection, option);
        EXPECT_EQ(ret, -1);

        OHOS::NetStack::WebSocketServer::SocketConnection connection2{
            .clientIP = "1.2.3.4",
            .clientPort = static_cast<uint32_t>(4321),
        };
        int ret2 = server->Close(connection2, option);
        EXPECT_EQ(ret2, WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerSend_ClientIPBranch_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(256);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 256, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const char *data = "x";
        OHOS::NetStack::WebSocketServer::SocketConnection connection{
            .clientIP = "",
            .clientPort = static_cast<uint32_t>(1111),
        };
        int ret = server->Send(data, static_cast<int>(strlen(data)), connection);
        EXPECT_EQ(ret, -1);

        OHOS::NetStack::WebSocketServer::SocketConnection connection2{
            .clientIP = "9.9.9.9",
            .clientPort = static_cast<uint32_t>(2222),
        };
        int ret2 = server->Send(data, static_cast<int>(strlen(data)), connection2);
        EXPECT_EQ(ret2, WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerStop_ServerClosed_ReturnsMinus1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();

        void *raw = std::malloc(1024);
        ASSERT_NE(raw, nullptr);
        std::fill_n(static_cast<char*>(raw), 1024, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(raw);
        server->GetServerContext()->SetContext(tmpCtx);

        server->GetServerContext()->Close(LWS_CLOSE_STATUS_GOINGAWAY, "");
        server->GetServerContext()->SetThreadStop(false);

        int ret = server->Stop();
        EXPECT_EQ(ret, -1);

        server->GetServerContext()->Close(LWS_CLOSE_STATUS_GOINGAWAY, "");
        server->GetServerContext()->SetThreadStop(true);

        int ret2 = server->Stop();
        EXPECT_EQ(ret2, -1);

        server->GetServerContext()->SetContext(nullptr);
        std::free(raw);
    }

    HWTEST_F(WebSocketTest, CloseAllConnection_Empty_NotThreadStop_SetsThreadStop, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        auto ctx = server->GetServerContext();
        EXPECT_NO_FATAL_FAILURE(OHOS::NetStack::WebSocketServer::CloseAllConnection(nullptr));

        ctx->SetThreadStop(false);
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> conns;
        ctx->ListAllConnections(conns);
        EXPECT_TRUE(conns.empty());

        OHOS::NetStack::WebSocketServer::CloseAllConnection(ctx);
        EXPECT_TRUE(ctx->IsThreadStop());

        ctx->SetThreadStop(false);
    }

    HWTEST_F(WebSocketTest, CloseAllConnection_Empty_AlreadyThreadStop_NoChange, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        auto ctx = server->GetServerContext();
        ctx->SetThreadStop(true);

        OHOS::NetStack::WebSocketServer::CloseAllConnection(ctx);
        EXPECT_TRUE(ctx->IsThreadStop());

        ctx->SetThreadStop(false);
    }

    HWTEST_F(WebSocketTest, CloseAllConnection_WithNullWsi_Continues, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        OHOS::NetStack::WebSocketServer::SocketConnection conn{
            .clientIP = "11.11.11.11",
            .clientPort = static_cast<uint32_t>(1111),
        };
        std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
        server->GetServerContext()->AddConnections(clientId, nullptr, conn);

        EXPECT_NO_FATAL_FAILURE(OHOS::NetStack::WebSocketServer::CloseAllConnection(server->GetServerContext()));
        auto wsiRet = server->GetServerContext()->GetClientWsi(clientId);
        EXPECT_EQ(wsiRet, nullptr);

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, CloseAllConnection_WithUserData_ClosesAndTriggersWritable, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(512);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        const size_t wsiPad = 8 * 1024;
        void *rawWsi = std::malloc(wsiPad);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), wsiPad, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);

        auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
        clientUserData->SetThreadStop(false);

        lws_set_wsi_user(tmpWsi, clientUserData.get());
        OHOS::NetStack::WebSocketServer::SocketConnection conn{
            .clientIP = "12.12.12.12",
            .clientPort = static_cast<uint32_t>(1212),
        };
        std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);

        server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
        server->GetServerContext()->AddConnections(clientId, tmpWsi, conn);

        OHOS::NetStack::WebSocketServer::CloseAllConnection(server->GetServerContext());
        EXPECT_TRUE(clientUserData->IsClosed());

        server->GetServerContext()->RemoveConnections(clientId);
        server->GetServerContext()->RemoveClientUserData(tmpWsi);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawWsi);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, OnServerError_NoCallback_NoCrash, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        EXPECT_NO_FATAL_FAILURE(OHOS::NetStack::WebSocketServer::OnServerError(nullptr, -1));

        void *rawCtx = std::malloc(128);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 128, 0);
        server->GetServerContext()->SetContext(reinterpret_cast<lws_context *>(rawCtx));
        EXPECT_NO_FATAL_FAILURE(OHOS::NetStack::WebSocketServer::OnServerError(server.get(), -1));

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, OnServerError_CallbackInvoked_WithMappedMessage, TestSize.Level1)
    {
        g_onErrorCalled = false;
        g_lastErrorResult = {};
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(128);
        ASSERT_NE(rawCtx, nullptr);

        std::fill_n(static_cast<char*>(rawCtx), 128, 0);
        server->GetServerContext()->SetContext(reinterpret_cast<lws_context *>(rawCtx));

        server->Registcallback(TestOnServerErrorCallback, nullptr, nullptr, nullptr);

        OHOS::NetStack::WebSocketServer::OnServerError(server.get(), -1);

        EXPECT_TRUE(g_onErrorCalled);
        EXPECT_EQ(g_lastErrorResult.errorCode, -1);
        EXPECT_TRUE(g_lastErrorResult.errorMessage != nullptr &&
                    std::strlen(g_lastErrorResult.errorMessage) > 0);
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, OnServerError_CallbackInvoked_UnknownCode, TestSize.Level1)
    {
        g_onErrorCalled = false;
        g_lastErrorResult = {};

        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        void *rawCtx = std::malloc(128);
        ASSERT_NE(rawCtx, nullptr);

        std::fill_n(static_cast<char*>(rawCtx), 128, 0);
        server->GetServerContext()->SetContext(reinterpret_cast<lws_context *>(rawCtx));

        server->Registcallback(TestOnServerErrorCallback, nullptr, nullptr, nullptr);

        const int unknownCode = 1234567;
        OHOS::NetStack::WebSocketServer::OnServerError(server.get(), unknownCode);

        EXPECT_TRUE(g_onErrorCalled);
        EXPECT_EQ(g_lastErrorResult.errorCode, unknownCode);
        EXPECT_TRUE(g_lastErrorResult.errorMessage == nullptr ||
                    std::strlen(g_lastErrorResult.errorMessage) == 0);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketClientConnectExSetCaPath015, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        client->GetClientContext()->isAtomicService = true;
        std::string userCertPath = "nonexistent_cert.pem";
        client->GetClientContext()->SetUserCertPath(userCertPath);
        OpenOptions option;
        client->ConnectEx("wss://example.com", option);
        EXPECT_STREQ(client->GetClientContext()->caPath.c_str(), userCertPath.c_str());
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExDataIsNull001, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        size_t length = 1;
        auto ret = client->SendEx(nullptr, length);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_SEND_DATA_NULL);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExExceedMaxLength001, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        char data[] = "hello";
        size_t maxDataLength = 5 * 1024 * 1024;
        auto ret = client->SendEx(data, maxDataLength);
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_DATA_LENGTH_EXCEEDS);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExClientContextIsNull001, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        char data[] = "hello";
        size_t dataLength = strlen(data);
        auto tmp = client->GetClientContext();
        client->clientContext = nullptr;
        auto ret = client->SendEx(data, dataLength);
        client->clientContext = tmp;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);
    }

    HWTEST_F(WebSocketTest, WebSocketClientSendExWriteText001, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        client->GetClientContext()->SetContext(tmpCtx);
        char data[] = "hello";
        size_t dataLength = strlen(data);

        auto ret = client->SendEx(data, dataLength);
        client->GetClientContext()->SetContext(nullptr);
        std::free(rawCtx);
        rawCtx = nullptr;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
        EXPECT_FALSE(client->GetClientContext()->IsEmpty());
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseExContextIsNull001, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        CloseOption Option;
        auto ret = client->CloseEx(Option);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseExRequestClose001, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        client->GetClientContext()->SetContext(tmpCtx);

        CloseOption Option;
        Option.code = LWS_CLOSE_STATUS_NOSTATUS;
        Option.reason = "request finish";
        auto ret = client->CloseEx(Option);
        client->GetClientContext()->SetContext(nullptr);
        std::free(rawCtx);
        rawCtx = nullptr;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseExRequestClose002, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        client->GetClientContext()->SetContext(tmpCtx);

        CloseOption Option;
        Option.code = LWS_CLOSE_STATUS_NOSTATUS;
        Option.reason = nullptr;
        auto ret = client->CloseEx(Option);
        client->GetClientContext()->SetContext(nullptr);
        std::free(rawCtx);
        rawCtx = nullptr;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseExRequestClose003, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        client->GetClientContext()->SetContext(tmpCtx);

        CloseOption Option;
        Option.code = LWS_CLOSE_STATUS_NORMAL;
        Option.reason = nullptr;
        auto ret = client->CloseEx(Option);
        client->GetClientContext()->SetContext(nullptr);
        std::free(rawCtx);
        rawCtx = nullptr;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientCloseExRequestClose004, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 512, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        client->GetClientContext()->SetContext(tmpCtx);

        CloseOption Option;
        Option.code = LWS_CLOSE_STATUS_NORMAL;
        Option.reason = "request finish";;
        auto ret = client->CloseEx(Option);
        client->GetClientContext()->SetContext(nullptr);
        std::free(rawCtx);
        rawCtx = nullptr;
        EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_NONE_ERR);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackClientAppendHandshakeHeader002, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        size_t length = 0;
        auto ret = LwsCallbackClientAppendHandshakeHeader(nullptr, reason, (void*)client.get(), nullptr, length);
        EXPECT_EQ(ret, -1);
        unsigned char *payload = nullptr;
        unsigned char **payloadPtr = &payload;
        ret = LwsCallbackClientAppendHandshakeHeader(nullptr, reason, (void*)client.get(), payloadPtr, length);
        EXPECT_EQ(ret, -1);
        unsigned char value[] = "test";
        *payloadPtr = value;
        ret = LwsCallbackClientAppendHandshakeHeader(nullptr, reason, (void*)client.get(), payloadPtr, length);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackClientAppendHandshakeHeader003, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        auto tmp = client->GetClientContext();
        client->clientContext = nullptr;
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        size_t length = 0;
        auto ret = LwsCallbackClientAppendHandshakeHeader(nullptr, reason, (void*)client.get(), nullptr, length);
        client->clientContext = tmp;
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackWsPeerInitiatedClose001, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        size_t length = sizeof(uint16_t) * 2;
        char value[] = "test";
        auto ret = LwsCallbackWsPeerInitiatedClose(nullptr, reason, (void*)client.get(), value, length);
        EXPECT_NE(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackWsPeerInitiatedClose002, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        auto tmp = client->GetClientContext();
        client->clientContext = nullptr;
        size_t length = 0;
        auto ret = LwsCallbackWsPeerInitiatedClose(nullptr, reason, (void*)client.get(), nullptr, length);
        client->clientContext = tmp;
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackWsPeerInitiatedClose003, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        char value[] = "test";
        const size_t unvaluableLength = 0;
        const size_t valuableLength = sizeof(uint16_t) * 2;
        auto ret = LwsCallbackWsPeerInitiatedClose(nullptr, reason, (void*)client.get(), nullptr, unvaluableLength);
        EXPECT_NE(ret, -1);

        ret = LwsCallbackWsPeerInitiatedClose(nullptr, reason, (void*)client.get(), nullptr, valuableLength);
        EXPECT_NE(ret, -1);

        ret = LwsCallbackWsPeerInitiatedClose(nullptr, reason, (void*)client.get(), value, unvaluableLength);
        EXPECT_NE(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackClientClosed001, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        client->Registcallback(nullptr, nullptr, nullptr, [](WebSocketClient *client, CloseResult closeResult) {});
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;

        char value[] = "test";
        size_t length = strlen(value);
        auto ret = LwsCallbackClientClosed(nullptr, reason, client.get(), value, length);
        EXPECT_NE(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackClientClosed002, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        std::string closeReason = "connect refused";
        client->GetClientContext()->Close(LWS_CLOSE_STATUS_NORMAL, closeReason);

        char value[] = "test";
        size_t length = strlen(value);
        auto ret = LwsCallbackClientClosed(nullptr, reason, client.get(), value, length);
        EXPECT_NE(ret, -1);
    }

    HWTEST_F(WebSocketTest, WebSocketClientLwsCallbackClientClosed003, TestSize.Level2)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        auto tmp = client->GetClientContext();
        client->clientContext = nullptr;

        lws_callback_reasons reason = LWS_CALLBACK_ESTABLISHED;
        char value[] = "test";
        size_t length = strlen(value);
        auto ret = LwsCallbackClientClosed(nullptr, reason, client.get(), value, length);
        client->clientContext = tmp;
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, GetPeerConnMsgFunctionBranchTest, TestSize.Level1)
    {
        void *rawWsi = std::malloc(1024);
        ASSERT_NE(rawWsi, nullptr);
        std::fill_n(static_cast<char*>(rawWsi), 1024, 0);
        lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);
        
        std::string clientId;
        OHOS::NetStack::WebSocketServer::SocketConnection conn;
        auto ret = OHOS::NetStack::WebSocketServer::GetPeerConnMsg(tmpWsi, clientId, conn);
        EXPECT_EQ(ret, false);
        
        std::free(rawWsi);
    }

    HWTEST_F(WebSocketTest, WebSocketServer_Start_Test, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        OHOS::NetStack::WebSocketServer::ServerConfig severCfg{
            .serverIP = "127.0.0.1",
            .serverPort = 8888,
            .serverCert = {},
            .maxConcurrentClientsNumber = 2,
            .protocol = "",
            .maxConnectionsForOneClient = 1};

        auto ret = server->Start(severCfg);
        EXPECT_EQ(ret, 0);
    }
    
    HWTEST_F(WebSocketTest, WebSocketServerConnectCallbackTest, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server != nullptr);
        
        g_onConnectCalled = false;
        server->Registcallback(nullptr, TestOnConnectCallback, nullptr, nullptr);
        
        OHOS::NetStack::WebSocketServer::SocketConnection conn = {
            .clientIP = "127.0.0.1",
            .clientPort = static_cast<uint32_t>(12345),
        };
        
        if (server->onConnectCallback_ != nullptr) {
            server->onConnectCallback_(server.get(), conn);
        }
        
        EXPECT_TRUE(g_onConnectCalled);
    }

    HWTEST_F(WebSocketTest, WebSocketServerListAllConnections002, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server != nullptr);

        void *rawCtx = std::malloc(128);
        ASSERT_NE(rawCtx, nullptr);
        std::fill_n(static_cast<char*>(rawCtx), 128, 0);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);

        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connectionList;
        auto ret = server->ListAllConnections(connectionList);
        EXPECT_EQ(ret, 0);

        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }

    HWTEST_F(WebSocketTest, WebSocketServerFillServerCertPathTest001, TestSize.Level1)
    {
        auto *serverContext = new OHOS::NetStack::WebSocketServer::ServerContext();
        ASSERT_TRUE(serverContext != nullptr);
        lws_context_creation_info info;
        OHOS::NetStack::WebSocketServer::ServerCert value {
            .certPath = "./",
            .keyPath = "./",
        };
        serverContext->startServerConfig_.serverCert = value;
        auto res = OHOS::NetStack::WebSocketServer::FillServerCertPath(serverContext, info);
        delete serverContext;
        serverContext = nullptr;
        EXPECT_TRUE(res);
    }

    HWTEST_F(WebSocketTest, WebSocketServerFillServerCertPathTest002, TestSize.Level2)
    {
        auto *serverContext = new OHOS::NetStack::WebSocketServer::ServerContext();
        ASSERT_TRUE(serverContext != nullptr);
        lws_context_creation_info info;
        OHOS::NetStack::WebSocketServer::ServerCert value {
            .certPath = "nonexistent_cert.pem",
            .keyPath = "nonexistent_cert.pem",
        };
        serverContext->startServerConfig_.serverCert = value;
        auto res = OHOS::NetStack::WebSocketServer::FillServerCertPath(serverContext, info);
        EXPECT_FALSE(res);

        value.certPath = "./";
        value.keyPath = "nonexistent_cert.pem";
        res = OHOS::NetStack::WebSocketServer::FillServerCertPath(serverContext, info);
        EXPECT_FALSE(res);

        value.certPath = "nonexistent_cert.pem";
        value.keyPath = "./";
        res = OHOS::NetStack::WebSocketServer::FillServerCertPath(serverContext, info);
        delete serverContext;
        serverContext = nullptr;
        EXPECT_FALSE(res);
    }

    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxConcurrentClientsCntTest, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server != nullptr);
        ASSERT_TRUE(server->GetServerContext() != nullptr);
        
        server->GetServerContext()->startServerConfig_.maxConcurrentClientsNumber = 3;
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connections;
        
        OHOS::NetStack::WebSocketServer::SocketConnection conn1{"192.168.1.1", 1001};
        OHOS::NetStack::WebSocketServer::SocketConnection conn2{"192.168.1.2", 1002};
        connections.push_back(conn1);
        connections.push_back(conn2);
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxConcurrentClientsCnt(
            server.get(), connections, "192.168.1.1");
        EXPECT_FALSE(result);
        
        OHOS::NetStack::WebSocketServer::SocketConnection conn3{"192.168.1.3", 1003};
        connections.push_back(conn3);
        
        result = OHOS::NetStack::WebSocketServer::IsOverMaxConcurrentClientsCnt(
            server.get(), connections, "192.168.1.1");
        EXPECT_FALSE(result);
        
        connections.clear();
        
        connections.push_back(conn1);
        connections.push_back(conn2);
        connections.push_back(conn3);
        
        result = OHOS::NetStack::WebSocketServer::IsOverMaxConcurrentClientsCnt(
            server.get(), connections, "192.168.1.4");
        EXPECT_TRUE(result);
        
        connections.clear();
        connections.push_back(conn1);
        connections.push_back(conn2);
        
        result = OHOS::NetStack::WebSocketServer::IsOverMaxConcurrentClientsCnt(
            server.get(), connections, "192.168.1.3");
        EXPECT_FALSE(result);
    }

    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxCntForOneClientTest, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server != nullptr);
        
        server->GetServerContext()->startServerConfig_.maxConnectionsForOneClient = 3;
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connections;
        std::string testIp = "192.168.1.1";
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxCntForOneClient(
            server.get(), connections, testIp);
        EXPECT_FALSE(result);
        
        connections.push_back({testIp, 8080});
        connections.push_back({testIp, 8081});
        result = OHOS::NetStack::WebSocketServer::IsOverMaxCntForOneClient(
            server.get(), connections, testIp);
        EXPECT_FALSE(result);
        
        connections.push_back({testIp, 8082});
        result = OHOS::NetStack::WebSocketServer::IsOverMaxCntForOneClient(
            server.get(), connections, testIp);
        EXPECT_TRUE(result);
        
        std::string differentIp = "192.168.1.2";
        
        result = OHOS::NetStack::WebSocketServer::IsOverMaxCntForOneClient(
            server.get(), connections, differentIp);
        EXPECT_FALSE(result);
    }

    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxClientConnsTest1, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server != nullptr);
        ASSERT_TRUE(server->GetServerContext() != nullptr);
        
        OHOS::NetStack::WebSocketServer::ServerConfig config;
        config.maxConcurrentClientsNumber = 3;
        config.maxConnectionsForOneClient = 3;
        server->GetServerContext()->startServerConfig_ = config;
        
        std::string testIp = "192.168.1.1";
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxClientConns(server.get(), testIp);
        EXPECT_FALSE(result);
    }
    
    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxClientConnsTest2, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server->GetServerContext() != nullptr);
        
        OHOS::NetStack::WebSocketServer::ServerConfig config;
        config.maxConcurrentClientsNumber = 3;
        config.maxConnectionsForOneClient = 3;
        server->GetServerContext()->startServerConfig_ = config;
        
        std::string testIp = "192.168.1.1";
        std::string differentIp1 = "192.168.1.2";
        std::string differentIp2 = "192.168.1.3";
        std::string differentIp3 = "192.168.1.4";

        void *rawCtx = std::malloc(512);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);
        
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connections;
        connections.push_back({differentIp1, 8081});
        connections.push_back({differentIp2, 8082});
        connections.push_back({differentIp3, 8083});
        
        std::vector<std::string> clientIds;
        std::vector<void *> wsiPtrs;
        
        for (auto &conn : connections) {
            std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
            clientIds.push_back(clientId);
            void *rawWsi = std::malloc(128);
            wsiPtrs.push_back(rawWsi);
            lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);
            auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
            server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
            server->GetServerContext()->AddConnections(clientId, tmpWsi, conn);
        }
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxClientConns(server.get(), testIp);
        EXPECT_TRUE(result);

        for (size_t i = 0; i < clientIds.size(); ++i) {
            server->GetServerContext()->RemoveClientUserData(wsiPtrs[i]);
            server->GetServerContext()->RemoveConnections(clientIds[i]);
            std::free(wsiPtrs[i]);
        }
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }
    
    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxClientConnsTest3, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server->GetServerContext() != nullptr);
        
        OHOS::NetStack::WebSocketServer::ServerConfig config;
        config.maxConcurrentClientsNumber = 3;
        config.maxConnectionsForOneClient = 3;
        server->GetServerContext()->startServerConfig_ = config;
        
        std::string testIp = "192.168.1.1";
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);
        
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connections;
        connections.push_back({testIp, 8081});
        connections.push_back({testIp, 8082});
        connections.push_back({testIp, 8083});
        
        std::vector<std::string> clientIds;
        std::vector<void *> wsiPtrs;
        
        for (auto &conn : connections) {
            std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
            clientIds.push_back(clientId);
            
            void *rawWsi = std::malloc(128);
            ASSERT_TRUE(rawWsi != nullptr);
            wsiPtrs.push_back(rawWsi);
            
            lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);
            auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
            server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
            server->GetServerContext()->AddConnections(clientId, tmpWsi, conn);
        }
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxClientConns(server.get(), testIp);
        EXPECT_TRUE(result);
        
        for (size_t i = 0; i < clientIds.size(); ++i) {
            server->GetServerContext()->RemoveClientUserData(wsiPtrs[i]);
            server->GetServerContext()->RemoveConnections(clientIds[i]);
            std::free(wsiPtrs[i]);
        }
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }
    
    HWTEST_F(WebSocketTest, WebSocketServerIsOverMaxClientConnsTest4, TestSize.Level1)
    {
        auto server = std::make_unique<OHOS::NetStack::WebSocketServer::WebSocketServer>();
        ASSERT_TRUE(server->GetServerContext() != nullptr);
        
        OHOS::NetStack::WebSocketServer::ServerConfig config;
        config.maxConcurrentClientsNumber = 3;
        config.maxConnectionsForOneClient = 3;
        server->GetServerContext()->startServerConfig_ = config;
        
        std::string testIp = "192.168.1.1";
        void *rawCtx = std::malloc(512);
        ASSERT_TRUE(rawCtx != nullptr);
        lws_context *tmpCtx = reinterpret_cast<lws_context *>(rawCtx);
        server->GetServerContext()->SetContext(tmpCtx);
        
        std::vector<OHOS::NetStack::WebSocketServer::SocketConnection> connections;
        connections.push_back({testIp, 8081});
        connections.push_back({testIp, 8082});
        
        std::vector<std::string> clientIds;
        std::vector<void *> wsiPtrs;
        
        for (auto &conn : connections) {
            std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
            clientIds.push_back(clientId);
            
            void *rawWsi = std::malloc(128);
            wsiPtrs.push_back(rawWsi);
            
            lws *tmpWsi = reinterpret_cast<lws *>(rawWsi);
            auto clientUserData = std::make_shared<OHOS::NetStack::WebSocketServer::UserData>(tmpCtx);
            server->GetServerContext()->AddClientUserData(tmpWsi, clientUserData);
            server->GetServerContext()->AddConnections(clientId, tmpWsi, conn);
        }
        
        bool result = OHOS::NetStack::WebSocketServer::IsOverMaxClientConns(server.get(), testIp);
        EXPECT_FALSE(result);
        
        for (size_t i = 0; i < clientIds.size(); ++i) {
            server->GetServerContext()->RemoveClientUserData(wsiPtrs[i]);
            server->GetServerContext()->RemoveConnections(clientIds[i]);
            std::free(wsiPtrs[i]);
        }
        server->GetServerContext()->SetContext(nullptr);
        std::free(rawCtx);
    }
    
    HWTEST_F(WebSocketTest, WebSocketCreatConnectInfoExBranchTest002, TestSize.Level1)
    {
        auto client = std::make_unique<WebSocketClient>();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);
        client->GetClientContext()->SetContext(nullptr);
        
        int32_t ret5 = OHOS::NetStack::WebSocketClient::CreatConnectInfoEx(
            "https://example.com", nullptr, client.get());
        EXPECT_EQ(ret5, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_URL_ERROR);
        
        int32_t ret6 = OHOS::NetStack::WebSocketClient::CreatConnectInfoEx("", nullptr, client.get());
        EXPECT_EQ(ret6, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_URL_ERROR);
        
        int32_t ret10 = OHOS::NetStack::WebSocketClient::CreatConnectInfoEx("invalid_url", nullptr, client.get());
        EXPECT_EQ(ret10, WebsocketErrorCode::WEBSOCKET_ERROR_CODE_URL_ERROR);
        
        client->GetClientContext()->SetContext(nullptr);
    }

    HWTEST_F(WebSocketTest, SplitTestEmptyString, TestSize.Level1)
    {
        std::string emptyStr = "";
        std::string sep = ",";
        size_t size = 10;
        
        auto result = Split(emptyStr, sep, size);
        EXPECT_TRUE(result.empty());
    }

    HWTEST_F(WebSocketTest, SplitTestSeparatorNotFound, TestSize.Level1)
    {
        std::string str = "hello world";
        std::string sep = ",";
        size_t size = 10;
        
        auto result = Split(str, sep, size);
        EXPECT_EQ(result.size(), 1);
        EXPECT_EQ(result[0], "hello world");
    }

    HWTEST_F(WebSocketTest, SplitTestSeparatorAtStart, TestSize.Level1)
    {
        std::string str = ",hello world";
        std::string sep = ",";
        size_t size = 10;
        
        auto result = Split(str, sep, size);
        EXPECT_EQ(result.size(), 2);
        EXPECT_EQ(result[0], "");
        EXPECT_EQ(result[1], "hello world");
    }

    HWTEST_F(WebSocketTest, SplitTestSeparatorAtEnd, TestSize.Level1)
    {
        std::string str = "hello world,";
        std::string sep = ",";
        size_t size = 10;
        
        auto result = Split(str, sep, size);
        EXPECT_EQ(result.size(), 1);
        EXPECT_EQ(result[0], "hello world");
    }

    HWTEST_F(WebSocketTest, SplitTestMultipleSeparatorsWithinSize, TestSize.Level1)
    {
        std::string str = "hello,world,test,case";
        std::string sep = ",";
        size_t size = 10;
        
        auto result = Split(str, sep, size);
        
        EXPECT_EQ(result.size(), 4);
        EXPECT_EQ(result[0], "hello");
        EXPECT_EQ(result[1], "world");
        EXPECT_EQ(result[2], "test");
        EXPECT_EQ(result[3], "case");
    }

    HWTEST_F(WebSocketTest, SplitTestMultipleSeparatorsReachSizeLimit, TestSize.Level1)
    {
        std::string str = "hello,world,test,case,demo";
        std::string sep = ",";
        size_t size = 3;
        
        auto result = Split(str, sep, size);
        
        EXPECT_EQ(result.size(), 3);
        EXPECT_EQ(result[0], "hello");
        EXPECT_EQ(result[1], "world");
        EXPECT_EQ(result[2], "test,case,demo");
    }

    HWTEST_F(WebSocketTest, ParseUrlExUrlTooLong, TestSize.Level1)
    {
        std::string longUrl;
        longUrl.reserve(MAX_URI_LENGTH + 10);
        longUrl.append("ws://");
        for (int i = 0; i < MAX_URI_LENGTH; ++i) {
            longUrl.append("a");
        }
        
        char prefix[MAX_URI_LENGTH] = {0};
        char address[MAX_URI_LENGTH] = {0};
        char path[MAX_URI_LENGTH] = {0};
        int port = 0;
        
        bool result = ParseUrlEx(longUrl, prefix, address, path, &port);
        EXPECT_FALSE(result);
    }

    HWTEST_F(WebSocketTest, ClientContextIsNullTest, TestSize.Level1)
    {
        client->clientContext = nullptr;
        int ret = LwsCallbackClientEstablished(nullptr, LWS_CALLBACK_CLIENT_ESTABLISHED, client, nullptr, 0);
        EXPECT_EQ(ret, -1);
    }

    HWTEST_F(WebSocketTest, NormalExecutionNoCallbackTest, TestSize.Level1)
    {
        WebSocketClient *client = new WebSocketClient();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);

        int ret = LwsCallbackClientEstablished(nullptr, LWS_CALLBACK_CLIENT_ESTABLISHED, client, nullptr, 0);
        EXPECT_EQ(ret, 0);

        delete client;
    }

    HWTEST_F(WebSocketTest, NormalExecutionWithCallbackTest, TestSize.Level1)
    {
        g_onOpenCalled = false;
        WebSocketClient *client = new WebSocketClient();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);

        client->GetClientContext()->openStatus = 1;
        client->GetClientContext()->openMessage = "test message";
        client->onOpenCallback_ = TestOnOpenCallback;
        
        int ret = LwsCallbackClientEstablished(nullptr, LWS_CALLBACK_CLIENT_ESTABLISHED, client, nullptr, 0);
        EXPECT_TRUE(g_onOpenCalled);
        EXPECT_EQ(g_lastOpenResult.status, 1);
        EXPECT_STREQ(g_lastOpenResult.message, "test message");
        EXPECT_EQ(ret, 0);

        delete client;
    }

    HWTEST_F(WebSocketTest, HttpDummyReturnValueTest, TestSize.Level1)
    {
        WebSocketClient *client = new WebSocketClient();
        ASSERT_TRUE(client != nullptr);
        ASSERT_TRUE(client->GetClientContext() != nullptr);

        int ret = LwsCallbackClientEstablished(nullptr, LWS_CALLBACK_CLIENT_ESTABLISHED, client, nullptr, 0);
        EXPECT_EQ(ret, 0);

        delete client;
    }
} // namespace