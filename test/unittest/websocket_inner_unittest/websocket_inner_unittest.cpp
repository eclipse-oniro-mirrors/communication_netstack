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

HWTEST_F(WebSocketTest, WebSocketRegistcallback001, TestSize.Level1)
{
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    closeOptions.code = LWS_CLOSE_STATUS_NORMAL;
    closeOptions.reason = "";
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    int32_t ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL);
}

HWTEST_F(WebSocketTest, WebSocketConnect002, TestSize.Level1)
{
    int32_t ret = 0;
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL);
}

HWTEST_F(WebSocketTest, WebSocketSend003, TestSize.Level1)
{
    int32_t ret;
    const char *data = "Hello, world!";
    int32_t length = std::strlen(data);
    client->Connect("www.baidu.com", openOptions);
    ret = client->Send(const_cast<char *>(data), length);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebSocketTest, WebSocketClose004, TestSize.Level1)
{
    const int32_t WEBSOCKET_NO_CONNECTION = 1017;
    CloseOption CloseOptions;
    CloseOptions.code = LWS_CLOSE_STATUS_NORMAL;
    CloseOptions.reason = "";
    int32_t ret = client->Close(CloseOptions);
    EXPECT_EQ(ret, WEBSOCKET_NO_CONNECTION);
}

HWTEST_F(WebSocketTest, WebSocketDestroy005, TestSize.Level1)
{
    int32_t ret;
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
    WebSocketClient *client = new WebSocketClient();
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
    EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);

    CloseOption options;
    ret = client->Close(options);
    EXPECT_EQ(ret, WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX);
}
} // namespace