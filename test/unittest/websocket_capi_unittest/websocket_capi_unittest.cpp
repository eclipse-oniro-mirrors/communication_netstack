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
#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>

#include "net_websocket.h"
#include "net_websocket_type.h"

class WebSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;

static void OnOpen(struct WebSocket *client, WebSocket_OpenResult openResult) {}

static void OnMessage(struct WebSocket *client, char *data, uint32_t length) {}

static void OnError(struct WebSocket *client, WebSocket_ErrorResult error) {}

static void OnClose(struct WebSocket *client, WebSocket_CloseResult closeResult) {}

HWTEST_F(WebSocketTest, WebSocketConstruct001, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = new WebSocket();
    const char *url1 = "www.baidu.com";
    struct WebSocket_Header header1;
    header1.fieldName = "Content-Type";
    header1.fieldValue = "application/json";
    header1.next = nullptr;
    client = OH_WebSocketClient_Constructor(OnOpen, OnMessage, OnError, OnClose);
    ret = OH_WebSocketClient_AddHeader(client, header1);
    OH_WebSocketClient_Connect(client, url1, client->requestOptions);
    OH_WebSocketClient_Destroy(client);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_OK);
}

HWTEST_F(WebSocketTest, WebSocketAddHeader002, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = nullptr;
    struct WebSocket_Header header1;
    header1.fieldName = "Content-Type";
    header1.fieldValue = "application/json";
    header1.next = nullptr;
    ret = OH_WebSocketClient_AddHeader(client, header1);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_CLIENT_NULL);
}

HWTEST_F(WebSocketTest, WebSocketConnect003, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = new WebSocket();
    const char *url1 = "www.baidu.com";
    ret = OH_WebSocketClient_Connect(client, url1, client->requestOptions);
    OH_WebSocketClient_Destroy(client);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_CLIENT_NOT_CREATED);
}

HWTEST_F(WebSocketTest, WebSocketSend004, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = nullptr;
    const char *senddata = "Hello, I love China!";
    int sendLength = std::strlen(senddata);
    ret = OH_WebSocketClient_Send(client, const_cast<char *>(senddata), sendLength);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_CLIENT_NULL);
}

HWTEST_F(WebSocketTest, WebSocketClose005, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = nullptr;
    struct WebSocket_CloseOption CloseOption;
    CloseOption.code = 1000;
    CloseOption.reason = " ";
    ret = OH_WebSocketClient_Close(client, CloseOption);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_CLIENT_NULL);
}

HWTEST_F(WebSocketTest, WebSocketDestroy006, TestSize.Level1)
{
    int32_t ret;
    struct WebSocket *client = new WebSocket();
    ret = OH_WebSocketClient_Destroy(client);
    EXPECT_EQ(ret, WebSocket_ErrCode::WEBSOCKET_CLIENT_NOT_CREATED);
}

} // namespace