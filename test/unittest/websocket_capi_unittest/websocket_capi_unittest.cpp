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
#include <functional>
#include <iostream>
#include <signal.h>
#include <string.h>

#include "net_websocket.h"

class WebsocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;

static void OnOpen(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_OpenResult openResult) {}

static void OnMessage(struct OH_NetStack_WebsocketClient *client, char *data, uint32_t length) {}

static void OnError(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_ErrorResult error) {}

static void OnClose(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_CloseResult closeResult) {}

HWTEST_F(WebsocketTest, WebsocketConstruct001, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *url1 = "www.baidu.com";
    struct OH_NetStack_WebsocketClient_Slist header1;
    header1.fieldName = "Content-Type";
    header1.fieldValue = "application/json";
    header1.next = nullptr;
    client = OH_NetStack_WebsocketClient_Construct(OnOpen, OnMessage, OnError, OnClose);
    ret = OH_NetStack_WebSocketClient_AddHeader(client, header1);
    OH_NetStack_WebSocketClient_Connect(client, url1, client->requestOptions);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, WebsocketAddHeader002, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = nullptr;
    struct OH_NetStack_WebsocketClient_Slist header1;
    header1.fieldName = "Content-Type";
    header1.fieldValue = "application/json";
    header1.next = nullptr;
    ret = OH_NetStack_WebSocketClient_AddHeader(client, header1);
    EXPECT_EQ(ret, 1001);
}

HWTEST_F(WebsocketTest, WebsocketConnect003, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *url1 = "www.baidu.com";
    ret = OH_NetStack_WebSocketClient_Connect(client, url1, client->requestOptions);

    EXPECT_EQ(ret, 1002);
}

HWTEST_F(WebsocketTest, WebsocketSend004, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = nullptr;
    const char *Senddata = "Hello, I love China!";
    int SendLength = std::strlen(Senddata);
    ret = OH_NetStack_WebSocketClient_Send(client, const_cast<char *>(Senddata), SendLength);
    EXPECT_EQ(ret, 1001);
}

HWTEST_F(WebsocketTest, WebsocketClose005, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = nullptr;
    struct OH_NetStack_WebsocketClient_CloseOption CloseOption;
    CloseOption.code = 1000;
    CloseOption.reason = " ";
    ret = OH_NetStack_WebSocketClient_Close(client, CloseOption);
    EXPECT_EQ(ret, 1001);
}

HWTEST_F(WebsocketTest, WebsocketDestroy006, TestSize.Level1)
{
    int ret;
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    ret = OH_NetStack_WebsocketClient_Destroy(client);
    EXPECT_EQ(ret, 1002);
}

} // namespace