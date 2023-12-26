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
    int ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebSocketTest, WebSocketConnect002, TestSize.Level1)
{
    int ret = 0;
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebSocketTest, WebSocketSend003, TestSize.Level1)
{
    int ret;
    const char *data = "Hello, world!";
    int length = std::strlen(data);
    client->Connect("www.baidu.com", openOptions);
    ret = client->Send(const_cast<char *>(data), length);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebSocketTest, WebSocketClose004, TestSize.Level1)
{
    CloseOption CloseOptions;
    CloseOptions.code = LWS_CLOSE_STATUS_NORMAL;
    CloseOptions.reason = "";
    int ret = client->Close(CloseOptions);
    EXPECT_EQ(ret, 1017);
}

HWTEST_F(WebSocketTest, WebSocketDestroy005, TestSize.Level1)
{
    int ret;
    ret = client->Destroy();
    delete client;
    EXPECT_EQ(ret, 0);
}

} // namespace