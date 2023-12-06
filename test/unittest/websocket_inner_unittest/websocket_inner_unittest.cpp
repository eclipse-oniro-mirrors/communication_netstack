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

class WebsocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::WebsocketClient;

OpenOptions openOptions;

static void OnMessage(WebsocketClient *client, const std::string &data, size_t length) {}

static void OnOpen(WebsocketClient *client, OpenResult openResult) {}

static void OnError(WebsocketClient *client, ErrorResult error) {}

static void OnClose(WebsocketClient *client, CloseResult closeResult) {}

HWTEST_F(WebsocketTest, WebsocketRegistcallback001, TestSize.Level1)
{
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    WebsocketClient *client = new WebsocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    int ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, WebsocketConnect002, TestSize.Level1)
{
    WebsocketClient *client = new WebsocketClient();
    int ret = client->Connect("www.baidu.com", openOptions);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, WebsocketSend003, TestSize.Level1)
{
    int ret;
    WebsocketClient *client = new WebsocketClient();
    const char *data = "Hello, world!";
    int length = std::strlen(data);
    ret = client->Send(const_cast<char *>(data), length);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, WebsocketClose004, TestSize.Level1)
{
    CloseOption CloseOptions;
    CloseOptions.code = LWS_CLOSE_STATUS_NORMAL;
    CloseOptions.reason = "";
    WebsocketClient *client = new WebsocketClient();
    int ret = client->Close(CloseOptions);
    EXPECT_EQ(ret, 1017);
}

HWTEST_F(WebsocketTest, WebsocketDestroy005, TestSize.Level1)
{
    int ret;
    WebsocketClient *client = new WebsocketClient();
    ret = client->Destroy();
    EXPECT_EQ(ret, 1018);
}

} // namespace