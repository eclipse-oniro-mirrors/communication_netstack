/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstring>

#include "gtest/gtest.h"

#include "websocket_async_work.h"
#include "websocket_exec.h"

namespace OHOS::NetStack {
using namespace testing::ext;
class WebsocketTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WebsocketTest::SetUpTestCase() {}

void WebsocketTest::TearDownTestCase() {}

void WebsocketTest::SetUp() {}

void WebsocketTest::TearDown() {}

HWTEST_F(WebsocketTest, TestExecConnect1, testing::ext::TestSize.Level4)
{
    bool ret = WebSocketExec::ExecConnect(nullptr);
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecConnect2, testing::ext::TestSize.Level4)
{
    auto context = new ConnectContext(nullptr, nullptr);
    bool ret = WebSocketExec::ExecConnect(context);
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecConnect3, testing::ext::TestSize.Level4)
{
    auto context = new ConnectContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecConnect(nullptr, context);
    bool ret = context->IsExecOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecConnect4, testing::ext::TestSize.Level4)
{
    auto context = new ConnectContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecConnect(nullptr, context);
    bool ret = context->IsParseOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecConnect5, testing::ext::TestSize.Level4)
{
    auto context = new ConnectContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecConnect(nullptr, context);
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, -1);
}

HWTEST_F(WebsocketTest, TestExecConnect6, testing::ext::TestSize.Level4)
{
    auto context = new ConnectContext(nullptr, nullptr);
    ASSERT_FALSE(WebSocketExec::ExecConnect(context));
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, TestExecClose1, testing::ext::TestSize.Level4)
{
    bool ret = WebSocketExec::ExecClose(nullptr);
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecClose2, testing::ext::TestSize.Level4)
{
    auto context = new CloseContext(nullptr, nullptr);
    bool ret = WebSocketExec::ExecClose(context);
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecClose3, testing::ext::TestSize.Level4)
{
    auto context = new CloseContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecClose(nullptr, context);
    bool ret = context->IsExecOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecClose4, testing::ext::TestSize.Level4)
{
    auto context = new CloseContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecClose(nullptr, context);
    bool ret = context->IsParseOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecClose5, testing::ext::TestSize.Level4)
{
    auto context = new CloseContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecClose(nullptr, context);
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, -1);
}

HWTEST_F(WebsocketTest, TestExecClose6, testing::ext::TestSize.Level4)
{
    auto context = new CloseContext(nullptr, nullptr);
    ASSERT_FALSE(WebSocketExec::ExecClose(context));
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, 0);
}

HWTEST_F(WebsocketTest, TestExecSend1, testing::ext::TestSize.Level4)
{
    bool ret = WebSocketExec::ExecSend(nullptr);
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecSend2, testing::ext::TestSize.Level4)
{
    auto context = new SendContext(nullptr, nullptr);
    bool ret = WebSocketExec::ExecSend(context);
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecSend3, testing::ext::TestSize.Level4)
{
    auto context = new SendContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecSend(nullptr, context);
    bool ret = context->IsExecOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecSend4, testing::ext::TestSize.Level4)
{
    auto context = new SendContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecSend(nullptr, context);
    bool ret = context->IsParseOK();
    delete context;
    ASSERT_FALSE(ret);
}

HWTEST_F(WebsocketTest, TestExecSend5, testing::ext::TestSize.Level4)
{
    auto context = new SendContext(nullptr, nullptr);
    WebSocketAsyncWork::ExecSend(nullptr, context);
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, -1);
}

HWTEST_F(WebsocketTest, TestExecSend6, testing::ext::TestSize.Level4)
{
    auto context = new SendContext(nullptr, nullptr);
    ASSERT_FALSE(WebSocketExec::ExecSend(context));
    int32_t ret = context->GetErrorCode();
    delete context;
    ASSERT_EQ(ret, 0);
}

} // namespace OHOS::NetStack