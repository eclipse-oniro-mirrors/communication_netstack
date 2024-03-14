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

#include <iostream>
#include <cstring>
#include "gtest/gtest.h"
#include "http_client_constant.h"
#include "netstack_log.h"

#define private public
#include "http_client.h"
#include "http_client_task.h"
#include <curl/curl.h>

using namespace OHOS::NetStack::HttpClient;

class HttpClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

HWTEST_F(HttpClientTest, AddRequestInfoTest001, TestSize.Level1)
{
    HttpClientRequest httpReq;
    std::string url = "http://www.baidu.com";
    httpReq.SetURL(url);

    HttpSession &session = HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    task->Start();

    while (task->GetStatus() != TaskStatus::IDLE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_EQ(task->GetStatus(), IDLE);
}

} // namespace