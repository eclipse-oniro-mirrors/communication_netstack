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


#include <cstring>
#include "gtest/gtest.h"

#ifdef GTEST_API_
#define private public
#endif

#include "http_exec.h"
#include "http_async_work.h"
#include "netstack_log.h"
#include "constant.h"
#include "secure_char.h"
#include "curl/curl.h"

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

class HttpExecTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;


HWTEST_F(HttpExecTest, SetOption001, TestSize.Level1)
{
    auto handle = curl_easy_init();

    napi_env env = nullptr;
    EventManager manager;
    OHOS::NetStack::Http::RequestContext context(env, &manager);

    EXPECT_TRUE(HttpExec::SetOption(handle, &context, context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetServerSSLCertOption001, TestSize.Level1)
{
    auto handle = curl_easy_init();

    napi_env env = nullptr;
    EventManager manager;
    OHOS::NetStack::Http::RequestContext context(env, &manager);

    EXPECT_TRUE(HttpExec::SetServerSSLCertOption(handle, &context));
}

} // namespace