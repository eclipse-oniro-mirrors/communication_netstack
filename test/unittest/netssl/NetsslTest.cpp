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
#include <iostream>

#include "cert_context.h"
#include "gtest/gtest.h"
#include "net_ssl.h"
#include "net_ssl_async_work.h"
#include "net_ssl_exec.h"
#include "net_ssl_module.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

class NetsslTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::Ssl;

HWTEST_F(NetsslTest, CertVerifyTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    CertContext context(env, nullptr);

    bool ret = SslExec::ExecVerify(&context);
    EXPECT_EQ(ret, false);
}
} // namespace
