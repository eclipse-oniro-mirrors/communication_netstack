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

#include <gtest/gtest.h>

#include "socket_error.h"

namespace OHOS {
namespace NetStack {
namespace {
using namespace testing::ext;
} // namespace

class SocketErrorTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(SocketErrorTest, MakeErrorStringTest, TestSize.Level2)
{
    std::string errorMsg = MakeErrnoString();
    ASSERT_FALSE(errorMsg.empty());
}

HWTEST_F(SocketErrorTest, MakeSSLErrorStringTest001, TestSize.Level2)
{
    std::string errorMsg = MakeSSLErrorString(TLSSOCKET_ERROR_SSL_NULL);
    EXPECT_STREQ(errorMsg.data(), "ssl is null");
}

HWTEST_F(SocketErrorTest, MakeSSLErrorStringTest002, TestSize.Level2)
{
    std::string errorMsg = MakeSSLErrorString(TLSSOCKET_ERROR_PARAM_INVALID);
    EXPECT_FALSE(errorMsg.empty());
}
} // namespace NetStack
} // namespace OHOS
