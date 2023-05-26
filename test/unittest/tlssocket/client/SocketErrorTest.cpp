/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <regex>
#include "socket_error.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
const int32_t ERROR_NOT_EXIT = 2303800;
} // namespace

class SocketErrorTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(SocketErrorTest, SocketError, TestSize.Level2)
{
    std::string errorMsg = MakeErrorMessage(TLS_ERR_SYS_EINTR);
    EXPECT_STREQ(errorMsg.data(), "Interrupted system call");
}

HWTEST_F(SocketErrorTest, SocketError2, TestSize.Level2)
{
    std::string errorMsg = MakeErrorMessage(ERROR_NOT_EXIT);
    std::regex value("^error:000002BC:lib.{5,12}reason.{5}");
    EXPECT_TRUE(std::regex_match(errorMsg, value) == true);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS