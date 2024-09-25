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

#include "gtest/gtest.h"

#include "socket_error.h"

namespace OHOS::NetStack::TlsSocket {
class SocketErrorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SocketErrorTest::SetUpTestCase() {}
void SocketErrorTest::TearDownTestCase() {}
void SocketErrorTest::SetUp() {}
void SocketErrorTest::TearDown() {}

HWTEST_F(SocketErrorTest, SocketErrorTest001, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(MakeErrorMessage(1107), strerror(errno));
}
} // namespace OHOS::NetStack::TlsSocket
