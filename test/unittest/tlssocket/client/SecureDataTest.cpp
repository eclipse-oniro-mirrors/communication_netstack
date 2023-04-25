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
#include <iostream>
#include <string>

#include "secure_data.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
} // namespace

class SecureDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(SecureDataTest, stringData, TestSize.Level2)
{
    std::string testString = "Secure Data string Test";
    SecureData structureData(testString);
    EXPECT_STREQ(structureData.Data(), "Secure Data string Test");

    SecureData copyData = structureData;
    EXPECT_STREQ(copyData.Data(), "Secure Data string Test");

    SecureData equalData;
    equalData = structureData;
    EXPECT_STREQ(equalData.Data(), "Secure Data string Test");

    SecureData defaultData;
    EXPECT_EQ(defaultData.Length(), 0);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS