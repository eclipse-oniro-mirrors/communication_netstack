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

#include "netstack_common_utils.h"

namespace OHOS {
namespace NetStack {
namespace CommonUtils {
namespace {
using namespace testing::ext;
static constexpr const char SPACE = ' ';
static constexpr const char *STATUS_LINE_COMMA = ",";
static constexpr const char *STATUS_LINE_SEP = " ";
static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;
} // namespace

class NetStackCommonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(NetStackCommonUtilsTest, CommonUtils, TestSize.Level2)
{
    std::string str = "The,weather,is,fine,today";
    std::vector<std::string> subStr = Split(str, STATUS_LINE_COMMA);
    EXPECT_STREQ(subStr[0].data(), "The");
    EXPECT_STREQ(subStr[1].data(), "weather");
    EXPECT_STREQ(subStr[2].data(), "is");
    EXPECT_STREQ(subStr[3].data(), "fine");
    EXPECT_STREQ(subStr[4].data(), "today");
    EXPECT_EQ(subStr.size(), 5);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils1, TestSize.Level2)
{
    std::string str = " The weather is fine today";
    std::string subStr = Strip(str, SPACE);
    EXPECT_STREQ(subStr.data(), "The weather is fine today");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils2, TestSize.Level2)
{
    std::string str = "HOWDOYOUDO";
    std::string strLower = ToLower(str);
    EXPECT_STREQ(strLower.data(), "howdoyoudo");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils3, TestSize.Level2)
{
    std::string str = "fine today";
    std::vector<std::string> strList = Split(str, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);;

    EXPECT_STREQ(strList[0].data(), "fine");
    EXPECT_STREQ(strList[1].data(), "today");
    EXPECT_EQ(strList.size(), 2);
}
} // namespace CommonUtils
} // namespace NetStack
} // namespace OHOS