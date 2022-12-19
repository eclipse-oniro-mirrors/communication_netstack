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
static constexpr const char *TEST_STR = "HOWDOYOUDO";
static constexpr const char *TEST_LOWER_STR = "howdoyoudo";
static constexpr const char *TEST_STR_SPLIT = "The,weather,is,fine,today";
static constexpr const char *TEST_STR_THE = "The";
static constexpr const char *TEST_STR_WEATHER = "weather";
static constexpr const char *TEST_STR_IS = "is";
static constexpr const char *TEST_STR_FINE = "fine";
static constexpr const char *TEST_STR_TODAY = "today";
static constexpr const uint32_t SUB_STR_SIZE = 5;
static constexpr const char *TEST_STR_STRIP = " The weather is fine today";
static constexpr const char *STR_STRIP = "The weather is fine today";
static constexpr const char *SPLIT_WITH_SIZE = "fine today";
static constexpr const char *SPLIT_WITH_SIZE_FINE = "fine";
static constexpr const char *SPLIT_WITH_SIZE_TODAY = "today";
static constexpr const uint32_t SPLIT_SIZE = 2;
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
    std::vector<std::string> subStr = Split(TEST_STR_SPLIT, STATUS_LINE_COMMA);
    EXPECT_STREQ(subStr[0].data(), TEST_STR_THE);
    EXPECT_STREQ(subStr[1].data(), TEST_STR_WEATHER);
    EXPECT_STREQ(subStr[2].data(), TEST_STR_IS);
    EXPECT_STREQ(subStr[3].data(), TEST_STR_FINE);
    EXPECT_STREQ(subStr[4].data(), TEST_STR_TODAY);
    EXPECT_EQ(subStr.size(), SUB_STR_SIZE);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils1, TestSize.Level2)
{
    std::string str = TEST_STR_STRIP;
    std::string subStr = Strip(str, SPACE);
    EXPECT_STREQ(subStr.data(), STR_STRIP);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils2, TestSize.Level2)
{
    std::string strLower = ToLower(TEST_STR);
    EXPECT_STREQ(strLower.data(), TEST_LOWER_STR);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils3, TestSize.Level2)
{
    std::vector<std::string> strList = Split(SPLIT_WITH_SIZE, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);

    EXPECT_STREQ(strList[0].data(), SPLIT_WITH_SIZE_FINE);
    EXPECT_STREQ(strList[1].data(), SPLIT_WITH_SIZE_TODAY);
    EXPECT_EQ(strList.size(), SPLIT_SIZE);
}
} // namespace CommonUtils
} // namespace NetStack
} // namespace OHOS