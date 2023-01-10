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

#include <map>

#include "gtest/gtest.h"

#include "base64_utils.h"

namespace OHOS {
namespace NetStack {
using namespace Base64;
using namespace testing::ext;
namespace {
const std::string TEST_TEXT[] = {
    "We are supporting a community where more than 28 million* people learn, share, and work together "
    "to build software. ",
    "这是一段用来测试的文本，测试加密内容。",
    "\\C6y\\83u\\F9C\\8As\\C8\\D1j.\\CFi\\83\\E2#Z:\\FB \\A7m\\8B\\D9\\E5ܫ\\E4\\D7PMY\\D6\\CF\\F0"
    "É",
};

const std::map<std::string, std::string> CODE_MAP = {
    {"abcde", "YWJjZGU="},
    {"测试加密解密", "5rWL6K+V5Yqg5a+G6Kej5a+G"},
    {"\\C6y\\83u\\F9C\\8As\\C8\\D1j.\\CFi\\83\\E2#Z:", "XEM2eVw4M3VcRjlDXDhBcxtcQzhcRDFqLlxDRmkeXDgzElxFMiNaETo="},
};
} // namespace

class Base64Test : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    void SetUp() {}

    void TearDown() {}
};

HWTEST_F(Base64Test, EncodeAndDecodeTest, TestSize.Level1)
{
    for (const auto &str : TEST_TEXT) {
        EXPECT_EQ(Decode(Encode(str)), str);
    }

    for (const auto &test : CODE_MAP) {
        EXPECT_EQ(Encode(test.first), test.second);
        EXPECT_EQ(Decode(test.second), test.first);
    }
}
} // namespace NetStack
} // namespace OHOS
