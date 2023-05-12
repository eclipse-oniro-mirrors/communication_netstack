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

#include <cstring>
#include "gtest/gtest.h"
#include "http_request_options.h"
#include "netstack_log.h"

using namespace OHOS::NetStack::Http;

class HttpRequestOptionsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;
constexpr char OTHER_CA_PATH[] = "/etc/ssl/certs/other.pem";

HWTEST_F(HttpRequestOptionsTest, CaPathTest001, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, HttpConstant::HTTP_DEFAULT_CA_PATH);
}

HWTEST_F(HttpRequestOptionsTest, CaPathTest002, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    requestOptions.SetCaPath("");
    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, HttpConstant::HTTP_DEFAULT_CA_PATH);
}

HWTEST_F(HttpRequestOptionsTest, CaPathTest003, TestSize.Level1)
{
    HttpRequestOptions requestOptions;

    requestOptions.SetCaPath(OTHER_CA_PATH);
    string path = requestOptions.GetCaPath();
    EXPECT_EQ(path, OTHER_CA_PATH);
}
} // namespace