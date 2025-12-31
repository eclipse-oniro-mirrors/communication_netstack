/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <iostream>
#include <cstring>
#include "gtest/gtest.h"
#include "http_client_constant.h"
#include "netstack_log.h"

#define private public
#include "http_client_response.h"

using namespace OHOS::NetStack::HttpClient;

class HttpClientResponseTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

HWTEST_F(HttpClientResponseTest, GetResponseCodeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    int responseTest = req.GetResponseCode();
    EXPECT_EQ(responseTest, ResponseCode::NONE);
}

HWTEST_F(HttpClientResponseTest, GetHeaderTest001, TestSize.Level1)
{
    HttpClientResponse req;

    string header = req.GetHeader();
    EXPECT_EQ(header, "");
}

HWTEST_F(HttpClientResponseTest, GetRequestTimeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    string requestTime = req.GetRequestTime();
    EXPECT_EQ(requestTime, "");
}

HWTEST_F(HttpClientResponseTest, GetResponseTimeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    string responseTime = req.GetResponseTime();
    EXPECT_EQ(responseTime, "");
}

HWTEST_F(HttpClientResponseTest, SetRequestTimeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    req.SetRequestTime("10");
    string requestTime = req.GetRequestTime();
    EXPECT_EQ(requestTime, "10");
}

HWTEST_F(HttpClientResponseTest, SetResponseTimeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    req.SetResponseTime("10");
    string responseTime = req.GetResponseTime();
    EXPECT_EQ(responseTime, "10");
}

HWTEST_F(HttpClientResponseTest, AppendHeaderTest001, TestSize.Level1)
{
    HttpClientResponse req;
    std::string add = "test";
    req.AppendHeader(add.data(), add.length());
    string header = req.GetHeader();
    EXPECT_EQ(header, "test");
}

HWTEST_F(HttpClientResponseTest, SetResponseCodeTest001, TestSize.Level1)
{
    HttpClientResponse req;

    req.SetResponseCode(ResponseCode::MULT_CHOICE);
    int responseTest = req.GetResponseCode();
    EXPECT_EQ(responseTest, ResponseCode::MULT_CHOICE);
}

HWTEST_F(HttpClientResponseTest, ResponseParseHeader001, TestSize.Level1)
{
    HttpClientResponse req;
    const char *emptyHead = " \r\n";
    const char *errHead = "test1 data1\r\n";
    const char *realHead = "test:data\r\n";
    req.AppendHeader(emptyHead, strlen(emptyHead));
    req.AppendHeader(errHead, strlen(errHead));
    req.AppendHeader(realHead, strlen(realHead));
 
    req.ParseHeaders();
    auto headers = req.GetHeaders();
    std::string ret;
    std::for_each(headers.begin(), headers.end(), [&ret](const auto &item) {
        if (!item.first.empty() && !item.second.empty()) {
            ret += item.first + ":" + item.second + "\r\n";
        }
    });
    EXPECT_EQ(realHead, ret);
}
 
HWTEST_F(HttpClientResponseTest, ResponseAppendCookie001, TestSize.Level1)
{
    HttpClientResponse req;
    const char *emptyHead = " \r\n";
    const char *errHead = "test data\r\n";
    const char *realHead = "test:data\r\n";
    string cookies = "";
    cookies.append(emptyHead);
    cookies.append(errHead);
    cookies.append(realHead);
    req.AppendCookies(emptyHead, strlen(emptyHead));
    req.AppendCookies(errHead, strlen(errHead));
    req.AppendCookies(realHead, strlen(realHead));
    auto ret = req.GetCookies();
    EXPECT_EQ(cookies, ret);
}
 
HWTEST_F(HttpClientResponseTest, ResponseSetCookie001, TestSize.Level1)
{
    HttpClientResponse req;
    const char *realHead = "test:data\r\n";
    req.SetCookies(realHead);
    auto result = req.GetCookies();
    EXPECT_EQ(realHead, result);
}
 
HWTEST_F(HttpClientResponseTest, ResponseSetWarning001, TestSize.Level1)
{
    HttpClientResponse req;
    const char *realHead = "test:data";
    const char *warningText = "Warning";
    req.SetWarning(realHead);
    auto headers = req.GetHeaders();
    for (auto &item: headers) {
        auto key = item.first.c_str();
        ASSERT_NE(strcmp(warningText, key), 0);
    }
    EXPECT_FALSE(true);
}
 
HWTEST_F(HttpClientResponseTest, ResponseSetRawHeader001, TestSize.Level1)
{
    HttpClientResponse req;
    const char *realHead = "test:data\r\n";
    req.SetRawHeader(realHead);
    auto header = req.GetHeader();
    EXPECT_EQ(realHead, header);
}
} // namespace