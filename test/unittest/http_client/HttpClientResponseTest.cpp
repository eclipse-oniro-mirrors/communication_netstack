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

HWTEST_F(HttpClientResponseTest, ResponseParseHeader002, TestSize.Level1)
{
    HttpClientResponse req;
    const char *emptyHead = "\r\n";
    const char *realCookie = "set-cookie:data\r\n";
    req.AppendHeader(emptyHead, strlen(emptyHead));
    req.AppendHeader(realCookie, strlen(realCookie));

    req.ParseHeaders();
    auto setCookie = req.GetsetCookie();
    std::string result = "set-cookie:";
    std::for_each(setCookie.begin(), setCookie.end(), [&result](const auto &item) {
        if (!item.empty()) {
            result += item + "\r\n";
        }
    });

    auto headers = req.GetHeaders();
    EXPECT_EQ(realCookie, result);
    EXPECT_TRUE(headers.empty());
}

HWTEST_F(HttpClientResponseTest, ResponseGetsetCookie001, TestSize.Level1)
{
    HttpClientResponse req;

    auto result = req.GetsetCookie();
    EXPECT_TRUE(result.empty());
}

HWTEST_F(HttpClientResponseTest, ResponseGetsetCookie002, TestSize.Level1)
{
    HttpClientResponse req;
    const char *realCookie = "set-cookie:data\r\n";
    req.AppendHeader(realCookie, strlen(realCookie));

    req.ParseHeaders();
    auto setCookie = req.GetsetCookie();
    std::string result = "set-cookie:";
    std::for_each(setCookie.begin(), setCookie.end(), [&result](const auto &item) {
        if (!item.empty()) {
            result += item + "\r\n";
        }
    });
    EXPECT_EQ(realCookie, result);
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
    for (auto &item : headers) {
        auto key = item.first.c_str();
        if (strcmp(warningText, key) == 0) {
            EXPECT_EQ(realHead, item.second);
            return;
        }
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

HWTEST_F(HttpClientResponseTest, GetPerformanceTimingTest001, TestSize.Level1)
{
    HttpClientResponse req;
    PerformanceInfo performanceInfo = req.GetPerformanceTiming();
    EXPECT_EQ(performanceInfo.dnsTiming, 0);
    EXPECT_EQ(performanceInfo.connectTiming, 0);
    EXPECT_EQ(performanceInfo.tlsTiming, 0);
    EXPECT_EQ(performanceInfo.firstSendTiming, 0);
    EXPECT_EQ(performanceInfo.firstReceiveTiming, 0);
    EXPECT_EQ(performanceInfo.totalTiming, 0);
    EXPECT_EQ(performanceInfo.redirectTiming, 0);
}

HWTEST_F(HttpClientResponseTest, ResponseSetResult, TestSize.Level1)
{
    HttpClientResponse req;
    const char *testResult = "test:data\r\n";
    req.SetResult(testResult);
    auto result = req.GetResult();
    EXPECT_EQ(testResult, result);
}

HWTEST_F(HttpClientResponseTest, ResponseGetHttpStatistics, TestSize.Level1)
{
    HttpClientResponse req;
    NetAddress netAddr;
    std::string testAddr = "test:address";
    netAddr.address_ = testAddr;
    req.SetNetAddress(netAddr);
    HttpStatistics httpStatistics = req.GetHttpStatistics();
    EXPECT_EQ(httpStatistics.serverIpAddress.address_, testAddr);
}

HWTEST_F(HttpClientResponseTest, ResponseGetRawHeader, TestSize.Level1)
{
    HttpClientResponse req;
    std::string testAddr = "test:rawHeader_";
    req.rawHeader_ = testAddr;
    auto ret = req.GetRawHeader();
    EXPECT_EQ(ret, testAddr);
}

HWTEST_F(HttpClientResponseTest, ResponseGetExpectDataType, TestSize.Level1)
{
    HttpClientResponse req;
    req.dataType_ = HttpDataType::STRING;
    auto ret = req.GetExpectDataType();
    EXPECT_EQ(ret, HttpDataType::STRING);
}

HWTEST_F(HttpClientResponseTest, ResponseClearHeaderCache001, TestSize.Level1)
{
    HttpClientResponse response_;
    const std::string rawHeader =
        "Content-Type: application/json\r\n"
        "Set-Cookie: sessionid=123456; Path=/\r\n"
        "Set-Cookie: token=abcdef; HttpOnly\r\n"
        "Accept: */*";
    response_.SetRawHeader(rawHeader);
    response_.ParseHeaders();
    EXPECT_FALSE(response_.GetHeaders().empty());
    EXPECT_EQ(response_.GetHeaders().size(), 2);
    EXPECT_FALSE(response_.GetsetCookie().empty());
    EXPECT_EQ(response_.GetsetCookie().size(), 2);
    response_.ClearHeaderCache();
    EXPECT_TRUE(response_.GetHeaders().empty());
    EXPECT_TRUE(response_.GetsetCookie().empty());
}

HWTEST_F(HttpClientResponseTest, ResponseReset001, TestSize.Level1)
{
    HttpClientResponse response;
    const char *header = "Content-Type: application/json\r\nSet-Cookie: sessionid=123456\r\n";
    response.AppendHeader(header, strlen(header));
    response.AppendResult("body data", 9);
    response.AppendCookies("cookie1=val1; ", 14);
    response.SetResponseCode(ResponseCode::OK);
    response.SetRequestTime("2024-01-01 00:00:00");
    response.SetResponseTime("2024-01-01 00:00:01");
    NetAddress netAddress;
    netAddress.address_ = "192.168.1.1";
    netAddress.family_ = FAMILY_IPV4;
    netAddress.port_ = 8080;
    response.SetNetAddress(netAddress);
    response.performanceInfo_.dnsTiming = 10.0;
    response.performanceInfo_.connectTiming = 20.0;
    response.performanceInfo_.tlsTiming = 30.0;
    response.performanceInfo_.firstSendTiming = 40.0;
    response.performanceInfo_.firstReceiveTiming = 50.0;
    response.performanceInfo_.totalTiming = 60.0;
    response.performanceInfo_.redirectTiming = 70.0;
    response.ParseHeaders();

    EXPECT_FALSE(response.GetResult().empty());
    EXPECT_FALSE(response.GetHeader().empty());
    EXPECT_FALSE(response.GetsetCookie().empty());
    EXPECT_FALSE(response.GetCookies().empty());
    EXPECT_EQ(response.GetResponseCode(), ResponseCode::OK);
    EXPECT_FALSE(response.GetRequestTime().empty());
    EXPECT_FALSE(response.GetResponseTime().empty());
    EXPECT_FALSE(response.GetHttpStatistics().serverIpAddress.address_.empty());
    EXPECT_NE(response.GetPerformanceTiming().dnsTiming, 0);

    response.Reset();

    EXPECT_TRUE(response.GetResult().empty());
    EXPECT_TRUE(response.GetHeader().empty());
    EXPECT_TRUE(response.GetsetCookie().empty());
    EXPECT_TRUE(response.GetCookies().empty());
    EXPECT_EQ(response.GetResponseCode(), ResponseCode::NONE);
    EXPECT_TRUE(response.GetRequestTime().empty());
    EXPECT_TRUE(response.GetResponseTime().empty());
    EXPECT_TRUE(response.GetHttpStatistics().serverIpAddress.address_.empty());
    PerformanceInfo performanceInfo = response.GetPerformanceTiming();
    EXPECT_EQ(performanceInfo.dnsTiming, 0);
    EXPECT_EQ(performanceInfo.connectTiming, 0);
    EXPECT_EQ(performanceInfo.tlsTiming, 0);
    EXPECT_EQ(performanceInfo.firstSendTiming, 0);
    EXPECT_EQ(performanceInfo.firstReceiveTiming, 0);
    EXPECT_EQ(performanceInfo.totalTiming, 0);
    EXPECT_EQ(performanceInfo.redirectTiming, 0);
}

HWTEST_F(HttpClientResponseTest, ResponseReset002, TestSize.Level1)
{
    HttpClientResponse response;

    // first round: populate then reset, verifying Reset clears populated state (not just ctor defaults)
    response.SetResult("first body");
    response.SetResponseCode(ResponseCode::OK);
    response.SetRequestTime("2024-01-01 00:00:00");
    response.performanceInfo_.dnsTiming = 12.5;
    response.Reset();
    EXPECT_TRUE(response.GetResult().empty());
    EXPECT_TRUE(response.GetHeader().empty());
    EXPECT_TRUE(response.GetsetCookie().empty());
    EXPECT_TRUE(response.GetCookies().empty());
    EXPECT_EQ(response.GetResponseCode(), ResponseCode::NONE);
    EXPECT_TRUE(response.GetRequestTime().empty());
    EXPECT_TRUE(response.GetResponseTime().empty());
    EXPECT_TRUE(response.GetHttpStatistics().serverIpAddress.address_.empty());
    EXPECT_EQ(response.GetPerformanceTiming().dnsTiming, 0);
    EXPECT_EQ(response.GetPerformanceTiming().totalTiming, 0);

    // second round: reuse the same object (redirect/handover scenario), populate with new values then reset
    response.SetResult("redirected body");
    response.SetResponseCode(ResponseCode::MOVED_PERM);
    response.SetResponseTime("2024-01-01 00:00:05");
    response.performanceInfo_.totalTiming = 88.8;
    response.Reset();
    EXPECT_TRUE(response.GetResult().empty());
    EXPECT_EQ(response.GetResponseCode(), ResponseCode::NONE);
    EXPECT_TRUE(response.GetResponseTime().empty());
    EXPECT_EQ(response.GetPerformanceTiming().totalTiming, 0);
}

HWTEST_F(HttpClientResponseTest, ResponseReset003, TestSize.Level1)
{
    HttpClientResponse response;
    response.SetExpectDataType(HttpDataType::STRING);
    EXPECT_EQ(response.GetExpectDataType(), HttpDataType::STRING);

    response.Reset();

    EXPECT_EQ(response.GetExpectDataType(), HttpDataType::STRING);
}
} // namespace
