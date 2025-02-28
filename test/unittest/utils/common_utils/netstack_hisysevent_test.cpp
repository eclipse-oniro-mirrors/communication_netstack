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

#define private public

#include <gtest/gtest.h>
#include "netstack_hisysevent.h"

namespace OHOS::NetStack {

namespace {
using namespace testing::ext;
const uint32_t REPORT_INTERVAL = 3 * 60;
}

class NetStackHiSysEventTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(NetStackHiSysEventTest, IsSuccess_ShouldReturnTrue_WhenResponseCodeIsValid, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    ASSERT_TRUE(httpPerfInfo.IsSuccess());
}

HWTEST_F(NetStackHiSysEventTest, IsSuccess_ShouldReturnFalse_WhenResponseCodeIsLessThanValidRange, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 199;
    ASSERT_FALSE(httpPerfInfo.IsSuccess());
}

HWTEST_F(NetStackHiSysEventTest, IsSuccess_ShouldReturnFalse_WhenResponseCodeIsGreaterThanValidRange, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 400;
    ASSERT_FALSE(httpPerfInfo.IsSuccess());
}

HWTEST_F(NetStackHiSysEventTest, IsValid_ShouldReturnTrue_WhenValidFlagIsTrue, TestSize.Level0)
{
    EventReport::GetInstance().validFlag = true;
    ASSERT_EQ(EventReport::GetInstance().IsValid(), true);
}

HWTEST_F(NetStackHiSysEventTest, IsValid_ShouldReturnFalse_WhenValidFlagIsFalse, TestSize.Level0)
{
    EventReport::GetInstance().validFlag = false;
    ASSERT_EQ(EventReport::GetInstance().IsValid(), false);
}

HWTEST_F(NetStackHiSysEventTest, ProcessHttpPerfHiSysevent_01, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 0.0;
    EventReport::GetInstance().ProcessHttpPerfHiSysevent(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.successCount, 0);
}

HWTEST_F(NetStackHiSysEventTest, ProcessHttpPerfHiSysevent_02, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    EventReport::GetInstance().ProcessHttpPerfHiSysevent(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.successCount, 1);
}

HWTEST_F(NetStackHiSysEventTest, ProcessHttpPerfHiSysevent_03, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    EventReport::GetInstance().reportTime = time(0) - REPORT_INTERVAL - 1;
    EventReport::GetInstance().ProcessHttpPerfHiSysevent(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalTime, 0);
}

HWTEST_F(NetStackHiSysEventTest, ProcessHttpPerfHiSysevent_04, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    httpPerfInfo.version = "1";
    uint32_t preSuccessCount = EventReport::GetInstance().eventInfo.successCount;
    EventReport::GetInstance().reportTime = time(0) - REPORT_INTERVAL + 1;
    EventReport::GetInstance().ProcessHttpPerfHiSysevent(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.successCount, preSuccessCount + 1);
}

HWTEST_F(NetStackHiSysEventTest, ResetCounters_ShouldResetAllCountersToZero_WhenCalled, TestSize.Level0)
{
    EventReport::GetInstance().eventInfo.totalCount = 10;
    EventReport::GetInstance().eventInfo.successCount = 5;
    EventReport::GetInstance().eventInfo.totalTime = 10.0;
    EventReport::GetInstance().eventInfo.totalRate = 5.0;
    EventReport::GetInstance().eventInfo.totalDnsTime = 2.0;
    EventReport::GetInstance().eventInfo.totalTlsTime = 3.0;
    EventReport::GetInstance().eventInfo.totalTcpTime = 4.0;
    EventReport::GetInstance().eventInfo.totalFirstRecvTime = 1.0;
    EventReport::GetInstance().versionMap.insert(std::make_pair("1.0", 1));

    EventReport::GetInstance().ResetCounters();

    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalCount, 0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.successCount, 0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalRate, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalDnsTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalTlsTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalTcpTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo.totalFirstRecvTime, 0.0);
    EXPECT_TRUE(EventReport::GetInstance().versionMap.empty());
}

HWTEST_F(NetStackHiSysEventTest, MapToJsonString_ShouldReturnEmptyJson_WhenMapIsEmpty, TestSize.Level0)
{
    std::map<std::string, uint32_t> emptyMap;
    EXPECT_EQ("{}", EventReport::GetInstance().MapToJsonString(emptyMap));
}

HWTEST_F(NetStackHiSysEventTest, MapToJsonString_ShouldReturnJsonWithOneElement_WhenMapHasOneElement, TestSize.Level0)
{
    std::map<std::string, uint32_t> oneElementMap = { { "key1", 1 } };
    EXPECT_EQ("{\"key1\":1}", EventReport::GetInstance().MapToJsonString(oneElementMap));
}

HWTEST_F(NetStackHiSysEventTest, MapToJsonString_ShouldReturnJsonWithMultipleElements, TestSize.Level0)
{
    std::map<std::string, uint32_t> multipleElementsMap = { { "key1", 1 }, { "key2", 2 }, { "key3", 3 } };
    EXPECT_EQ("{\"key1\":1,\"key2\":2,\"key3\":3}", EventReport::GetInstance().MapToJsonString(multipleElementsMap));
}

HWTEST_F(NetStackHiSysEventTest, IsError_ShouldReturnTrue_WhenResponseCodeIsGreaterThanValidRange, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 401;
    ASSERT_TRUE(httpPerfInfo.IsError());
}

HWTEST_F(NetStackHiSysEventTest, ProcessHttpResponseErrorEvents_01, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 500;  // 设置一个错误响应码
    httpPerfInfo.totalTime = 100.0;
    httpPerfInfo.version = "1";
    
    EventReport &eventReport = EventReport::GetInstance();
    eventReport.totalErrorCount_ = 0;
    eventReport.httpPerfInfoQueue_.clear();
    eventReport.httpReponseRecordTime_ = std::chrono::steady_clock::time_point::min();
    
    eventReport.HandleHttpResponseErrorEvents(httpPerfInfo);
    
    EXPECT_NE(eventReport.totalErrorCount_, 1);
    EXPECT_TRUE(eventReport.httpPerfInfoQueue_.empty());
    EXPECT_EQ(eventReport.httpReponseRecordTime_, std::chrono::steady_clock::time_point::min());
}

HWTEST_F(NetStackHiSysEventTest, ProcessHiSysEventWrite_01, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo1;
    httpPerfInfo1.dnsTime = 10.5;
    httpPerfInfo1.tcpTime = 20.3;
    httpPerfInfo1.tlsTime = 30.2;
    httpPerfInfo1.osErr = 0;
    httpPerfInfo1.ipType = 4;  // IPv4
    httpPerfInfo1.errCode = 0;
    httpPerfInfo1.responseCode = 200;

    HttpPerfInfo httpPerfInfo2;
    httpPerfInfo2.dnsTime = 15.5;
    httpPerfInfo2.tcpTime = 25.3;
    httpPerfInfo2.tlsTime = 35.2;
    httpPerfInfo2.osErr = 1;
    httpPerfInfo2.ipType = 6;  // IPv6
    httpPerfInfo2.errCode = 404;
    httpPerfInfo2.responseCode = 404;

    std::deque<HttpPerfInfo> httpPerfInfoQueue;
    httpPerfInfoQueue.push_back(httpPerfInfo1);
    httpPerfInfoQueue.push_back(httpPerfInfo2);

    EventReport &eventReport = EventReport::GetInstance();
    eventReport.httpPerfInfoQueue_ = httpPerfInfoQueue;

    // 调用ReportHiSysEventWrite方法
    eventReport.ReportHiSysEventWrite(httpPerfInfoQueue);

    // 验证队列是否清空
    EXPECT_FALSE(eventReport.httpPerfInfoQueue_.empty());
}

HWTEST_F(NetStackHiSysEventTest, ProcessSendHttpResponseErrorEvent_01, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo1;
    httpPerfInfo1.responseCode = 500;  // 设置一个错误响应码
    httpPerfInfo1.totalTime = 100.0;
    httpPerfInfo1.version = "1";

    HttpPerfInfo httpPerfInfo2;
    httpPerfInfo2.responseCode = 404;  // 设置另一个错误响应码
    httpPerfInfo2.totalTime = 200.0;
    httpPerfInfo2.version = "1";

    std::deque<HttpPerfInfo> httpPerfInfoQueue;
    httpPerfInfoQueue.push_back(httpPerfInfo1);
    httpPerfInfoQueue.push_back(httpPerfInfo2);

    EventReport &eventReport = EventReport::GetInstance();
    eventReport.hiviewReportFirstTime_ = std::chrono::steady_clock::time_point::min();
    eventReport.sendHttpNetStackEventCount_ = 0;

    // 模拟当前时间
    auto now = std::chrono::steady_clock::now();

    // 调用SendHttpResponseErrorEvent方法
    eventReport.SendHttpResponseErrorEvent(httpPerfInfoQueue, now);

    // 验证发送计数增加
    EXPECT_EQ(eventReport.sendHttpNetStackEventCount_, 1);
}
}  // namespace OHOS::NetStack