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
#include "parameters.h"

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
    EventReport::GetInstance().validFlag_ = true;
    ASSERT_EQ(EventReport::GetInstance().IsValid(), true);
}
 
HWTEST_F(NetStackHiSysEventTest, IsValid_ShouldReturnFalse_WhenValidFlagIsFalse, TestSize.Level0)
{
    EventReport::GetInstance().validFlag_ = false;
    ASSERT_EQ(EventReport::GetInstance().IsValid(), false);
}
 
HWTEST_F(NetStackHiSysEventTest, ProcessHttpHiSysevent_01, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 0.0;
    EventReport::GetInstance().ProcessEvents(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.successCount, 0);
}
 
HWTEST_F(NetStackHiSysEventTest, ProcessHttpHiSysevent_02, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    EventReport::GetInstance().ProcessEvents(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.successCount, 1);
}
 
HWTEST_F(NetStackHiSysEventTest, ProcessHttpHiSysevent_03, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    EventReport::GetInstance().reportTime_ = time(0) - REPORT_INTERVAL - 1;
    EventReport::GetInstance().ProcessEvents(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalTime, 0);
}
 
HWTEST_F(NetStackHiSysEventTest, ProcessHttpHiSysevent_04, TestSize.Level0)
{
    HttpPerfInfo httpPerfInfo;
    httpPerfInfo.responseCode = 200;
    httpPerfInfo.totalTime = 100.0;
    httpPerfInfo.version = "1";
    uint32_t preSuccessCount = EventReport::GetInstance().eventInfo_.successCount;
    EventReport::GetInstance().reportTime_ = time(0) - REPORT_INTERVAL + 1;
    EventReport::GetInstance().ProcessEvents(httpPerfInfo);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.successCount, preSuccessCount + 1);
}
 
HWTEST_F(NetStackHiSysEventTest, ResetCounters_ShouldResetAllCountersToZero_WhenCalled, TestSize.Level0)
{
    EventReport::GetInstance().eventInfo_.totalCount = 10;
    EventReport::GetInstance().eventInfo_.successCount = 5;
    EventReport::GetInstance().eventInfo_.totalTime = 10.0;
    EventReport::GetInstance().eventInfo_.totalRate = 5.0;
    EventReport::GetInstance().eventInfo_.totalDnsTime = 2.0;
    EventReport::GetInstance().eventInfo_.totalTlsTime = 3.0;
    EventReport::GetInstance().eventInfo_.totalTcpTime = 4.0;
    EventReport::GetInstance().eventInfo_.totalFirstRecvTime = 1.0;
    EventReport::GetInstance().versionMap_.insert(std::make_pair("1.0", 1));
 
    EventReport::GetInstance().ResetCounters();
 
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalCount, 0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.successCount, 0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalRate, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalDnsTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalTlsTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalTcpTime, 0.0);
    EXPECT_EQ(EventReport::GetInstance().eventInfo_.totalFirstRecvTime, 0.0);
    EXPECT_TRUE(EventReport::GetInstance().versionMap_.empty());
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
}  // namespace OHOS::NetStack