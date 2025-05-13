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
#include <iostream>

#include "curl/curl.h"
#include "netstack_chr_client.h"
#include "netstack_chr_report.h"
#include "want.h"

namespace OHOS::NetStack {
namespace {
using namespace testing::ext;
// static constexpr const char *REQUEST_ID = "123";
// static constexpr const char *HTTP_VERSION_2 = "2";
static constexpr const char *REQUEST_URL = "https://127.0.0.1";
// static constexpr const char *REQUEST_ID_ADDRESS = "127.0.0.1";
// static constexpr const char *REQUEST_STRING = "unused";
// static constexpr const char *REQUEST_HEADERS = "HTTP/1.1 200 OK\r\nk:v";
// static constexpr const char *REQUEST_REASON_PARSE = "OK";
// static constexpr const uint64_t REQUEST_BEGIN_TIME = 100;
// static constexpr const double REQUEST_DNS_TIME = 10;

CURL *GetCurlHandle()
{
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, REQUEST_URL);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    return handle;
}
}

class NetStackChrClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest001, TestSize.Level2)
{
    CURL *handle = GetCurlHandle();
    ChrClient::NetStackChrClient::GetInstance().GetDfxInfoFromCurlHandleAndReport(NULL, 0);
    ChrClient::NetStackChrClient::GetInstance().GetDfxInfoFromCurlHandleAndReport(handle, 0);
    ChrClient::DataTransChrStats dataTransChrStats{};
    ChrClient::NetStackChrClient::GetInstance().GetHttpInfoFromCurl(handle, dataTransChrStats.httpInfo);
    EXPECT_EQ(dataTransChrStats.httpInfo.responseCode, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest002, TestSize.Level2)
{
    ChrClient::DataTransTcpInfo tcpInfo;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd >0) {
        ChrClient::NetStackChrClient::GetInstance().GetTcpInfoFromSock(sockfd, tcpInfo);
        EXPECT_EQ(tcpInfo.unacked, 0);
        EXPECT_EQ(tcpInfo.srcPort, 0);
        EXPECT_EQ(tcpInfo.dstPort, 0);
        close(sockfd);
    }
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd > 0) {
        ChrClient::NetStackChrClient::GetInstance().GetTcpInfoFromSock(sockfd, tcpInfo);
        EXPECT_EQ(tcpInfo.unacked, 0);
        EXPECT_EQ(tcpInfo.srcPort, 0);
        EXPECT_EQ(tcpInfo.dstPort, 0);
        close(sockfd);
    }
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest003, TestSize.Level2)
{
    ChrClient::DataTransHttpInfo httpInfo;
    httpInfo.curlCode = 0;
    httpInfo.responseCode = 200;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(httpInfo);
    EXPECT_EQ(res, -1);

    httpInfo.curlCode = 1;
    res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(httpInfo);
    EXPECT_EQ(res, 0);

    httpInfo.curlCode = 0;
    httpInfo.responseCode = 500001;
    res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest004, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    AAFwk::Want want;

    chrStats.processName = "process_name_test";
    netstackChrReport.SetWantParam(want, chrStats);

    std::string processNameTest = want.GetStringParam("PROCESS_NAME");
    EXPECT_EQ(processNameTest, "process_name_test");
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest005, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    AAFwk::Want want;

    chrStats.httpInfo.totalTime = 100;
    netstackChrReport.SetHttpInfo(want, chrStats.httpInfo);

    std::string httpInfoStr = want.GetStringParam("DATA_TRANS_HTTP_INFO");
    const auto &httpWant = AAFwk::Want::FromString(httpInfoStr);
    long totalTimeTRes = httpWant->GetLongParam("total_time", -1);
    EXPECT_EQ(totalTimeTRes, 100);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest006, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    AAFwk::Want want;

    chrStats.tcpInfo.rtt = 200;
    netstackChrReport.SetTcpInfo(want, chrStats.tcpInfo);

    std::string tcpInfoStr = want.GetStringParam("DATA_TRANS_TCP_INFO");
    const auto &tcpWant = AAFwk::Want::FromString(tcpInfoStr);
    int rttRes = httpWant->GetIntParam("tcpi_rtt", -1);
    EXPECT_EQ(rttRes, 200);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTest007, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    
    netstackChrReport.ReportCommonEvent(chrStats);
    int second_ret = netstackChrReport.ReportCommonEvent(chrStats);
    EXPECT_EQ(second_ret, -1);
}