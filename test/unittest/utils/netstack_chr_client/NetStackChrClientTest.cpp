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

void FillNormalvalue(ChrClient::DataTransChrStats& chrStats)
{
    chrStats.processName = "CHR_Unit_Test_Case";

    chrStats.httpInfo.uid = 100;
    chrStats.httpInfo.responseCode = 200;
    chrStats.httpInfo.totalTime = 500000;
    chrStats.httpInfo.nameLookUpTime = 10000;
    chrStats.httpInfo.connectTime = 50000;
    chrStats.httpInfo.preTransferTime = 80000;
    chrStats.httpInfo.sizeUpload = 30;
    chrStats.httpInfo.sizeDownload = 60;
    chrStats.httpInfo.speedDownload = 440;
    chrStats.httpInfo.speedUpload = 180;
    chrStats.httpInfo.effectiveMethod = "POST";
    chrStats.httpInfo.startTransferTime = "application/json; charset=utf-8";
    chrStats.httpInfo.contentType = 0;
    chrStats.httpInfo.redirectTime = 0;
    chrStats.httpInfo.redirectCount = 0;
    chrStats.httpInfo.osError = 0;
    chrStats.httpInfo.sslVerifyResult= 0;
    chrStats.httpInfo.appconnectTime = 80000;
    chrStats.httpInfo.retryAfter = 0;
    chrStats.httpInfo.proxyError = 0;
    chrStats.httpInfo.queueTime = 12000;
    chrStats.httpInfo.curlCode = 0;
    chrStats.httpInfo.requestStartTime = 1747359000000;

    chrStats.tcpInfo.unacked = 0;
    chrStats.tcpInfo.lastDataSent = 1000;
    chrStats.tcpInfo.lastAckSent = 0;
    chrStats.tcpInfo.lastDataRecv 1000;
    chrStats.tcpInfo.lastAckRecv = 1000;
    chrStats.tcpInfo.rtt = 12000;
    chrStats.tcpInfo.rttvar = 4000;
    chrStats.tcpInfo.retransmits = 0;
    chrStats.tcpInfo.totalRetrans = 0;
    chrStats.tcpInfo.srcIp = "7.246.***.***";
    chrStats.tcpInfo.dstIp = "7.246.***.***";
    chrStats.tcpInfo.srcPort = 54000;
    chrStats.tcpInfo.dstPort = 54000;
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestResponseCode, TestSize.Level2)
{
    CURL *handle = GetCurlHandle();
    ChrClient::NetStackChrClient::GetInstance().GetDfxInfoFromCurlHandleAndReport(NULL, 0);
    ChrClient::NetStackChrClient::GetInstance().GetDfxInfoFromCurlHandleAndReport(handle, 0);
    ChrClient::DataTransChrStats dataTransChrStats{};
    ChrClient::NetStackChrClient::GetInstance().GetHttpInfoFromCurl(handle, dataTransChrStats.httpInfo);
    EXPECT_EQ(dataTransChrStats.httpInfo.responseCode, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestPort, TestSize.Level2)
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

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestNotReport, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, -1);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestResponseCodeError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    chrStats.httpInfo.responseCode = 301;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestOSError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    chrStats.httpInfo.osError = 1;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestProxyError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    chrStats.httpInfo.proxyError = 1;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestCurlCodeError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    chrStats.httpInfo.curlCode = 1;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestShortRequestButTimeout, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);
    
    chrStats.httpInfo.sizeUpload = 50000;
    chrStats.httpInfo.sizeDownload = 50000;
    chrStats.httpInfo.totalTime = 501000;
    int res = ChrClient::NetStackChrClient::GetInstance().shouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestTimeLimits, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    
    netstackChrReport.ReportCommonEvent(chrStats);
    int second_ret = netstackChrReport.ReportCommonEvent(chrStats);
    EXPECT_EQ(second_ret, -1);
}