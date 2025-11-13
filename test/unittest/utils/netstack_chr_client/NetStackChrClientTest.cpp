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
static constexpr const char *REQUEST_URL = "https://127.0.0.1";

static constexpr const char *PROCESS_NAME_DEFAULT_VALUE = "CHR_UT";

static constexpr const int UID_DEFAULT_VALUE = 100;
static constexpr const long RESPONSE_CODE_DEFAULT_VALUE = 200;
static constexpr const curl_off_t TOTAL_TIME_DEFAULT_VALUE = 500000;
static constexpr const curl_off_t NAME_LOOK_UP_TIME_DEFAULT_VALUE = 10000;
static constexpr const curl_off_t CONNECT_TIME_DEFAULT_VALUE = 50000;
static constexpr const curl_off_t PRE_TRANSFER_TIME_DEFAULT_VALUE = 80000;
static constexpr const curl_off_t SIZE_UPLOAD_DEFAULT_VALUE = 30;
static constexpr const curl_off_t SIZE_DOWNLOAD_DEFAULT_VALUE = 60;
static constexpr const curl_off_t SPEED_DOWNLOAD_DEFAULT_VALUE = 440;
static constexpr const curl_off_t SPEED_UPLOAD_DEFAULT_VALUE = 180;
static constexpr const char *EFFECTIVE_METHOD_DEFAULT_VALUE = "POST";
static constexpr const curl_off_t START_TRANSFER_TIME_DEFAULT_VALUE = 500;
static constexpr const char *CONTENT_TYPE_DEFAULT_VALUE = "application/json; charset=utf-8";
static constexpr const curl_off_t REDIRECT_TIME_DEFAULT_VALUE = 0;
static constexpr const long REDIRECT_COUNT_DEFAULT_VALUE = 0;
static constexpr const long OS_ERROR_DEFAULT_VALUE = 0;
static constexpr const long SSL_VERIFYRESULT_DEFAULT_VALUE = 0;
static constexpr const curl_off_t APPCONNECT_TIME_DEFAULT_VALUE = 80000;
static constexpr const curl_off_t RETRY_AFTER_DEFAULT_VALUE = 0;
static constexpr const long PROXY_ERROR_DEFAULT_VALUE = 0;
static constexpr const curl_off_t QUEUE_TIME_DEFAULT_VALUE = 12000;
static constexpr const long CURL_CODE_DEFAULT_VALUE = 0;
static constexpr const long REQUEST_START_TIME_DEFAULT_VALUE = 1747359000000;

static constexpr const uint32_t UNACKED_DEFAULT_VALUE = 0;
static constexpr const uint32_t LAST_DATA_SENT_DEFAULT_VALUE = 1000;
static constexpr const uint32_t LAST_ACK_SENT_DEFAULT_VALUE = 0;
static constexpr const uint32_t LAST_DATA_RECV_DEFAULT_VALUE = 1000;
static constexpr const uint32_t LAST_ACK_RECV_DEFAULT_VALUE = 1000;
static constexpr const uint32_t RTT_DEFAULT_VALUE = 12000;
static constexpr const uint32_t RTTVAR_DEFAULT_VALUE = 4000;
static constexpr const uint16_t RETRANSMITS_DEFAULT_VALUE = 0;
static constexpr const uint32_t TOTAL_RETRANS_DEFAULT_VALUE = 0;
static constexpr const char *SRC_IP_DEFAULT_VALUE = "7.246.***.***";
static constexpr const char *DST_IP_DEFAULT_VALUE = "7.246.***.***";
static constexpr const uint16_t SRC_PORT_DEFAULT_VALUE = 54000;
static constexpr const uint16_t DST_PORT_DEFAULT_VALUE = 54000;

static constexpr const long RESPONSE_ERROR_CODE_BELOW = 101;
static constexpr const long RESPONSE_ERROR_CODE_BEYOND = 301;
static constexpr const long OS_ERROR_CODE = 1;
static constexpr const long PROXY_ERROR_CODE = 1;
static constexpr const long CURL_ERROR_CODE = 1;
static constexpr const curl_off_t SIZE_UPLOAD_TEST = 50000;
static constexpr const curl_off_t SIZE_DOWNLOAD_TEST = 50000;
static constexpr const curl_off_t TOTAL_TIME_TEST = 501000;

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
    chrStats.processName = PROCESS_NAME_DEFAULT_VALUE;

    chrStats.httpInfo.uid = UID_DEFAULT_VALUE;
    chrStats.httpInfo.responseCode = RESPONSE_CODE_DEFAULT_VALUE;
    chrStats.httpInfo.totalTime = TOTAL_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.nameLookUpTime = NAME_LOOK_UP_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.connectTime = CONNECT_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.preTransferTime = PRE_TRANSFER_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.sizeUpload = SIZE_UPLOAD_DEFAULT_VALUE;
    chrStats.httpInfo.sizeDownload = SIZE_DOWNLOAD_DEFAULT_VALUE;
    chrStats.httpInfo.speedDownload = SPEED_DOWNLOAD_DEFAULT_VALUE;
    chrStats.httpInfo.speedUpload = SPEED_UPLOAD_DEFAULT_VALUE;
    chrStats.httpInfo.effectiveMethod = EFFECTIVE_METHOD_DEFAULT_VALUE;
    chrStats.httpInfo.startTransferTime = START_TRANSFER_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.contentType = CONTENT_TYPE_DEFAULT_VALUE;
    chrStats.httpInfo.redirectTime = REDIRECT_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.redirectCount = REDIRECT_COUNT_DEFAULT_VALUE;
    chrStats.httpInfo.osError = OS_ERROR_DEFAULT_VALUE;
    chrStats.httpInfo.sslVerifyResult= SSL_VERIFYRESULT_DEFAULT_VALUE;
    chrStats.httpInfo.appconnectTime = APPCONNECT_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.retryAfter = RETRY_AFTER_DEFAULT_VALUE;
    chrStats.httpInfo.proxyError = PROXY_ERROR_DEFAULT_VALUE;
    chrStats.httpInfo.queueTime = QUEUE_TIME_DEFAULT_VALUE;
    chrStats.httpInfo.curlCode = CURL_CODE_DEFAULT_VALUE;
    chrStats.httpInfo.requestStartTime = REQUEST_START_TIME_DEFAULT_VALUE;

    chrStats.tcpInfo.unacked = UNACKED_DEFAULT_VALUE;
    chrStats.tcpInfo.lastDataSent = LAST_DATA_SENT_DEFAULT_VALUE;
    chrStats.tcpInfo.lastAckSent = LAST_ACK_SENT_DEFAULT_VALUE;
    chrStats.tcpInfo.lastDataRecv = LAST_DATA_RECV_DEFAULT_VALUE;
    chrStats.tcpInfo.lastAckRecv = LAST_ACK_RECV_DEFAULT_VALUE;
    chrStats.tcpInfo.rtt = RTT_DEFAULT_VALUE;
    chrStats.tcpInfo.rttvar = RTTVAR_DEFAULT_VALUE;
    chrStats.tcpInfo.retransmits = RETRANSMITS_DEFAULT_VALUE;
    chrStats.tcpInfo.totalRetrans = TOTAL_RETRANS_DEFAULT_VALUE;
    chrStats.tcpInfo.srcIp = SRC_IP_DEFAULT_VALUE;
    chrStats.tcpInfo.dstIp = DST_IP_DEFAULT_VALUE;
    chrStats.tcpInfo.srcPort = SRC_PORT_DEFAULT_VALUE;
    chrStats.tcpInfo.dstPort = DST_PORT_DEFAULT_VALUE;
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

    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, -1);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestResponseCodeError1, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);

    chrStats.httpInfo.responseCode = RESPONSE_ERROR_CODE_BELOW;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
    
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestResponseCodeError2, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalValue(chrStats);
    chrStats.httpInfo.responseCode = RESPONSE_ERROR_CODE_BEYOND;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestOSError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);

    chrStats.httpInfo.osError = OS_ERROR_CODE;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestProxyError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);

    chrStats.httpInfo.proxyError = PROXY_ERROR_CODE;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestCurlCodeError, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);

    chrStats.httpInfo.curlCode = CURL_ERROR_CODE;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestShortRequestButTimeout, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;
    FillNormalvalue(chrStats);

    chrStats.httpInfo.sizeUpload = SIZE_UPLOAD_TEST;
    chrStats.httpInfo.sizeDownload = SIZE_DOWNLOAD_TEST;
    chrStats.httpInfo.totalTime = TOTAL_TIME_TEST;
    int res = ChrClient::NetStackChrClient::GetInstance().ShouldReportHttpAbnormalEvent(chrStats.httpInfo);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NetStackChrClientTest, NetStackChrClientTestTimeLimits, TestSize.Level2)
{
    ChrClient::NetStackChrReport netstackChrReport;
    ChrClient::DataTransChrStats chrStats;

    netstackChrReport.ReportCommonEvent(chrStats);
    int second_ret = netstackChrReport.ReportCommonEvent(chrStats);
    EXPECT_EQ(second_ret, 1);
}
}