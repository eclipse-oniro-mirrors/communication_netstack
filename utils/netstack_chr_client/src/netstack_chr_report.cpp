/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "i_netstack_chr_client.h"
#include "netstack_chr_report.h"
#include "netstack_log.h"
#include "common_event_manager.h"

using namespace OHOS::NetStack::ChrClient;

static constexpr const char* REPORT_HTTP_EVENT_NAME = "custom.event.CHR_REPORT_HTTP";
static constexpr const std::int32_t CHR_UID = 1201;
static constexpr const int REPORT_TIME_LIMIT_MINUTE = 5;

static constexpr const int REPORT_CHR_RESULT_SUCCESS = 0;
static constexpr const int REPORT_CHR_RESULT_TIME_LIMIT_ERROR = 1;
static constexpr const int REPORT_CHR_RESULT_REPORT_FAIL = 2;

NetStackChrReport::NetStackChrReport()
{}

NetStackChrReport::~NetStackChrReport()
{}

int NetStackChrReport::ReportCommonEvent(DataTransChrStats chrStats)
{
    std::lock_guard<std::mutex> lock(report_mutex_);
    auto currentTime = std::chrono::system_clock::now();
    auto timeDifference = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastReceivedTime_);
    if (timeDifference.count() < REPORT_TIME_LIMIT_MINUTE) {
        ignoreReportTimes_ += 1;
        return REPORT_CHR_RESULT_TIME_LIMIT_ERROR;
    }
    AAFwk::Want want;
    want.SetAction(REPORT_HTTP_EVENT_NAME);
    SetWantParam(want, chrStats);

    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberUid({CHR_UID});
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo)) {
        NETSTACK_LOGE("Subscriber is nullptr, report to CHR failed.");
        return REPORT_CHR_RESULT_REPORT_FAIL;
    }
    NETSTACK_LOGI("Report to CHR success, %{public}d reports are ignore before this.", ignoreReportTimes_);
    lastReceivedTime_ = currentTime;
    ignoreReportTimes_ = 0;

    return REPORT_CHR_RESULT_SUCCESS;
}

void NetStackChrReport::SetWantParam(AAFwk::Want& want, DataTransChrStats chrStats)
{
    std::string httpInfoJsonStr;
    std::string tcpInfoJsonStr;
    SetHttpInfoJsonStr(chrStats.httpInfo, httpInfoJsonStr);
    SetTcpInfoJsonStr(chrStats.tcpInfo, tcpInfoJsonStr);

    want.SetParam("PROCESS_NAME", chrStats.processName);
    want.SetParam("DATA_TRANS_HTTP_INFO", httpInfoJsonStr);
    want.SetParam("DATA_TRANS_TCP_INFO", tcpInfoJsonStr);
}

void NetStackChrReport::SetHttpInfoJsonStr(DataTransHttpInfo httpInfo, std::string& httpInfoJsonStr)
{
    httpInfoJsonStr =
        "{\"uid\":" + std::to_string(httpInfo.uid) +
        ",{\"response_code\":" + std::to_string(httpInfo.responseCode) +
        ",{\"total_time\":" + std::to_string(httpInfo.totalTime) +
        ",{\"namelookup_time\":" + std::to_string(httpInfo.nameLookUpTime) +
        ",{\"connect_time\":" + std::to_string(httpInfo.connectTime) +
        ",{\"pretransfer_time\":" + std::to_string(httpInfo.preTransferTime) +
        ",{\"size_upload\":" + std::to_string(httpInfo.sizeUpload) +
        ",{\"size_download\":" + std::to_string(httpInfo.sizeDownload) +
        ",{\"speed_download\":" + std::to_string(httpInfo.speedDownload) +
        ",{\"speed_upload\":" + std::to_string(httpInfo.speedUpload) +
        ",{\"effective_method\":\"" + httpInfo.effectiveMethod +
        "\",{\"starttransfer_time\":" + std::to_string(httpInfo.startTransferTime) +
        ",{\"content_type\":\"" + httpInfo.contentType +
        "\",{\"redirect_time\":" + std::to_string(httpInfo.redirectTime) +
        ",{\"redirect_count\":" + std::to_string(httpInfo.redirectCount) +
        ",{\"os_errno\":" + std::to_string(httpInfo.osError) +
        ",{\"ssl_verifyresult\":" + std::to_string(httpInfo.sslVerifyResult) +
        ",{\"appconnect_time\":" + std::to_string(httpInfo.appconnectTime) +
        ",{\"retry_after\":" + std::to_string(httpInfo.uid) +
        ",{\"proxy_error\":" + std::to_string(httpInfo.proxyError) +
        ",{\"queue_time\":" + std::to_string(httpInfo.queueTime) +
        ",{\"curl_code\":" + std::to_string(httpInfo.curlCode) +
        ",{\"request_start_time\":" + std::to_string(httpInfo.requestStartTime) + "}";
}

void NetStackChrReport::SetTcpInfoJsonStr(DataTransTcpInfo tcpInfo, std::string& tcpInfoJsonStr)
{
    tcpInfoJsonStr =
        "{\"tcpi_unacked\":" + std::to_string(tcpInfo.unacked) +
        ",{\"tcpi_last_data_sent\":" + std::to_string(tcpInfo.lastDataSent) +
        ",{\"tcpi_last_ack_sent\":" + std::to_string(tcpInfo.lastAckSent) +
        ",{\"tcpi_last_data_recv\":" + std::to_string(tcpInfo.lastDataRecv) +
        ",{\"tcpi_last_ack_recv\":" + std::to_string(tcpInfo.lastAckRecv) +
        ",{\"tcpi_rtt\":" + std::to_string(tcpInfo.rtt) +
        ",{\"tcpi_rttvar\":" + std::to_string(tcpInfo.rttvar) +
        ",{\"tcpi_retransmits\":" + std::to_string(tcpInfo.retransmits) +
        ",{\"tcpi_total_retrans\":" + std::to_string(tcpInfo.totalRetrans) +
        ",{\"src_ip\":\"" + tcpInfo.srcIp +
        "\",{\"dst_ip\":\"" + tcpInfo.dstIp +
        "\",{\"src_port\":" + std::to_string(tcpInfo.srcPort) +
        ",{\"dst_port\":" + std::to_string(tcpInfo.dstPort) + "}";
}